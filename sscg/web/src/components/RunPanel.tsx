import { useEffect, useMemo, useState } from "react";
import { Bot, FolderOpen, GitBranch, Play, ShieldCheck } from "lucide-react";
import { api, Meta, Targets } from "../api";
import { Button, Callout, Field, inputCls, Segmented, Toggle } from "./ui";

const LLM_LABEL: Record<string, string> = {
  auto: "Auto (first key found)", claude: "Claude (Anthropic)", gemini: "Gemini (Google)", groq: "Groq",
  deepseek: "DeepSeek", grok: "Grok (xAI)", none: "None: rules only, nothing leaves the machine",
};

const EXAMPLES = ["https://github.com/snyk-labs/nodejs-goof", "https://github.com/juice-shop/juice-shop", "https://github.com/OWASP/NodeGoat"];
const isUrl = (s: string) => /^https:\/\/[^/\s]+\/[^/\s]+\/[^/\s]+/i.test(s.trim())
  || /^(github\.com|gitlab\.com|bitbucket\.org)\/[\w.-]+\/[\w.-]+/i.test(s.trim());

export function RunPanel({ meta, targets, initialRepo, onStarted }:
  { meta: Meta | null; targets: Targets | null; initialRepo?: string; onStarted: (jobId: string, project: string) => void }) {
  const presets = targets?.presets || [];
  const startsRemote = !initialRepo || isUrl(initialRepo);
  const [source, setSource] = useState<"url" | "folder">(startsRemote ? "url" : "folder");
  const [url, setUrl] = useState(startsRemote ? initialRepo || "" : "");
  const [folder, setFolder] = useState(!startsRemote ? initialRepo! : presets.find((p) => p.name === "sscg-demo-target")?.path || presets[0]?.path || "");
  const repo = source === "url" ? url.trim() : folder.trim();
  const examples = [...new Set([...(targets?.fetched || []).map((f) => f.url), ...EXAMPLES])].slice(0, 6);
  const urlInvalid = source === "url" && !!url.trim() && !isUrl(url);
  const [mode, setMode] = useState<"scan" | "agent" | "remediation">("remediation");
  const [llm, setLlm] = useState(meta?.llm_default || "auto");
  const [osv, setOsv] = useState(true);
  const [offline, setOffline] = useState(false);
  const [base, setBase] = useState("HEAD~1");
  const [focus, setFocus] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => { if (meta) setLlm(meta.llm_default); }, [meta]);
  const keyless = useMemo(() => llm !== "none" && meta && (llm === "auto" ? !Object.values(meta.llm_keys).some(Boolean) : !meta.llm_keys[llm]), [llm, meta]);

  async function start() {
    setBusy(true); setErr(null);
    try {
      const job = await api.run({ repo, agentic: mode !== "scan", remediate: mode === "remediation", llm, osv, offline, base, focus });
      onStarted(job.id, job.project);
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  }

  return (
    <div className="space-y-5">
      <div>
        <div className="mb-2 flex items-center justify-between gap-3">
          <span className="text-xs font-medium text-slate-600">Repository</span>
          <Segmented value={source} onChange={setSource} options={[
            { id: "url", label: <span className="inline-flex items-center gap-1"><GitBranch className="h-3 w-3" /> Repository URL</span> },
            { id: "folder", label: <span className="inline-flex items-center gap-1"><FolderOpen className="h-3 w-3" /> Local folder</span> },
          ]} />
        </div>
        {source === "url" ? (
          <>
            <input className={inputCls + " font-mono text-xs"} value={url} onChange={(e) => setUrl(e.target.value)} autoFocus
              placeholder="https://github.com/owner/repository" />
            <p className={`mt-1.5 text-xs ${urlInvalid ? "text-red-600" : "text-slate-500"}`}>
              {urlInvalid ? "Use an https link, e.g. https://github.com/owner/repository"
                : "Any public https git repository (GitHub, GitLab, Bitbucket, …). Add /tree/<branch|tag|commit> for a specific version. It is fetched into sscg/repos/ with its full history; no credentials are used."}
            </p>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {examples.map((u) => (
                <button key={u} type="button" onClick={() => setUrl(u)}
                  className={`rounded-full px-3 py-1 font-mono text-[11px] ring-1 ring-inset ${url === u ? "bg-brand-600 text-white ring-brand-600" : "bg-white text-slate-600 ring-slate-300 hover:bg-slate-50"}`}>
                  {u.replace(/^https:\/\//, "")}
                </button>
              ))}
            </div>
          </>
        ) : (
          <>
            <div className="mb-2 flex flex-wrap gap-1.5">
              {presets.map((p) => (
                <button key={p.path} type="button" onClick={() => setFolder(p.path)}
                  className={`rounded-full px-3 py-1 text-xs font-medium ring-1 ring-inset ${folder === p.path ? "bg-brand-600 text-white ring-brand-600" : "bg-white text-slate-600 ring-slate-300 hover:bg-slate-50"}`}>
                  {p.name}
                </button>
              ))}
            </div>
            <input className={inputCls + " font-mono text-xs"} value={folder} onChange={(e) => setFolder(e.target.value)} placeholder="C:\path\to\repository" />
          </>
        )}
      </div>

      <div>
        <span className="mb-1.5 block text-xs font-medium text-slate-600">Pipeline</span>
        <Segmented value={mode} onChange={setMode} options={[
          { id: "scan", label: "Detect (rules only)" },
          { id: "agent", label: "Detect + AI agents" },
          { id: "remediation", label: "Full: detect → remediate" },
        ]} />
        <p className="mt-2 text-xs text-slate-500">
          {mode === "scan" && "Discovers components, builds the SBOM and dependency graph, and detects vulnerabilities and suspicious changes. Deterministic, no AI."}
          {mode === "agent" && "The same pipeline run as LangGraph agents, plus AI triage of suspicious changes and an AI summary."}
          {mode === "remediation" && "Adds prioritisation (KEV/EPSS + reachability) and remediation proposals. The run then pauses for your approval on the Remediation page."}
        </p>
      </div>

      {mode !== "scan" && (
        <Field label="LLM provider">
          <select className={inputCls} value={llm} onChange={(e) => setLlm(e.target.value)}>
            {(meta?.llm_choices || ["auto", "none"]).map((c) => (
              <option key={c} value={c}>{LLM_LABEL[c] || c}{c !== "auto" && c !== "none" && meta ? (meta.llm_keys[c] ? "  ✓ key set" : "  (no key)") : ""}</option>
            ))}
          </select>
          {keyless && <p className="mt-1.5 text-xs text-amber-700">No API key for this provider in sscg/.env: the agents will use the rules-only fallback.</p>}
        </Field>
      )}

      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Compare with commit" hint="Base revision for 'what changed'. Empty = skip the comparison.">
          <input className={inputCls + " font-mono text-xs"} value={base} onChange={(e) => setBase(e.target.value)} placeholder="HEAD~1" />
        </Field>
        <Field label="Focus graph on package (optional)">
          <input className={inputCls} value={focus} onChange={(e) => setFocus(e.target.value)} placeholder="e.g. lodash" />
        </Field>
      </div>
      <div className="flex flex-wrap gap-x-6 gap-y-3">
        <Toggle checked={osv} onChange={setOsv} label="Vulnerability lookup (OSV.dev)" />
        <Toggle checked={offline} onChange={setOffline} label="Offline (cache only)" />
      </div>

      <Callout tone="info" icon={<ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />}>
        Read-only: nothing from the repository is installed or run, and it is never modified. Fixes are applied only after human approval, in a temporary copy whose builds and tests run as local processes (secrets removed): validate only repositories you are authorised to run.
      </Callout>
      {err && <Callout tone="error">{err}</Callout>}
      <div className="flex justify-end">
        <Button variant="primary" onClick={start} disabled={busy || !repo || urlInvalid}>
          {mode === "scan" ? <Play className="h-4 w-4" /> : <Bot className="h-4 w-4" />} Start
        </Button>
      </div>
    </div>
  );
}
