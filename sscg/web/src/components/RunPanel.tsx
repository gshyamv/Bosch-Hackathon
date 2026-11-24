import { useEffect, useMemo, useState } from "react";
import { Bot, Play, ShieldCheck } from "lucide-react";
import { api, Meta, Targets } from "../api";
import { Button, Callout, Field, inputCls, Segmented, Toggle } from "./ui";

const LLM_LABEL: Record<string, string> = {
  auto: "Auto (first key found)", claude: "Claude (Anthropic)", gemini: "Gemini (Google)", groq: "Groq",
  deepseek: "DeepSeek", grok: "Grok (xAI)", ollama: "Ollama (local)", none: "None: rules only, nothing leaves the machine",
};

export function RunPanel({ meta, targets, initialRepo, onStarted }:
  { meta: Meta | null; targets: Targets | null; initialRepo?: string; onStarted: (jobId: string, project: string) => void }) {
  const presets = targets?.presets || [];
  const [repo, setRepo] = useState(initialRepo || presets.find((p) => p.name === "sscg-demo-target")?.path || presets[0]?.path || "");
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
      <Field label="Target: folder, GitHub URL or page URL">
        <div className="mb-2 flex flex-wrap gap-1.5">
          {presets.map((p) => (
            <button key={p.path} type="button" onClick={() => setRepo(p.path)}
              className={`rounded-full px-3 py-1 text-xs font-medium ring-1 ring-inset ${repo === p.path ? "bg-brand-600 text-white ring-brand-600" : "bg-white text-slate-600 ring-slate-300 hover:bg-slate-50"}`}>
              {p.name}
            </button>
          ))}
        </div>
        <input className={inputCls + " font-mono text-xs"} value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="https://github.com/owner/repo  or  C:\path\to\repository" />
      </Field>

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
        Read-only: the repository is never modified. Fixes are applied and built only in a sandbox copy, and only after human approval.
      </Callout>
      {err && <Callout tone="error">{err}</Callout>}
      <div className="flex justify-end">
        <Button variant="primary" onClick={start} disabled={busy || !repo.trim()}>
          {mode === "scan" ? <Play className="h-4 w-4" /> : <Bot className="h-4 w-4" />} Start
        </Button>
      </div>
    </div>
  );
}
