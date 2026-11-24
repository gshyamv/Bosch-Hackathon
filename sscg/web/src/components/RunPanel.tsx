import { useEffect, useMemo, useState } from "react";
import { Bot } from "lucide-react";
import { api, Meta, Targets } from "../api";
import { Button, Callout, Field, inputCls } from "./ui";

const LLM_LABEL: Record<string, string> = {
  auto: "Auto (first key found)", claude: "Claude (Anthropic)", gemini: "Gemini (Google)", groq: "Groq",
  deepseek: "DeepSeek", grok: "Grok (xAI)", ollama: "Ollama (local)", none: "None: rules only, nothing leaves the machine",
};

export function RunPanel({ meta, targets, initialRepo, onStarted }:
  { meta: Meta | null; targets: Targets | null; initialRepo?: string; onStarted: (jobId: string, project: string) => void }) {
  const presets = targets?.presets || [];
  const [repo, setRepo] = useState(initialRepo || presets.find((p) => p.name === "sscg-demo-app")?.path || presets[0]?.path || "");
  const [llm, setLlm] = useState(meta?.llm_default || "auto");
  const [source, setSource] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => { if (meta) setLlm(meta.llm_default); }, [meta]);
  const keyless = useMemo(() => llm !== "none" && meta && (llm === "auto" ? !Object.values(meta.llm_keys).some(Boolean) : !meta.llm_keys[llm]), [llm, meta]);

  async function start() {
    setBusy(true); setErr(null);
    try {
      const job = await api.run({ repo, source, agentic: true, remediate: true, llm, osv: true, offline: false, base: "HEAD~1", focus: "" });
      onStarted(job.id, job.project);
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  }

  return (
    <div className="space-y-5">
      <Field label="Target: folder, GitHub URL or page URL">
        <div className="mb-2 flex flex-wrap gap-1.5">
          {presets.map((p) => (
            <button key={p.path} type="button" onClick={() => { setRepo(p.path); setSource((p as any).source || ""); }}
              className={`rounded-full px-3 py-1 text-xs font-medium ring-1 ring-inset ${repo === p.path ? "bg-brand-600 text-white ring-brand-600" : "bg-white text-slate-600 ring-slate-300 hover:bg-slate-50"}`}>
              {p.name}
            </button>
          ))}
        </div>
        <input className={inputCls + " font-mono text-xs"} value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="https://github.com/owner/repo  or  C:\path\to\repository" />
      </Field>
      {/^https?:\/\//.test(repo) && !/github\.com\//.test(repo) && (
        <Field label="Source repository of this application (optional)" hint="GitHub URL. Fixes are proposed and validated against it.">
          <input className={inputCls + " font-mono text-xs"} value={source} onChange={(e) => setSource(e.target.value)} placeholder="https://github.com/juice-shop/juice-shop" />
        </Field>
      )}

        <Field label="LLM provider">
          <select className={inputCls} value={llm} onChange={(e) => setLlm(e.target.value)}>
            {(meta?.llm_choices || ["auto", "none"]).map((c) => (
              <option key={c} value={c}>{LLM_LABEL[c] || c}{c !== "auto" && c !== "none" && meta ? (meta.llm_keys[c] ? "  ✓ key set" : "  (no key)") : ""}</option>
            ))}
          </select>
          {keyless && <p className="mt-1.5 text-xs text-amber-700">No API key for this provider in sscg/.env: the agents will use the rules-only fallback.</p>}
        </Field>

      {err && <Callout tone="error">{err}</Callout>}
      <div className="flex justify-end">
        <Button variant="primary" onClick={start} disabled={busy || !repo.trim()}>
          <Bot className="h-4 w-4" /> Start
        </Button>
      </div>
    </div>
  );
}
