import { useState } from "react";
import { Bot, Download, ShieldCheck, Sparkles } from "lucide-react";
import { fileUrl, Project, Triage } from "../api";
import { ConfidencePill, KindBadge, KindLegend, ReasoningCard, VerdictBadge } from "../components/FindingDetail";
import { Badge, Callout, Card, Code, DataTable, DetailRow, Drawer, Empty, LinkButton, PageHeader, Pre, Stat } from "../components/ui";

export function AiTriage({ p }: { p: Project }) {
  const ag = p.agentic;
  const [open, setOpen] = useState<Triage | null>(null);
  if (!ag) return (
    <div>
      <PageHeader title="AI triage" />
      <Empty icon={<Bot className="h-8 w-8" />} title="No agent run for this repository yet">
        Start a run with <b>Detect + AI agents</b> or <b>Full: detect → remediate</b>. Without an API key the agents use the rules-only fallback.
      </Empty>
    </div>
  );
  const tri = Object.values(ag.triage).sort((a, b) => a.finding_id.localeCompare(b.finding_id));
  const count = (v: string) => tri.filter((t) => t.verdict === v).length;
  const grounded = tri.filter((t) => t.grounding?.ok !== false).length;
  const u = ag.llm_usage || { calls: 0, input_tokens: 0, output_tokens: 0, secrets_redacted: 0 };
  const nar = ag.narrative;
  const all = p.findings?.findings || [];
  const findings = Object.fromEntries(all.map((f) => [f.finding_id, f]));
  const nVuln = all.filter((f) => f.category === "vulnerability").length;
  const nAno = all.length - nVuln;
  const basis = ag.triage_basis || {};
  const detRules = all.filter((f) => f.category === "anomaly" && !ag.triage[f.finding_id] && (basis[f.finding_id] || "").startsWith("deterministic")).length;
  return (
    <div>
      <PageHeader title="AI triage" description="Inference by the LangGraph agents, kept apart from the evidence: it cites finding and evidence IDs and never changes a finding or its risk score."
        actions={<LinkButton href={fileUrl(p.name, "agentic.json", true)} download><Download className="h-4 w-4" /> agentic.json</LinkButton>} />
      {ag.stale && <div className="mb-4"><Callout tone="warn">This AI triage is from an earlier agent run; the findings were rescanned since. Run the agents again to refresh it.</Callout></div>}
      <div className="mb-4"><KindLegend counts={{ vulnerability: nVuln, anomaly: nAno }} /></div>
      <div className="mb-6">
        <Callout tone="info" icon={<ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />}>
          <b>Triage scope.</b> The agent judges only suspicious changes whose rule needs judgement: <b>{tri.length}</b> triaged.
          {" "}<b>{nVuln}</b> vulnerabilities are <i>deterministic — no AI needed</i> (a published advisory affects that exact version)
          {detRules ? <>, and <b>{detRules}</b> suspicious changes come from rules with an unambiguous outcome</> : null}.
        </Callout>
      </div>
      <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Engine" value={<span className="text-base">{ag.engine}</span>} hint={`knowledge base ${ag.kb_version}`} />
        <Stat label="Malicious" value={count("likely_malicious")} tone="red" />
        <Stat label="Suspicious" value={count("suspicious")} tone="orange" />
        <Stat label="Needs human" value={count("needs_human_review")} tone="brand" />
        <Stat label="Grounding passed" value={`${grounded}/${tri.length}`} tone="green" hint="every cited ID exists in the evidence" />
        <Stat label="LLM calls" value={u.calls} hint={`${u.input_tokens.toLocaleString()} in / ${u.output_tokens.toLocaleString()} out tokens`} />
      </div>
      {nar && (
        <Card className="mb-6" title={<span className="flex items-center gap-2"><Sparkles className="h-4 w-4 text-violet-600" /> Summary</span>}>
          <p className="font-medium text-slate-900">{nar.headline}</p>
          <dl className="mt-3 divide-y divide-slate-100">
            <DetailRow label="In the application">{nar.what_is_in_the_app}</DetailRow>
            <DetailRow label="What changed">{nar.what_changed}</DetailRow>
            <DetailRow label="What appears risky">{nar.what_appears_risky}</DetailRow>
          </dl>
          {nar.top_concerns?.length > 0 && (
            <div className="mt-3 space-y-1.5">
              {nar.top_concerns.map((c) => <div key={c.finding_id} className="flex gap-2 text-sm"><Code>{c.finding_id}</Code><span className="text-slate-700">{c.why}</span></div>)}
            </div>
          )}
          {nar.caveats?.length > 0 && <div className="mt-3 space-y-1 text-xs text-slate-500">{nar.caveats.map((c, i) => <p key={i}>{c}</p>)}</div>}
        </Card>
      )}
      <Card pad={false} title={<span className="flex items-center gap-2">Triage decisions <KindBadge category="anomaly" /></span>}
        subtitle="Suspicious changes the Triage agent investigated with its evidence tools. Click a row for its reasoning.">
        <DataTable rows={tri} rowKey={(t) => t.finding_id} onRow={setOpen} cols={[
          { key: "id", label: "ID", render: (t) => <span className="whitespace-nowrap font-mono text-xs text-slate-500">{t.finding_id}</span> },
          { key: "f", label: "Finding", render: (t) => <span className="line-clamp-2 max-w-xs text-slate-800">{findings[t.finding_id]?.title || t.rule}</span> },
          { key: "v", label: "Verdict", render: (t) => <VerdictBadge verdict={t.verdict} /> },
          { key: "c", label: "Confidence", render: (t) => <ConfidencePill confidence={t.confidence} /> },
          { key: "s", label: "Summary", render: (t) => <span className="line-clamp-2 max-w-md text-xs text-slate-600">{t.summary || t.rationale}</span> },
          { key: "g", label: "Grounded", render: (t) => t.grounding?.ok === false ? <Badge className="bg-amber-50 text-amber-800 ring-amber-600/20">no</Badge> : <Badge className="bg-emerald-50 text-emerald-700 ring-emerald-600/20">yes</Badge> },
          { key: "r", label: "Rounds", render: (t) => t.rounds },
          { key: "by", label: "By", render: (t) => <span className="text-xs text-slate-500">{t.basis === "rules_fallback" || t.generated_by === "rules-fallback" ? "rules only" : t.generated_by}</span> },
        ]} />
      </Card>
      <Card className="mt-6" title={<span className="flex items-center gap-2"><ShieldCheck className="h-4 w-4" /> Agent runs</span>}
        subtitle={`Secrets redacted before sending to the LLM: ${u.secrets_redacted}`} pad={false}>
        <DataTable rows={ag.agent_runs.map((r, i) => ({ ...r, i }))} rowKey={(r) => String(r.i)} maxHeight={320} cols={[
          { key: "a", label: "Agent", render: (r) => <b className="font-medium">{r.agent}</b> },
          { key: "k", label: "Kind", render: (r) => <Badge className={r.kind === "llm" ? "bg-violet-50 text-violet-700 ring-violet-600/20" : r.kind === "human" ? "bg-sky-50 text-sky-700 ring-sky-600/20" : undefined}>{r.kind}</Badge> },
          { key: "s", label: "Status", render: (r) => r.status },
          { key: "t", label: "Seconds", render: (r) => r.seconds, className: "text-right tabular-nums" },
          { key: "tok", label: "Tokens in/out", render: (r) => (r.input_tokens != null ? `${r.input_tokens}/${r.output_tokens}` : "-"), className: "text-right tabular-nums" },
        ]} />
      </Card>
      {open && (
        <Drawer open onClose={() => setOpen(null)} title={<span className="flex items-center gap-2"><span className="font-mono text-slate-500">{open.finding_id}</span><VerdictBadge verdict={open.verdict} /></span>}
          subtitle={findings[open.finding_id]?.title}>
          <ReasoningCard f={findings[open.finding_id]} triage={open} />
          {findings[open.finding_id] && (
            <dl className="mt-4 divide-y divide-slate-100">
              <DetailRow label="Finding"><KindBadge category={findings[open.finding_id].category} /> <span className="ml-1">{findings[open.finding_id].type}</span> <span className="text-slate-400">· rule {open.rule}</span></DetailRow>
              {findings[open.finding_id].location && <DetailRow label="Where"><Code>{findings[open.finding_id].location}</Code></DetailRow>}
            </dl>
          )}
          {(ag.tool_evidence[open.finding_id] || []).length > 0 && (
            <div className="mt-5 space-y-3">
              <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Tool evidence</h4>
              {ag.tool_evidence[open.finding_id].map((e) => (
                <details key={e.id} className="rounded-lg border border-slate-200">
                  <summary className="cursor-pointer px-3 py-2 text-sm"><Code>{e.id}</Code> tool <b>{e.tool}</b> <span className="text-slate-500">(round {e.round + 1})</span></summary>
                  <div className="p-3 pt-0"><Pre text={JSON.stringify(e.result, null, 2)} /></div>
                </details>
              ))}
            </div>
          )}
        </Drawer>
      )}
    </div>
  );
}
