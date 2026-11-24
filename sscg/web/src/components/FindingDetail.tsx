import { Sparkles } from "lucide-react";
import type { Finding, Priority, Triage } from "../api";
import { Badge, Callout, Code, DepPath, DetailRow, Drawer, EvidenceLine, LevelBadge, NewBadge, PriorityBadge, SeverityBadge } from "./ui";

export function FindingDrawer({ f, triage, priority, onClose }:
  { f: Finding | null; triage?: Triage; priority?: Priority; onClose: () => void }) {
  if (!f) return null;
  const c = f.component, r = f.risk;
  const advisories = f.evidence.filter((e) => e.type === "advisory");
  const other = f.evidence.filter((e) => e.type !== "advisory");
  return (
    <Drawer open onClose={onClose}
      title={<span className="flex flex-wrap items-center gap-2"><span className="font-mono text-slate-500">{f.finding_id}</span>
        <LevelBadge level={r.level} score={r.score} />{f.new_in_change && <NewBadge />}
        {priority && <PriorityBadge priority={priority.priority} urgent={priority.urgent} />}</span>}
      subtitle={f.title}>
      <dl className="divide-y divide-slate-100">
        <DetailRow label="Type">{f.type} <span className="text-slate-400">· rule {f.rule}</span></DetailRow>
        {c && (
          <DetailRow label="Component">
            <Code>{c.label}</Code> <span className="text-slate-500">· {c.ecosystem} · scope {c.scope} · {c.direct ? "direct" : "transitive"}</span>
            {c.purl && <div className="mt-1 font-mono text-xs text-slate-500">{c.purl}</div>}
          </DetailRow>
        )}
        {f.location && <DetailRow label="Where"><Code>{f.location}</Code></DetailRow>}
        {f.dependency_paths.length > 0 && (
          <DetailRow label="Dependency path">
            <div className="space-y-1.5">{f.dependency_paths.map((p, i) => <DepPath key={i} path={p} />)}</div>
          </DetailRow>
        )}
        {f.severity && (
          <DetailRow label="Official severity">
            <SeverityBadge label={f.severity.label} />{f.severity.cvss != null && <span className="ml-2">CVSS {f.severity.cvss}</span>}
            <span className="ml-2 text-xs text-slate-500">({f.severity.source})</span>
          </DetailRow>
        )}
        {f.fixes && (
          <DetailRow label="Fix available">
            {f.fixes.upgrade_to_at_least ? <>upgrade to ≥ <Code>{f.fixes.upgrade_to_at_least}</Code></> : "no fixed version published"}
            {f.fixes.advisories_without_fix.length > 0 && <span className="text-slate-500"> · no fix for {f.fixes.advisories_without_fix.join(", ")}</span>}
          </DetailRow>
        )}
        <DetailRow label="Initial risk">
          <div>{r.level} ({r.score}): {r.reasons.join("; ")}</div>
          <div className="mt-0.5 text-xs italic text-slate-500">{r.label}</div>
        </DetailRow>
        {priority && (
          <DetailRow label="Priority">
            <div className="mb-1">score <b>{priority.score}</b> · {priority.bucket} · confidence {priority.confidence}</div>
            <ul className="list-disc space-y-0.5 pl-4 text-slate-600">{priority.reasons.map((x, i) => <li key={i}>{x}</li>)}</ul>
          </DetailRow>
        )}
        <DetailRow label="Why it matters">{f.why_it_matters}</DetailRow>
        <DetailRow label="Basis">
          <Badge className={f.classification === "verified_fact" ? "bg-emerald-50 text-emerald-700 ring-emerald-600/20" : "bg-amber-50 text-amber-800 ring-amber-600/20"}>
            {f.classification.replace(/_/g, " ")}</Badge>
          <span className="ml-2 text-slate-500">confidence {f.confidence}</span>
        </DetailRow>
      </dl>

      {other.length > 0 && (
        <div className="mt-5">
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Evidence</h4>
          <ol className="space-y-2">
            {other.map((e, i) => (
              <li key={i} className="flex gap-2.5 text-sm">
                <span className="mt-0.5 shrink-0 font-mono text-[11px] text-slate-400">E{i + 1}</span><EvidenceLine e={e} />
              </li>
            ))}
          </ol>
        </div>
      )}
      {advisories.length > 0 && (
        <div className="mt-5">
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Advisories ({advisories.length})</h4>
          <div className="overflow-hidden rounded-lg border border-slate-200">
            <table className="min-w-full text-sm">
              <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
                <tr><th className="px-3 py-2">Advisory</th><th className="px-3 py-2">Severity</th><th className="px-3 py-2">Fixed in</th><th className="px-3 py-2">Summary</th></tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {advisories.map((e) => (
                  <tr key={e.id}>
                    <td className="px-3 py-2 align-top">
                      <a href={e.url} target="_blank" rel="noreferrer" className="font-medium text-brand-700 hover:underline">{e.id}</a>
                      <div className="text-xs text-slate-500">{(e.cves || []).join(", ")}</div>
                    </td>
                    <td className="px-3 py-2 align-top"><SeverityBadge label={e.severity} />{e.cvss_score != null && <div className="mt-0.5 text-xs text-slate-500">CVSS {e.cvss_score}</div>}</td>
                    <td className="px-3 py-2 align-top font-mono text-xs">{e.fixed_in || <span className="text-slate-400">no fix</span>}</td>
                    <td className="px-3 py-2 align-top text-slate-600">{e.summary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {triage && (
        <div className="mt-6 rounded-xl border border-violet-200 bg-violet-50/50 p-4">
          <div className="mb-2 flex flex-wrap items-center gap-2 text-sm font-semibold text-violet-900">
            <Sparkles className="h-4 w-4" /> AI triage (inference, not evidence)
            <VerdictBadge verdict={triage.verdict} /> <span className="text-xs font-normal text-violet-700">confidence {triage.confidence} · {triage.generated_by}</span>
          </div>
          <p className="text-sm text-slate-700">{triage.rationale}</p>
          {triage.recommended_next_step && <p className="mt-2 text-sm"><b>Reviewer should check:</b> {triage.recommended_next_step}</p>}
          {triage.grounding && triage.grounding.ok === false && <div className="mt-2"><Callout tone="warn">Grounding check failed: the AI cited something that is not in the evidence.</Callout></div>}
        </div>
      )}
    </Drawer>
  );
}

const VERDICT: Record<string, string> = {
  likely_malicious: "bg-red-600 text-white ring-red-700", suspicious: "bg-orange-50 text-orange-700 ring-orange-600/20",
  needs_human_review: "bg-sky-50 text-sky-700 ring-sky-600/20", likely_benign: "bg-emerald-50 text-emerald-700 ring-emerald-600/20",
};
export function VerdictBadge({ verdict }: { verdict: string }) {
  return <Badge className={VERDICT[verdict]}>{verdict.replace(/_/g, " ")}</Badge>;
}
