import type { ReactNode } from "react";
import { AlertTriangle, BookOpen, Bug, ExternalLink, FileCode2, GitCommit, GitPullRequestArrow, Network, Package, Scale, ShieldCheck, Sparkles } from "lucide-react";
import type { Finding, Priority, Triage, TriageReason } from "../api";
import { Badge, Callout, Code, cx, DepPath, DetailRow, Drawer, EvidenceLine, LevelBadge, NewBadge, PriorityBadge, SeverityBadge } from "./ui";

export function FindingDrawer({ f, triage, priority, basis, onClose }:
  { f: Finding | null; triage?: Triage; priority?: Priority; basis?: string; onClose: () => void }) {
  if (!f) return null;
  const c = f.component, r = f.risk;
  const advisories = f.evidence.filter((e) => e.type === "advisory");
  const other = f.evidence.filter((e) => e.type !== "advisory");
  return (
    <Drawer open onClose={onClose}
      title={<span className="flex flex-wrap items-center gap-2"><span className="font-mono text-slate-500">{f.finding_id}</span>
        <KindBadge category={f.category} /><LevelBadge level={r.level} score={r.score} />{f.new_in_change && <NewBadge />}
        {priority && <PriorityBadge priority={priority.priority} urgent={priority.urgent} />}</span>}
      subtitle={f.title}>
      <div className="mb-4"><ReasoningCard f={f} triage={triage} basis={basis} /></div>
      <dl className="divide-y divide-slate-100">
        <DetailRow label="Type">{f.type} <span className="text-slate-400">· rule {f.rule}</span></DetailRow>
        {c && (
          <DetailRow label="Component">
            <Code>{c.label}</Code> <span className="text-slate-500">· {c.ecosystem} · scope {c.scope} · {c.direct ? "direct" : "transitive"}</span>
            {c.purl && <div className="mt-1 font-mono text-xs text-slate-500">{c.purl}</div>}
          </DetailRow>
        )}
        {f.location && <DetailRow label="Where"><Code>{f.location}</Code>{f.permalink && <a className="ml-2 text-brand-700 hover:underline" href={f.permalink} target="_blank" rel="noreferrer">open at this commit</a>}</DetailRow>}
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

    </Drawer>
  );
}

// ------------------------------------------------------------------ the two kinds of finding
export type Kind = "vulnerability" | "anomaly";
export const KIND_INFO: Record<Kind, { title: string; short: string; line: string; badge: string; bar: string; icon: ReactNode }> = {
  vulnerability: {
    title: "Vulnerabilities (known advisories)", short: "Vulnerability",
    line: "A published advisory (CVE / GHSA via OSV) affects this exact version. A verified fact: no AI judgement, fixed by upgrading.",
    badge: "bg-teal-50 text-teal-800 ring-teal-600/30", bar: "border-l-teal-500", icon: <Bug className="h-3 w-3" />,
  },
  anomaly: {
    title: "Suspicious changes (supply-chain behaviour)", short: "Suspicious change",
    line: "Behaviour or provenance a rule flagged (install scripts, untrusted sources, look-alike names, CI/CD, new dependencies). A heuristic, often with no CVE at all: it needs judgement.",
    badge: "bg-fuchsia-50 text-fuchsia-800 ring-fuchsia-600/30", bar: "border-l-fuchsia-500", icon: <GitPullRequestArrow className="h-3 w-3" />,
  },
};
export function KindBadge({ category }: { category: string }) {
  const k = KIND_INFO[category as Kind] || KIND_INFO.anomaly;
  return <Badge className={k.badge} title={k.line}>{k.icon}{k.short}</Badge>;
}
/** One-line explanation of one kind, for page headers. */
export function KindIntro({ category, count }: { category: Kind; count?: number }) {
  const k = KIND_INFO[category];
  return (
    <div className={cx("flex flex-wrap items-center gap-x-2 gap-y-1 rounded-lg border border-l-4 border-slate-200 bg-white px-3.5 py-2.5 text-sm", k.bar)}>
      <Badge className={k.badge}>{k.icon}{k.title}{count !== undefined && <span className="tabular-nums opacity-70">{count}</span>}</Badge>
      <span className="min-w-0 text-slate-600">{k.line}</span>
    </div>
  );
}
/** Both kinds side by side: the difference in one line each. */
export function KindLegend({ counts }: { counts?: { vulnerability: number; anomaly: number } }) {
  return (
    <div className="grid gap-2 lg:grid-cols-2">
      <KindIntro category="vulnerability" count={counts?.vulnerability} />
      <KindIntro category="anomaly" count={counts?.anomaly} />
    </div>
  );
}

// ------------------------------------------------------------------ agent reasoning
const VERDICT: Record<string, string> = {
  likely_malicious: "bg-red-600 text-white ring-red-700", suspicious: "bg-orange-50 text-orange-700 ring-orange-600/20",
  needs_human_review: "bg-sky-50 text-sky-700 ring-sky-600/20", likely_benign: "bg-emerald-50 text-emerald-700 ring-emerald-600/20",
};
export const VERDICT_LABEL: Record<string, string> = {
  likely_malicious: "Malicious", malicious: "Malicious", suspicious: "Suspicious", likely_benign: "Likely benign",
  needs_human_review: "Needs human", needs_human: "Needs human",
};
export function VerdictBadge({ verdict }: { verdict: string }) {
  const style = VERDICT[verdict] || (verdict === "malicious" ? VERDICT.likely_malicious : VERDICT.needs_human_review);
  return <Badge className={style}>{VERDICT_LABEL[verdict] || verdict.replace(/_/g, " ")}</Badge>;
}
const CONF_DOTS: Record<string, string> = { high: "●●●", medium: "●●○", low: "●○○" };
export function ConfidencePill({ confidence }: { confidence: string }) {
  return (
    <span className="inline-flex items-center gap-1 text-xs text-slate-600" title={`confidence ${confidence}`}>
      <span className="tracking-tighter text-violet-500">{CONF_DOTS[confidence] || "○○○"}</span>{confidence} confidence
    </span>
  );
}
const KIND_ICON: Record<string, ReactNode> = {
  file: <FileCode2 className="h-3 w-3" />, advisory: <Bug className="h-3 w-3" />, okf: <BookOpen className="h-3 w-3" />,
  registry: <Package className="h-3 w-3" />, commit: <GitCommit className="h-3 w-3" />, graph: <Network className="h-3 w-3" />,
  finding: <AlertTriangle className="h-3 w-3" />, rule: <Scale className="h-3 w-3" />,
};
/** One evidence reference of a reason: file:line, tool result, advisory, OKF concept. Links when a permalink exists. */
export function EvidenceChip({ r }: { r: TriageReason }) {
  const label = r.label || r.evidence || "no reference";
  const bad = r.verified === false;
  const cls = cx("inline-flex max-w-full items-center gap-1 rounded-md px-1.5 py-0.5 font-mono text-[11px] ring-1 ring-inset",
    bad ? "bg-amber-50 text-amber-800 ring-amber-600/30" : "bg-slate-50 text-slate-700 ring-slate-300");
  const title = bad ? "This reference is not in the evidence the agent was given" : `${r.kind} evidence ${r.evidence}`;
  const body = <>{KIND_ICON[r.kind] || null}<span className="truncate">{label}</span></>;
  return r.permalink
    ? <a href={r.permalink} target="_blank" rel="noreferrer" title={title} className={cx(cls, "hover:bg-brand-50 hover:text-brand-700")}>{body}<ExternalLink className="h-3 w-3 shrink-0" /></a>
    : <span title={title} className={cls}>{body}{bad && <span className="font-sans">· not in evidence</span>}</span>;
}

/** The reasoning card: the agent's verdict on a suspicious change, or the "deterministic" note for everything else. */
export function ReasoningCard({ f, triage, basis, compact }: { f?: Finding | null; triage?: Triage; basis?: string; compact?: boolean }) {
  if (!triage) {
    if (f?.category === "vulnerability" || basis?.startsWith("deterministic: verified")) return (
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 rounded-xl border border-teal-200 bg-teal-50/60 px-4 py-3 text-sm">
        <ShieldCheck className="h-4 w-4 text-teal-700" />
        <b className="text-teal-900">Deterministic — no AI needed</b>
        <span className="text-teal-800">Verified advisory: severity and fixed versions come straight from OSV for this exact version.</span>
      </div>
    );
    if (basis?.startsWith("deterministic")) return (
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm">
        <ShieldCheck className="h-4 w-4 text-slate-600" />
        <b className="text-slate-800">Deterministic — no AI needed</b>
        <span className="text-slate-600">Rule {f?.rule} has an unambiguous outcome (its playbook needs no triage): the evidence below is the verdict.</span>
      </div>
    );
    if (basis) return <Callout tone="info">Not triaged: {basis}.</Callout>;
    return null;
  }
  const t = triage;
  const fallback = t.basis === "rules_fallback" || t.generated_by === "rules-fallback";
  const reasons = t.reasons || [];
  const summary = t.summary || (reasons.length ? "" : t.rationale);   // older agentic.json: rationale only
  const action = t.recommended_action || t.recommended_next_step;
  const g = t.grounding || {};
  return (
    <div className="overflow-hidden rounded-xl border border-violet-200 bg-white shadow-sm">
      <div className="flex flex-wrap items-center gap-2 border-b border-violet-100 bg-violet-50/60 px-4 py-2.5">
        <Sparkles className="h-4 w-4 text-violet-600" />
        <span className="text-sm font-semibold text-violet-900">Agent reasoning</span>
        <VerdictBadge verdict={t.verdict} />
        <ConfidencePill confidence={t.confidence} />
        <span className="ml-auto rounded px-1.5 py-0.5 text-[11px] italic text-slate-500 ring-1 ring-inset ring-slate-200"
          title={fallback ? "No LLM was used: playbook default adjusted by simple evidence signals" : "Language-model inference over the evidence, not evidence itself"}>
          {fallback ? "Rules-only fallback — verify" : "AI inference — verify"}
        </span>
      </div>
      <div className="space-y-3 px-4 py-3">
        {summary && <p className="text-sm font-medium leading-relaxed text-slate-900">{summary}</p>}
        {reasons.length > 0 && (
          <ol className="space-y-2.5">
            {reasons.map((r, i) => (
              <li key={i} className="flex gap-2.5 text-sm">
                <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-violet-100 text-[11px] font-semibold text-violet-800">{i + 1}</span>
                <div className="min-w-0 space-y-1"><p className="text-slate-700">{r.text}</p><EvidenceChip r={r} /></div>
              </li>
            ))}
          </ol>
        )}
        {action && (
          <div className="rounded-lg bg-slate-50 px-3 py-2 text-sm">
            <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Recommended action</div>
            <div className="mt-0.5 text-slate-800">{action}</div>
          </div>
        )}
        {!compact && (t.benign_explanations?.length || t.matched_patterns?.length) ? (
          <div className="space-y-1 text-xs text-slate-500">
            {t.benign_explanations?.length ? <p><b className="font-medium text-slate-600">Innocent explanations considered:</b> {t.benign_explanations.join("; ")}</p> : null}
            {t.matched_patterns?.length ? <p><b className="font-medium text-slate-600">Attack patterns matched:</b> {t.matched_patterns.join(", ")}</p> : null}
          </div>
        ) : null}
        {g.ok === false && (
          <Callout tone="warn">
            Grounding check: the agent referred to something that is not in its evidence
            {(g.unknown_ids || []).length ? <> ({g.unknown_ids.join(", ")}; verdict lowered to needs human)</> : null}
            {(g.unverified_reasons || []).length ? <> (unverified reference: {g.unverified_reasons.join(", ")})</> : null}.
          </Callout>
        )}
        <div className="text-[11px] text-slate-400">by <Code>{t.generated_by}</Code> · {t.rounds} evidence round(s) · never changes the finding or its risk score</div>
      </div>
    </div>
  );
}
