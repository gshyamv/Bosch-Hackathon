import { useMemo, useState } from "react";
import { ArrowRight, CheckCircle2, ChevronDown, ChevronRight, Download, FileText, FlaskConical, Hourglass, Send, ShieldCheck, Sparkles, Wrench, XCircle } from "lucide-react";
import { api, RemediationRun, fileUrl, Finding, Pending, Project, Proposal, Step } from "../api";
import { FindingDrawer } from "../components/FindingDetail";
import { Badge, Button, Callout, Card, Code, cx, DataTable, DetailRow, Diff, Drawer, Empty, Field, inputCls, LinkButton, PageHeader, Pre, PriorityBadge, Stat, StatusBadge, Tabs } from "../components/ui";

const DECISIONS = [
  { id: "defer", label: "Defer", on: "bg-slate-700 text-white" },
  { id: "approve", label: "Approve", on: "bg-emerald-600 text-white" },
  { id: "reject", label: "Reject", on: "bg-red-600 text-white" },
  { id: "accept_risk", label: "Accept risk", on: "bg-amber-500 text-white" },
  { id: "request_changes", label: "Request changes", on: "bg-sky-600 text-white" },
] as const;
type Decision = (typeof DECISIONS)[number]["id"];
const ACTION_LABEL: Record<string, string> = {
  upgrade: "Upgrade", replace: "Replace", remove: "Remove", pin: "Pin", block: "Block", mitigate: "Mitigate",
  update_base_image: "Update base image", escalate_review: "Escalate for review",
};

export function Remediation({ p, onJob }: { p: Project; onJob: (jobId: string) => void }) {
  return (
    <div>
      <PageHeader title="Remediation" description="Prioritised risk → recommended fix → human approval → build & test in a sandbox → rescan → verified remediation. The original repository is never modified." />
      {p.pending ? <Approval p={p} pend={p.pending} onJob={onJob} />
        : p.remediation ? <Results p={p} rem={p.remediation} onJob={onJob} />
        : <Empty icon={<Wrench className="h-8 w-8" />} title="No remediation run yet">Start a <b>Full: detect → remediate</b> run. It prioritises the findings, proposes exact fixes, and pauses here for your approval.</Empty>}
    </div>
  );
}

// ------------------------------------------------------------------ proposal details (shared)
function ProposalBody({ pr }: { pr: Proposal }) {
  const checklist = Array.isArray(pr.ai_reviewer_checklist) ? pr.ai_reviewer_checklist : pr.ai_reviewer_checklist ? [pr.ai_reviewer_checklist] : [];
  const sg = pr.system_suggestion;
  return (
    <div className="grid gap-5 lg:grid-cols-2">
    <div className="space-y-4 min-w-0">
      <dl className="divide-y divide-slate-100">
        <DetailRow label="Why (verified)">{pr.rationale}</DetailRow>
        {pr.expected_risk_reduction && <DetailRow label="Risk reduction">{pr.expected_risk_reduction}</DetailRow>}
        <DetailRow label="Compatibility"><Badge className={pr.compatibility_level === "high" ? "bg-red-50 text-red-700 ring-red-600/20" : pr.compatibility_level === "medium" ? "bg-amber-50 text-amber-800 ring-amber-600/20" : "bg-emerald-50 text-emerald-700 ring-emerald-600/20"}>{pr.compatibility_level}</Badge> <span className="text-slate-600">{pr.compatibility_impact}</span></DetailRow>
        {!!pr.cluster_ids?.length && <DetailRow label="Root cause">{pr.cluster_ids.map((c) => <Code key={c}>{c}</Code>)}</DetailRow>}
        {pr.rollback && <DetailRow label="Rollback">{pr.rollback}</DetailRow>}
        <DetailRow label="Findings">{pr.finding_ids.map((f) => <Code key={f}>{f}</Code>).reduce((a: any[], c, i) => (i ? [...a, " ", c] : [c]), [])}</DetailRow>
        {pr.files_affected?.length > 0 && <DetailRow label="Files">{pr.files_affected.map((f) => <Code key={f}>{f}</Code>)}</DetailRow>}
        {pr.residual_advisories?.length > 0 && <DetailRow label="Residual advisories"><span className="text-amber-700">{pr.residual_advisories.join(", ")}</span></DetailRow>}
        {pr.notes && <DetailRow label="Notes">{pr.notes}</DetailRow>}
      </dl>
      {pr.diff ? <Diff text={pr.diff} /> : <p className="text-sm italic text-slate-500">No automatic patch: this needs a human change (guidance on the right).</p>}
    </div>
    <div className="space-y-3 min-w-0">
      <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">Reasoning: read before you decide</div>
      <div className="rounded-lg border border-slate-200 bg-slate-50 p-3.5 text-sm"><div className="mb-1 font-semibold text-slate-800">Why this fix (verified facts)</div><p className="text-slate-700">{pr.rationale}</p></div>
      {sg && (
        <div className="rounded-lg border border-teal-300 bg-teal-50 p-3.5 text-sm">
          <div className="mb-1 flex items-center gap-2 font-semibold text-teal-900"><Badge className="bg-teal-600 text-white ring-teal-600">System suggestion</Badge> {DECISIONS.find((d) => d.id === sg.decision)?.label || sg.decision} <span className="text-xs font-normal text-teal-700">({sg.confidence} confidence)</span></div>
          <p className="text-slate-700">{sg.reason}</p>
        </div>
      )}
      {(pr.ai_rationale || checklist.length > 0) && (
        <div className="rounded-lg border border-violet-200 bg-violet-50/50 p-3.5 text-sm">
          <div className="mb-1.5 flex items-center gap-1.5 font-semibold text-violet-900"><Sparkles className="h-4 w-4" /> Remediation advisor (AI inference)</div>
          {pr.ai_rationale && <p className="text-slate-700">{pr.ai_rationale}</p>}
          {checklist.length > 0 && <ul className="mt-2 list-disc space-y-1 pl-5 text-slate-700">{checklist.map((c, i) => <li key={i}>{c}</li>)}</ul>}
        </div>
      )}
      {!pr.ai_rationale && <p className="text-xs italic text-slate-500">No AI advisor note (rules-only run or no LLM key).</p>}
    </div>
    </div>
  );
}

function ProposalTitle({ pr }: { pr: Proposal }) {
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-2">
      <span className="font-mono text-xs text-slate-500">{pr.proposal_id}</span>
      <PriorityBadge priority={pr.priority} urgent={pr.urgent} />
      <Badge className="bg-ink-900 text-white ring-ink-900">{ACTION_LABEL[pr.action] || pr.action}</Badge>
      <span className="truncate font-mono text-sm text-slate-900">{pr.component || pr.files_affected?.[0] || ""}</span>
      {pr.to_version && <span className="inline-flex items-center gap-1 font-mono text-xs text-slate-500">{pr.from_version} <ArrowRight className="h-3 w-3" /> <span className="text-emerald-700">{pr.to_version}</span></span>}
      {!pr.patchable && <Badge className="bg-sky-50 text-sky-700 ring-sky-600/20">manual</Badge>}
      {pr.system_suggestion && <Badge className="bg-teal-50 text-teal-800 ring-teal-600/30">System suggestion: {DECISIONS.find((d) => d.id === pr.system_suggestion!.decision)?.label || pr.system_suggestion.decision}</Badge>}
    </div>
  );
}

// ------------------------------------------------------------------ paused run: human approval
function Approval({ p, pend, onJob }: { p: Project; pend: Pending; onJob: (id: string) => void }) {
  const props = pend.proposals;
  const [dec, setDec] = useState<Record<string, Decision>>(() => Object.fromEntries(props.map((x) => [x.proposal_id, "defer"])));
  const [expanded, setExpanded] = useState<Record<string, boolean>>(() => Object.fromEntries(props.map((x) => [x.proposal_id, true])));
  const [by, setBy] = useState("");
  const [reason, setReason] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const counts = DECISIONS.map((d) => ({ ...d, n: Object.values(dec).filter((v) => v === d.id).length }));
  const approvedPatch = props.filter((x) => dec[x.proposal_id] === "approve" && x.patchable).length;
  const setAll = (fn: (x: Proposal) => Decision | null) => setDec((d) => ({ ...d, ...Object.fromEntries(props.map((x) => [x.proposal_id, fn(x) ?? d[x.proposal_id]])) }));

  async function submit() {
    if (!by.trim()) { setErr("Enter the approver's name: every decision is recorded with who made it."); return; }
    setBusy(true); setErr(null);
    try { onJob((await api.approve(p.name, { decisions: dec, by, reason })).id); }
    catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  }

  return (
    <div className="pb-40">
      <Callout tone="warn" icon={<Hourglass className="mt-0.5 h-4 w-4 shrink-0" />}>
        <b>Waiting for your approval.</b> Run <Code>{pend.run_id}</Code> paused at the human-approval step ({new Date(pend.created).toLocaleString()}).
        Only <b>approved proposals with a patch</b> are applied, in a sandbox copy, then built, tested and rescanned. Manual proposals can be risk-accepted or sent back.
      </Callout>
      <div className="my-4 flex flex-wrap items-center gap-2">
        <Button onClick={() => setAll((x) => (x.patchable ? "approve" : null))}><CheckCircle2 className="h-4 w-4 text-emerald-600" /> Approve all patchable</Button>
        <Button onClick={() => setAll((x) => (x.urgent && x.patchable ? "approve" : null))}>Approve urgent only</Button>
        <Button onClick={() => setAll((x) => (x.system_suggestion && (x.system_suggestion.decision !== "approve" || x.patchable) ? x.system_suggestion.decision as Decision : null))}>Apply system suggestions (low priority)</Button>
        <Button onClick={() => setAll((x) => (!x.patchable ? "request_changes" : null))}>Escalate manual items</Button>
        <Button variant="ghost" onClick={() => setAll(() => "defer")}>Reset</Button>
        <Button variant="ghost" onClick={() => setExpanded(Object.fromEntries(props.map((x) => [x.proposal_id, !Object.values(expanded).some(Boolean)])))}>Expand / collapse all</Button>
      </div>
      <div className="space-y-2.5">
        {props.map((pr) => {
          const open = !!expanded[pr.proposal_id];
          const d = dec[pr.proposal_id];
          return (
            <div key={pr.proposal_id} className={cx("rounded-xl border bg-white shadow-card transition",
              d === "approve" ? "border-emerald-300" : d === "reject" ? "border-red-300" : d === "defer" ? "border-slate-200" : "border-amber-300")}>
              <div className="flex flex-wrap items-center gap-3 px-4 py-3">
                <button onClick={() => setExpanded((e) => ({ ...e, [pr.proposal_id]: !open }))} className="flex min-w-0 flex-1 items-center gap-2 text-left">
                  {open ? <ChevronDown className="h-4 w-4 shrink-0 text-slate-400" /> : <ChevronRight className="h-4 w-4 shrink-0 text-slate-400" />}
                  <ProposalTitle pr={pr} />
                </button>
                <div className="inline-flex flex-wrap rounded-lg bg-slate-100 p-0.5">
                  {DECISIONS.map((o) => (
                    <button key={o.id} type="button" onClick={() => setDec((x) => ({ ...x, [pr.proposal_id]: o.id }))}
                      disabled={o.id === "approve" && !pr.patchable} title={o.id === "approve" && !pr.patchable ? "No automatic patch: accept the risk or request changes" : undefined}
                      className={cx("rounded-md px-2.5 py-1 text-xs font-medium transition disabled:cursor-not-allowed disabled:opacity-40",
                        d === o.id ? o.on + " shadow-sm" : "text-slate-500 hover:text-slate-800")}>
                      {o.label}
                    </button>
                  ))}
                </div>
              </div>
              {open && <div className="border-t border-slate-100 px-5 py-4"><ProposalBody pr={pr} /></div>}
            </div>
          );
        })}
      </div>

      {/* sticky decision bar */}
      <div className="fixed bottom-0 left-0 right-0 z-30 border-t border-slate-200 bg-white/95 backdrop-blur lg:left-64">
        <div className="mx-auto flex max-w-[1500px] flex-wrap items-end gap-4 px-6 py-3.5">
          <div className="flex flex-wrap gap-1.5 text-xs">
            {counts.filter((c) => c.n).map((c) => <span key={c.id} className={cx("rounded-md px-2 py-1 font-medium", c.on)}>{c.label}: {c.n}</span>)}
          </div>
          <div className="w-48"><Field label="Approver *"><input className={inputCls} value={by} onChange={(e) => setBy(e.target.value)} placeholder="Your name" /></Field></div>
          <div className="min-w-[200px] flex-1"><Field label="Reason (recorded in the audit trail)"><input className={inputCls} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Approved critical CVEs and malicious typosquats" /></Field></div>
          <Button variant="primary" onClick={submit} disabled={busy}><Send className="h-4 w-4" /> Submit & validate{approvedPatch ? ` (${approvedPatch} fixes)` : ""}</Button>
          {err && <div className="w-full"><Callout tone="error">{err}</Callout></div>}
        </div>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ results of the last remediation run
type RTab = "post" | "proof" | "prio" | "props" | "val" | "report";
function Results({ p, rem, onJob }: { p: Project; rem: RemediationRun; onJob: (id: string) => void }) {
  const val = rem.validations?.[rem.validations.length - 1];
  const verdict = val?.verdict || "not_run";
  const [tab, setTab] = useState<RTab>(p.post_analysis ? "post" : "prio");
  const [openF, setOpenF] = useState<Finding | null>(null);
  const [openP, setOpenP] = useState<Proposal | null>(null);
  const fmap = useMemo(() => Object.fromEntries((p.findings?.findings || []).map((f) => [f.finding_id, f])), [p.findings]);
  const prio = useMemo(() => Object.fromEntries(rem.priorities.map((x) => [x.finding_id, x])), [rem]);
  const appr = Object.fromEntries(rem.approvals.map((a) => [a.proposal_id, a]));
  const introduced = (val?.new || []).filter((n) => n.kind === "introduced").length;
  const pc = (k: string) => rem.priorities.filter((x) => x.priority === k).length;
  const hero = verdict === "verified" ? { tone: "border-emerald-200 bg-gradient-to-r from-emerald-50 to-white", icon: <ShieldCheck className="h-8 w-8 text-emerald-600" />, title: "Remediation verified" }
    : verdict === "partially_verified" ? { tone: "border-amber-200 bg-gradient-to-r from-amber-50 to-white", icon: <FlaskConical className="h-8 w-8 text-amber-600" />, title: "Partially verified" }
    : verdict === "failed" ? { tone: "border-red-200 bg-gradient-to-r from-red-50 to-white", icon: <XCircle className="h-8 w-8 text-red-600" />, title: "Validation failed" }
    : { tone: "border-slate-200 bg-white", icon: <Hourglass className="h-8 w-8 text-slate-400" />, title: "Not validated" };

  return (
    <div>
      <div className={cx("mb-6 flex flex-wrap items-center gap-5 rounded-xl border p-5 shadow-card", hero.tone)}>
        {hero.icon}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2 text-lg font-semibold text-slate-900">{hero.title}{val && <span className="text-sm font-normal text-slate-500">confidence {val.confidence}</span>}</div>
          <ul className="mt-1 space-y-0.5 text-sm text-slate-600">{(val?.reasons || []).map((r, i) => <li key={i}>• {r}</li>)}</ul>
        </div>
        <div className="flex flex-wrap gap-2">
          {p.files.includes("report.html") && <LinkButton href={fileUrl(p.name, "report.html")}><FileText className="h-4 w-4" /> Report</LinkButton>}
          {p.files.includes("report.pdf") && <LinkButton href={fileUrl(p.name, "report.pdf", true)} download><Download className="h-4 w-4" /> PDF</LinkButton>}
        </div>
      </div>
      <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Findings before → after" value={val ? `${val.findings_before} → ${val.findings_after}` : "-"} />
        <Stat label="Resolved" value={val?.resolved.length ?? 0} tone="green" />
        <Stat label="Newly introduced" value={introduced} tone={introduced ? "red" : undefined} hint="excl. expected & still-vulnerable" />
        <Stat label="Proposals" value={rem.proposals.length} hint={`${rem.approvals.filter((a) => a.decision === "approve").length} approved`} />
        <Stat label="P0 / P1" value={`${pc("P0")} / ${pc("P1")}`} tone="red" hint={`${rem.priorities.filter((x) => x.urgent).length} urgent`} />
        <Stat label="Network service" value={rem.exposure?.network_service ? "yes" : "no"} hint={rem.exposure?.evidence?.[0]} />
      </div>
      <Tabs value={tab} onChange={setTab} tabs={[
        { id: "post", label: "Post-analysis (before → after)" }, { id: "proof", label: "Sandbox proof (Docker)" },
        { id: "prio", label: "Prioritised risks" }, { id: "props", label: "Proposals & decisions" },
        { id: "val", label: "Validation" }, { id: "report", label: "Report & patch" },
      ]} />

      {tab === "post" && (p.post_analysis ? <PostAnalysisView pa={p.post_analysis} workdir={(val as any)?.workdir} onJob={onJob} /> : <Empty title="No post-analysis yet" />)}
      {tab === "proof" && <SandboxProofView t={p.sandbox_trace} />}

      {tab === "prio" && (
        <Card pad={false} title="Prioritised risks" subtitle={`Initial risk + signed points for CISA KEV (${rem.exploitability_sources?.kev?.date?.slice(0, 10) || "n/a"}), EPSS (${rem.exploitability_sources?.epss?.date || "n/a"}), reachability (${Object.entries(rem.reachability_summary || {}).map(([k, v]) => `${k} ${v}`).join(", ")}) and exposure. Deterministic.`}>
          <DataTable rows={rem.priorities} rowKey={(x) => x.finding_id} maxHeight={680} onRow={(x) => fmap[x.finding_id] && setOpenF(fmap[x.finding_id])} cols={[
            { key: "p", label: "Priority", render: (x) => <PriorityBadge priority={x.priority} urgent={x.urgent} /> },
            { key: "s", label: "Score", render: (x) => <b className="tabular-nums">{x.score}</b>, sort: (x) => x.score },
            { key: "id", label: "ID", render: (x) => <span className="whitespace-nowrap font-mono text-xs text-slate-500">{x.finding_id}</span> },
            { key: "t", label: "Finding", render: (x) => <div className="max-w-md"><div className="line-clamp-2 text-slate-800">{x.title}</div>{x.component && <div className="font-mono text-xs text-slate-500">{x.component}</div>}</div> },
            { key: "w", label: "Why", render: (x) => <div className="max-w-md text-xs text-slate-600">{x.reasons.slice(1, 4).join("; ")}</div> },
            { key: "c", label: "Confidence", render: (x) => x.confidence },
          ]} />
        </Card>
      )}

      {tab === "props" && (
        <Card pad={false} title="Proposals & decisions" subtitle="Click a proposal for its rationale, rollback and exact patch">
          <DataTable rows={rem.proposals} rowKey={(x) => x.proposal_id} onRow={setOpenP} cols={[
            { key: "id", label: "ID", render: (x) => <span className="whitespace-nowrap font-mono text-xs text-slate-500">{x.proposal_id}</span> },
            { key: "p", label: "Priority", render: (x) => <PriorityBadge priority={x.priority} urgent={x.urgent} /> },
            { key: "a", label: "Action", render: (x) => <Badge className="bg-ink-900 text-white ring-ink-900">{ACTION_LABEL[x.action] || x.action}</Badge> },
            { key: "c", label: "Component", render: (x) => <span className="font-mono text-xs">{x.component || x.files_affected?.[0]}</span> },
            { key: "v", label: "Change", render: (x) => x.to_version ? <span className="font-mono text-xs">{x.from_version} → <span className="text-emerald-700">{x.to_version}</span></span> : "-" },
            { key: "cmp", label: "Compat.", render: (x) => x.compatibility_level },
            { key: "d", label: "Decision", render: (x) => appr[x.proposal_id] ? <span><StatusBadge status={appr[x.proposal_id].decision} /> <span className="text-xs text-slate-500">{appr[x.proposal_id].approver}</span></span> : <StatusBadge status={x.status} /> },
            { key: "val", label: "Validation", render: (x) => val?.per_proposal?.[x.proposal_id] ? <StatusBadge status={val.per_proposal[x.proposal_id].status} /> : <span className="text-slate-400">-</span> },
          ]} />
        </Card>
      )}

      {tab === "val" && (verdict === "not_run" || !val ? <Empty title="No approved proposal with a patch was validated" /> : <ValidationView val={val} />)}

      {tab === "report" && (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2">
            {(["report.pdf", "remediation/remediation.patch", "remediation/remediation.json"]).filter((f) => p.files.includes(f)).map((f) => (
              <LinkButton key={f} href={fileUrl(p.name, f, true)} download><Download className="h-4 w-4" /> {f.split("/").pop()}</LinkButton>
            ))}
          </div>
          {p.files.includes("report.html") && (
            <Card pad={false}><iframe src={fileUrl(p.name, "report.html") + `?t=${p.scanned_at}`} title="Guardian report" sandbox="" className="h-[78vh] w-full rounded-xl border-0" /></Card>
          )}
        </div>
      )}

      <FindingDrawer f={openF} onClose={() => setOpenF(null)} triage={openF ? p.agentic?.triage[openF.finding_id] : undefined} priority={openF ? prio[openF.finding_id] : undefined} />
      {openP && (
        <Drawer open onClose={() => setOpenP(null)} title={<ProposalTitle pr={openP} />}
          subtitle={appr[openP.proposal_id] ? `Decision: ${appr[openP.proposal_id].decision} by ${appr[openP.proposal_id].approver}${appr[openP.proposal_id].reason ? ` · “${appr[openP.proposal_id].reason}”` : ""}` : `Status: ${openP.status}`}>
          <ProposalBody pr={openP} />
        </Drawer>
      )}
    </div>
  );
}

function ValidationView({ val }: { val: NonNullable<RemediationRun["validations"]>[number] }) {
  const name = (s: Step) => s.step.split(": ").slice(1).join(": ");
  const before = Object.fromEntries(val.steps_before.map((s) => [name(s), s]));
  const after = Object.fromEntries(val.steps_after.map((s) => [name(s), s]));
  const all = [...new Set([...val.steps_after.map(name), ...val.steps_before.map(name)])];
  const failed = [...val.steps_after, ...val.steps_before].filter((s) => s.status === "failed" || s.status === "timeout");
  const sd = val.sbom_diff || {};
  const KIND: Record<string, string> = { introduced: "bg-red-50 text-red-700 ring-red-600/20", still_vulnerable: "bg-amber-50 text-amber-800 ring-amber-600/20", expected: "bg-slate-50 text-slate-600 ring-slate-500/20" };
  return (
    <div className="space-y-4">
      <Card pad={false} title="Build, test and rescan" subtitle="The unchanged repository is built the same way as a baseline, so a failure that already existed is not blamed on the fix">
        <DataTable rows={all} rowKey={(s) => s} cols={[
          { key: "s", label: "Step", render: (s) => <span className="font-medium">{s}</span> },
          { key: "b", label: "Before (unchanged)", render: (s) => before[s] ? <StatusBadge status={before[s].status} /> : <span className="text-slate-400">-</span> },
          { key: "a", label: "After (remediated)", render: (s) => after[s] ? <StatusBadge status={after[s].status} /> : <span className="text-slate-400">-</span> },
          { key: "t", label: "Seconds", render: (s) => after[s]?.seconds ?? before[s]?.seconds ?? "-", className: "text-right tabular-nums" },
          { key: "n", label: "Note", render: (s) => { const x = after[s] || before[s]; return x?.status === "skipped" ? <span className="text-xs text-slate-500">{x.log}</span> : null; } },
        ]} />
      </Card>
      {failed.length > 0 && (
        <Card title="Failed step logs">
          <div className="space-y-2">{failed.map((s, i) => (
            <details key={i} className="rounded-lg border border-slate-200"><summary className="cursor-pointer px-3 py-2 text-sm"><StatusBadge status={s.status} /> {s.step}</summary>
              <div className="p-3 pt-0"><Pre text={s.log} maxHeight={260} /></div></details>
          ))}</div>
        </Card>
      )}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="SBOM before → after" subtitle={`${(sd.changed || []).length} changed · ${(sd.added || []).length} added · ${(sd.removed || []).length} removed`}>
          <ul className="max-h-80 space-y-1 overflow-auto font-mono text-xs">
            {(sd.changed || []).map((x) => <li key={"c" + x} className="text-amber-800">↕ {x}</li>)}
            {(sd.added || []).map((x) => <li key={"a" + x} className="text-emerald-700">+ {x}</li>)}
            {(sd.removed || []).map((x) => <li key={"r" + x} className="text-red-700">− {x}</li>)}
          </ul>
        </Card>
        <Card title="Findings that only exist after the fix">
          {val.new.length ? <ul className="space-y-2 text-sm">{val.new.map((n, i) => (
            <li key={i} className="flex gap-2"><Badge className={KIND[n.kind]}>{n.kind.replace(/_/g, " ")}</Badge><span className="text-slate-700">{n.title}</span></li>
          ))}</ul> : <p className="text-sm text-emerald-700">None.</p>}
        </Card>
      </div>
      <Card title="Resolved and remaining">
        <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Resolved ({val.resolved.length})</div>
        <div className="mb-4 flex flex-wrap gap-1.5">{val.resolved.map((f) => <Badge key={f} className="bg-emerald-50 text-emerald-700 ring-emerald-600/20">{f}</Badge>)}</div>
        <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Remaining ({val.remaining.length})</div>
        <div className="flex flex-wrap gap-1.5">{val.remaining.map((f) => <Badge key={f}>{f}</Badge>)}</div>
      </Card>
    </div>
  );
}

// ------------------------------------------------------------------ post-analysis: the same view, after the fix
const LEVELS = ["Critical", "High", "Medium", "Low", "Info", "Unknown"];
const LEVEL_TONE: Record<string, string> = { Critical: "bg-red-600", High: "bg-orange-500", Medium: "bg-amber-400", Low: "bg-sky-400", Info: "bg-slate-300", Unknown: "bg-slate-300" };

function PostAnalysisView({ pa, workdir, onJob }: { pa: NonNullable<Project["post_analysis"]>; workdir?: string; onJob: (id: string) => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const max = Math.max(1, ...LEVELS.flatMap((l) => [pa.before.by_level[l] || 0, pa.after.by_level[l] || 0]));
  const delta = pa.before.total - pa.after.total;
  async function again() {
    if (!workdir) return;
    setBusy(true); setErr(null);
    try { onJob((await api.run({ repo: workdir.replace(/[\\/]$/, "") + "/after", agentic: true, remediate: true, llm: "auto", osv: true, base: "", focus: "" })).id); }
    catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  }
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Findings before" value={pa.before.total} />
        <Stat label="Findings after (sandbox rescan)" value={pa.after.total} tone={pa.after.total ? undefined : "green"} />
        <Stat label="Reduction" value={`${delta >= 0 ? "-" : "+"}${Math.abs(delta)} (${pa.before.total ? Math.round((100 * delta) / pa.before.total) : 0}%)`} tone={delta > 0 ? "green" : "red"} />
        <Stat label="Built & tested in Docker" value={pa.docker ? "yes" : "no"} tone={pa.docker ? "green" : "red"} />
      </div>
      <Card title="Findings by level" subtitle="Initial scan vs. rescan of the patched copy inside the sandbox">
        <div className="space-y-2">
          {LEVELS.filter((l) => pa.before.by_level[l] || pa.after.by_level[l]).map((l) => (
            <div key={l} className="grid grid-cols-[90px_1fr] items-center gap-3 text-sm">
              <span className="text-slate-600">{l}</span>
              <div className="space-y-1">
                {(["before", "after"] as const).map((k) => (
                  <div key={k} className="flex items-center gap-2">
                    <div className={cx("h-3 rounded", k === "before" ? "bg-slate-300" : LEVEL_TONE[l])} style={{ width: `${(100 * (pa[k].by_level[l] || 0)) / max}%`, minWidth: 2 }} />
                    <span className="text-xs tabular-nums text-slate-500">{k} {pa[k].by_level[l] || 0}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </Card>
      <div className="grid gap-5 lg:grid-cols-2">
        <Card title={`Resolved (${pa.resolved.length})`}><div className="flex flex-wrap gap-1">{pa.resolved.map((r) => <Code key={r}>{r}</Code>)}</div></Card>
        <Card title={`Still open after the fix (${pa.after_findings.length})`}>
          <ul className="max-h-72 space-y-1 overflow-auto text-sm">{pa.after_findings.map((f) => <li key={f.finding_id}><Badge className="bg-slate-100 text-slate-700 ring-slate-300">{f.level}</Badge> {f.title}</li>)}</ul>
        </Card>
      </div>
      {pa.new.length > 0 && <Callout tone="warn">New after the fix: {pa.new.map((n) => `${n.title} (${n.kind})`).join("; ")}</Callout>}
      <Card title="Next iteration" subtitle="Scan the patched copy again: the agents triage what is left and propose the next fixes, until findings reach zero or stop going down.">
        <Button variant="primary" onClick={again} disabled={busy || !workdir || pa.after.total === 0}><Wrench className="h-4 w-4" /> Scan the fixed version again</Button>
        {pa.after.total === 0 && <span className="ml-3 text-sm text-emerald-700">No findings left.</span>}
        {err && <div className="mt-2"><Callout tone="error">{err}</Callout></div>}
      </Card>
    </div>
  );
}

function SandboxProofView({ t }: { t?: Project["sandbox_trace"] }) {
  if (!t || !t.containers?.length) return <Empty title="No sandbox trace">Docker is used only after you approve patchable fixes, and only when Docker is running.</Empty>;
  return (
    <div className="space-y-5">
      <Card title="Temporary Docker sandbox" subtitle="Every container below was created on this machine's Docker engine for this run and removed afterwards.">
        <dl className="divide-y divide-slate-100">
          <DetailRow label="Sandbox id"><Code>{t.sandbox}</Code></DetailRow>
          <DetailRow label="Docker engine">{t.docker_server}</DetailRow>
          <DetailRow label="Volume / network"><Code>{t.volume}</Code> <Code>{t.network}</Code> (internal network, exit only via allow-list proxy)</DetailRow>
          <DetailRow label="Verify yourself"><Code>{`docker events --since 24h --filter label=sscg.sandbox=${t.sandbox}`}</Code></DetailRow>
        </dl>
      </Card>
      <Card pad={false} title={`Containers (${t.containers.length})`}>
        <DataTable rows={t.containers} rowKey={(c) => c.container} cols={[
          { key: "n", label: "Container", render: (c) => <span className="font-mono text-xs">{c.container}</span> },
          { key: "s", label: "Started", render: (c) => <span className="whitespace-nowrap text-xs">{c.started}</span> },
          { key: "c", label: "Command", render: (c) => <span className="font-mono text-xs">{c.cmd}</span> },
          { key: "net", label: "Network", render: (c) => c.network },
          { key: "e", label: "Exit", render: (c) => <StatusBadge status={c.status} /> },
          { key: "t", label: "Seconds", render: (c) => c.seconds },
          { key: "i", label: "Image (pinned digest)", render: (c) => <span className="break-all font-mono text-[10px] text-slate-500">{c.image}</span> },
        ]} />
      </Card>
      <Card title={`docker events (${t.events?.length || 0})`} subtitle="Raw event stream from the Docker daemon, filtered by this sandbox's label">
        <Pre text={(t.events || []).join("\n") || "no events captured"} maxHeight={320} />
      </Card>
    </div>
  );
}
