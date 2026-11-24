import { useState } from "react";
import { Check, Hand, Minus, X } from "lucide-react";
import type { Job, Project } from "../api";
import type { Page } from "../App";
import { cx, Spinner } from "./ui";

/** The Guardian pipeline as one horizontal stepper, fed either by a live job log or by the saved project files. */

export type StepStatus = "pending" | "running" | "done" | "waiting" | "skipped" | "failed";
export interface StepView { status: StepStatus; detail?: string }

export const STEPS: { id: string; label: string; explain: string; page: Page }[] = [
  { id: "discover", label: "Discover", page: "supply",
    explain: "Reads the manifests and lockfiles, then builds the SBOM and the dependency graph." },
  { id: "intel", label: "Vulnerability intel", page: "vulns",
    explain: "Looks up every component in OSV for known vulnerabilities (CVEs and advisories)." },
  { id: "detect", label: "Detect", page: "evidence",
    explain: "Rules flag supply-chain red flags: install scripts, odd sources, look-alike names, risky CI." },
  { id: "triage", label: "AI triage", page: "ai",
    explain: "An AI agent checks unclear findings with read-only tools and explains its verdict." },
  { id: "prioritise", label: "Prioritise", page: "remediation",
    explain: "Ranks findings by known exploitation (CISA KEV, EPSS), reachability and exposure." },
  { id: "propose", label: "Propose fixes", page: "remediation",
    explain: "Plans the smallest safe upgrade or patch for each risk and explains the trade-off." },
  { id: "approval", label: "Human approval", page: "remediation",
    explain: "Nothing is changed until a person approves, rejects or accepts the risk of each fix." },
  { id: "sandbox", label: "Sandbox build & test", page: "remediation",
    explain: "Applies the approved fixes to a copy and builds and tests it in an isolated Docker container." },
  { id: "rescan", label: "Rescan / post-analysis", page: "remediation",
    explain: "Rescans the fixed copy and compares findings before and after to prove the risk went down." },
];

const N = STEPS.length;
const APPROVAL = 6, SANDBOX = 7, RESCAN = 8;

// Backend log tags: `rt.log("Name", ...)` prints "  [Name] msg"; bus handoffs print "  [Bus] A → B (kind): ...".
const TAG_STEP: Record<string, number> = {
  "Orchestrator": 0, "Discovery": 0, "Vulnerability Intel": 1, "Detection": 2,
  "Evidence Gatherer": 3, "Triage": 3, "Triage join": 3, "Narrator": 3, "Reporter": 3,
  "Exploit Intel": 4, "Reachability": 4, "Exploit Intel + Reachability": 4, "Prioritizer": 4,
  "Remediation": 5, "Remediation Planner": 5, "Remediation Advisor": 5,
  "Human Approval": APPROVAL, "Validation": SANDBOX, "Validation (Docker sandbox)": SANDBOX, "Remediation Reporter": RESCAN,
};

// ------------------------------------------------------------------ live: incremental log tracker
export interface LogTrack {
  seen: boolean[]; predicted: number; paused: boolean; finished: boolean;
  forced: (StepStatus | null)[]; notes: (string | null)[];
}
export const emptyTrack = (): LogTrack =>
  ({ seen: Array(N).fill(false), predicted: -1, paused: false, finished: false, forced: Array(N).fill(null), notes: Array(N).fill(null) });

/** Pure: returns a new tracker after reading more console lines (lines are fed once, so trimming the console is safe). */
export function feedLog(t: LogTrack, lines: string[]): LogTrack {
  if (!lines.length) return t;
  const s: LogTrack = { ...t, seen: [...t.seen], forced: [...t.forced], notes: [...t.notes] };
  const see = (i: number, note?: string) => { s.seen[i] = true; if (note) s.notes[i] = note.slice(0, 160); };
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    if (/PAUSED for human approval/.test(line)) { s.paused = true; see(APPROVAL, line); continue; }
    // rules-only console summary (pipeline.print_console)
    if (/^① components/.test(line)) { see(0, line); continue; }
    if (/^③ vulnerabilities/.test(line)) { see(1, line); continue; }
    if (/^[④⑤] /.test(line)) { see(2, line); continue; }
    const m = /^\[([^\]]+)\]\s*(.*)$/.exec(line);
    if (!m) continue;
    const [, tag, msg] = m;
    if (tag === "Bus") {
      const b = /^(.+?) → (.+?) \(\w+\):/.exec(msg);
      if (!b) continue;
      const from = TAG_STEP[b[1]] ?? -1;
      let to = TAG_STEP[b[2]] ?? -1;
      if (b[2] === "Human reviewer") to = from >= 0 && from < APPROVAL ? APPROVAL : -1;
      if (b[1] === "Remediation Reporter") s.finished = true;
      if (from >= 0) see(from);
      if (to > s.predicted) s.predicted = to;
      continue;
    }
    const i = TAG_STEP[tag];
    if (i === undefined) continue;
    if (tag === "Human Approval") {
      if (/graph is paused/.test(msg)) s.paused = true;
      else s.paused = false;
      see(APPROVAL, msg);
      continue;
    }
    if (tag === "Validation") {
      if (/nothing approved to validate/.test(msg)) { s.forced[SANDBOX] = "skipped"; s.forced[RESCAN] = "skipped"; see(SANDBOX, msg); continue; }
      if (/Docker is not available/.test(msg)) { s.forced[SANDBOX] = "skipped"; see(SANDBOX, "Docker not available: lockfile change + rescan only"); continue; }
      if (/sandbox error/.test(msg)) { s.forced[SANDBOX] = "failed"; see(SANDBOX, msg); continue; }
      if (/^rescanning/.test(msg)) { see(SANDBOX); see(RESCAN, msg); continue; }
      const v = /^(VERIFIED|PARTIALLY_VERIFIED|FAILED|NOT_RUN)\b/.exec(msg);
      if (v) { see(RESCAN, msg); if (v[1] === "FAILED") s.forced[RESCAN] = "failed"; continue; }
    }
    see(i, msg);
  }
  return s;
}

/** Step states for a live (or just finished) job. */
export function stepsFromLog(t: LogTrack, job: Pick<Job, "kind" | "status"> | null): StepView[] {
  const kind = job?.kind || "agent", status = job?.status || "running";
  const seen = [...t.seen];
  if (kind === "approve") for (let i = 0; i < APPROVAL; i++) seen[i] = true;   // earlier steps ran in the paused run
  const maxSeen = seen.lastIndexOf(true);
  const floor = kind === "approve" ? APPROVAL : 0;
  const current = Math.max(maxSeen, t.predicted, floor);
  const out: StepView[] = STEPS.map((_, i) => ({ status: "pending", detail: t.notes[i] || undefined }));
  for (let i = 0; i < N; i++) {
    const o = out[i];
    if (kind === "scan" && i > 2) { o.status = "skipped"; o.detail = "not in a rules-only scan"; continue; }
    if (status === "running") {
      if (kind === "scan") o.status = seen[i] ? "done" : "running";
      else if (i < current) o.status = seen[i] ? "done" : "skipped";
      else if (i === current) o.status = "running";
    } else if (status === "ok") {
      if (seen[i]) o.status = "done";
      else if (i < maxSeen) o.status = "skipped";
      else { o.status = "skipped"; o.detail = o.detail || "not in this run"; }
    } else {   // failed
      if (i < current) o.status = seen[i] ? "done" : "skipped";
      else if (i === current) o.status = "failed";
    }
    if (t.forced[i] && (o.status === "done" || o.status === "running")) o.status = t.forced[i]!;
  }
  if (t.paused && !t.finished) {
    out[APPROVAL] = { status: "waiting", detail: t.notes[APPROVAL] || "waiting for your decision" };
    for (let i = APPROVAL + 1; i < N; i++) out[i] = { status: "pending" };
  }
  return out;
}

// ------------------------------------------------------------------ saved results: from the project files
export function stepsFromProject(p: Project): StepView[] {
  const doc = p.findings, ag = p.agentic, pend = p.pending, rem = p.remediation, pa = p.post_analysis;
  const val = rem?.validations?.[rem.validations.length - 1];
  const out: StepView[] = STEPS.map(() => ({ status: "pending" }));
  if (p.summary) out[0] = { status: "done", detail: `${p.summary.components_total} components` };
  if (doc) {
    out[1] = { status: "done", detail: `${doc.counts.vulnerabilities} vulnerable` };
    out[2] = { status: "done", detail: `${doc.counts.total} findings` };
  }
  const later = !!(pend || rem);
  if (ag) out[3] = { status: "done", detail: `${Object.keys(ag.triage || {}).length} reviewed` };
  else if (later) out[3] = { status: "skipped", detail: "rules only" };
  else if (doc) out[3] = { status: "pending", detail: "needs an agent run" };
  if (later) {
    const n = (pend?.proposals || rem?.proposals || []).length;
    out[4] = { status: "done", detail: rem?.priorities?.length ? `${rem.priorities.length} ranked` : "ranked" };
    out[5] = { status: "done", detail: `${n} proposal${n === 1 ? "" : "s"}` };
  }
  if (pend) {
    out[APPROVAL] = { status: "waiting", detail: `${pend.proposals.length} to decide` };
    return out;   // sandbox / rescan files on disk belong to an older run
  }
  if (rem) {
    const ok = rem.approvals.filter((a) => a.decision === "approve" || a.decision === "approved").length;
    out[APPROVAL] = rem.proposals.length ? { status: "done", detail: `${ok} approved` } : { status: "skipped", detail: "nothing to fix" };
    if (!val) { out[SANDBOX] = out[RESCAN] = { status: "skipped", detail: "not run" }; return out; }
    if (val.verdict === "not_run") { out[SANDBOX] = out[RESCAN] = { status: "skipped", detail: "nothing approved" }; return out; }
    const docker = pa ? pa.docker : !!val.docker;
    const broke = (val.steps_after || []).some((s) => s.status === "failed" || s.status === "timeout");
    out[SANDBOX] = !docker ? { status: "skipped", detail: "Docker not available" }
      : broke ? { status: "failed", detail: "build/test failed" } : { status: "done", detail: "build & tests ran" };
    out[RESCAN] = { status: val.verdict === "failed" ? "failed" : "done",
                    detail: `${val.findings_before}→${val.findings_after} findings · ${val.verdict.replace(/_/g, " ")}` };
  }
  return out;
}

// ------------------------------------------------------------------ view
const WORD: Record<StepStatus, string> = {
  pending: "pending", running: "running…", done: "done", waiting: "waiting for you", skipped: "skipped", failed: "failed",
};

function Dot({ s, n, dark }: { s: StepStatus; n: number; dark?: boolean }) {
  const base = "relative z-10 flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-xs font-semibold ring-4";
  const ring = dark ? "ring-ink-950" : "ring-white";
  if (s === "done") return <span className={cx(base, ring, "bg-emerald-600 text-white")}><Check className="h-4 w-4" /></span>;
  if (s === "running") return <span className={cx(base, ring, "bg-brand-600 text-white")}><Spinner className="h-3.5 w-3.5" /></span>;
  if (s === "waiting") return <span className={cx(base, ring, "animate-pulse bg-amber-500 text-white")}><Hand className="h-4 w-4" /></span>;
  if (s === "failed") return <span className={cx(base, ring, "bg-red-600 text-white")}><X className="h-4 w-4" /></span>;
  if (s === "skipped") return <span className={cx(base, ring, "border-2 border-dashed", dark ? "border-ink-600 bg-ink-900 text-slate-500" : "border-slate-300 bg-white text-slate-400")}><Minus className="h-3.5 w-3.5" /></span>;
  return <span className={cx(base, ring, dark ? "bg-ink-800 text-slate-400" : "bg-slate-100 text-slate-500")}>{n}</span>;
}

/** Horizontal stepper. Hover (or focus) a step to read what it does; finished steps open their page when `onGo` is given. */
export function PipelineStepper({ steps, onGo, dark, className }:
  { steps: StepView[]; onGo?: (p: Page) => void; dark?: boolean; className?: string }) {
  const [hover, setHover] = useState<number | null>(null);
  const focus = hover ?? (() => {
    const live = steps.findIndex((s) => s.status === "running" || s.status === "waiting" || s.status === "failed");
    return live >= 0 ? live : steps.findIndex((s) => s.status === "pending");
  })();
  const reached = (s?: StepView) => !!s && s.status !== "pending";
  return (
    <div className={className}>
      <div className="overflow-x-auto pb-1">
        <ol className="flex min-w-[720px]">
          {STEPS.map((st, i) => {
            const v = steps[i] || { status: "pending" as StepStatus };
            const click = onGo && (v.status === "done" || v.status === "waiting" || v.status === "failed");
            const line = (on: boolean) => on ? "bg-emerald-500" : dark ? "bg-ink-700" : "bg-slate-200";
            return (
              <li key={st.id} className="relative flex min-w-0 flex-1 flex-col items-center">
                {i > 0 && <span className={cx("absolute left-0 right-1/2 top-[15px] h-0.5", line(reached(v)))} />}
                {i < N - 1 && <span className={cx("absolute left-1/2 right-0 top-[15px] h-0.5", line(reached(steps[i + 1])))} />}
                <button type="button" disabled={!click} onClick={() => click && onGo!(st.page)}
                  onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}
                  onFocus={() => setHover(i)} onBlur={() => setHover(null)}
                  title={`${st.label}: ${st.explain}${v.detail ? `\n${v.detail}` : ""}`}
                  className={cx("flex w-full flex-col items-center gap-1 rounded-lg px-1 pb-1 text-center outline-none focus-visible:ring-2 focus-visible:ring-brand-500",
                    click ? "cursor-pointer" : "cursor-default", click && (dark ? "hover:bg-ink-900" : "hover:bg-slate-50"))}>
                  <Dot s={v.status} n={i + 1} dark={dark} />
                  <span className={cx("text-[11px] font-semibold leading-tight",
                    dark ? (v.status === "pending" ? "text-slate-500" : "text-slate-100") : (v.status === "pending" ? "text-slate-500" : "text-slate-900"))}>
                    {st.label}
                  </span>
                  <span className={cx("w-full truncate text-[10px] leading-tight",
                    v.status === "waiting" ? "font-medium text-amber-500" : v.status === "failed" ? "text-red-500"
                      : v.status === "running" ? (dark ? "text-brand-400" : "text-brand-600") : dark ? "text-slate-500" : "text-slate-400")}>
                    {v.status === "done" || v.status === "skipped" ? (v.detail || WORD[v.status]) : WORD[v.status]}
                  </span>
                </button>
              </li>
            );
          })}
        </ol>
      </div>
      {focus >= 0 && (
        <p className={cx("mt-1 text-xs", dark ? "line-clamp-2 break-words text-slate-400" : "text-slate-500")}>
          <b className={dark ? "text-slate-200" : "text-slate-700"}>{focus + 1}. {STEPS[focus].label}</b>
          <span className="mx-1">·</span>{STEPS[focus].explain}
          {steps[focus]?.detail && steps[focus].status !== "done" && <span className="ml-1 opacity-80">({steps[focus].detail})</span>}
        </p>
      )}
    </div>
  );
}
