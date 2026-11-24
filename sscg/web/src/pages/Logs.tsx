import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ArrowRight, Download, ExternalLink, RefreshCw, ScrollText, Terminal } from "lucide-react";
import { followJob, LogLine, logApi, LogRun, logUrl } from "../api";
import { Badge, Button, Card, Chips, cx, Empty, LinkButton, PageHeader, SearchInput, Spinner, StatusBadge, Toggle } from "../components/ui";

/** Every background job's full console log (out/<project>/logs/), parsed into stages, handoffs and decisions. */

const KIND_LABEL: Record<string, string> = { scan: "Scan", agent: "Agents", approve: "Approve & validate" };
const FIXED: Record<string, string> = {
  Scan: "#2563eb", Orchestrator: "#475569", Discovery: "#2563eb", "Vulnerability Intel": "#dc2626", Detection: "#ea580c",
  "Evidence Gatherer": "#0891b2", Triage: "#7c3aed", "Triage join": "#7c3aed", Narrator: "#db2777", Reporter: "#0d9488",
  "Exploit Intel": "#b91c1c", Reachability: "#65a30d", Prioritizer: "#d97706", Remediation: "#16a34a",
  "Remediation Planner": "#16a34a", "Remediation Advisor": "#15803d", "Human Approval": "#f59e0b", Validation: "#0284c7",
  "Remediation Reporter": "#0f766e", Context: "#64748b", Bus: "#94a3b8",
};
const PALETTE = ["#2563eb", "#16a34a", "#d97706", "#dc2626", "#7c3aed", "#0891b2", "#db2777", "#65a30d", "#ea580c", "#0d9488"];
const colorOf = (s: string | null) => {
  if (!s) return "#94a3b8";
  if (FIXED[s]) return FIXED[s];
  let h = 0;
  for (const c of s) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return PALETTE[h % PALETTE.length];
};
const WORKFLOW_KINDS = new Set(["header", "handoff", "decision", "question", "answer", "summary", "error"]);
const isWorkflow = (l: LogLine) => l.transition || WORKFLOW_KINDS.has(l.kind);
const RENDER_CAP = 4000;

// ------------------------------------------------------------------ parser (same rules as sscg/joblog.py parse)
const TAG = /^\s*\[([^\]\n]{1,60})\]\s?(.*)$/, BUS = /^(.+?) → (.+?) \((\w+)\):\s?(.*)$/, HEADER = /^\s*=== (.+?) ===\s*$/;
const SUMMARY = /^\s*[①②③④⑤]\s/;
const ERROR = /Traceback \(most recent call last\)|^\s*(error|ERROR|Error)\b|^\s*!\s|\w+Error: |\bException\b/;
const DECISION = /PAUSED for human approval|LLM disabled|verdict|Validation: |decisions: /i;
interface ParseState { prevTag: string | null; stage: string | null; n: number }

function parseLive(texts: string[], st: ParseState): LogLine[] {
  const out: LogLine[] = [];
  for (const text of texts) {
    const rec: LogLine = { n: st.n++, ts: new Date().toISOString(), text, tag: null, stage: null, kind: "text", message: text.trim(), transition: false };
    const h = HEADER.exec(text), m = TAG.exec(text);
    if (h) {
      const t = h[1].startsWith("Guardian scan") ? "Scan" : h[1].startsWith("Guardian agents") ? "Orchestrator" : h[1].includes("resuming") ? "Human Approval" : null;
      Object.assign(rec, { kind: "header", tag: t, stage: t, message: h[1] }); st.prevTag = t;
    } else if (m) {
      const tag = m[1].trim();
      Object.assign(rec, { tag, stage: tag, kind: "agent", message: m[2] });
      if (tag === "Bus") {
        const b = BUS.exec(m[2]);
        if (b) Object.assign(rec, { stage: b[1], kind: b[3], message: b[4], from: b[1], to: b[2] });
      }
      st.prevTag = tag;
    } else if (SUMMARY.test(text)) {
      Object.assign(rec, { tag: "Scan", stage: "Scan", kind: "summary" }); st.prevTag = "Scan";
    } else if (text.startsWith("    ") && st.prevTag && st.prevTag !== "Bus") {
      Object.assign(rec, { tag: st.prevTag, stage: st.prevTag, kind: "detail" });
    } else if (!text.trim()) st.prevTag = null;
    if (ERROR.test(text)) rec.kind = "error";
    else if ((rec.kind === "agent" || rec.kind === "detail") && DECISION.test(text)) rec.kind = "decision";
    if (rec.stage && rec.stage !== st.stage && rec.kind !== "detail") { rec.transition = true; st.stage = rec.stage; }
    out.push(rec);
  }
  return out;
}

function stateAfter(lines: LogLine[]): ParseState {
  const last = lines[lines.length - 1];
  const stage = [...lines].reverse().find((l) => l.stage && l.kind !== "detail")?.stage ?? null;
  return { prevTag: last && last.text.trim() && last.tag !== "Bus" ? last.tag : null, stage, n: lines.length };
}

// ------------------------------------------------------------------ helpers
const ms = (ts: string | null) => (ts ? Date.parse(ts) : NaN);
const clock = (ts: string | null) => (ts ? new Date(ts).toLocaleTimeString([], { hour12: false }) : "");
function dur(sec: number | null | undefined) {
  if (sec == null || !isFinite(sec)) return "-";
  if (sec < 1) return `${Math.round(sec * 1000)}ms`;
  if (sec < 60) return `${sec.toFixed(sec < 10 ? 1 : 0)}s`;
  const m = Math.floor(sec / 60), s = Math.round(sec % 60);
  return m < 60 ? `${m}m ${s}s` : `${Math.floor(m / 60)}h ${m % 60}m`;
}
const runDur = (r: LogRun) => (r.started ? ((r.ended || (r.status === "running" ? Date.now() / 1000 : r.started)) - r.started) : null);

interface StageSpan { stage: string; start: number; end: number; lines: number }
function timeline(lines: LogLine[]): StageSpan[] {
  const m = new Map<string, StageSpan>();
  for (const l of lines) {
    const t = ms(l.ts);
    if (!l.stage || !isFinite(t)) continue;
    const s = m.get(l.stage);
    if (s) { s.end = Math.max(s.end, t); s.lines++; } else m.set(l.stage, { stage: l.stage, start: t, end: t, lines: 1 });
  }
  return [...m.values()].sort((a, b) => a.start - b.start);
}

// ------------------------------------------------------------------ page
export function Logs({ current }: { current?: string | null }) {
  const [runs, setRuns] = useState<LogRun[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [project, setProject] = useState<string>("");
  const [sel, setSel] = useState<LogRun | null>(null);
  const [lines, setLines] = useState<LogLine[]>([]);
  const [loading, setLoading] = useState(false);
  const [live, setLive] = useState(false);
  const [q, setQ] = useState("");
  const [stages, setStages] = useState<string[]>([]);
  const [workflow, setWorkflow] = useState(false);
  const [follow, setFollow] = useState(true);
  const box = useRef<HTMLDivElement>(null);

  const loadRuns = useCallback(() => logApi.list().then((r) => { setRuns(r); setErr(null); return r; }).catch((e) => { setErr(e.message); return null; }), []);
  useEffect(() => { loadRuns(); }, [loadRuns]);
  useEffect(() => {   // keep the list fresh (new runs appear, running ones finish)
    const t = setInterval(loadRuns, runs?.some((r) => r.status === "running") ? 4000 : 15000);
    return () => clearInterval(t);
  }, [runs, loadRuns]);
  useEffect(() => {   // pick the newest run (of the current application if it has one) on first load
    if (sel || !runs?.length) return;
    setSel(runs.find((r) => r.project === current) || runs[0]);
  }, [runs]); // eslint-disable-line react-hooks/exhaustive-deps

  // load the selected log; follow it over SSE while the job is still running
  useEffect(() => {
    if (!sel) return;
    let stop = false, close: (() => void) | null = null;
    setLoading(true); setLines([]); setStages([]); setLive(false);
    (async () => {
      try {
        const doc = await logApi.get(sel.project, sel.file);
        if (stop) return;
        setLines(doc.lines);
        if (doc.meta.status !== "running") return;
        const j = await logApi.job(sel.id).catch(() => null);   // null: the server restarted, the job is gone
        if (stop || !j) return;
        if (j.status !== "running") {   // it finished in between: read the complete file again
          const again = await logApi.get(sel.project, sel.file);
          if (!stop) { setLines(again.lines); loadRuns(); }
          return;
        }
        const st = stateAfter(doc.lines);
        setLive(true);
        close = followJob(sel.id, Math.max(0, doc.lines.length - (j.dropped || 0)),
          (u) => { if (u.lines.length) { const add = parseLive(u.lines, st); setLines((l) => [...l, ...add]); } },
          async () => {   // finished: the file is the authoritative record (real timestamps, nothing trimmed)
            if (stop) return;
            setLive(false);
            try { setLines((await logApi.get(sel.project, sel.file)).lines); } catch { /* keep the live lines */ }
            loadRuns();
          });
      } catch (e: any) { if (!stop) setErr(e.message); } finally { if (!stop) setLoading(false); }
    })();
    return () => { stop = true; close?.(); };
  }, [sel?.project, sel?.file]); // eslint-disable-line react-hooks/exhaustive-deps

  const cur = (sel && runs?.find((r) => r.project === sel.project && r.file === sel.file)) || sel;   // fresh status / end time
  const projects = useMemo(() => [...new Set((runs || []).map((r) => r.project))].sort(), [runs]);
  const shownRuns = useMemo(() => (runs || []).filter((r) => !project || r.project === project), [runs, project]);
  const spans = useMemo(() => timeline(lines), [lines]);
  const allStages = useMemo(() => spans.map((s) => s.stage).filter((s) => s !== "Bus"), [spans]);
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return lines.filter((l) => (!stages.length || (l.stage && stages.includes(l.stage)) || (l.from && stages.includes(l.from)) || (l.to && stages.includes(l.to)))
      && (!workflow || isWorkflow(l)) && (!needle || l.text.toLowerCase().includes(needle)));
  }, [lines, stages, workflow, q]);
  const counts = useMemo(() => ({
    handoffs: lines.filter((l) => l.kind === "handoff").length, decisions: lines.filter((l) => l.kind === "decision").length,
    errors: lines.filter((l) => l.kind === "error").length,
  }), [lines]);

  useEffect(() => { if (follow && live && box.current) box.current.scrollTop = box.current.scrollHeight; }, [filtered, follow, live]);

  return (
    <div className="space-y-5">
      <PageHeader title="Logs"
        description="The complete console output of every scan, agent run and approval, kept in out/<application>/logs/. Read it to follow the workflow: which agent ran when, what it handed to whom, and what was decided."
        actions={<Button variant="secondary" onClick={loadRuns}><RefreshCw className="h-4 w-4" /> Refresh</Button>} />
      {err && <Empty title="Logs not available">{err}</Empty>}
      {runs && !runs.length && (
        <Empty icon={<ScrollText className="h-10 w-10" />} title="No logs yet">
          Every run started from the dashboard (New run, or approving fixes) writes its full log here.
        </Empty>
      )}
      {!!runs?.length && (
        <div className="grid gap-5 lg:grid-cols-[320px_minmax(0,1fr)]">
          {/* ---------------- runs */}
          <Card pad={false} title="Runs" subtitle={`${shownRuns.length} of ${runs.length}`} className="self-start"
            actions={projects.length > 1 && (
              <select value={project} onChange={(e) => setProject(e.target.value)}
                className="max-w-[160px] rounded-md border-0 py-1 pl-2 pr-7 text-xs ring-1 ring-inset ring-slate-300 focus:ring-2 focus:ring-brand-500">
                <option value="">All applications</option>
                {projects.map((p) => <option key={p} value={p}>{p}</option>)}
              </select>
            )}>
            <div className="max-h-[70vh] overflow-y-auto">
              {shownRuns.map((r) => (
                <button key={`${r.project}/${r.file}`} onClick={() => setSel(r)}
                  className={cx("block w-full border-b border-slate-100 px-4 py-2.5 text-left transition last:border-0",
                    sel?.file === r.file && sel.project === r.project ? "bg-brand-50" : "hover:bg-slate-50")}>
                  <div className="flex items-center gap-2">
                    <span className="min-w-0 flex-1 truncate text-sm font-medium text-slate-900">{r.project}</span>
                    {r.status === "running" ? <Badge className="bg-brand-50 text-brand-700 ring-brand-600/20"><Spinner className="h-3 w-3" /> running</Badge> : <StatusBadge status={r.status} />}
                  </div>
                  <div className="mt-0.5 flex items-center gap-2 text-xs text-slate-500">
                    <span className="font-medium text-slate-600">{KIND_LABEL[r.kind] || r.kind}</span>
                    <span>·</span><span>{r.started ? new Date(r.started * 1000).toLocaleString() : "-"}</span>
                    <span className="ml-auto tabular-nums">{dur(runDur(r))}</span>
                  </div>
                </button>
              ))}
            </div>
          </Card>

          {/* ---------------- one log */}
          {!sel ? <Empty title="Pick a run" /> : (
            <div className="min-w-0 space-y-4">
              <Card pad={false}
                title={<span className="flex items-center gap-2">{KIND_LABEL[cur!.kind] || cur!.kind} · {cur!.project}
                  {live && <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2 py-0.5 text-[11px] font-medium text-emerald-700 ring-1 ring-inset ring-emerald-600/20"><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-500" /> live</span>}</span>}
                subtitle={<span>{cur!.started ? new Date(cur!.started * 1000).toLocaleString() : ""} · {dur(runDur(cur!))} · {lines.length} lines
                  {cur!.returncode != null && ` · exit ${cur!.returncode}`} · {counts.handoffs} handoffs · {counts.decisions} decisions
                  {counts.errors > 0 && <span className="text-red-600"> · {counts.errors} errors</span>}</span>}
                actions={<>
                  <LinkButton href={logUrl(sel.project, sel.file)}><ExternalLink className="h-4 w-4" /> Raw</LinkButton>
                  <LinkButton href={logUrl(sel.project, sel.file, true)} download><Download className="h-4 w-4" /> Download</LinkButton>
                </>}>
                {cur!.command && (
                  <div className="flex items-center gap-2 border-b border-slate-100 px-5 py-2 font-mono text-[11px] text-slate-500">
                    <Terminal className="h-3 w-3 shrink-0" /><span className="truncate" title={cur!.command!}>{cur!.command}</span>
                  </div>
                )}
                <Timeline spans={spans} active={stages} onPick={(s) => setStages(stages.includes(s) ? stages.filter((x) => x !== s) : [...stages, s])} />
              </Card>

              <Card pad={false}>
                <div className="flex flex-wrap items-center gap-3 border-b border-slate-100 px-4 py-3">
                  <SearchInput value={q} onChange={setQ} placeholder="Search the log" />
                  <Toggle checked={workflow} onChange={setWorkflow} label="Workflow only" hint="Only stage changes, handoffs, decisions and errors" />
                  {live && <Toggle checked={follow} onChange={setFollow} label="Follow" hint="Keep the newest line in view" />}
                  <span className="ml-auto text-xs tabular-nums text-slate-500">{filtered.length} / {lines.length} lines</span>
                </div>
                {allStages.length > 1 && (
                  <div className="flex items-start gap-2 border-b border-slate-100 px-4 py-2.5">
                    <span className="mt-1 text-xs font-medium text-slate-500">Stages</span>
                    <Chips options={allStages} value={stages} onChange={setStages} />
                    {!!stages.length && <button onClick={() => setStages([])} className="mt-1 text-xs text-brand-600 hover:underline">clear</button>}
                  </div>
                )}
                <div ref={box} className="max-h-[68vh] min-h-[240px] overflow-auto rounded-b-xl bg-ink-950 py-2 font-mono text-[11.5px] leading-relaxed text-slate-300">
                  {loading && !lines.length ? <div className="flex items-center gap-2 px-4 py-6 text-slate-400"><Spinner /> Loading log…</div>
                    : !filtered.length ? <div className="px-4 py-6 text-slate-500">{lines.length ? "No line matches the filters." : "This log is empty."}</div>
                    : <>
                      {filtered.length > RENDER_CAP && <div className="px-4 pb-2 text-amber-300">Showing the last {RENDER_CAP} of {filtered.length} matching lines: narrow the filters or download the log for the rest.</div>}
                      {filtered.slice(-RENDER_CAP).map((l) => <Line key={l.n} l={l} />)}
                    </>}
                </div>
              </Card>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Line({ l }: { l: LogLine }) {
  const c = colorOf(l.stage);
  const bus = l.tag === "Bus" && l.from;
  return (
    <div className={cx("group flex gap-3 px-4 hover:bg-white/5", l.transition && l.n > 0 && "mt-1.5 border-t border-white/10 pt-1.5",
      l.kind === "error" && "bg-red-500/10")}>
      <span className="w-6 shrink-0 select-none text-right text-slate-600">{l.n + 1}</span>
      <span className="w-16 shrink-0 select-none tabular-nums text-slate-500">{clock(l.ts)}</span>
      <span className="w-36 shrink-0 truncate" style={{ color: c }} title={l.stage || ""}>
        {l.stage ? (l.kind === "detail" ? "" : `● ${l.stage}`) : ""}
      </span>
      <span className={cx("min-w-0 flex-1 whitespace-pre-wrap break-words",
        l.kind === "error" ? "text-red-300" : l.kind === "header" ? "font-semibold text-white"
        : l.kind === "decision" ? "text-amber-200" : l.kind === "summary" ? "text-sky-200" : l.kind === "detail" ? "text-slate-400" : "")}>
        {bus ? (
          <>
            <span style={{ color: colorOf(l.from!) }}>{l.from}</span>
            <ArrowRight className="mx-1 inline h-3 w-3 text-slate-500" />
            <span style={{ color: colorOf(l.to!) }}>{l.to}</span>
            <span className={cx("mx-1.5 rounded px-1 text-[10px] uppercase", l.kind === "decision" ? "bg-amber-400/20 text-amber-200" : "bg-white/10 text-slate-300")}>{l.kind}</span>
            <span className="text-slate-300">{l.message}</span>
          </>
        ) : (l.kind === "header" || l.tag ? l.message : l.text) || " "}
      </span>
    </div>
  );
}

function Timeline({ spans, active, onPick }: { spans: StageSpan[]; active: string[]; onPick: (s: string) => void }) {
  const rows = spans.filter((s) => s.stage !== "Bus");
  if (!rows.length) return <div className="px-5 py-3 text-xs text-slate-500">No stages found in this log.</div>;
  const t0 = Math.min(...rows.map((s) => s.start)), t1 = Math.max(...rows.map((s) => s.end));
  const total = Math.max(1, t1 - t0);
  return (
    <div className="px-5 py-3">
      <div className="mb-1.5 flex items-center justify-between text-[11px] font-medium uppercase tracking-wider text-slate-500">
        <span>Stage timeline</span><span className="normal-case tracking-normal tabular-nums">{dur(total / 1000)} total</span>
      </div>
      <div className="space-y-0.5">
        {rows.map((s) => {
          const left = ((s.start - t0) / total) * 100, width = Math.max(0.6, ((s.end - s.start) / total) * 100);
          const on = !active.length || active.includes(s.stage);
          return (
            <button key={s.stage} onClick={() => onPick(s.stage)} title={`${s.stage}: started +${dur((s.start - t0) / 1000)}, lasted ${dur((s.end - s.start) / 1000)}, ${s.lines} lines`}
              className={cx("grid w-full grid-cols-[130px_minmax(0,1fr)_120px] items-center gap-2 rounded px-1 py-0.5 text-left text-xs transition hover:bg-slate-50", !on && "opacity-40")}>
              <span className="truncate font-medium" style={{ color: colorOf(s.stage) }}>{s.stage}</span>
              <span className="relative h-2.5 rounded-full bg-slate-100">
                <span className="absolute inset-y-0 rounded-full" style={{ left: `${Math.min(left, 99.4)}%`, width: `${Math.min(width, 100 - Math.min(left, 99.4))}%`, background: colorOf(s.stage) }} />
              </span>
              <span className="truncate text-right tabular-nums text-slate-500">+{dur((s.start - t0) / 1000)} · {dur((s.end - s.start) / 1000)}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
