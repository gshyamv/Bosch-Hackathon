import { useEffect, useRef, useState } from "react";
import { CheckCircle2, ChevronDown, ChevronUp, Terminal, X, XCircle } from "lucide-react";
import { api, Job } from "../api";
import { cx, Spinner } from "./ui";

/** Follows one background job (scan / agent / approve) and streams its console output. */
export function JobConsole({ jobId, onDone, onClose }: { jobId: string; onDone: (job: Job) => void; onClose: () => void }) {
  const [job, setJob] = useState<Job | null>(null);
  const [lines, setLines] = useState<string[]>([]);
  const [open, setOpen] = useState(true);
  const since = useRef(0);
  const box = useRef<HTMLDivElement>(null);
  const done = useRef(false);

  useEffect(() => {
    since.current = 0; done.current = false; setLines([]); setJob(null);
    let stop = false;
    async function tick() {
      try {
        const j = await api.job(jobId, since.current);
        if (stop) return;
        since.current = j.line_count;
        if (j.lines.length) setLines((l) => [...l, ...j.lines].slice(-3000));
        setJob(j);
        if (j.status !== "running") {
          if (!done.current) { done.current = true; onDone(j); }
          return;
        }
      } catch { /* server restarting: keep polling */ }
      if (!stop) setTimeout(tick, 900);
    }
    const apply = (j: Job) => {
      since.current = j.line_count;
      if (j.lines.length) setLines((l) => [...l, ...j.lines].slice(-3000));
      setJob(j);
      if (j.status !== "running" && !done.current) { done.current = true; onDone(j); }
    };
    const es = new EventSource(`/api/jobs/${jobId}/events`);
    es.onmessage = (m) => { const j = JSON.parse(m.data); apply(j); if (j.status !== "running") es.close(); };
    es.onerror = () => { es.close(); if (!stop && !done.current) tick(); };   // fall back to polling
    return () => { stop = true; es.close(); };
  }, [jobId]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { if (box.current) box.current.scrollTop = box.current.scrollHeight; }, [lines, open]);

  const running = !job || job.status === "running";
  const elapsed = job ? Math.round(((job.ended || Date.now() / 1000) - job.started)) : 0;
  const last = [...lines].reverse().find((l) => l.trim()) || "starting…";
  return (
    <div className="fixed bottom-4 right-4 z-40 w-[min(720px,calc(100vw-2rem))] overflow-hidden rounded-xl border border-ink-700 bg-ink-950 text-slate-200 shadow-2xl">
      <div className="flex items-center gap-3 px-4 py-2.5">
        {running ? <Spinner className="text-brand-400" /> : job?.status === "ok"
          ? <CheckCircle2 className="h-4 w-4 text-emerald-400" /> : <XCircle className="h-4 w-4 text-red-400" />}
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">
            {job?.kind === "approve" ? "Validating approved fixes" : job?.kind === "agent" ? "Agents at work" : "Scanning"} · {job?.project || "…"}
            <span className="ml-2 text-xs font-normal text-slate-400">{elapsed}s</span>
          </div>
          {!open && <div className="truncate font-mono text-xs text-slate-400">{last}</div>}
        </div>
        <button onClick={() => setOpen(!open)} className="rounded p-1 text-slate-400 hover:bg-ink-800 hover:text-white">
          {open ? <ChevronDown className="h-4 w-4" /> : <ChevronUp className="h-4 w-4" />}
        </button>
        {!running && <button onClick={onClose} className="rounded p-1 text-slate-400 hover:bg-ink-800 hover:text-white"><X className="h-4 w-4" /></button>}
      </div>
      {open && (
        <>
          {job?.command && (
            <div className="flex items-center gap-2 border-t border-ink-800 px-4 py-1.5 font-mono text-[11px] text-slate-500">
              <Terminal className="h-3 w-3 shrink-0" /><span className="truncate">{job.command}</span>
            </div>
          )}
          <div ref={box} className="h-64 overflow-auto border-t border-ink-800 px-4 py-2 font-mono text-[11.5px] leading-relaxed">
            {lines.map((l, i) => (
              <div key={i} className={cx("whitespace-pre-wrap break-all",
                /error|failed|traceback/i.test(l) ? "text-red-300" : /verified|wrote|✔|resolved/i.test(l) ? "text-emerald-300"
                : /^\s*\[/.test(l) ? "text-brand-200" : "text-slate-300")}>{l || " "}</div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
