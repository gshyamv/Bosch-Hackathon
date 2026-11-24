import { useEffect, useMemo, useState } from "react";
import { ArrowRight, Bot, MessagesSquare, Repeat } from "lucide-react";
import { AgentMessage, api, Project } from "../api";
import { Badge, Card, cx, DataTable, Empty, PageHeader, StatusBadge } from "../components/ui";

const KIND_TONE: Record<string, string> = {
  handoff: "bg-slate-100 text-slate-700 ring-slate-300",
  question: "bg-sky-50 text-sky-800 ring-sky-600/30",
  answer: "bg-violet-50 text-violet-800 ring-violet-600/30",
  decision: "bg-emerald-50 text-emerald-800 ring-emerald-600/30",
};

export function Agents({ p, go }: { p: Project; go?: (project: string) => void }) {
  const [msgs, setMsgs] = useState<AgentMessage[]>(p.messages || []);
  const [kind, setKind] = useState<string>("all");
  useEffect(() => {
    setMsgs(p.messages || []);
    const t = setInterval(() => api.messages(p.name).then(setMsgs).catch(() => {}), 3000);   // live while a run is going
    return () => clearInterval(t);
  }, [p.name, p.messages]);
  const shown = useMemo(() => msgs.filter((m) => kind === "all" || m.kind === kind), [msgs, kind]);
  const agents = useMemo(() => Array.from(new Set(msgs.flatMap((m) => [m.sender, m.recipient]))), [msgs]);
  const its = p.iterations || [];

  return (
    <div className="space-y-6">
      <PageHeader title="Agents & remediation loop"
        description="How the agents hand work to each other (handoffs), ask each other for evidence (questions / answers) and decide. Each loop iteration rescans the fixed sandbox copy." />

      <Card title="Remediation loop" subtitle="Iteration 0 is the original target; every next iteration scans the copy fixed and validated in Docker by the previous one."
        actions={<Repeat className="h-4 w-4 text-slate-400" />}>
        {its.length === 0 ? <p className="text-sm text-slate-500">No iterations yet.</p> : (
          <div className="flex flex-wrap items-center gap-2">
            {its.map((it, i) => (
              <div key={it.project} className="flex items-center gap-2">
                {i > 0 && <ArrowRight className="h-4 w-4 text-slate-400" />}
                <button type="button" onClick={() => go?.(it.project)}
                  className={cx("rounded-lg border px-3 py-2 text-left text-sm shadow-card", it.project === p.name ? "border-brand-500 bg-brand-50" : "border-slate-200 bg-white hover:bg-slate-50")}>
                  <div className="font-semibold text-slate-900">Iteration {it.iteration}</div>
                  <div className="text-xs text-slate-600">{it.findings ?? "?"} findings{it.after_fix != null ? ` → ${it.after_fix} after fix` : ""}</div>
                  {it.verdict && <div className="mt-1"><StatusBadge status={it.verdict} /></div>}
                </button>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card pad={false} title={`Agent conversation (${msgs.length})`} subtitle={`${agents.length} agents involved`}
        actions={
          <div className="inline-flex rounded-lg bg-slate-100 p-0.5 text-xs">
            {["all", "handoff", "question", "answer", "decision"].map((k) => (
              <button key={k} type="button" onClick={() => setKind(k)} className={cx("rounded-md px-2.5 py-1 font-medium", kind === k ? "bg-white shadow-sm text-slate-900" : "text-slate-500")}>{k}</button>
            ))}
          </div>
        }>
        {msgs.length === 0 ? <Empty icon={<MessagesSquare className="h-8 w-8" />} title="No agent messages yet">Start a run: the agents post their handoffs here as they work.</Empty> : (
          <DataTable rows={shown} rowKey={(m) => `${m.at}-${m.sender}-${m.content.slice(0, 40)}`} maxHeight={640} cols={[
            { key: "t", label: "Time", render: (m) => <span className="whitespace-nowrap font-mono text-xs text-slate-500">{m.at.slice(11, 19)}</span> },
            { key: "f", label: "From → To", render: (m) => <span className="whitespace-nowrap text-sm"><Bot className="mr-1 inline h-3.5 w-3.5 text-brand-600" /><b>{m.sender}</b> <ArrowRight className="mx-1 inline h-3 w-3 text-slate-400" /> {m.recipient}</span> },
            { key: "k", label: "Kind", render: (m) => <Badge className={KIND_TONE[m.kind] || KIND_TONE.handoff}>{m.kind}</Badge> },
            { key: "c", label: "Message", render: (m) => <span className="text-sm text-slate-700">{m.content}</span> },
          ]} />
        )}
      </Card>
    </div>
  );
}
