import { useMemo, useState } from "react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { AlertTriangle, ArrowRight, Boxes, GitCommit, Hourglass, ShieldAlert, Sparkles } from "lucide-react";
import { Finding, LEVELS, Project } from "../api";
import { FindingDrawer } from "../components/FindingDetail";
import { PipelineStepper, stepsFromProject } from "../components/PipelineStepper";
import { Button, Callout, Card, Code, DataTable, LEVEL_HEX, LevelBadge, NewBadge, PageHeader, Stat, StatusBadge } from "../components/ui";
import type { Page } from "../App";

/** Labelled horizontal bars: every label stays readable, unlike an axis that drops ticks when space is short. */
function BarList({ data, color }: { data: { name: string; value: number }[]; color: string }) {
  const max = Math.max(1, ...data.map((d) => d.value));
  return (
    <ul className="max-h-48 space-y-2 overflow-y-auto pr-1">
      {data.map((d) => (
        <li key={d.name} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 text-xs">
          <span className="truncate text-slate-600" title={d.name}>{d.name}</span>
          <span className="font-semibold tabular-nums text-slate-900">{d.value}</span>
          <span className="col-span-2 mt-1 h-1.5 overflow-hidden rounded-full bg-slate-100">
            <span className="block h-full rounded-full" style={{ width: `${(d.value / max) * 100}%`, background: color }} />
          </span>
        </li>
      ))}
    </ul>
  );
}

export function Overview({ p, go }: { p: Project; go: (page: Page) => void }) {
  const s = p.summary!, doc = p.findings;
  const F = doc?.findings || [];
  const [open, setOpen] = useState<Finding | null>(null);
  const val = p.remediation?.validations?.[p.remediation.validations.length - 1];
  const prio = useMemo(() => Object.fromEntries((p.remediation?.priorities || []).map((x) => [x.finding_id, x])), [p.remediation]);

  const steps = useMemo(() => stepsFromProject(p), [p]);

  const levelData = LEVELS.map((l) => ({ name: l, value: doc?.counts.by_level[l] || 0 })).filter((x) => x.value);
  const typeData = Object.entries(doc?.counts.by_type || {}).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value);
  const ecoData = Object.entries(s.by_ecosystem).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value);
  const top = [...F].sort((a, b) => b.risk.score - a.risk.score).slice(0, 8);
  const ch = doc?.change;
  const nar = p.agentic?.narrative;

  return (
    <div>
      <PageHeader title="Overview" description="What is in the application, what changed, what appears risky, and where remediation stands." />

      {/* pipeline */}
      <div className="mb-6 rounded-xl border border-slate-200 bg-white px-4 pb-3 pt-4 shadow-card">
        <PipelineStepper steps={steps} onGo={go} />
        <p className="mt-2 border-t border-slate-100 pt-2 text-xs text-slate-500">
          <b className="text-slate-700">How it works:</b> map every dependency, flag known vulnerabilities and supply-chain red flags,
          let AI explain the unclear ones, then rank them and propose fixes. Nothing changes until you approve; approved fixes are
          built, tested and rescanned in a Docker sandbox. Click a finished step to open its results.
        </p>
      </div>

      {p.pending && (
        <div className="mb-6">
          <Callout tone="warn" icon={<Hourglass className="mt-0.5 h-4 w-4 shrink-0" />}>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <span><b>Human approval needed.</b> Run <Code>{p.pending.run_id}</Code> paused with {p.pending.proposals.length} remediation proposals.</span>
              <Button variant="primary" onClick={() => go("remediation")}>Review proposals <ArrowRight className="h-4 w-4" /></Button>
            </div>
          </Callout>
        </div>
      )}

      {/* KPIs */}
      <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Components" value={s.components_total} hint={`${s.direct} direct · ${s.transitive} transitive`} icon={<Boxes className="h-4 w-4" />} />
        <Stat label="Vulnerable components" value={doc?.counts.vulnerabilities ?? "-"} hint={doc?.counts.advisories ? `${doc.counts.advisories} advisories` : undefined} tone="orange" />
        <Stat label="Suspicious changes" value={doc?.counts.anomalies ?? "-"} hint="non-CVE supply-chain risks" tone="violet" />
        <Stat label="Critical findings" value={doc?.counts.by_level.Critical ?? 0} tone="red" />
        <Stat label="High findings" value={doc?.counts.by_level.High ?? 0} tone="orange" />
        <Stat label="New in latest change" value={doc?.counts.new_in_change ?? 0} hint={ch ? `${ch.base.short} → ${ch.head.short}` : "no base commit"} />
      </div>

      <div className="mb-6 grid gap-4 lg:grid-cols-3">
        <Card title="Findings by risk level">
          <div className="flex items-center gap-4">
            <div className="h-44 w-44 shrink-0">
              <ResponsiveContainer>
                <PieChart>
                  <Pie isAnimationActive={false} data={levelData} dataKey="value" nameKey="name" innerRadius={48} outerRadius={78} paddingAngle={2} stroke="none">
                    {levelData.map((d) => <Cell key={d.name} fill={LEVEL_HEX[d.name]} />)}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <ul className="flex-1 space-y-2 text-sm">
              {LEVELS.map((l) => (
                <li key={l} className="flex items-center justify-between">
                  <span className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-sm" style={{ background: LEVEL_HEX[l] }} />{l}</span>
                  <span className="font-semibold tabular-nums">{doc?.counts.by_level[l] || 0}</span>
                </li>
              ))}
            </ul>
          </div>
        </Card>
        <Card title="Findings by type">
          <BarList data={typeData} color="#2f7df6" />
        </Card>
        <Card title="Components by ecosystem">
          <BarList data={ecoData} color="#1a4fb0" />
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          {nar && (
            <Card title={<span className="flex items-center gap-2"><Sparkles className="h-4 w-4 text-violet-600" /> AI summary</span>}
              subtitle={`Inference by ${p.agentic!.engine}: cites finding IDs and never changes a finding or its risk`}>
              <p className="text-sm font-medium text-slate-900">{nar.headline}</p>
              <div className="mt-3 grid gap-3 text-sm text-slate-600 md:grid-cols-3">
                <div><div className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">In the application</div>{nar.what_is_in_the_app}</div>
                <div><div className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">What changed</div>{nar.what_changed}</div>
                <div><div className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">What appears risky</div>{nar.what_appears_risky}</div>
              </div>
            </Card>
          )}
          <Card title="Top findings" subtitle="Highest initial risk first; click a row for evidence" pad={false}
            actions={<Button variant="ghost" onClick={() => go("evidence")}>All findings <ArrowRight className="h-4 w-4" /></Button>}>
            <DataTable rows={top} rowKey={(f) => f.finding_id} onRow={setOpen} cols={[
              { key: "id", label: "ID", render: (f) => <span className="whitespace-nowrap font-mono text-xs text-slate-500">{f.finding_id}</span> },
              { key: "risk", label: "Risk", render: (f) => <LevelBadge level={f.risk.level} score={f.risk.score} /> },
              { key: "title", label: "Finding", render: (f) => <div className="max-w-xl"><div className="line-clamp-2 text-slate-800">{f.title}</div><div className="text-xs text-slate-500">{f.type}</div></div> },
              { key: "new", label: "", render: (f) => (f.new_in_change ? <NewBadge /> : null) },
            ]} />
          </Card>
        </div>
        <div className="space-y-4">
          {ch && (
            <Card title={<span className="flex items-center gap-2"><GitCommit className="h-4 w-4" /> What changed</span>}
              actions={<Button variant="ghost" onClick={() => go("changes")}>Details <ArrowRight className="h-4 w-4" /></Button>}>
              <div className="space-y-3 text-sm">
                <div className="flex items-center gap-2 font-mono text-xs"><Code>{ch.base.short}</Code><ArrowRight className="h-3 w-3 text-slate-400" /><Code>{ch.head.short}</Code></div>
                <p className="text-slate-800">“{ch.head.message}”</p>
                <p className="text-slate-600">by <b>{ch.head.author}</b>
                  {ch.first_time_author && <span className="ml-2 inline-flex items-center gap-1 rounded bg-red-50 px-1.5 py-0.5 text-xs font-medium text-red-700"><AlertTriangle className="h-3 w-3" /> first-time contributor</span>}</p>
                <div className="grid grid-cols-4 gap-2 text-center">
                  {[["files", ch.files.length], ["added", ch.added.length], ["removed", ch.removed.length], ["changed", ch.changed.length]].map(([k, v]) => (
                    <div key={k as string} className="rounded-lg bg-slate-50 py-2"><div className="text-lg font-semibold tabular-nums">{v}</div><div className="text-[11px] text-slate-500">{k}</div></div>
                  ))}
                </div>
              </div>
            </Card>
          )}
          <Card title={<span className="flex items-center gap-2"><ShieldAlert className="h-4 w-4" /> Remediation status</span>}
            actions={(p.remediation || p.pending) ? <Button variant="ghost" onClick={() => go("remediation")}>Open <ArrowRight className="h-4 w-4" /></Button> : undefined}>
            {val ? (
              <div className="space-y-3 text-sm">
                <div className="flex items-center gap-2"><StatusBadge status={val.verdict} /><span className="text-slate-500">confidence {val.confidence}</span></div>
                <div className="grid grid-cols-3 gap-2 text-center">
                  <div className="rounded-lg bg-slate-50 py-2"><div className="text-lg font-semibold tabular-nums">{val.findings_before}→{val.findings_after}</div><div className="text-[11px] text-slate-500">findings</div></div>
                  <div className="rounded-lg bg-emerald-50 py-2"><div className="text-lg font-semibold tabular-nums text-emerald-700">{val.resolved.length}</div><div className="text-[11px] text-slate-500">resolved</div></div>
                  <div className="rounded-lg bg-slate-50 py-2"><div className="text-lg font-semibold tabular-nums">{val.new.filter((n) => n.kind === "introduced").length}</div><div className="text-[11px] text-slate-500">newly introduced</div></div>
                </div>
              </div>
            ) : p.pending ? <p className="text-sm text-slate-600">Waiting for a human decision on {p.pending.proposals.length} proposals.</p>
              : <p className="text-sm text-slate-500">No remediation run yet. Start a <b>Full: detect → remediate</b> run to get prioritised, validated fixes.</p>}
          </Card>
        </div>
      </div>
      <FindingDrawer f={open} onClose={() => setOpen(null)} triage={open ? p.agentic?.triage[open.finding_id] : undefined} priority={open ? prio[open.finding_id] : undefined} />
    </div>
  );
}
