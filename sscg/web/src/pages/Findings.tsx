import { useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2, Download, FileText, GitCommit } from "lucide-react";
import { fileUrl, Finding, Level, LEVELS, Project } from "../api";
import { FindingDrawer } from "../components/FindingDetail";
import { Badge, Callout, Card, Chips, Code, DataTable, Empty, LevelBadge, LinkButton, NewBadge, PageHeader, SearchInput, SeverityBadge, Stat, Toggle } from "../components/ui";

function usePrio(p: Project) {
  return useMemo(() => Object.fromEntries((p.remediation?.priorities || []).map((x) => [x.finding_id, x])), [p.remediation]);
}

function Detail({ p, f, onClose }: { p: Project; f: Finding | null; onClose: () => void }) {
  const prio = usePrio(p);
  return <FindingDrawer f={f} onClose={onClose} triage={f ? p.agentic?.triage[f.finding_id] : undefined} priority={f ? prio[f.finding_id] : undefined} />;
}

const findingCols = [
  { key: "id", label: "ID", render: (f: Finding) => <span className="whitespace-nowrap font-mono text-xs text-slate-500">{f.finding_id}</span>, sort: (f: Finding) => f.finding_id },
  { key: "risk", label: "Risk", render: (f: Finding) => <LevelBadge level={f.risk.level} score={f.risk.score} />, sort: (f: Finding) => f.risk.score },
  { key: "title", label: "Finding", render: (f: Finding) => <div className="max-w-2xl"><div className="line-clamp-2 text-slate-800">{f.title}</div><div className="text-xs text-slate-500">{f.type}</div></div> },
  { key: "loc", label: "Location", render: (f: Finding) => f.location ? <span className="font-mono text-xs text-slate-500">{f.location}</span> : null },
  { key: "new", label: "", render: (f: Finding) => (f.new_in_change ? <NewBadge /> : null) },
];

// ------------------------------------------------------------------ ③ vulnerabilities
const SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
export function Vulnerabilities({ p }: { p: Project }) {
  const vul = (p.findings?.findings || []).filter((f) => f.category === "vulnerability");
  const [sev, setSev] = useState<string[]>(SEVS);
  const [kind, setKind] = useState<string[]>(["direct", "transitive"]);
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<Finding | null>(null);
  const rows = vul.filter((f) => sev.includes(f.severity?.label || "UNKNOWN") && kind.includes(f.is_direct ? "direct" : "transitive")
    && (!q || f.title.toLowerCase().includes(q.toLowerCase())));
  const cnt = (l: string) => vul.filter((f) => f.severity?.label === l).length;
  return (
    <div>
      <PageHeader title="Vulnerabilities" description="Components with published advisories (OSV.dev), their severity, fixes, and the dependency path that pulls them in." />
      <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Vulnerable components" value={vul.length} />
        <Stat label="Advisories" value={p.findings?.counts.advisories ?? vul.reduce((a, f) => a + f.evidence.length, 0)} />
        <Stat label="Highest = Critical" value={cnt("CRITICAL")} tone="red" />
        <Stat label="Highest = High" value={cnt("HIGH")} tone="orange" />
        <Stat label="Highest = Medium" value={cnt("MEDIUM")} />
        <Stat label="With a fix" value={vul.filter((f) => f.fixes?.upgrade_to_at_least).length} tone="green" />
      </div>
      {!vul.length ? <Empty icon={<CheckCircle2 className="h-8 w-8" />} title="No component version has a published advisory" /> : (
        <Card pad={false} title="Vulnerable components" subtitle="Click a row for advisories and the path to its source"
          actions={<><Chips options={SEVS} value={sev} onChange={setSev} /><Chips options={["direct", "transitive"]} value={kind} onChange={setKind} /><SearchInput value={q} onChange={setQ} /></>}>
          <DataTable rows={rows} rowKey={(f) => f.finding_id} onRow={setOpen} maxHeight={640} cols={[
            { key: "id", label: "ID", render: (f) => <span className="whitespace-nowrap font-mono text-xs text-slate-500">{f.finding_id}</span> },
            { key: "comp", label: "Component", render: (f) => <div><div className="font-mono text-xs font-medium text-slate-900">{f.component?.label}</div><div className="text-xs text-slate-500">{f.component?.ecosystem}</div></div>, sort: (f) => f.component?.label || "" },
            { key: "dep", label: "Dependency", render: (f) => <Badge className={f.is_direct ? "bg-brand-50 text-brand-700 ring-brand-600/20" : undefined}>{f.is_direct ? "direct" : "transitive"}</Badge> },
            { key: "sev", label: "Severity", render: (f) => <SeverityBadge label={f.severity?.label || "UNKNOWN"} />, sort: (f) => f.severity?.cvss || 0 },
            { key: "cvss", label: "CVSS", render: (f) => <span className="tabular-nums">{f.severity?.cvss ?? "-"}</span>, sort: (f) => f.severity?.cvss || 0 },
            { key: "adv", label: "Advisories", render: (f) => f.evidence.length, sort: (f) => f.evidence.length },
            { key: "cves", label: "CVEs", render: (f) => { const c = [...new Set(f.evidence.flatMap((e) => e.cves || []))] as string[];
              return <div className="whitespace-nowrap text-xs text-slate-500">{c.slice(0, 2).map((x) => <div key={x}>{x}</div>)}{c.length > 2 && <div className="text-slate-400">+{c.length - 2} more</div>}</div>; } },
            { key: "fix", label: "Fix (≥)", render: (f) => f.fixes?.upgrade_to_at_least ? <Code>{f.fixes.upgrade_to_at_least}</Code> : <span className="text-xs text-slate-400">no fix</span> },
            { key: "via", label: "Introduced via", render: (f) => <span className="text-xs">{f.introduced_by.join(", ") || "(direct)"}</span> },
            { key: "risk", label: "Risk", render: (f) => <LevelBadge level={f.risk.level} score={f.risk.score} />, sort: (f) => f.risk.score },
          ]} />
        </Card>
      )}
      <Detail p={p} f={open} onClose={() => setOpen(null)} />
    </div>
  );
}

// ------------------------------------------------------------------ ④ suspicious changes
export function Changes({ p }: { p: Project }) {
  const ano = (p.findings?.findings || []).filter((f) => f.category === "anomaly");
  const ch = p.findings?.change;
  const [open, setOpen] = useState<Finding | null>(null);
  const byType = Object.entries(ano.reduce((a: Record<string, number>, f) => ({ ...a, [f.type]: (a[f.type] || 0) + 1 }), {})).sort((a, b) => b[1] - a[1]);
  const compRows = ch ? [
    ...ch.added.map((a) => ({ k: "added", c: a.label, d: a.source })),
    ...ch.removed.map((a) => ({ k: "removed", c: a.label, d: a.source })),
    ...ch.changed.map((x) => ({ k: "changed", c: `${x.base} → ${x.head}`, d: x.fields.join(", ") })),
  ] : [];
  const KS: Record<string, string> = { added: "bg-emerald-50 text-emerald-700 ring-emerald-600/20", removed: "bg-red-50 text-red-700 ring-red-600/20", changed: "bg-amber-50 text-amber-800 ring-amber-600/20" };
  return (
    <div>
      <PageHeader title="Suspicious changes" description="Supply-chain risks beyond known CVEs: typosquats, malicious packages, install scripts, lockfile tampering, untrusted images and unsafe CI/CD." />
      <Card className="mb-6" title={<span className="flex items-center gap-2"><GitCommit className="h-4 w-4" /> What changed</span>}>
        {ch ? (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
              <span>Base <Code>{ch.base.short}</Code> <i className="text-slate-500">{ch.base.message}</i></span>
              <span>→ HEAD <Code>{ch.head.short}</Code> <i className="text-slate-500">{ch.head.message}</i>{ch.head_dirty && " + uncommitted changes"}</span>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-sm">
              Author <b>{ch.head.author}</b> <span className="text-slate-500">&lt;{ch.head.email}&gt;</span>
              {ch.first_time_author === true && <Badge className="bg-red-50 text-red-700 ring-red-600/20"><AlertTriangle className="h-3 w-3" /> first-time contributor</Badge>}
            </div>
            <div className="grid gap-4 lg:grid-cols-[320px_1fr]">
              <div className="overflow-hidden rounded-lg border border-slate-200">
                <DataTable rows={ch.files} rowKey={(f) => f.path} cols={[
                  { key: "s", label: "", render: (f) => <Badge>{f.status}</Badge> },
                  { key: "p", label: `Files (${ch.files.length})`, render: (f) => <span className="font-mono text-xs">{f.path}</span> },
                ]} />
              </div>
              <div className="overflow-hidden rounded-lg border border-slate-200">
                <DataTable rows={compRows} rowKey={(r) => r.k + r.c} maxHeight={320} cols={[
                  { key: "k", label: "Change", render: (r) => <Badge className={KS[r.k]}>{r.k}</Badge> },
                  { key: "c", label: "Component", render: (r) => <span className="font-mono text-xs">{r.c}</span> },
                  { key: "d", label: "Detail", render: (r) => <span className="text-xs text-slate-500">{r.d}</span> },
                ]} />
              </div>
            </div>
          </div>
        ) : <Callout tone="info">No base commit compared (shallow clone, first commit, or comparison turned off). Anomalies describe the current state only.</Callout>}
      </Card>
      <Card pad={false} title={`Anomalies (${ano.length})`} subtitle={byType.map(([t, n]) => `${t}: ${n}`).join(" · ")}>
        <DataTable rows={[...ano].sort((a, b) => b.risk.score - a.risk.score)} rowKey={(f) => f.finding_id} onRow={setOpen} cols={findingCols} empty="No supply-chain anomaly detected." />
      </Card>
      <Detail p={p} f={open} onClose={() => setOpen(null)} />
    </div>
  );
}

// ------------------------------------------------------------------ ⑤ evidence (all findings)
export function Evidence({ p }: { p: Project }) {
  const F = p.findings?.findings || [];
  const [lv, setLv] = useState<Level[]>(LEVELS);
  const [cat, setCat] = useState<string[]>(["vulnerability", "anomaly"]);
  const [onlyNew, setOnlyNew] = useState(false);
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<Finding | null>(null);
  const rows = F.filter((f) => lv.includes(f.risk.level) && cat.includes(f.category) && (!onlyNew || f.new_in_change)
    && (!q || `${f.finding_id} ${f.title} ${f.type}`.toLowerCase().includes(q.toLowerCase())));
  const has = (f: string) => p.files.includes(f);
  return (
    <div>
      <PageHeader title="Evidence" description="Every finding with its component, dependency path, supporting evidence and initial risk level."
        actions={<div className="flex flex-wrap gap-2">
          {has("findings.json") && <LinkButton href={fileUrl(p.name, "findings.json", true)} download><Download className="h-4 w-4" /> findings.json</LinkButton>}
          {has("report.md") && <LinkButton href={fileUrl(p.name, "report.html")}><FileText className="h-4 w-4" /> Report</LinkButton>}
          {has("report.md") && <LinkButton href={fileUrl(p.name, "report.pdf", true)} download><Download className="h-4 w-4" /> PDF</LinkButton>}
        </div>} />
      <Card pad={false} title={`Findings (${rows.length} of ${F.length})`}
        actions={<><Chips options={LEVELS} value={lv} onChange={setLv} /><Chips options={["vulnerability", "anomaly"]} value={cat} onChange={setCat} />
          <Toggle checked={onlyNew} onChange={setOnlyNew} label="Only new" /><SearchInput value={q} onChange={setQ} /></>}>
        <DataTable rows={rows} rowKey={(f) => f.finding_id} onRow={setOpen} maxHeight={680} cols={[
          ...findingCols.slice(0, 2),
          { key: "cat", label: "Category", render: (f: Finding) => <Badge className={f.category === "anomaly" ? "bg-violet-50 text-violet-700 ring-violet-600/20" : undefined}>{f.category}</Badge> },
          ...findingCols.slice(2),
          { key: "basis", label: "Basis", render: (f: Finding) => <span className="text-xs text-slate-500">{f.classification.replace(/_/g, " ")}</span> },
        ]} />
      </Card>
      {(p.findings?.notes || []).length > 0 && (
        <div className="mt-4 space-y-1 text-xs text-slate-500">{p.findings!.notes.map((n, i) => <p key={i}>ℹ {n}</p>)}</div>
      )}
      <Detail p={p} f={open} onClose={() => setOpen(null)} />
    </div>
  );
}
