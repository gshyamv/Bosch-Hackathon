import { useEffect, useMemo, useState } from "react";
import { Library } from "lucide-react";
import { api, OkfCard, OkfGraph } from "../api";
import { Badge, Card, cx, Drawer, Empty, PageHeader, Pre, Spinner } from "../components/ui";

const PALETTE = ["#2563eb", "#16a34a", "#d97706", "#dc2626", "#7c3aed", "#0891b2", "#db2777", "#65a30d", "#475569", "#ea580c"];
const W = 1000, H = 640;

/** Small deterministic force layout (no extra dependency): types start on a circle, links pull, nodes repel. */
function layout(g: OkfGraph, types: string[]) {
  const idx = new Map(g.nodes.map((n, i) => [n.id, i]));
  const pos = g.nodes.map((n, i) => {
    const t = types.indexOf(n.type || "?"), a = (2 * Math.PI * t) / Math.max(1, types.length);
    const r = 220 + ((i * 37) % 60);
    return { x: W / 2 + r * Math.cos(a) + ((i * 13) % 40) - 20, y: H / 2 + r * Math.sin(a) + ((i * 29) % 40) - 20 };
  });
  const E = g.edges.map((e) => [idx.get(e.source)!, idx.get(e.target)!]).filter(([a, b]) => a != null && b != null);
  const n = pos.length, iters = n > 300 ? 60 : 140;
  for (let it = 0; it < iters; it++) {
    const f = pos.map(() => ({ x: 0, y: 0 }));
    for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) {
      const dx = pos[i].x - pos[j].x, dy = pos[i].y - pos[j].y, d2 = dx * dx + dy * dy + 0.01;
      if (d2 > 40000) continue;
      const k = 900 / d2;
      f[i].x += dx * k; f[i].y += dy * k; f[j].x -= dx * k; f[j].y -= dy * k;
    }
    for (const [a, b] of E) {
      const dx = pos[b].x - pos[a].x, dy = pos[b].y - pos[a].y;
      f[a].x += dx * 0.02; f[a].y += dy * 0.02; f[b].x -= dx * 0.02; f[b].y -= dy * 0.02;
    }
    for (let i = 0; i < n; i++) {
      pos[i].x = Math.min(W - 10, Math.max(10, pos[i].x + Math.max(-8, Math.min(8, f[i].x)) + (W / 2 - pos[i].x) * 0.003));
      pos[i].y = Math.min(H - 10, Math.max(10, pos[i].y + Math.max(-8, Math.min(8, f[i].y)) + (H / 2 - pos[i].y) * 0.003));
    }
  }
  return { pos, E };
}


// What each concept type is, who writes it and who reads it (sscg/okf.py, agents/tools.py, agents/kb.py).
const TYPE_INFO: Record<string, { what: string; writes: string; reads: string }> = {
  playbook: { what: "How to judge and fix one detection rule: what to check, false-positive hints, fix options.", writes: "Shipped with the app (curated)", reads: "Triage agent (opened for every finding of that rule), Remediation advisor" },
  "attack-pattern": { what: "A known supply-chain attack technique (typosquatting, malicious install script, dependency confusion…).", writes: "Shipped with the app (curated)", reads: "Triage agent, to compare a finding with real attacks" },
  policy: { what: "Your organisation's rules, e.g. allowed package sources and what needs human review.", writes: "Shipped with the app (curated)", reads: "Triage agent, Prioritizer" },
  advisory: { what: "A published vulnerability advisory (CVE / GHSA / OSV) found on a component in a scan.", writes: "Vulnerability-intel step (deterministic, from OSV.dev) and rule R02 (OpenSSF Malicious Packages index: ~241k reported malicious packages)", reads: "Triage agent (evidence), Remediation advisor" },
  scan: { what: "One pipeline run: target, commit and what was found.", writes: "Orchestrator, at the start of each run", reads: "Every agent, to link its notes to the run" },
  "risk-cluster": { what: "A group of findings that share one root cause, e.g. one outdated package behind many CVEs.", writes: "Detection / Prioritizer (deterministic)", reads: "Prioritizer, Remediation planner (one fix per cluster)" },
  triage: { what: "The triage agent's verdict and reasoning on one suspicious finding (AI-written, unverified until a human confirms).", writes: "Triage agent", reads: "Triage agent in later scans (same package), reviewers" },
  "remediation-plan": { what: "A proposed fix: upgrade / replace / remove, with the exact patch and rationale.", writes: "Remediation planner + advisor", reads: "Human approval step, Validation" },
  decision: { what: "A human's approve / reject / accept-risk decision on a proposal, with who and why.", writes: "Human approval step", reads: "Remediation advisor and Triage in later scans (past decisions on the same package)" },
  "validation-result": { what: "Outcome of building, testing and rescanning the approved fix in the Docker sandbox.", writes: "Validation step (sandbox)", reads: "Remediation report, next iteration" },
};

export function Knowledge() {
  const [g, setG] = useState<OkfGraph | null>(null);
  const [type, setType] = useState<string>("");
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState<OkfCard | null>(null);
  const [body, setBody] = useState<string>("");
  const [hover, setHover] = useState<string | null>(null);
  useEffect(() => { setG(null); api.okfGraph(type || undefined).then(setG).catch((e) => setErr(e.message)); }, [type]);
  useEffect(() => { if (open) api.okfConcept(open.id).then((c) => setBody(c.body)).catch(() => setBody("")); }, [open]);
  const allTypes = useMemo(() => Object.keys(g?.types || {}).sort(), [g]);
  const color = (t: string) => PALETTE[Math.max(0, allTypes.indexOf(t)) % PALETTE.length];
  const L = useMemo(() => (g ? layout(g, allTypes) : null), [g, allTypes]);
  const near = useMemo(() => {
    if (!hover || !g) return null;
    return new Set([hover, ...g.edges.filter((e) => e.source === hover || e.target === hover).flatMap((e) => [e.source, e.target])]);
  }, [hover, g]);

  return (
    <div className="space-y-5">
      <PageHeader title="Knowledge (OKF)"
        description="OKF (Open Knowledge Format) is the agents' shared memory: a folder of small Markdown documents ('concepts'), each with a type, a trust level and links to related concepts. It is NOT a graph database: the picture at the bottom only maps which documents link to which. Agents search it and read concepts as evidence; humans' decisions are written back so the next scan learns from them." />
      {err && <Empty title="Knowledge store not available">{err}</Empty>}
      {!g && !err && <div className="flex justify-center py-16"><Spinner className="h-6 w-6" /></div>}
      {g && L && (
        <>
          <Card title="What is stored, and which agent uses it" subtitle="Click a type to show only those concepts below.">
            <div className="grid gap-2.5 sm:grid-cols-2 xl:grid-cols-3">
              {allTypes.map((t) => {
                const info = TYPE_INFO[t];
                return (
                  <button key={t} type="button" onClick={() => setType(t === type ? "" : t)}
                    className={cx("rounded-lg border p-3 text-left text-sm transition", type === t ? "border-ink-900 ring-1 ring-ink-900" : "border-slate-200 hover:border-slate-400")}>
                    <div className="mb-1 flex items-center gap-2 font-semibold text-slate-900">
                      <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: color(t) }} /> {t}
                      <span className="ml-auto text-xs font-normal tabular-nums text-slate-500">{g.types[t]}</span>
                    </div>
                    <p className="text-slate-700">{info?.what || "Concept type."}</p>
                    {info && <p className="mt-1.5 text-xs text-slate-500"><b className="text-slate-600">Written by:</b> {info.writes}<br /><b className="text-slate-600">Used by:</b> {info.reads}</p>}
                  </button>
                );
              })}
            </div>
            {type && <button type="button" onClick={() => setType("")} className="mt-3 text-xs font-medium text-brand-600 hover:underline">Show all types</button>}
          </Card>
          <Card pad={false} title={`Link map: ${g.nodes.length} concepts · ${g.edges.length} links`} subtitle="Each dot is one document; a line means one document references another. Hover to highlight, click to read. Faded = unverified (AI-written, not yet confirmed by a human).">
            {g.nodes.length === 0 ? <Empty icon={<Library className="h-8 w-8" />} title="No concepts" /> : (
              <svg viewBox={`0 0 ${W} ${H}`} className="h-[640px] w-full bg-slate-50">
                {L.E.map(([a, b], i) => {
                  const on = near && near.has(g.nodes[a].id) && near.has(g.nodes[b].id);
                  return <line key={i} x1={L.pos[a].x} y1={L.pos[a].y} x2={L.pos[b].x} y2={L.pos[b].y} stroke={on ? "#0f172a" : "#cbd5e1"} strokeWidth={on ? 1.5 : 0.6} opacity={near && !on ? 0.15 : 1} />;
                })}
                {g.nodes.map((nd, i) => {
                  const dim = near && !near.has(nd.id);
                  return (
                    <g key={nd.id} transform={`translate(${L.pos[i].x},${L.pos[i].y})`} className="cursor-pointer"
                      onMouseEnter={() => setHover(nd.id)} onMouseLeave={() => setHover(null)} onClick={() => setOpen(nd)}>
                      <circle r={hover === nd.id ? 8 : 5} fill={color(nd.type)} opacity={dim ? 0.15 : nd.trust === "unverified" ? 0.45 : 1} stroke="#fff" strokeWidth={1} />
                      {(hover === nd.id || (near && near.has(nd.id))) && <text x={9} y={4} fontSize={11} fill="#0f172a">{nd.title || nd.id}</text>}
                    </g>
                  );
                })}
              </svg>
            )}
          </Card>
        </>
      )}
      <Drawer open={!!open} onClose={() => { setOpen(null); setBody(""); }} title={open?.title || open?.id || ""} subtitle={open?.id}>
        {open && (
          <div className="space-y-3">
            <div className="flex flex-wrap gap-2"><Badge className="bg-slate-100 text-slate-700 ring-slate-300">{open.type}</Badge><Badge className="bg-slate-100 text-slate-700 ring-slate-300">trust: {open.trust}</Badge>{open.stale && <Badge className="bg-amber-50 text-amber-800 ring-amber-600/30">stale</Badge>}</div>
            {open.description && <p className="text-sm text-slate-700">{open.description}</p>}
            <Pre text={body || "…"} maxHeight={520} />
          </div>
        )}
      </Drawer>
    </div>
  );
}
