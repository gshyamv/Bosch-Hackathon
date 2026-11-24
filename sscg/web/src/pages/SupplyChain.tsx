import { useEffect, useMemo, useState } from "react";
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Container, Download, ExternalLink, Globe, Search, Workflow } from "lucide-react";
import { api, fileUrl, GraphEcosystem, GraphMeta, graphUrl, Project, WhyHit } from "../api";
import { Badge, Button, Callout, Card, Code, DataTable, DepPath, Empty, inputCls, LinkButton, PageHeader, SearchInput, Segmented, Spinner, Stat, Tabs, Toggle } from "../components/ui";

type Tab = "graph" | "sbom" | "infra" | "origins";
type View = "levels" | "direct" | "subtree" | "full";

export function SupplyChain({ p }: { p: Project }) {
  const [tab, setTab] = useState<Tab>("graph");
  const s = p.summary!;
  return (
    <div>
      <PageHeader title="Supply chain" description="Every direct and transitive component, where it comes from, and how it reaches the application." />
      <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">
        <Stat label="Components" value={s.components_total} />
        <Stat label="Libraries" value={s.packages} />
        <Stat label="Direct" value={s.direct} tone="brand" />
        <Stat label="Transitive" value={s.transitive} />
        <Stat label="Max depth" value={s.max_depth} />
        <Stat label="Container images" value={s.container_images.length} />
        <Stat label="CI actions" value={s.by_ecosystem["github-actions"] || 0} />
      </div>
      <Tabs value={tab} onChange={setTab} tabs={[
        { id: "graph", label: "Dependency graph" }, { id: "sbom", label: "SBOM (CycloneDX)" },
        { id: "infra", label: "Containers & CI/CD" }, { id: "origins", label: "Origins" },
      ]} />
      {tab === "graph" && <GraphTab p={p} />}
      {tab === "sbom" && <SbomTab p={p} />}
      {tab === "infra" && <InfraTab p={p} />}
      {tab === "origins" && <OriginsTab p={p} />}
    </div>
  );
}

function GraphTab({ p }: { p: Project }) {
  const s = p.summary!;
  const [view, setView] = useState<View>("levels");
  const [libsOnly, setLibsOnly] = useState(true);
  const [meta, setMeta] = useState<GraphMeta | null>(null);
  const [root, setRoot] = useState<string | null>(null);
  const maxd = meta?.max_depth || s.max_depth || 1;
  const [levels, setLevels] = useState(Math.min(maxd, s.packages > 300 ? 3 : maxd));
  const [loading, setLoading] = useState(true);
  // ecosystems the user switched off (empty = show all; an ecosystem new to a rescan is shown by default)
  const [ecoOff, setEcoOff] = useState<Set<string>>(new Set());
  const metaLibs = view === "full" ? false : libsOnly;   // the full graph also draws images / CI / downloads

  useEffect(() => { api.graphMeta(p.name, metaLibs).then(setMeta).catch(() => setMeta(null)); }, [p.name, p.scanned_at, metaLibs]);
  useEffect(() => setEcoOff(new Set()), [p.name]);
  const ecos = meta?.ecosystems || [];
  const ecoOn = ecos.filter((e) => !ecoOff.has(e.id)).map((e) => e.id);
  const ecoParam = ecoOn.length < ecos.length && ecoOn.length > 0 ? ecoOn.join(",") : "";
  const toggleEco = (id: string) => setEcoOff((prev) => {
    const next = new Set(prev);
    if (next.has(id)) next.delete(id);
    else if (ecos.some((e) => e.id !== id && !next.has(e.id))) next.add(id);   // never hide the last one
    return next;
  });
  const onlyEco = (id: string) => setEcoOff(new Set(ecos.filter((e) => e.id !== id).map((e) => e.id)));
  useEffect(() => { setLevels(Math.min(maxd, s.packages > 300 ? 3 : maxd)); }, [maxd, s.packages]);
  useEffect(() => { if (view === "subtree" && !root && meta?.directs.length) setRoot(meta.directs[0].id); }, [view, meta, root]);
  const rootInfo = meta?.directs.find((d) => d.id === root);
  const lvMax = view === "subtree" ? Math.max(rootInfo?.depth_below || 1, 1) : maxd;
  const effLevels = Math.min(levels, lvMax);
  const src = useMemo(() => graphUrl(p.name, { mode: view, levels: effLevels, libsOnly, root: view === "subtree" ? root : null })
    + (ecoParam ? `&ecosystems=${encodeURIComponent(ecoParam)}` : "") + `&t=${p.scanned_at}`,
    [p.name, p.scanned_at, view, effLevels, libsOnly, root, ecoParam]);
  useEffect(() => setLoading(true), [src]);

  const hist = Object.entries(s.depth_histogram).map(([k, v]) => ({ level: Number(k), kind: Number(k) === 1 ? "Direct" : "Transitive", libraries: v })).sort((a, b) => a.level - b.level);

  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-[1fr_340px]">
        <Card pad={false}>
          <div className="flex flex-wrap items-center gap-3 border-b border-slate-100 px-4 py-3">
            <Segmented value={view} onChange={setView} options={[
              { id: "levels", label: "By level" }, { id: "direct", label: "Direct only" },
              { id: "subtree", label: "One dependency's tree" }, { id: "full", label: "Full graph (risk)" },
            ]} />
            {view !== "full" && <Toggle checked={libsOnly} onChange={setLibsOnly} label="Libraries only" hint="Hide container images, CI actions and downloaded files" />}
            {view === "subtree" && meta && (
              <select className={inputCls + " !w-auto max-w-xs py-1.5 text-xs"} value={root || ""} onChange={(e) => setRoot(e.target.value)}>
                {meta.directs.map((d) => <option key={d.id} value={d.id}>{d.label} (+{d.transitive})</option>)}
              </select>
            )}
            {(view === "levels" || view === "subtree") && lvMax > 1 && (
              <label className="flex items-center gap-2 text-xs text-slate-600">
                Levels <input type="range" min={1} max={lvMax} value={effLevels} onChange={(e) => setLevels(Number(e.target.value))} className="accent-brand-600" />
                <span className="w-4 font-semibold tabular-nums">{effLevels}</span>
              </label>
            )}
            <div className="ml-auto"><LinkButton href={fileUrl(p.name, "graph.html")}><ExternalLink className="h-4 w-4" /> Open full screen</LinkButton></div>
          </div>
          {ecos.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5 border-b border-slate-100 px-4 py-2" role="group" aria-label="Filter by ecosystem">
              <span className="mr-1 text-xs font-medium text-slate-500">Ecosystems</span>
              {ecos.map((e) => {
                const on = !ecoOff.has(e.id);
                return (
                  <button key={e.id} type="button" aria-pressed={on} onClick={() => toggleEco(e.id)}
                    onDoubleClick={() => onlyEco(e.id)}
                    title={`${e.label}: ${e.count} component${e.count === 1 ? "" : "s"}${e.vulnerable ? `, ${e.vulnerable} with advisories` : ""}. Click to ${on ? "hide" : "show"}, double-click to show only this.`}
                    className={"inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ring-1 ring-inset transition "
                      + (on ? "bg-white text-slate-800 ring-slate-300 hover:bg-slate-50" : "bg-slate-50 text-slate-400 ring-slate-200 line-through")}>
                    <EcoGlyph e={e} muted={!on} />
                    {e.label}
                    <span className="tabular-nums text-slate-500">{e.count}</span>
                    {e.vulnerable > 0 && <span className="tabular-nums text-red-700">· {e.vulnerable} vuln</span>}
                  </button>
                );
              })}
              {ecoOff.size > 0 && <button type="button" onClick={() => setEcoOff(new Set())} className="ml-1 text-xs font-medium text-brand-700 hover:underline">Show all</button>}
            </div>
          )}
          <div className="relative h-[820px] bg-[#fcfcfb]">
            {loading && <div className="absolute inset-0 z-10 flex items-center justify-center gap-2 text-sm text-slate-500"><Spinner /> Drawing graph…</div>}
            <iframe key={src} src={src} title="Dependency graph" onLoad={() => setLoading(false)} sandbox="allow-scripts" className="h-full w-full border-0" />
          </div>
        </Card>
        <div className="space-y-4">
          <Card title="Libraries per dependency level" subtitle="Level 1 = direct; deeper = transitive">
            <div className="h-40">
              <ResponsiveContainer>
                <BarChart data={hist} margin={{ left: -24, right: 4, top: 4, bottom: 0 }}>
                  <XAxis dataKey="level" tick={{ fontSize: 11, fill: "#475569" }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip cursor={{ fill: "#f1f5f9" }} />
                  <Bar isAnimationActive={false} dataKey="libraries" radius={[4, 4, 0, 0]} barSize={24}>
                    {/* neutral inks: blue / orange now mean npm / PyPI in the graph */}
                    {hist.map((h) => <Cell key={h.level} fill={h.level === 1 ? "#52514e" : "#b4b2a9"} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Card>
          <Card title="Legend">
            <ul className="space-y-1.5 text-xs text-slate-600">
              <li>Colour + shape = ecosystem{ecos.length > 0 && ":"}</li>
              {ecos.length > 0 && (
                <li className="flex flex-wrap gap-x-3 gap-y-1 pl-1">
                  {ecos.map((e) => <span key={e.id} className="inline-flex items-center gap-1"><EcoGlyph e={e} />{e.label}</span>)}
                </li>
              )}
              <li>Big / dark outline = direct dependency · small = transitive</li>
              <li>★ repository · dark box = manifest / Dockerfile / workflow</li>
              <li><span className="mr-1 inline-block h-2.5 w-2.5 rounded-full border-[2.5px] border-[#d03b3b] align-[-1px] shadow-[0_0_4px_rgba(208,59,59,.6)]" /><span className="text-red-700">red ring</span> = published advisories · ◆ = suspicious</li>
              <li>Hover a node for version, path, advisories and finding IDs.</li>
            </ul>
          </Card>
          <Card title="Top blast radius" pad={false}>
            <DataTable rows={s.top_blast_radius.slice(0, 6)} rowKey={(r) => r.package} cols={[
              { key: "package", label: "Package", render: (r) => <span className="font-mono text-xs">{r.package}</span> },
              { key: "d", label: "Used by", render: (r) => r.dependents_transitive, className: "text-right" },
            ]} />
          </Card>
          <Card title="Heaviest direct dependencies" pad={false}>
            <DataTable rows={s.heaviest_direct_deps.slice(0, 6)} rowKey={(r) => r.package} cols={[
              { key: "package", label: "Package", render: (r) => <span className="font-mono text-xs">{r.package}</span> },
              { key: "b", label: "Brings in", render: (r) => r.brings_in, className: "text-right" },
            ]} />
          </Card>
        </div>
      </div>
      <WhyCard name={p.name} duplicates={s.duplicates} />
    </div>
  );
}

/** The ecosystem's node shape and colour, as drawn in the graph (vis shape names from graph/meta). */
function EcoGlyph({ e, muted }: { e: Pick<GraphEcosystem, "shape" | "color">; muted?: boolean }) {
  const fill = muted ? "#cbd5e1" : e.color;
  const pts: Record<string, string> = {
    triangle: "6,1 11,11 1,11", triangleDown: "1,1 11,1 6,11",
    hexagon: "3,1 9,1 11.5,6 9,11 3,11 0.5,6", diamond: "6,0.5 11.5,6 6,11.5 0.5,6",
  };
  return (
    <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true" className="shrink-0">
      {e.shape === "square" ? <rect x="1.5" y="1.5" width="9" height="9" rx="1" fill={fill} />
        : pts[e.shape] ? <polygon points={pts[e.shape]} fill={fill} />
        : <circle cx="6" cy="6" r="5" fill={fill} />}
    </svg>
  );
}

function WhyCard({ name, duplicates }: { name: string; duplicates: Record<string, string[]> }) {
  const [q, setQ] = useState("");
  const [hits, setHits] = useState<WhyHit[] | null>(null);
  const [busy, setBusy] = useState(false);
  async function go(e?: React.FormEvent) {
    e?.preventDefault();
    if (!q.trim()) return;
    setBusy(true);
    try { setHits((await api.why(name, q)).hits); } finally { setBusy(false); }
  }
  const dups = Object.entries(duplicates);
  return (
    <Card title={<span className="flex items-center gap-2"><Search className="h-4 w-4" /> Why is this package here?</span>}
      subtitle="Every dependency path from the repository to a package">
      <form onSubmit={go} className="flex gap-2">
        <input className={inputCls + " max-w-sm"} placeholder="package name, e.g. minimist" value={q} onChange={(e) => setQ(e.target.value)} />
        <Button type="submit" variant="primary" disabled={busy}>{busy ? <Spinner /> : <Search className="h-4 w-4" />} Trace</Button>
      </form>
      {hits && (
        <div className="mt-4 space-y-4">
          {!hits.length && <p className="text-sm text-slate-500">Not in the graph.</p>}
          {hits.map((h) => (
            <div key={h.id}>
              <div className="mb-1.5 flex flex-wrap items-center gap-2 text-sm">
                <b className="font-mono">{h.label}</b><Badge>{h.ecosystem}</Badge><Badge>scope {h.scope}</Badge>
                {h.findings.map((f) => <Badge key={f} className="bg-red-50 text-red-700 ring-red-600/20">{f}</Badge>)}
                {h.origin && <span className="truncate text-xs text-slate-500">{h.origin}</span>}
              </div>
              <div className="space-y-1.5">{h.paths.map((pt, i) => <DepPath key={i} path={pt} />)}</div>
            </div>
          ))}
        </div>
      )}
      {dups.length > 0 && (
        <div className="mt-5 border-t border-slate-100 pt-4">
          <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Same package in several versions ({dups.length})</div>
          <div className="flex flex-wrap gap-2">{dups.map(([k, v]) => <Badge key={k}><span className="font-mono">{k}</span>: {v.join(", ")}</Badge>)}</div>
        </div>
      )}
    </Card>
  );
}

function SbomTab({ p }: { p: Project }) {
  const [bom, setBom] = useState<any>(null);
  const [q, setQ] = useState("");
  useEffect(() => { api.sbom(p.name).then(setBom).catch(() => setBom(null)); }, [p.name, p.scanned_at]);
  if (!bom) return <Empty title="Loading SBOM…" />;
  const comps: any[] = bom.components || [];
  const rows = comps.filter((c) => !q || `${c.name} ${c.version} ${c.purl}`.toLowerCase().includes(q.toLowerCase()));
  const types = comps.reduce((a: Record<string, number>, c) => ({ ...a, [c.type]: (a[c.type] || 0) + 1 }), {});
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Format" value={`${bom.bomFormat} ${bom.specVersion}`} />
        <Stat label="SBOM components" value={comps.length} hint={Object.entries(types).map(([t, n]) => `${t} ${n}`).join(" · ")} />
        <Stat label="Dependency entries" value={(bom.dependencies || []).length} />
        <Stat label="With hashes" value={comps.filter((c) => c.hashes?.length).length} />
      </div>
      <Card title="Components" subtitle="Consume an existing SBOM instead: python -m sscg scan <repo> --sbom bom.cdx.json" pad={false}
        actions={<><SearchInput value={q} onChange={setQ} placeholder="Filter components" /><LinkButton href={fileUrl(p.name, "sbom.cdx.json", true)} download><Download className="h-4 w-4" /> sbom.cdx.json</LinkButton></>}>
        <DataTable rows={rows} maxHeight={560} rowKey={(c) => c["bom-ref"] || `${c.type}:${c.name}@${c.version}`} cols={[
          { key: "type", label: "Type", render: (c) => <Badge>{c.type}</Badge>, sort: (c) => c.type },
          { key: "name", label: "Name", render: (c) => <span className="font-medium text-slate-900">{c.name}</span>, sort: (c) => c.name },
          { key: "version", label: "Version", render: (c) => <span className="font-mono text-xs">{c.version || ""}</span> },
          { key: "scope", label: "Scope", render: (c) => c.scope || "" },
          { key: "purl", label: "purl", render: (c) => <span className="font-mono text-[11px] text-slate-500">{c.purl || ""}</span> },
        ]} />
      </Card>
    </div>
  );
}

function InfraTab({ p }: { p: Project }) {
  const s = p.summary!;
  return (
    <div className="space-y-4">
      <Card title={<span className="flex items-center gap-2"><Container className="h-4 w-4" /> Container images</span>} pad={false}>
        {s.container_images.length ? (
          <>
            <DataTable rows={s.container_images} rowKey={(r) => r.image + r.used_in.join()} cols={[
              { key: "image", label: "Image", render: (r) => <span className="font-mono text-xs">{r.image}</span> },
              { key: "registry", label: "Registry" },
              { key: "official", label: "Publisher", render: (r) => r.official_image ? <Badge className="bg-emerald-50 text-emerald-700 ring-emerald-600/20">official</Badge> : <Badge className="bg-red-50 text-red-700 ring-red-600/20">unverified</Badge> },
              { key: "pin", label: "Pinned", render: (r) => r.pinned_by_digest ? <Badge className="bg-emerald-50 text-emerald-700 ring-emerald-600/20">digest</Badge> : <Badge className="bg-amber-50 text-amber-800 ring-amber-600/20">mutable tag</Badge> },
              { key: "used", label: "Used in", render: (r) => <span className="font-mono text-xs">{r.used_in.join(", ")}</span> },
            ]} />
            <div className="space-y-1 border-t border-slate-100 px-5 py-3 text-sm text-slate-600">
              {s.dockerfiles.map((d) => (
                <div key={d.file}><Code>{d.file}</Code> · images {d.images.join(", ") || "none"}{d.runs_as && <> · runs as: {d.runs_as}</>}
                  {d.downloads.length > 0 && <span className="text-red-700"> · downloads: {d.downloads.join(", ")}</span>}</div>
              ))}
            </div>
          </>
        ) : <p className="px-5 py-6 text-sm text-slate-500">No Dockerfile or compose file found.</p>}
      </Card>
      <Card title={<span className="flex items-center gap-2"><Workflow className="h-4 w-4" /> CI/CD workflows</span>}>
        {s.ci_workflows.length ? s.ci_workflows.map((w) => (
          <div key={w.file} className="mb-4 last:mb-0">
            <div className="mb-2 flex flex-wrap items-center gap-2 text-sm">
              <b>{w.workflow}</b><Code>{w.file}</Code>
              {w.triggers.map((t) => <Badge key={t} className={t === "pull_request_target" ? "bg-red-50 text-red-700 ring-red-600/20" : undefined}>{t}</Badge>)}
              <Badge className={w.permissions === "write-all" ? "bg-red-50 text-red-700 ring-red-600/20" : undefined}>permissions: {w.permissions}</Badge>
            </div>
            <div className="overflow-hidden rounded-lg border border-slate-200">
              <DataTable rows={w.actions} rowKey={(a) => a.source} cols={[
                { key: "action", label: "Action", render: (a) => <span className="font-mono text-xs">{a.action}</span> },
                { key: "pin", label: "Pinned to SHA", render: (a) => a.pinned_to_sha ? <Badge className="bg-emerald-50 text-emerald-700 ring-emerald-600/20">yes</Badge> : <Badge className="bg-amber-50 text-amber-800 ring-amber-600/20">no ({a.ref})</Badge> },
                { key: "source", label: "Source", render: (a) => <span className="font-mono text-xs text-slate-500">{a.source}</span> },
              ]} />
            </div>
          </div>
        )) : <p className="text-sm text-slate-500">No GitHub Actions workflow found.</p>}
      </Card>
      {s.remote_artifacts.length > 0 && (
        <Card title={<span className="flex items-center gap-2"><Globe className="h-4 w-4" /> Files downloaded during build / CI</span>} pad={false}>
          <DataTable rows={s.remote_artifacts} rowKey={(r) => r.url + r.source} cols={[
            { key: "url", label: "URL", render: (r) => <span className="font-mono text-xs text-red-700">{r.url}</span> },
            { key: "scope", label: "Scope" }, { key: "source", label: "Source", render: (r) => <span className="font-mono text-xs">{r.source}</span> },
          ]} />
        </Card>
      )}
    </div>
  );
}

function OriginsTab({ p }: { p: Project }) {
  const s = p.summary!;
  const rows = Object.entries(s.origins).map(([host, n]) => ({ host, n })).sort((a, b) => b.n - a.n);
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Where components come from" subtitle="Host of the download / registry URL" pad={false}>
        <DataTable rows={rows} rowKey={(r) => r.host} cols={[
          { key: "host", label: "Host", render: (r) => <span className="font-mono text-xs">{r.host}</span> },
          { key: "n", label: "Components", render: (r) => r.n, className: "text-right", sort: (r) => r.n },
        ]} />
      </Card>
      <div className="space-y-4">
        <Card title="npm packages not served by the npm registry">
          {s.untrusted_origins.length ? <div className="space-y-1">{s.untrusted_origins.map((u) => <div key={u}><Callout tone="error">{u}</Callout></div>)}</div>
            : <p className="text-sm text-slate-500">None.</p>}
        </Card>
        <Card title="Packages with install scripts" subtitle="Lockfile hasInstallScript: code that runs on npm install">
          {s.install_scripts.length ? <div className="flex flex-wrap gap-2">{s.install_scripts.map((u) => <Badge key={u} className="bg-amber-50 text-amber-800 ring-amber-600/20">{u}</Badge>)}</div>
            : <p className="text-sm text-slate-500">None.</p>}
        </Card>
        {s.notes.length > 0 && <Card title="Notes"><ul className="list-disc space-y-1 pl-4 text-sm text-slate-600">{s.notes.map((n, i) => <li key={i}>{n}</li>)}</ul></Card>}
      </div>
    </div>
  );
}
