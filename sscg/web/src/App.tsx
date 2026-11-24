import { useCallback, useEffect, useState } from "react";
import { Bot, Boxes, Bug, FileText, GitPullRequestArrow, LayoutDashboard, Menu, Plus, RefreshCw, ShieldCheck, Sparkles, Wrench } from "lucide-react";
import { api, Job, Meta, Project, Targets } from "./api";
import { JobConsole } from "./components/JobConsole";
import { RunPanel } from "./components/RunPanel";
import { Button, Callout, cx, Drawer, Empty, fmtTime, Spinner } from "./components/ui";
import { AiTriage } from "./pages/AiTriage";
import { Changes, Evidence, Vulnerabilities } from "./pages/Findings";
import { Overview } from "./pages/Overview";
import { Remediation } from "./pages/Remediation";
import { Reports } from "./pages/Reports";
import { SupplyChain } from "./pages/SupplyChain";

export type Page = "overview" | "supply" | "vulns" | "changes" | "evidence" | "ai" | "remediation" | "reports";

const NAV: { id: Page; label: string; icon: any; group: string }[] = [
  { id: "overview", label: "Overview", icon: LayoutDashboard, group: "" },
  { id: "supply", label: "Supply chain", icon: Boxes, group: "Discover & detect" },
  { id: "vulns", label: "Vulnerabilities", icon: Bug, group: "Discover & detect" },
  { id: "changes", label: "Suspicious changes", icon: GitPullRequestArrow, group: "Discover & detect" },
  { id: "evidence", label: "Evidence", icon: FileText, group: "Discover & detect" },
  { id: "ai", label: "AI triage", icon: Sparkles, group: "Analyze & remediate" },
  { id: "remediation", label: "Remediation", icon: Wrench, group: "Analyze & remediate" },
  { id: "reports", label: "Reports", icon: FileText, group: "Report" },
];

const store = {
  get: (k: string) => { try { return localStorage.getItem(k); } catch { return null; } },
  set: (k: string, v: string) => { try { localStorage.setItem(k, v); } catch { /* storage blocked */ } },
};

export default function App() {
  const [meta, setMeta] = useState<Meta | null>(null);
  const [targets, setTargets] = useState<Targets | null>(null);
  const [name, setName] = useState<string | null>(store.get("sscg.project"));
  const [project, setProject] = useState<Project | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [page, setPage] = useState<Page>(() => {
    const h = window.location.hash.replace("#", "") as Page;
    return NAV.some((n) => n.id === h) ? h : (store.get("sscg.page") as Page) || "overview";
  });
  const [runOpen, setRunOpen] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const [navOpen, setNavOpen] = useState(false);

  const loadTargets = useCallback(async () => {
    const t = await api.targets();
    setTargets(t);
    return t;
  }, []);

  const loadProject = useCallback(async (n: string) => {
    setLoading(true); setErr(null);
    try { setProject(await api.project(n)); } catch (e: any) { setErr(e.message); setProject(null); } finally { setLoading(false); }
  }, []);

  useEffect(() => {
    api.meta().then(setMeta).catch(() => undefined);
    loadTargets().then((t) => {
      if (!t.projects.length) return;
      const keep = name && t.projects.some((p) => p.name === name) ? name : (t.projects.find((p) => p.name === "sscg-demo-target") || t.projects[0]).name;
      setName(keep);
    }).catch((e) => setErr(`Cannot reach the API (${e.message}). Start it with: python -m sscg serve`));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { if (name) { store.set("sscg.project", name); loadProject(name); } }, [name, loadProject]);
  useEffect(() => {
    store.set("sscg.page", page);
    if (window.location.hash !== `#${page}`) window.history.replaceState(null, "", `#${page}`);
    window.scrollTo(0, 0);
  }, [page]);
  useEffect(() => {
    const h = () => { const p = window.location.hash.replace("#", "") as Page; if (NAV.some((n) => n.id === p)) setPage(p); };
    window.addEventListener("hashchange", h);
    return () => window.removeEventListener("hashchange", h);
  }, []);

  const onJobDone = useCallback(async (job: Job) => {
    await loadTargets();
    if (job.status === "ok") {
      if (job.project === name) await loadProject(job.project); else setName(job.project);
      if (job.kind === "approve") setPage("remediation");
    }
  }, [name, loadTargets, loadProject]);

  const go = (p: Page) => { setPage(p); setNavOpen(false); };
  const info = targets?.projects.find((p) => p.name === name);
  const presetPath = targets?.fetched?.find((p) => p.name === name)?.url || targets?.presets.find((p) => p.name === name)?.path;

  const sidebar = (
    <nav className="flex h-full flex-col bg-ink-950 text-slate-300">
      <div className="flex items-center gap-2.5 px-5 py-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-brand-600 shadow-lg shadow-brand-600/30"><ShieldCheck className="h-5 w-5 text-white" /></div>
        <div className="leading-tight">
          <div className="text-sm font-semibold text-white">Supply Chain Guardian</div>
          <div className="text-[11px] text-slate-500">Know what you build. Trust what you ship.</div>
        </div>
      </div>
      <div className="px-3 pb-3">
        <label className="mb-1 block px-2 text-[11px] font-medium uppercase tracking-wider text-slate-500">Application</label>
        <select value={name || ""} onChange={(e) => setName(e.target.value)}
          className="w-full rounded-lg border-0 bg-ink-800 px-3 py-2 text-sm text-white ring-1 ring-inset ring-ink-700 focus:ring-2 focus:ring-brand-500">
          {!targets?.projects.length && <option value="">No scans yet</option>}
          {targets?.projects.map((p) => <option key={p.name} value={p.name}>{p.name}{p.remediation === "pending" ? "  ⏸" : ""}</option>)}
        </select>
        <button onClick={() => setRunOpen(true)} className="mt-2 flex w-full items-center justify-center gap-1.5 rounded-lg bg-brand-600 px-3 py-2 text-sm font-medium text-white transition hover:bg-brand-500">
          <Plus className="h-4 w-4" /> New run
        </button>
      </div>
      <div className="flex-1 overflow-y-auto px-3 py-2">
        {NAV.map((n, i) => (
          <div key={n.id}>
            {n.group && n.group !== NAV[i - 1]?.group && <div className="mb-1 mt-4 px-2 text-[11px] font-medium uppercase tracking-wider text-slate-500">{n.group}</div>}
            <button onClick={() => go(n.id)}
              className={cx("mb-0.5 flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition",
                page === n.id ? "bg-ink-800 font-medium text-white" : "hover:bg-ink-900 hover:text-white")}>
              <n.icon className={cx("h-4 w-4", page === n.id ? "text-brand-400" : "text-slate-500")} />
              <span className="flex-1 text-left">{n.label}</span>
              {n.id === "remediation" && project?.pending && <span className="rounded-full bg-amber-500 px-1.5 py-0.5 text-[10px] font-semibold text-ink-950">Approve</span>}
              {n.id === "vulns" && project?.findings && <span className="text-xs tabular-nums text-slate-500">{project.findings.counts.vulnerabilities}</span>}
              {n.id === "changes" && project?.findings && <span className="text-xs tabular-nums text-slate-500">{project.findings.counts.anomalies}</span>}
            </button>
          </div>
        ))}
      </div>
      <div className="border-t border-ink-800 px-5 py-4 text-[11px] text-slate-500">
        <div className="flex items-center gap-1.5"><Bot className="h-3.5 w-3.5" /> Human approval required for every fix</div>
        <div className="mt-1">Repositories are never modified · fixes validated in a temporary copy</div>
      </div>
    </nav>
  );

  return (
    <div className="min-h-screen bg-slate-50">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-64 lg:block">{sidebar}</aside>
      {navOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-ink-950/50" onClick={() => setNavOpen(false)} />
          <aside className="relative h-full w-64">{sidebar}</aside>
        </div>
      )}
      <div className="lg:pl-64">
        <header className="sticky top-0 z-20 flex items-center gap-3 border-b border-slate-200 bg-white/90 px-4 py-3 backdrop-blur sm:px-6">
          <button className="rounded-md p-1.5 text-slate-500 hover:bg-slate-100 lg:hidden" onClick={() => setNavOpen(true)}><Menu className="h-5 w-5" /></button>
          <div className="min-w-0 flex-1">
            <div className="truncate text-sm font-semibold text-slate-900">{name || "No application selected"}</div>
            {project && <div className="truncate text-xs text-slate-500">Scanned {fmtTime(project.scanned_at)}{project.agentic ? ` · agents: ${project.agentic.engine}` : " · rules only"}</div>}
          </div>
          {name && <Button variant="ghost" onClick={() => loadProject(name)} title="Reload results">{loading ? <Spinner /> : <RefreshCw className="h-4 w-4" />}</Button>}
          <Button variant="primary" onClick={() => setRunOpen(true)}><Plus className="h-4 w-4" /> New run</Button>
        </header>
        <main className="mx-auto max-w-[1500px] px-4 py-6 sm:px-6">
          {err && <div className="mb-4"><Callout tone="error">{err}</Callout></div>}
          {!project ? (
            loading ? <div className="flex items-center justify-center gap-2 py-24 text-slate-500"><Spinner /> Loading results…</div>
              : <Empty icon={<ShieldCheck className="h-10 w-10" />} title="No scan results yet">
                  Click <b>New run</b> and pick a repository: the Guardian discovers its components, builds the SBOM and dependency graph, and detects risks.
                  <div className="mt-4"><Button variant="primary" onClick={() => setRunOpen(true)}><Plus className="h-4 w-4" /> New run</Button></div>
                </Empty>
          ) : !project.summary ? <Empty title="This result folder has no summary.json" /> : (
            <>
              {page === "overview" && <Overview p={project} go={go} />}
              {page === "supply" && <SupplyChain p={project} />}
              {page === "vulns" && <Vulnerabilities p={project} />}
              {page === "changes" && <Changes p={project} />}
              {page === "evidence" && <Evidence p={project} />}
              {page === "ai" && <AiTriage p={project} />}
              {page === "remediation" && <Remediation p={project} onJob={setJobId} />}
              {page === "reports" && <Reports p={project} />}
            </>
          )}
        </main>
      </div>
      <Drawer open={runOpen} onClose={() => setRunOpen(false)} title="New run" subtitle="Scan a repository with the Guardian pipeline">
        <RunPanel meta={meta} targets={targets} initialRepo={presetPath || (info as any)?.repo || undefined}
          onStarted={(id) => { setJobId(id); setRunOpen(false); }} />
      </Drawer>
      {jobId && <JobConsole jobId={jobId} onDone={onJobDone} onClose={() => setJobId(null)} />}
    </div>
  );
}
