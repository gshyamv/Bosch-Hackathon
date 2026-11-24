import { Download, ExternalLink, FileJson, FileText } from "lucide-react";
import { fileUrl, Project } from "../api";
import { Card, DataTable, Empty, LinkButton, PageHeader } from "../components/ui";

/** The one human-readable report (report.html / report.pdf); everything else is raw data. */
const REPORT_FILES = new Set(["report.md", "report.html", "report.pdf"]);
const LEGACY = /^remediation\/remediation_report\.(md|html|pdf)$/;

const DESCRIBE: Record<string, string> = {
  "sbom.cdx.json": "CycloneDX 1.5 SBOM", "graph.json": "Dependency graph (nodes, edges)", "graph.html": "Interactive dependency graph",
  "graph.mmd": "Mermaid graph", "summary.json": "Counts, origins, container and CI inventory",
  "findings.json": "Vulnerabilities + suspicious changes with full evidence", "agentic.json": "AI triage, tool evidence, audit trail",
  "remediation/remediation.json": "Priorities, proposals, approvals, validation", "remediation/pending.json": "Run waiting for approval",
  "remediation/remediation.patch": "Every approved change as one patch", "remediation/post_analysis.json": "Before / after counts, resolved, remaining, new",
  "remediation/sandbox_trace.json": "Sandbox containers, images and exit codes",
};

export function Reports({ p }: { p: Project }) {
  const hasReport = p.files.includes("report.md") || p.files.includes("report.html");
  const data = p.files.filter((f) => !REPORT_FILES.has(f) && !LEGACY.test(f));
  const src = fileUrl(p.name, "report.html");
  const state = p.pending ? "awaiting human approval" : p.post_analysis ? "before and after remediation"
    : p.remediation ? "remediation decided" : "before-state (remediation not run)";
  return (
    <div>
      <PageHeader title="Report" description="One Guardian report: executive summary, vulnerabilities and suspicious changes kept apart, decisions, before / after and sandbox evidence. Raw data files are below." />
      <Card pad={false} title="Guardian report" subtitle={`out/${p.name}/report.pdf · ${state}`} actions={hasReport ? <>
        <LinkButton href={fileUrl(p.name, "report.pdf", true)} download><Download className="h-4 w-4" /> Download PDF</LinkButton>
        <LinkButton href={src}><ExternalLink className="h-4 w-4" /> Open</LinkButton></> : undefined}>
        {hasReport
          ? <iframe key={src} src={`${src}?t=${p.scanned_at}`} title="Guardian report" sandbox="" className="h-[78vh] w-full rounded-b-xl border-0 bg-white" />
          : <div className="p-5"><Empty title="No report yet">Run a scan to generate the report.</Empty></div>}
      </Card>
      <div className="mt-4">
        <Card title="Raw data" subtitle="Machine-readable outputs (secondary downloads)" pad={false}
          actions={p.agentic?.run_id ? <LinkButton href={`/api/runs/${p.agentic.run_id}/okf.zip`}><Download className="h-4 w-4" /> OKF context</LinkButton> : undefined}>
          <DataTable rows={data} rowKey={(f) => f} cols={[
            { key: "f", label: "File", render: (f) => (
              <div className="flex items-start gap-2">
                {f.endsWith(".json") ? <FileJson className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" /> : <FileText className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" />}
                <div><div className="font-mono text-xs font-medium text-slate-900">{f}</div><div className="text-xs text-slate-500">{DESCRIBE[f] || ""}</div></div>
              </div>) },
            { key: "d", label: "", render: (f) => (
              <div className="flex justify-end gap-1">
                {/\.html$/.test(f) && <a className="rounded p-1.5 text-slate-500 hover:bg-slate-100" href={fileUrl(p.name, f)} target="_blank" rel="noreferrer" title="Open"><ExternalLink className="h-4 w-4" /></a>}
                <a className="rounded p-1.5 text-slate-500 hover:bg-slate-100" href={fileUrl(p.name, f, true)} title="Download"><Download className="h-4 w-4" /></a>
              </div>) },
          ]} />
        </Card>
      </div>
    </div>
  );
}
