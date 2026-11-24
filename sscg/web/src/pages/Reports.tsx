import { useState } from "react";
import { Download, ExternalLink, FileJson, FileText } from "lucide-react";
import { fileUrl, Project } from "../api";
import { Card, cx, DataTable, LinkButton, PageHeader, Segmented } from "../components/ui";

const DESCRIBE: Record<string, string> = {
  "sbom.cdx.json": "CycloneDX 1.5 SBOM", "graph.json": "Dependency graph (nodes, edges)", "graph.html": "Interactive dependency graph",
  "graph.mmd": "Mermaid graph", "summary.json": "Counts, origins, container and CI inventory",
  "findings.json": "Vulnerabilities + anomalies with evidence (machine-readable)", "report.md": "Evidence report (Markdown)",
  "report.html": "Evidence report (web page)", "report.pdf": "Evidence report (PDF)", "agentic.json": "AI triage, tool evidence, audit trail",
  "remediation/remediation.json": "Priorities, proposals, approvals, validation (machine-readable)", "remediation/pending.json": "Run waiting for approval",
  "remediation/remediation_report.md": "Remediation report (Markdown)", "remediation/remediation_report.html": "Remediation report (web page)",
  "remediation/remediation_report.pdf": "Remediation report (PDF)", "remediation/remediation.patch": "Every approved change as one patch",
};

export function Reports({ p }: { p: Project }) {
  const hasD2 = p.files.includes("remediation/remediation_report.html");
  const [which, setWhich] = useState<"evidence" | "remediation">(hasD2 ? "remediation" : "evidence");
  const files = p.files.includes("report.md") && !p.files.includes("report.html") ? [...p.files, "report.html", "report.pdf"] : p.files;
  const src = which === "remediation" ? fileUrl(p.name, "remediation/remediation_report.html") : fileUrl(p.name, "report.html");
  return (
    <div>
      <PageHeader title="Reports" description="The Guardian report in human-readable (Markdown, HTML, PDF) and machine-readable (JSON, CycloneDX, patch) form." />
      <div className="grid gap-4 xl:grid-cols-[420px_1fr]">
        <Card title="Output files" actions={p.agentic?.run_id ? <LinkButton href={`/api/runs/${p.agentic.run_id}/okf.zip`}><Download className="h-4 w-4" /> OKF context</LinkButton> : undefined} subtitle={`out/${p.name}/`} pad={false}>
          <DataTable rows={files} rowKey={(f) => f} cols={[
            { key: "f", label: "File", render: (f) => (
              <div className="flex items-start gap-2">
                {f.endsWith(".json") ? <FileJson className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" /> : <FileText className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" />}
                <div><div className="font-mono text-xs font-medium text-slate-900">{f}</div><div className="text-xs text-slate-500">{DESCRIBE[f] || ""}</div></div>
              </div>) },
            { key: "d", label: "", render: (f) => (
              <div className="flex justify-end gap-1">
                {/\.(html|pdf)$/.test(f) && <a className="rounded p-1.5 text-slate-500 hover:bg-slate-100" href={fileUrl(p.name, f)} target="_blank" rel="noreferrer" title="Open"><ExternalLink className="h-4 w-4" /></a>}
                <a className="rounded p-1.5 text-slate-500 hover:bg-slate-100" href={fileUrl(p.name, f, true)} title="Download"><Download className="h-4 w-4" /></a>
              </div>) },
          ]} />
        </Card>
        <Card pad={false} title="Preview" actions={<>
          {hasD2 && <Segmented value={which} onChange={setWhich} options={[{ id: "evidence", label: "Evidence report" }, { id: "remediation", label: "Remediation report" }]} />}
          <LinkButton href={src}><ExternalLink className="h-4 w-4" /> Open</LinkButton></>}>
          <iframe key={src} src={`${src}?t=${p.scanned_at}`} title="Report" sandbox="" className={cx("h-[78vh] w-full rounded-b-xl border-0 bg-white")} />
        </Card>
      </div>
    </div>
  );
}
