// Types for the JSON files the pipeline writes (out/<repo>/...) and the small API in sscg/sscg/server.py.

export type Level = "Critical" | "High" | "Medium" | "Low" | "Info";
export const LEVELS: Level[] = ["Critical", "High", "Medium", "Low", "Info"];

export interface Component {
  id: string; purl: string | null; name: string; version: string; ecosystem: string; label: string;
  scope: string; direct: boolean; resolution?: string; origin?: string | null;
}
export interface Evidence { type: string; [k: string]: any }
export interface Finding {
  finding_id: string; category: "vulnerability" | "anomaly"; type: string; rule: string; title: string;
  component: Component | null; is_direct: boolean | null; location: string | null;
  dependency_paths: string[][]; introduced_by: string[]; evidence: Evidence[];
  why_it_matters: string; classification: string; confidence: string; new_in_change: boolean;
  severity?: { label: string; cvss: number | null; source: string };
  fixes?: { upgrade_to_at_least: string | null; advisories_without_fix: string[] };
  permalink?: string;
  risk: { level: Level; score: number; reasons: string[]; label: string };
}
export interface Commit { sha: string; short: string; author: string; email: string; date: string; message: string }
export interface Change {
  base: Commit; head: Commit; head_dirty: boolean; first_time_author: boolean | null;
  files: { status: string; path: string }[];
  added: { label: string; source: string }[]; removed: { label: string; source: string }[];
  changed: { base: string; head: string; fields: string[] }[];
}
export interface FindingsDoc {
  scan: any; change: Change | null; findings: Finding[]; notes: string[];
  counts: { total: number; vulnerabilities: number; anomalies: number; new_in_change: number; advisories?: number;
            by_level: Record<Level, number>; by_type: Record<string, number> };
}
export interface Summary {
  apps: string[]; components_total: number; packages: number; edges: number; by_ecosystem: Record<string, number>;
  direct: number; transitive: number; max_depth: number; depth_histogram: Record<string, number>;
  by_scope: Record<string, number>; resolution: Record<string, number>; origins: Record<string, number>;
  untrusted_origins: string[]; install_scripts: string[]; duplicates: Record<string, string[]>;
  top_blast_radius: { package: string; dependents_transitive: number }[];
  heaviest_direct_deps: { package: string; brings_in: number }[];
  container_images: { image: string; registry: string; tag: string | null; digest: string | null; pinned_by_digest: boolean;
                      official_image: boolean; scope: string; used_in: string[] }[];
  dockerfiles: { file: string; stages: number; runs_as?: string; images: string[]; downloads: string[] }[];
  ci_workflows: { workflow: string; file: string; triggers: string[]; permissions: string;
                  actions: { action: string; ref: string; pinned_to_sha: boolean; source: string }[];
                  images: string[]; downloads: string[] }[];
  remote_artifacts: { url: string; host: string; scope: string; source: string }[];
  notes: string[];
}
export interface Triage {
  finding_id: string; rule: string; verdict: string; confidence: string; rationale: string; rounds: number;
  grounding: { ok?: boolean; [k: string]: any }; generated_by: string; benign_explanations?: string[];
  recommended_next_step?: string; matched_patterns?: string[];
  // structured reasoning (newer agentic.json; older files only have rationale / recommended_next_step)
  summary?: string; reasons?: TriageReason[]; recommended_action?: string; basis?: "ai_inference" | "rules_fallback" | string;
}
export interface TriageReason {
  text: string; evidence: string; kind: "file" | "advisory" | "okf" | "registry" | "commit" | "graph" | "finding" | "rule" | "other";
  label: string; permalink?: string | null; verified: boolean;
}
export interface Agentic {
  run_id: string; generated_at: string; engine: string; kb_version: string; stale: boolean;
  narrative?: { headline: string; what_is_in_the_app: string; what_changed: string; what_appears_risky: string;
                top_concerns: { finding_id: string; why: string }[]; caveats: string[] };
  triage: Record<string, Triage>;
  triage_basis?: Record<string, string>;   // finding_id -> "deterministic: verified advisory" | "ai_inference" | ...
  tool_evidence: Record<string, { id: string; tool: string; round: number; result: any }[]>;
  llm_usage: { calls: number; input_tokens: number; output_tokens: number; secrets_redacted: number };
  agent_runs: { agent: string; kind: string; seconds: number; status: string; input_tokens?: number; output_tokens?: number }[];
}
export interface Proposal {
  proposal_id: string; finding_ids: string[]; action: string; component: string | null; from_version: string | null;
  to_version: string | null; files_affected: string[]; diff: string; patchable: boolean; priority: string; urgent: boolean;
  rationale: string; expected_risk_reduction?: string; compatibility_level: string; compatibility_impact?: string;
  residual_advisories: string[]; rollback?: string; notes?: string; ai_rationale?: string; cluster_ids?: string[];
  ai_reviewer_checklist?: string[] | string; status: string;
  system_suggestion?: { decision: string; reason: string; confidence: string } | null;
}
export interface PostAnalysis {
  before: { total: number; by_level: Record<string, number> }; after: { total: number; by_level: Record<string, number> };
  resolved: string[]; remaining: string[]; new: { title: string; kind: string; level: string; component?: string }[];
  docker: boolean; verdict: string; confidence: string; reasons: string[];
  sbom_diff?: Record<string, any>; after_findings: { finding_id: string; title: string; rule: string; level: string }[];
}
export interface SandboxTrace {
  sandbox?: string; docker_server?: string; volume?: string; network?: string; events?: string[];
  containers?: { container: string; image: string; cmd: string; network: string; started: string; seconds: number; exit: number | null; status: string; log_tail: string }[];
}
export interface Priority {
  finding_id: string; priority: string; score: number; urgent: boolean; bucket: string; title: string;
  category: string; component: string | null; reasons: string[]; confidence: string;
  factors?: Record<string, { value: any; points: number }>;
}
export interface Step { step: string; cmd: string; cwd: string; status: string; exit: number | null; seconds: number; log: string }
export interface Validation {
  proposal_ids: string[]; verdict: string; confidence: string; reasons: string[];
  steps_before: Step[]; steps_after: Step[]; findings_before: number; findings_after: number;
  resolved: string[]; remaining: string[];
  new: { title: string; kind: string; severity?: string; level?: string; component?: string }[];
  per_proposal: Record<string, { targeted: string[]; resolved: string[]; status: string }>;
  sbom_diff: { added?: string[]; removed?: string[]; changed?: string[] };
  docker?: any;
}
export interface RemediationRun {
  run_id: string; application: string; generated_at: string;
  exploitability_sources: { kev?: { available: boolean; date?: string; entries?: number };
                            epss?: { available: boolean; date?: string; scored_cves?: number } };
  exposure: { network_service: boolean; evidence: string[] };
  reachability_summary: Record<string, number>;
  priorities: Priority[]; proposals: Proposal[];
  approvals: { proposal_id: string; decision: string; approver: string; reason: string; decided_at: string }[];
  validations: Validation[];
}
export interface Pending { run_id: string; repo: string; created: string; proposals: Proposal[] }
export interface Project {
  name: string; scanned_at: number | null; summary: Summary | null; findings: FindingsDoc | null;
  agentic: Agentic | null; pending: Pending | null; remediation: RemediationRun | null; files: string[];
  post_analysis?: PostAnalysis | null; sandbox_trace?: SandboxTrace | null;
  messages?: AgentMessage[]; iteration?: { parent: string; iteration: number } | null; iterations?: IterationRow[];
}
export interface ProjectInfo { name: string; scanned_at: number; has_findings: boolean; has_agentic: boolean; remediation: string | null }
export interface Targets { presets: { name: string; path: string; source?: string }[]; projects: ProjectInfo[] }
export interface Meta { llm_choices: string[]; llm_default: string; llm_keys: Record<string, boolean> }
export interface Job {
  id: string; kind: string; project: string; status: "running" | "ok" | "failed"; returncode: number | null;
  started: number; ended: number | null; lines: string[]; line_count: number; command: string;
}
export interface GraphMeta {
  directs: { id: string; label: string; transitive: number; depth_below: number }[];
  max_depth: number; nodes: number; edges: number;
  ecosystems?: GraphEcosystem[];
}
/** One ecosystem in the graph: same colour / vis shape the graph view draws it with. */
export interface GraphEcosystem { id: string; label: string; color: string; shape: string; count: number; vulnerable: number }
export interface WhyHit { id: string; label: string; ecosystem: string; scope: string; origin: string; findings: string[]; paths: string[][] }

async function req<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, { ...init, headers: { "Content-Type": "application/json", ...(init?.headers || {}) } });
  if (!r.ok) {
    let msg = `${r.status} ${r.statusText}`;
    try { const j = await r.json(); msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail); } catch { /* not JSON */ }
    throw new Error(msg);
  }
  return r.json();
}

const enc = encodeURIComponent;
export const api = {
  meta: () => req<Meta>("/api/meta"),
  targets: () => req<Targets>("/api/targets"),
  project: (name: string) => req<Project>(`/api/projects/${enc(name)}`),
  sbom: (name: string) => req<any>(`/api/projects/${enc(name)}/sbom`),
  graphMeta: (name: string, libsOnly: boolean) => req<GraphMeta>(`/api/projects/${enc(name)}/graph/meta?libs_only=${libsOnly}`),
  why: (name: string, q: string) => req<{ hits: WhyHit[] }>(`/api/projects/${enc(name)}/why?q=${enc(q)}`),
  run: (body: Record<string, unknown>) => req<Job>("/api/runs", { method: "POST", body: JSON.stringify(body) }),
  approve: (name: string, body: Record<string, unknown>) =>
    req<Job>(`/api/projects/${enc(name)}/approve`, { method: "POST", body: JSON.stringify(body) }),
  job: (id: string, since: number) => req<Job>(`/api/jobs/${id}?since=${since}`),
  messages: (name: string) => req<AgentMessage[]>(`/api/projects/${enc(name)}/messages`),
  okfGraph: (type?: string) => req<OkfGraph>(`/api/okf/graph${type ? `?type=${enc(type)}` : ""}`),
  okfConcept: (id: string) => req<{ id: string; meta: any; body: string; trust: string; stale: boolean }>(`/api/okf/concepts/${id}`),
};

export interface AgentMessage { at: string; run_id: string; iteration: number; sender: string; recipient: string; kind: string; content: string; refs: string[] }
export interface OkfCard { id: string; type: string; title: string; description?: string; status?: string; trust: string; stale: boolean }
export interface OkfGraph { nodes: OkfCard[]; edges: { source: string; target: string }[]; types: Record<string, number>; total: number }
export interface IterationRow { project: string; iteration: number; findings: number | null; after_fix: number | null; verdict: string | null }

export const fileUrl = (name: string, path: string, download = false) =>
  `/api/projects/${enc(name)}/files/${path}${download ? "?download=true" : ""}`;
export const graphUrl = (name: string, p: { mode: string; levels: number; libsOnly: boolean; root?: string | null }) =>
  `/api/projects/${enc(name)}/graph/view?mode=${p.mode}&levels=${p.levels}&libs_only=${p.libsOnly}` +
  (p.root ? `&root=${enc(p.root)}` : "");

// ------------------------------------------------------------------ persisted job logs (Logs page)
export interface LogRun {
  id: string; kind: string; project: string; command: string | null; started: number | null; ended: number | null;
  returncode: number | null; status: "running" | "ok" | "failed" | "interrupted" | "unknown"; file: string; size: number; lines: number | null;
}
export interface LogLine {
  n: number; ts: string | null; text: string; tag: string | null; stage: string | null; kind: string; message: string;
  transition: boolean; from?: string; to?: string;
}
export const logApi = {
  list: () => req<LogRun[]>("/api/logs"),
  get: (project: string, file: string) => req<{ meta: LogRun; lines: LogLine[] }>(`/api/logs/${enc(project)}/${enc(file)}`),
  job: (id: string) => req<Job & { dropped?: number }>(`/api/jobs/${id}?since=999999999`),
};
export const logUrl = (project: string, file: string, download = false) =>
  `/api/logs/${enc(project)}/${enc(file)}${download ? "?download=true" : "?raw=true"}`;

/** Follows a running job over the server-sent events stream (/api/jobs/{id}/events). Returns a stop function. */
export function followJob(id: string, since: number, onUpdate: (j: Job) => void, onEnd: () => void): () => void {
  const es = new EventSource(`/api/jobs/${id}/events?since=${since}`);
  es.onmessage = (m) => { const j: Job = JSON.parse(m.data); onUpdate(j); if (j.status !== "running") { es.close(); onEnd(); } };
  es.onerror = () => { es.close(); onEnd(); };
  return () => es.close();
}
