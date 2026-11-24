# The SSCG Dashboard: What Happens in the UI

The dashboard is a **React** single-page app (`sscg/web`) on top of a small **FastAPI** server (`sscg/sscg/server.py`).
It walks through the whole Guardian workflow of the problem statement, *Discover → Detect → Analyze → Remediate → Validate*,
including the **human approval** step.

| Page | Workflow stage |
|---|---|
| Overview | the whole workflow at a glance: what is in the app, what is risky, where remediation stands |
| Supply chain | Discover: components, SBOM, dependency graph, containers, CI/CD |
| Vulnerabilities | Detect: known vulnerabilities |
| Suspicious changes | Detect: suspicious changes (+ "what changed") |
| Evidence | Detect: evidence per finding |
| AI triage | the agents' inference, kept apart from the evidence |
| Remediation | Analyze (prioritize) · Remediate (recommend, human approval) · Validate & report |
| Reports | the human-readable and machine-readable Guardian report |

---

## 1. Starting the dashboard

```powershell
cd sscg\web
npm install            # once (Node.js 18+)
npm run build          # once, and after UI changes: writes sscg/web/dist
cd ..
python -m sscg serve   # http://127.0.0.1:8000   (--port N to use another port)
```

**Developing the UI:** keep `python -m sscg serve` running and start `npm run dev` in `sscg/web`. Vite serves the UI on
http://localhost:5173 with hot reload and forwards `/api` to port 8000.

## 2. How it works

```
Browser (React, sscg/web)  --/api-->  FastAPI (sscg/sscg/server.py)  --reads-->  out/<repo>/*.json, remediation/*
                                                 |
                                                 +--starts-->  python -m sscg scan | agent | approve   (background job)
```

* The API **reads the files the pipeline writes** (`summary.json`, `findings.json`, `graph.json`, `sbom.cdx.json`,
  `agentic.json`, `remediation/pending.json`, `remediation/remediation.json`, reports). Nothing is computed twice.
* **New run** and **Submit & validate** start the same CLI commands you would type, as background jobs. The job's console
  output streams into the panel at the bottom right. When a job finishes, the results reload by themselves.
* The server listens on **127.0.0.1 only**. File downloads are limited to the result folder and to report/data file
  types. The graph and the reports are shown in **sandboxed iframes**.
* The selected application and page are remembered in the browser. Every page also has its own link (`#remediation`,
  `#supply`, …), which is handy in a demo.

## 3. New run

Click **New run** (sidebar or top right).

| Control | Meaning |
|---|---|
| Repository | one of the sample apps in `targets/`, or any folder path |
| Pipeline | **Detect (rules only)**: `python -m sscg scan`, deterministic, no AI · **Detect + AI agents**: `python -m sscg agent` · **Full: detect → remediate**: `agent --remediate --decisions later`, which pauses for approval |
| LLM provider | auto, Claude, Gemini, Groq, DeepSeek, Grok or none. Shows which providers have a key in `sscg/.env`, never the key itself. Without a key the agents use the rules-only fallback |
| Compare with commit | base revision for "what changed" (default `HEAD~1`; empty = skip) |
| Focus graph on package | limits `graph.html` to one package's ancestors and descendants |
| Vulnerability lookup / Offline | OSV.dev on or off; offline answers from `sscg/.cache` only |

## 4. Overview

* **Five stage cards** (Discover, Detect, Analyze, Remediate, Validate), green when done and amber when waiting
  (for example, waiting for approval). Click a card to open its page.
* **KPIs:** components (direct and transitive), vulnerable components and advisories, suspicious changes, Critical,
  High, and findings new in the latest change.
* **Charts:** findings by risk level, findings by type, and components by ecosystem.
* **AI summary** (when the agents ran), **top findings** (click one for its evidence), **what changed** (commit, author,
  first-time-contributor flag) and **remediation status** (verdict, findings before → after).

## 5. Supply chain

* **Dependency graph** with four views: *by level* (columns = dependency levels, with a level slider), *direct only*
  (each with "+N transitive"), *one dependency's tree*, and the *full risk graph*. Hover a node for its version, path,
  advisories and finding IDs. Next to it: libraries per level, legend, top blast radius, and heaviest direct
  dependencies.
* **Why is this package here?** Type a package name to get every path from the repository to it, plus its scope, origin and findings.
  Packages present in several versions are listed below.
* **SBOM (CycloneDX):** format, counts, a searchable component table, and the download.
* **Containers & CI/CD:** images (official or unverified publisher, digest or mutable tag), Dockerfiles (user,
  downloads), workflows (triggers, token permissions, actions pinned to a SHA or not), files downloaded during build or CI.
* **Origins:** download hosts, npm packages not served by the npm registry, and packages with install scripts.

## 6. Vulnerabilities, Suspicious changes, Evidence

* **Vulnerabilities:** counts by highest severity, plus a table you can filter by severity, direct or transitive, and search text. Columns:
  CVEs, CVSS, advisories, fix (upgrade to ≥), introduced via, and risk.
* **Suspicious changes:** the base and head commits, author, first-time-contributor flag, changed files, and
  components added, removed or changed, followed by the anomaly table.
* **Evidence:** every finding, filterable by risk level, category and "only new", plus search; download
  `findings.json` and the report.
* **Clicking a finding opens a side panel:** type and rule, component and purl, location, **dependency paths**, official
  severity, fix, **numbered evidence** (file lines, hashes, commits, advisories with links), initial risk with its
  reasons, the **priority** and its factors, the basis (verified fact or heuristic), and the **AI triage verdict
  in a separate violet box** labelled as inference.

## 7. AI triage

Engine and knowledge-base version, verdict counts, how many triage decisions passed the **grounding check** (every
cited ID exists in the evidence), LLM calls and tokens, and the narrative summary. Click a decision to see its
rationale, the innocent explanations it considered, what the reviewer should check, the matched attack patterns, and
the raw **tool evidence** of each investigation round. The agent-runs table shows each agent's kind
(deterministic, llm or human), status, time and tokens. A warning appears when the triage is older than the findings.

## 8. Remediation

**While a run is paused**, the page is the **human-approval board**:

* One card per proposal: ID, priority (P0–P3, URGENT), action (upgrade, replace, pin, block, mitigate, update base
  image, escalate), component, from → to. Expand a card for the verified rationale, risk reduction, compatibility,
  rollback, findings, files, residual advisories, the **AI advisor's rationale and reviewer checklist**, and the
  **exact diff**.
* Per-card decision: **Defer · Approve · Reject · Accept risk · Request changes**. *Approve* is disabled for manual
  proposals that have no automatic patch.
* Bulk actions: *Approve all patchable*, *Approve urgent only*, *Escalate manual items*, *Reset*.
* The sticky bar at the bottom shows the decision counts and has fields for the **approver** (required, recorded in the
  audit trail) and the **reason**. **Submit & validate** runs `python -m sscg approve …`. Only approved proposals with a
  patch are applied, **in a sandbox copy**, which is then built, tested and rescanned.

**After validation:**

* A verdict banner (verified, partially verified, failed) with its reasons and links to the report.
* KPIs: findings before → after, resolved, newly introduced, proposals and approvals, P0/P1, network exposure.
* **Prioritised risks:** score, priority, and the reasons (KEV, EPSS, reachability, exposure, triage). Click a row for the finding.
* **Proposals & decisions:** who decided what, and the validation status per proposal. Click a row for the full proposal.
* **Validation:** each build/test step **before (unchanged) vs after (remediated)**, logs of failed steps, the SBOM diff,
  findings that exist only after the fix (introduced, still vulnerable, expected), and resolved vs remaining findings.
* **Report & patch:** downloads of the remediation report (PDF, HTML, Markdown), `remediation.patch` and `remediation.json`, plus an inline preview.

## 9. Reports

Every file in `out/<repo>/` with a short description, buttons to open or download it, and a preview of the evidence report
and the remediation report.

## 10. A five-minute demo

1. **New run** → `sscg-demo-app` → **Full: detect → remediate** → Start. Show the live console: discovery, OSV,
   detection, triage, prioritisation, "PAUSED for human approval".
2. **Overview:** *"31 components, 41 findings, 25 introduced by one commit from a first-time contributor."*
3. **Supply chain → graph:** hover a red-outlined node. **Why is this package here?** `minimist` → `acme-orders → mkdirp → minimist`.
4. **Evidence:** open **F-005** (lodash, same version but a different hash) and **F-001** (install script with a decoded
   endpoint): *"every claim has a file line, a before/after value or a commit behind it; the AI verdict is separate."*
5. **Remediation:** expand P-001 (log4j, KEV + EPSS 1.0 + imported → P0 14.5) and show the diff. Click **Approve all patchable**
   and **Escalate manual items**, enter your name and a reason, then **Submit & validate**.
6. After about a minute: **Remediation verified**. Show the before/after build table (Docker, npm, pip), the SBOM diff,
   and "no new Critical/High". Finish on the **Reports** page with the remediation PDF.

## 11. Troubleshooting

| What you see | Cause and fix |
|---|---|
| "Cannot reach the API" | Start the server: `python -m sscg serve` (from `sscg/`). |
| Page says "The web UI is not built yet" | Run `npm install && npm run build` in `sscg/web`. |
| "a job is already running for …" | Wait for the running job (console panel, bottom right). |
| Run fails immediately | Wrong path: paste the full folder path. The console shows the error. |
| Validation: docker build *skipped* | Docker Desktop is not running. Start it and run the remediation again. |
| Validation: mvn *skipped* | Maven is not installed, so the Java module is only rescanned. |
| AI triage says "rules-fallback" | No API key for the chosen provider in `sscg/.env`. |
| Graph shows only a few levels | Large graphs: use the level slider, *one dependency's tree*, or **Focus graph on package**. |
