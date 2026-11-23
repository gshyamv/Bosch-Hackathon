# Software Supply Chain Guardian: Hackathon Master Plan
*Know What You Build. Trust What You Ship.*

---

## 0. How to read this plan

Your master prompt is huge (8 agents, 14 dashboard pages, cost module, multi-tenant). The Bosch slides say:

- **Day 1 = "Build the Guardian's Eyes"** (visibility + detection). Remediation comes on Day 2.
- **Core capabilities show completeness. Stretch goals show innovation.**
- Judges want a **working end-to-end workflow** (Discover > Detect > Analyze > Remediate > Validate), not 14 half-finished pages.

So the plan is tiered. **Build the thin end-to-end slice first, then deepen.**

| Tier | Meaning | Rule |
|---|---|---|
| **P0 - MUST** | Bosch core + Day 1 checkpoint | Done before anything else. Demo fails without it. |
| **P1 - SHOULD** | Bosch stretch goals + your differentiators | Only after P0 works end-to-end. |
| **P2 - COULD** | Nice-to-have from your master prompt | Only if time remains; otherwise list as "Roadmap" in the deck. |

---

## 0.5 Why now: verified statistics for the pitch

Use as "according to X (year)". Most are vendor-reported with different methodologies, so don't present them as universal facts.

| Stat | Source (year) | Feature it supports |
|---|---|---|
| Third-party involvement in breaches doubled from 15% to 30% | Verizon DBIR (2025), 12,195 confirmed breaches analyzed | Supply chain visibility |
| Exploitation of vulnerabilities reached 20% of initial access vectors | Verizon DBIR (2025) | Vulnerability intelligence |
| 86% of commercial codebases had open source vulnerabilities; 81% had high/critical ones | Black Duck OSSRA (2025), 965 codebases | Core scanning |
| 64% of components are transitive; nearly half of high/critical vulns come from transitive dependencies | Black Duck OSSRA (2025) | Dependency graph and paths |
| 91% of codebases contained outdated components | Black Duck OSSRA (2025) | Remediation and upgrades |
| Mean components per application rose 911 > 1,180; audited codebases average 581 vulnerabilities | Black Duck OSSRA (2026) | Scale and prioritization |
| Aerospace/automotive/transportation codebases all contained open source | Black Duck OSSRA (2024) | Relevance to Bosch |
| Malicious packages up 156% year over year; 704,000+ identified since 2019 | Sonatype (2024) | Anomaly detection |
| 454,000+ further malicious packages in 2025; 9.8 trillion component downloads | Sonatype (2026) | Anomaly detection |
| npm accounted for 98.5% of malicious packages observed | Sonatype (2024) | Why the demo uses npm |
| Supply chain compromise: 15% of breaches, 2nd most common vector | IBM Cost of a Data Breach (2025) | Continuous monitoring |
| Average cost USD 4.91M and 267 days to resolve (longest of all vectors) | IBM (2025) | Speed and cost module |
| Security AI and automation saved USD 1.9M and 80 days on average | IBM (2025) | Automation and cost story |
| Only 1.2% of 1.1M transitively affected Maven projects use the vulnerable code | Maven reachability study (arXiv 2301.07972); Java ecosystem only | Reachability |
| About 3% of open source flaws "attackable" | ShiftLeft (2022); vendor-reported | Reachability (cite with caveat) |
| CRA vulnerability/incident reporting applies since 11 Sept 2026 | EU Commission (CRA Art. 14) | Compliance relevance |
| CRA full application and machine-readable SBOMs: 11 Dec 2027 | TechTarget / CRA texts | SBOM generation |
| CRA reporting fines up to EUR 15M or 2.5% of worldwide turnover | Goodwin (2026) | Business case |

**Use with caution (label as predictions/projections, or leave out):**
- Gartner predicted that by 2025, 45% of organizations would experience software supply chain attacks (3x the 2021 level). It was a forecast, not a measured result.
- Cybersecurity Ventures projects supply chain attack costs rising from $60B (2025) to $138B (2031). A projection that is often criticised.
- The widely circulated "742% increase in supply chain attacks" could not be traced to its original methodology. Do not use it.
- The IBM 2026 edition reports a 247-day mean to identify and contain a breach; I only confirmed that figure and that supply chain compromise adds the most cost. Prefer the 2025 figures unless you read the 2026 report yourself.

**Rules for using stats:** always name the source and year; never apply a statistic to Bosch or BGSW specifically; do not claim your tool "prevents breaches" or "saves X dollars" without your own measured numbers from the cost module.

**Sources:** Verizon 2025 DBIR (verizon.com); Sonatype State of the Software Supply Chain 2024 and 2026 (sonatype.com); Black Duck OSSRA 2024/2025/2026 (blackduck.com/ossra); IBM Cost of a Data Breach 2025 (ibm.com); Maven reachability study (arxiv.org/abs/2301.07972); ShiftLeft 2022 AppSec Progress Report; European Commission CRA reporting page (digital-strategy.ec.europa.eu/en/policies/cra-reporting); TechTarget and Goodwin CRA analyses; Gartner (2021, refreshed 2022); Cybersecurity Ventures. Re-verify each figure against the original report before final submission.

---

## 1. Requirements traceability (nothing missed)

### 1.1 Bosch core ("What a team's solution should do")
| # | Requirement | Tier | Where in plan |
|---|---|---|---|
| 1 | Discover direct + transitive deps, container components, versions, relationships | P0 | Agent 1, Sec 5 |
| 2 | Generate/consume SBOM (CycloneDX or SPDX) + dependency graph | P0 | Agent 1, Sec 5 |
| 3 | Detect known vulns (CVE, severity, fix version) | P0 | Agent 2 |
| 4 | Detect >=1 supply-chain anomaly (typosquat, unexpected dep, suspicious update/install script, untrusted image, modified lockfile) | P0 | Agent 3 |
| 5 | Inspect >=1 container image or CI/CD workflow | P0 | Agent 1 + 3 |
| 6 | Analyze & prioritize with AI (exploitability, exposure, provenance, app context) | P0 | Agents 4-5 |
| 7 | Recommend safe remediation (upgrade/replace/pin/remove/mitigate/block/review) | P0 (Day 2) | Agent 6 |
| 8 | Validate: build, test, rescan, verify risk reduced, detect new problems, evidence report | P0 (Day 2) | Agent 7 |
| 9 | Present evidence: what, which component, dependency path, evidence, initial risk | P0 | Dashboard + Agent 8 |

### 1.2 Bosch stretch goals
| # | Stretch goal | Tier | Plan |
|---|---|---|---|
| S1 | Reachability analysis | **P1 (do this one)** | Import/call-site analysis, 3-level confidence |
| S2 | Automated remediation (patch/PR + rationale + validation + rollback) | **P1 (do this one)** | Generate patch + local branch, never merge |
| S3 | Provenance verification (Cosign/Sigstore/in-toto/SLSA) | P1 | `cosign verify` on the image; `cosign verify-attestation` for in-toto/SLSA provenance on a signed image; `npm audit signatures` for npm registry signatures and provenance; report SLSA level as "verified / not available / failed" |
| S4 | Advanced package risk (dependency confusion, maintainer changes, release anomalies) | P1 | Registry metadata heuristics |
| S5 | Policy-as-code (OPA/Conftest) | **P1 (cheap, high impact)** | 4-5 Rego rules gating the pipeline |
| S6 | Continuous monitoring ("yesterday vs today") | **P1 (your killer demo)** | Scheduled rescan + SBOM diff |

### 1.3 Bosch deliverables checklist
- [ ] Working prototype showing complete workflow
- [ ] Architecture overview (agents, tools, data sources, AI interactions, approval points, evidence storage)
- [ ] Source code + setup instructions + config + sample policies + **prompts** + known limitations
- [ ] Live end-to-end demo (discovery, detection, prioritization, remediation, approval, validation)
- [ ] Guardian Report (human + machine readable): inventory and dependency paths, findings + evidence, risk ranking + actions, validation results, remaining/accepted risks
- [ ] **Responsible AI & Security Note** (where AI is used, hallucination control, which actions need human approval, how code/credentials/secrets are protected)
- [ ] Documentation of repo, setup steps, dependencies, tools used

### 1.4 Out of scope (hard guardrails, build these into code)
- No scanning real production systems.
- No access to registries/infra outside the authorized sandbox (use read-only public registry metadata lookups only; see 11.2).
- **Never publish** malicious/modified packages to public registries.
- No real credentials/secrets/tokens.
- **No auto merge/deploy/release**: human approval is mandatory.
- Nothing affecting other teams or shared infrastructure.

---

## 2. Strategy and scope decisions

### 2.1 Pick the demo app (decide in the first 30 min)
Criteria: free OSS, public repo, package.json + lockfile, Dockerfile, existing tests, real dependency tree, **builds fast**.

| Option | Pros | Cons |
|---|---|---|
| **OWASP Juice Shop** (Node) | Large dep tree, Dockerfile, tests, real known vulns in deps, well known to judges | Intentionally vulnerable: judges may see findings as "too easy"; heavy build/test time |
| **OWASP NodeGoat** | Smaller, simpler | Old deps, build may break on modern Node |
| **A small Express/React sample app** (e.g. a todo/realworld Express API) | Fast builds and tests (critical for Day 2 validation loop), easy to control | Fewer organic findings; you must pin an older dependency to create vulns |

**Recommendation:** use a **small-to-medium Node/Express app with a lockfile + Dockerfile + tests** that builds in under about 2 minutes, then pin a known-vulnerable older version of a library to create a genuine, reproducible finding (genuine OSV records, not invented). Keep Juice Shop only as a second app for the cross-application demo if time permits. Whatever you pick, record repo URL, commit SHA, and license in `docs/SOURCES.md`.

### 2.2 Language/ecosystem focus
**Node (npm) first**, Python (requirements.txt) second as P1 to prove ecosystem-agnosticism. Don't attempt Java/Maven unless a teammate owns it.

### 2.3 Where LLMs are actually used (keeps it "agentic" but reliable)
Deterministic tools do detection; the LLM does **reasoning, explanation, and drafting**. This is also your hallucination-control story.

| Agent | Deterministic core | LLM role |
|---|---|---|
| 1 Discovery | Parsers, Trivy/Syft, CycloneDX | none (maybe summary) |
| 2 Vuln Intel | OSV/GHSA/NVD/CISA KEV APIs | summarize advisory text |
| 3 Anomaly | git diff, hash/metadata/script checks, rules | explain + confidence; **cannot declare malicious** |
| 4 Reachability | AST/grep import and call-site analysis | explain impact, classify reachable/potential/unknown |
| 5 Risk | formula-based scoring | write the "why dangerous / do first" narrative |
| 6 Remediation | `npm view`, semver resolution | draft rationale, rollback notes, regression risk |
| 7 Validation | Docker build, tests, rescan, diff | summarize result |
| 8 Reporting | templates + JSON | executive summary |
| Chat | | RAG over findings JSON only |

**Rule:** the LLM only receives structured evidence JSON and must cite finding/evidence IDs. Post-validate every LLM output: any CVE ID, version, or package it mentions must exist in the evidence store, else drop it.

---

## 3. Architecture

### 3.1 Logical layers
```
[Dashboard (Streamlit)]  <->  [API/CLI (FastAPI optional)]
                                   |
                        [Guardian Orchestrator]
          (state machine, contracts, approvals, audit log, policy gate)
        |-------------|---------------|----------------|-------------|
   Agent1 Discovery  Agent2 VulnIntel  Agent3 Anomaly  Agent4 Reachability   <- parallel (1,2,3 after inventory; 4 after 1)
                                   |
                       Agent5 Risk & Prioritization
                                   |
                       Agent6 Remediation (proposal only)
                                   |
                     [HUMAN APPROVAL GATE]  <- mandatory
                                   |
                       Agent7 Validation (Docker sandbox)
                                   |
                       Agent8 Reporting (PDF/JSON/SBOM)
        Shared: Evidence Store (SQLite + files), OPA policy, Cache, Audit log
```

### 3.2 Orchestration flow
1. **Ingest** repo (local clone, read-only) and create `scan_id`.
2. **Phase A (parallel):** Agent 1 builds inventory/SBOM, then fan-out: Agent 2 (vulns), Agent 3 (anomalies), Agent 4 (reachability).
3. **Aggregate evidence** and resolve conflicts (e.g. Trivy says vulnerable, OSV says not: re-verify against a third source; mark `disputed`).
4. **Agent 5** scores and ranks.
5. **Agent 6** proposes patches (branch + diff, not merged).
6. **Approval gate:** the human approves/rejects per remediation in dashboard; recorded with timestamp, identity, justification.
7. **Agent 7** applies the approved patch **in a sandbox copy**, builds, tests, regenerates SBOM, rescans, diffs.
8. **Agent 8** produces report.
9. **Scheduler** repeats steps 1-4 for continuous monitoring and produces a "what changed" delta.

### 3.3 Orchestrator implementation
Keep it simple and demonstrable: a Python **state machine** (`asyncio` or `concurrent.futures` for parallel agents), each agent a class with `run(context) -> AgentResult`. LangGraph is optional; plain Python is faster and easier to explain. Track per-agent status, duration, tokens, cost in the `agent_runs` table.

### 3.4 Stack (justified, nothing extra)
| Need | Choice | Why |
|---|---|---|
| Backend/orchestration | Python 3.11 | team speed |
| UI | Streamlit (+ `streamlit-agraph` or `pyvis`/Plotly for graph) | fastest |
| SBOM | **CycloneDX** via Syft or `cyclonedx-npm`; Trivy can emit it too | standard, VEX-capable |
| Vulns | **OSV API** (primary), GitHub Advisory (via OSV or GraphQL), NVD (enrichment, rate-limited), **CISA KEV** (known exploited), **EPSS** (exploit probability) | authoritative |
| Scanner | **Trivy** (fs + image + config) | one tool for deps, containers, misconfig |
| Graph | NetworkX | path queries, centrality |
| Change detection | Git (GitPython) + SBOM diff | |
| Sandbox | Docker (no network after install, resource limits, non-root, read-only mounts) | |
| Signatures | Cosign (`cosign verify`) | |
| Policy | OPA/Conftest + Rego | |
| LLM | Claude via API (structured JSON output) | |
| DB | SQLite (schema Postgres-ready, tenant_id column) | |
| PDF | WeasyPrint or ReportLab | |

---

## 4. Data contracts (define Hour 1; the whole team codes against these)

### 4.1 Finding (common envelope)
```json
{
  "finding_id": "F-0001",
  "scan_id": "S-20261123-01",
  "application": "demo-app",
  "category": "vulnerability | anomaly | provenance | config | policy",
  "component": {"purl": "pkg:npm/lodash@4.17.15", "name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
  "dependency_path": ["demo-app", "express-validator@x", "lodash@4.17.15"],
  "is_direct": false,
  "evidence": [{"evidence_id": "E-101", "source": "OSV", "url": "...", "retrieved_at": "ISO8601", "raw_ref": "evidence/E-101.json"}],
  "severity": {"cvss": 7.4, "cvss_source": "OSV/NVD", "label": "HIGH"},
  "classification": "verified_fact | heuristic | ai_recommendation",
  "confidence": 0.0,
  "reachability": "confirmed | potential | unknown",
  "timestamp": "ISO8601",
  "recommended_next_action": "upgrade | replace | pin | remove | mitigate | block | review"
}
```
Never mix: official CVSS lives in `severity`, Guardian's heuristic lives in a separate `risk` object (below).

### 4.2 Risk object
```json
{"finding_id": "F-0001", "guardian_risk_score": 78, "band": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
 "factors": {"cvss":..,"epss":..,"kev":..,"reachability":..,"criticality":..,"exposure":..,"provenance":..,"anomaly":..,"cross_app":..},
 "explanation": "...", "label": "Guardian heuristic score, not CVSS"}
```

### 4.3 Other contracts
`Inventory`, `AnomalySignal`, `RemediationProposal` (files affected, diff, justification, regression risks, rollback, validation plan), `ApprovalRecord` (who/when/decision/reason), `ValidationReport` (before/after counts, tests, new vulns, SBOM hash, verdict), `ScanSnapshot` (for diffs). Put JSON Schemas in `/schemas` and validate every inter-agent message with `pydantic`.

### 4.4 Evidence store
`evidence/` directory of immutable JSON/text files named by hash, indexed in SQLite with `retrieved_at`, `source`, `sha256`. Every claim in the report links to an evidence ID. Record DB timestamps (OSV last-modified, Trivy DB version/date).

### 4.5 Database tables
`tenants, applications, scans, components, edges, sbom_snapshots, findings, risk_scores, anomalies, reachability, remediations, approvals, validations, agent_runs, evidence, audit_log, cost_metrics, cve_cache`.

---

## 5. Agent specifications and build notes

### Agent 1: Discovery
- **Inputs:** repo path. **Outputs:** `Inventory` + CycloneDX SBOM + NetworkX graph (GraphML/JSON).
- **Build:** detect manifests (package.json, package-lock.json, requirements.txt, pyproject.toml, Dockerfile, `.github/workflows/*.yml`, docker-compose). Parse `package-lock.json` (v2/v3 `packages` map) for the full tree incl. `resolved` and `integrity` hashes; build edges from each package's `dependencies`. Run Syft/Trivy for the container image SBOM. Record: missing lockfile, unpinned ranges (`^`, `~`, `*`, `latest`), git/URL deps, undocumented components (installed but not declared).
- **Component origin (Day 1 slide: "identify where each component originates"):** for every component record `origin` = registry/host from `resolved`, source repo URL from package metadata, and how it entered the tree (direct declaration, transitive via X, base image layer, CI action). Show it in the component drawer.
- **Java/Maven (slide shows pom.xml):** optional P2 connector. Syft/Trivy can read `pom.xml` and emit CycloneDX with no custom code, so list it as "supported via Trivy/Syft, not deeply analyzed."
- **Dependency path:** `nx.all_simple_paths` / shortest path from root to component. "Why is it included" = path; "introduced by" = first-level ancestor.
- **Acceptance:** SBOM validates against CycloneDX schema; component count matches `npm ls --all`; every transitive component has >=1 path to root.
- **Limits:** dynamic requires, dev vs prod scope (tag `scope`), monorepos.

### Agent 2: Vulnerability Intelligence
- **Build:** batch query OSV (`/v1/querybatch` by purl), fetch details; cross-check with Trivy results; enrich with NVD CVSS, **EPSS** and **CISA KEV** (known exploited). Compute `published` date and flag `new_in_last_90_days`; separately flag `first_seen_by_guardian_at` (the "newly disclosed vs newly discovered" distinction). Cache with TTL (e.g. 6h) and store DB timestamps.
- **Never fabricate:** if a source is unreachable, say "source unavailable at time T"; do not fall back to memory.
- **Acceptance:** each finding has advisory ID(s), affected range, fixed version(s) (or "no fix"), references, retrieval timestamp; the vulnerable version actually falls inside the affected range (semver check).
- **Limits:** advisories lacking fixed versions; version-range ambiguity; alias dedupe (CVE vs GHSA).

### Agent 3: Anomaly Detection
Signals (each emits `AnomalySignal` with evidence + confidence; wording "investigate", never "malicious"):
1. **Typosquat:** edit distance / homoglyph / keyboard-swap against a top-N popular-package list (offline list bundled).
2. **Unexpected dependency:** git diff of package.json/lockfile adds package with no import in source.
3. **Lockfile tampering:** lockfile changed without manifest change; `resolved` URL host not the official registry; `integrity` hash changed for the same version.
4. **Install scripts:** `preinstall/install/postinstall` in package metadata; flag network calls, `eval`, base64, `child_process` in scripts.
5. **Unusual version change:** major jump, downgrade, version published very recently, big size change.
6. **Maintainer/release anomalies (P1):** npm registry metadata: maintainer set changed, release burst, dormant package suddenly updated, no repo link.
7. **Dependency confusion (P1):** internal-looking scoped name also on public registry.
8. **Container:** `FROM` with `:latest`, unpinned digest, unknown registry, digest changed between scans; no Cosign signature.
9. **CI/CD:** GitHub Actions not pinned to commit SHA, `pull_request_target` misuse, `curl | bash`, overly broad `permissions`.
10. **Build config changes:** Dockerfile/CI diff.
- **Acceptance:** each planted fixture in the demo scenario is detected with correct category, with a precision check on the clean baseline (no more than a few false positives, explained).
- **Limits:** heuristics only; list in report.

### Agent 4: Reachability (stretch S1; do it simply)
- **Build (npm):** map vulnerable package > vulnerable function/module (from advisory text or OSV `ecosystem_specific` when present; otherwise "package-level"). Use `@babel/parser`/`madge`/regex AST in Python (`tree-sitter`) to find `require/import` of the package and usage of specific functions in app source.
- **Levels:**
  - **Confirmed:** app code imports the package AND calls the vulnerable function/API with a traceable call path.
  - **Potential:** imported directly, or transitively loaded, but affected function not confirmed.
  - **Unknown:** no static evidence (dynamic loading, native, or no function info).
  - Also **Not imported by app code (present only)**. Treat as lower priority, not "safe".
- **Output:** files, lines, module list, "blast radius" (which app modules depend on the owner package).
- **Acceptance:** on the demo vulnerable package, correctly marks reachable vs present-only for two cases.
- **Limits:** static analysis only; state it prominently.

### Agent 5: Risk Prioritization
Transparent weighted model (all factors normalized 0-1), e.g.:
```
score = 100 * ( 0.25*cvss/10 + 0.15*epss + 0.20*kev(0/1)
              + 0.20*reachability(confirmed=1, potential=0.5, unknown=0.25, none=0.05)
              + 0.05*criticality + 0.05*exposure + 0.05*provenance_penalty
              + 0.05*anomaly_boost ) + cross_app_bonus (capped)
```
Bands: >=80 Critical, 60-79 High, 40-59 Medium, 20-39 Low, <20 Info. Override rules: KEV + reachable = at least High; anomaly with high-confidence integrity failure = escalate to review immediately. Always show factor breakdown and label as **"Guardian Risk Score (heuristic), not CVSS"**. Make weights configurable in `policies/risk_weights.yaml`.
- **Acceptance:** deterministic (same input > same score); ranking changes sensibly when reachability changes; LLM narrative cites only factors present.

### Agent 6: Remediation
- **Build:** for each finding choose action: upgrade to the **lowest compatible fixed version** (semver-aware: prefer same-major patch/minor; flag major bumps), `overrides`/`resolutions` for transitive deps, replace, remove (if unused), pin, mitigate (config), block (policy), review. Query `npm view <pkg> versions` / peer deps to check compatibility. Create a **git branch + patch file** only; never push/merge. Output rationale, files affected, regression risk (semver delta, changelog keywords, test coverage), rollback (`git revert`/restore lockfile), validation plan.
- **Container:** suggest pinned digest / slimmer or maintained base image.
- **Acceptance:** patch applies cleanly; proposal has all required fields; no action executed without approval.

### Approval gate (Orchestrator + UI)
Approve / Reject / Request changes / Accept risk (with expiry + reason). Persist `ApprovalRecord`; Agent 7 refuses to run without an approval ID (enforced in code **and** by an OPA rule).

### Agent 7: Validation and Trust
- **Build:** copy repo to a temp sandbox; apply patch; `docker build` (no secrets, non-root, CPU/mem limits, `--network none` for the test stage after dependency install); run `npm test`; regenerate SBOM; rescan; diff before/after (resolved, remaining, **newly introduced**); verify integrity hashes, and `cosign verify` where signatures exist; record durations, CPU/memory (for sustainability metrics).
- **Verdict logic:** `SUCCESS` only if target vuln gone **and** build/tests pass **and** no new High/Critical introduced; else `PARTIAL`/`FAILED` with reason. A version bump alone never = success.
- **Acceptance:** fixture patch yields SUCCESS; a deliberately breaking patch yields FAILED and is reported honestly.

### Agent 8: Reporting
- **Build:** Jinja2 > HTML > PDF; plus `guardian_report.json`, `sbom.cdx.json` (before and after), VEX (optional, P2). Sections: exec summary, inventory, dependency graph snapshot, findings + evidence refs, recent CVEs (90d), anomalies, impact, risk ranking, remediation, approvals, validation, accepted risks, timeline (yesterday vs today), cost, limitations, appendices (tools, versions, timestamps). Label each statement: verified fact / heuristic / AI-generated.

---

## 6. Continuous monitoring: "Yesterday vs Today" (your signature demo)

**Mechanism**
1. Each scan saves a `ScanSnapshot` (SBOM hash, component list, vuln list with timestamps, image digests, lockfile hash, vuln DB versions).
2. Scheduler (cron/APScheduler/GitHub Actions locally) triggers rescans; incremental: only re-query components whose version or advisory-DB timestamp changed (cache hit otherwise).
3. `diff(snapshot_prev, snapshot_now)` returns: new/removed components, version changes, new advisories (with `published` dates), digest changes, new anomalies, score deltas.
4. Notification (dashboard banner + webhook/email stub) if band increases or KEV newly applies.
5. The chat/report answers: *"Was this app safe at previous scan, and what changed?"*, with citations to both snapshots.

**Demo without faking:** the app source is unchanged. Ensure Scan T0 occurred **before** an advisory was published or with an older vuln-DB snapshot (cache OSV responses at T0), then T1 uses the newer DB. If no suitable real new CVE exists, use a **clearly labeled simulation**: replay a snapshot with a controlled fixture advisory marked `SIMULATED`. Do not claim it's real. Also demonstrate a lockfile re-resolution (a caret range pulls a newer transitive version) and an image digest change in a local test registry.

**Acceptance:** diff output lists the exact changed advisory/component with both timestamps; no source-code diff yet posture changed.

---

## 7. Demo scenario (controlled, honest)

Use a local clone and **local fixtures only**. Nothing published to public registries.

| # | Scenario element | How (safe) |
|---|---|---|
| 1 | Vulnerable **direct** dependency | Pin a real older version with genuine OSV records |
| 2 | Vulnerable **transitive** dependency | Real tree path (show `root > A > B > vuln`) |
| 3 | Suspicious package/version change | Local-only fixture package (e.g. in a **local Verdaccio** registry or `file:` dependency) with a postinstall script that only writes a harmless marker file; labeled `SIMULATION`; plus a typosquat-style *name* added to package.json in a fixture branch (never installed from public registry) |
| 4 | Lockfile modification | Commit that edits `resolved` URL / `integrity` without changing package.json |
| 5 | Untrusted container | Dockerfile with `FROM node:latest` (unpinned), no signature; compare with pinned + Cosign-signed alternative |
| 6 | CI/CD issue | Workflow with action pinned to `@main`/tag, `curl | bash` step |
| 7 | Cross-app exposure | Register 2-3 apps (your demo app + second sample app + a tiny Python app) sharing a component; show the exposure map |

Use branches: `baseline` (clean-ish), `scenario/supply-chain-incident` (introduces 3-6). Git diff between them is the "what changed" evidence. Document every fixture in `docs/SIMULATIONS.md`.

---

## 8. Dashboard plan (Streamlit; build in this order)

**P0 pages (Day 1):** (1) Security Overview, (2) Software Inventory, (3) Interactive Dependency Graph, (4) Vulnerabilities, (5) Suspicious Changes, (6) Component Detail drawer, (7) Evidence/Report.
**P0 pages (Day 2):** (8) Risk Prioritization, (9) Remediation Approval Center, (10) Before/After Validation.
**P1:** (11) Reachability view, (12) Recent CVE monitoring + timeline ("yesterday vs today"), (13) Cross-application exposure, (14) Cost and Efficiency, (15) Chat assistant.

**Component Detail view must answer (from your prompt):** what is it, why included (path), introduced by, which apps use it, known vulns, what changed, risk + factors, evidence links, recommended action, validation status.

**Graph UX:** color by risk band; shape by direct/transitive; highlight selected path from root; filter (ecosystem, scope, band); click node > detail drawer. For large trees show only paths to risky nodes by default.

**Chat assistant:** RAG over the evidence store only; tool-calling functions like `get_findings(filter)`, `get_path(component)`, `diff_scans(a,b)`; refuse answers lacking evidence ("no evidence in scan data"); every answer cites finding/evidence IDs.

---

## 9. Policy-as-code (S5): quick wins
Rego rules evaluated by OPA/Conftest on the Guardian JSON/SBOM:
1. Deny: any **Critical/High reachable** vuln without an approved exception.
2. Deny: **KEV** vulnerability present.
3. Deny: lockfile missing or `resolved` host not in allowlist.
4. Deny: container `FROM` not pinned by digest / `:latest`.
5. Deny: GitHub Action not pinned to SHA.
6. Deny: install-script package not on allowlist.
7. Deny: remediation executed without `approval_id`.
Show a "policy gate failed > fix > policy gate passed" moment in the demo.

---

## 10. Cost, efficiency, sustainability module

**Measure (real, logged per scan):** wall-clock time per agent, scan time, time-to-prioritize, CPU-seconds, peak memory, cache hit rate, bytes stored, LLM input/output tokens and $ (from API usage), number of components analyzed, components skipped by incremental scan.
**Energy:** if available use `codecarbon`; otherwise report CPU-seconds and label energy as "not measured". Don't claim fewer deps = lower emissions.

**Cost model (transparent, editable `cost_assumptions.yaml`):**
```
cost_per_scan       = compute_cost + llm_cost + storage_cost
cost_per_component  = cost_per_scan / components_analyzed
manual_baseline     = components * minutes_per_component * hourly_rate   (ASSUMPTION, labeled)
hours_saved         = manual_hours - (automated_review_hours)
savings             = hours_saved * hourly_rate - guardian_cost
```
Compare: first full scan vs incremental rescan; manual vs automated. Label all assumptions as estimates; no breach-loss or guaranteed-savings claims. Show sensitivity (low/base/high assumptions).

---

## 11. Safety, security, and responsible AI

### 11.1 Controls to implement and show
- Read-only mount of target repo; all work in temp sandbox copies.
- Docker sandbox: non-root, dropped capabilities, CPU/mem/time limits, `--network none` during tests.
- Secret handling: `.env` not committed; secret scanner (Trivy secret / gitleaks) on repo; redact secrets before sending anything to the LLM; **no real credentials in the demo**.
- Send the LLM only metadata and minimal code snippets (not whole repo); log what was sent.
- Allowlist of outbound hosts (OSV, GHSA, NVD, CISA, FIRST EPSS, npm registry metadata, LLM API).
- Approval gate enforced in code and policy; append-only **audit log** (hash-chained).
- Tenant isolation: `tenant_id` on every row and query.

### 11.2 Boundary reminder
Registry/API lookups for public vulnerability/metadata are read-only and the standard way scanners work. Confirm with organizers that querying public advisory DBs and public npm metadata counts as "authorized." Don't touch anything else.

### 11.3 Responsible AI & Security Note (outline for the deliverable)
1. Where AI is used (explanation, narrative, drafting; not detection or decisions).
2. Hallucination control (structured evidence in; citation required; post-validation; "unknown" is an allowed answer).
3. Fact vs heuristic vs AI labels everywhere.
4. Human-approval points (remediation, risk acceptance, anything touching files).
5. Data protection (what leaves the machine, redaction).
6. Limitations (static reachability, heuristic anomalies, DB lag, false positives/negatives).
7. Misuse prevention (no exploit generation, no publishing, sandbox).

---

## 12. Scalability and reuse (show in architecture + one demo)
- Connector interface per ecosystem (`npm`, `pypi`, `container`, `ci`); adding one = implement `discover()`, `normalize()`.
- Standard formats: CycloneDX in, CycloneDX out; OSV schema for vulns.
- Multi-tenant data model and policies per tenant/business unit.
- Cross-app exposure: component-to-application index from SBOMs (purl > apps). Demo: a vulnerable shared component lights up 3 apps **using only SBOMs/repos you were given**, no access to other systems.
- Postgres migration path (SQLAlchemy models), job queue (RQ/Celery) as roadmap.

---

## 13. Repository structure
```
guardian/
  README.md  docs/ (ARCHITECTURE.md, SETUP.md, SOURCES.md, SIMULATIONS.md, LIMITATIONS.md, RESPONSIBLE_AI.md, COST.md, PROMPTS.md)
  schemas/            # JSON schemas / pydantic models
  guardian/
    orchestrator/     # state machine, approvals, audit
    agents/           # discovery.py vuln_intel.py anomaly.py reachability.py risk.py remediation.py validation.py reporting.py
    connectors/       # npm.py pypi.py docker.py ci.py
    intel/            # osv.py ghsa.py nvd.py kev.py epss.py cache.py
    graph/            # builder.py queries.py
    llm/              # client.py prompts/ guardrails.py
    store/            # models.py evidence.py
    policy/           # *.rego, risk_weights.yaml
    cost/             # meter.py assumptions.yaml
    chat/             # rag tools
  dashboard/          # streamlit app + pages/
  fixtures/           # scenario branches, local registry, fake advisories (labeled)
  scripts/            # run_scan.sh, rescan_cron.sh, demo_reset.sh
  tests/              # acceptance tests per agent
  docker/             # sandbox Dockerfile, compose (verdaccio, opa)
```

---

## 14. Time-boxed schedule

I don't know your exact hackathon hours, so this is by **blocks**. Scale to your real hours; Day 1 = visibility, Day 2 = remediation (per the Bosch slides). Today is Mon 23 Nov; confirm submission deadlines with the organizers.

### Block 0: Kickoff (about 1-2 h)
- Choose app, clone to isolated folder, record SHA/license. Install Docker, Trivy, Syft, Cosign, OPA, Python env. Verify the app builds/tests locally. Freeze data contracts (Sec 4). Assign owners. Create repo, CI for lint/tests.
- **Gate:** app builds and tests green; contracts agreed.

### Day 1: "Build the Guardian's Eyes" (target: Day 1 Checkpoint)
Checkpoint line: *"Show us what is in the application, what changed, and what appears risky."*

| Block | Work | Output |
|---|---|---|
| D1-A | Agent 1: parse lockfile, SBOM, graph, Dockerfile + CI discovery | `sbom.cdx.json`, graph JSON |
| D1-B | Agent 2: OSV + Trivy + KEV/EPSS, 90-day flag, caching | vuln findings with evidence |
| D1-C (parallel) | Agent 3: git-diff anomalies (lockfile, new dep, install script, typosquat, Docker) + scenario branch | anomaly report |
| D1-D | Skeleton orchestrator (parallel fan-out + evidence store) | one command runs A>B>C |
| D1-E | Dashboard P0 pages 1-7 incl. graph + component drawer | demoable UI |
| D1-F | Simple (formula) risk level + evidence view; write Day-1 demo script; rehearse | Day 1 demo |
- **Gate (must pass before Day 2):** repo > SBOM > graph > vulns > >=1 anomaly > evidence on screen; transitive path displayed.

### Day 2: Remediate, validate, deepen
| Block | Work |
|---|---|
| D2-A | Agent 6 proposals + patch branch generation |
| D2-B | Approval gate (UI + persistence + enforcement) |
| D2-C | Agent 7 sandbox validation + before/after diff + verdict logic |
| D2-D | Agent 4 reachability (simple) + Agent 5 full scoring + LLM narratives |
| D2-E | Agent 8 report (PDF/JSON/SBOM) |
| D2-F | Yesterday-vs-today snapshots/diff + scheduler |
| D2-G | OPA policy gate (Sec 9) |
| D2-H | Chat assistant, cross-app view, cost page (as time permits, in this order) |
| D2-I | Docs, Responsible AI note, architecture diagrams, deck, demo rehearsals x3, backup recording |
- **Feature freeze** at about 75% of Day 2 time. Remaining time = integration, bug fixes, docs, rehearsal.

### Cut list if behind schedule (cut in this order)
1. Multi-org tenancy UI (keep data column + slide)
2. Python ecosystem connector
3. Energy measurement (report CPU-seconds)
4. Maintainer-anomaly heuristics, dependency confusion
5. Cosign (keep as a single verify call on one image)
6. Chat assistant (keep a simple Q&A box on top of the findings JSON)
**Never cut:** SBOM, graph, one real vuln + transitive path, one anomaly, approval gate, validation with before/after, report, Responsible AI note.

---

## 15. Team roles (adjust to headcount; solo, do them in this order)
| Role | Owns |
|---|---|
| Lead/Orchestrator | contracts, orchestrator, audit log, integration, deck |
| Discovery + Graph | Agent 1, graph, SBOM, connectors |
| Intel + Risk | Agents 2 and 5, caching, scoring, cost metrics |
| Anomaly + Reachability | Agents 3 and 4, fixtures/scenario |
| Remediation + Validation | Agents 6 and 7, Docker sandbox, OPA |
| Frontend + Report | Streamlit, graph UI, Agent 8, chat, PDF |

---

## 16. Test and acceptance matrix
| Test | Pass condition |
|---|---|
| SBOM validity | validates vs CycloneDX schema; count matches `npm ls` |
| Path correctness | for 5 random components, shown path exists in lockfile |
| Vuln accuracy | 100% of reported findings have source URL + timestamp; version is in affected range |
| No fabrication | LLM output post-check finds zero IDs/versions absent from evidence |
| Anomaly recall | all planted fixtures detected; baseline false positives explained |
| Reachability | reachable vs present-only correct on 2 known cases |
| Risk determinism | same input > same score; weights configurable |
| Approval enforcement | validation call without approval ID is rejected (code + OPA) |
| Validation honesty | breaking patch > FAILED; good patch > SUCCESS; new vulns detected |
| Yesterday vs today | diff shows changed advisory with both timestamps, no source change |
| Safety | no network in test stage; no secrets in LLM payload logs; nothing pushed/merged |
| Report | PDF + JSON + SBOM generated and consistent |

---

## 17. Demo script (about 8-10 min; rehearse)
1. **Hook (30s):** "Your app was safe yesterday. Nobody touched the code. Is it safe today?"
2. **Discover:** point Guardian at the repo; SBOM and graph appear; show transitive path.
3. **Detect:** vulns with fix versions + 90-day badge; anomaly panel (lockfile, install script, unpinned image) each with evidence.
4. **Yesterday vs today:** snapshot diff shows what changed and why risk rose.
5. **Prioritize:** ranked register; click top item > factor breakdown + reachability evidence + "why first".
6. **Remediate:** proposed patch, regression risk, rollback.
7. **Approve:** human clicks Approve (audit record appears).
8. **Validate:** sandbox build/tests/rescan > before/after, no new vulns > SUCCESS. Show one rejected/failed case for honesty.
9. **Policy gate:** red > green.
10. **Cross-app + cost:** shared component affects 3 apps; cost per scan/component and hours saved (labeled estimates).
11. **Report + Responsible AI:** open PDF, mention limitations.
12. **Close:** tagline. Keep a **pre-recorded backup** and cached API responses in case of Wi-Fi failure.

---

## 18. Risks and mitigations
| Risk | Mitigation |
|---|---|
| API rate limits / no Wi-Fi | cache OSV/NVD/KEV/EPSS responses; offline demo mode |
| Slow builds kill validation | choose a fast app; pre-warm Docker layers/npm cache |
| Scope creep (the 14-page vision) | strict P0/P1/P2, feature freeze, cut list |
| LLM hallucination | evidence-only inputs, post-validation, deterministic scoring |
| Few real recent CVEs | cached DB snapshot at T0 + clearly labeled simulation |
| False positives in anomalies | confidence levels + "investigate" wording |
| Breaking Bosch rules | guardrails coded in; all fixtures local; nothing published |
| Integration chaos | contracts frozen early; integrate continuously, not at the end |

---

## 19. Final submission checklist
- [ ] Repo + README + setup (works from clean clone in <10 commands)
- [ ] Architecture diagram + agent orchestration diagram (agents, tools, data sources, AI interactions, approval points, evidence storage)
- [ ] SBOM (before/after), dependency graph export
- [ ] Guardian Report: PDF + JSON
- [ ] Prompts file, sample OPA policies, config, known limitations
- [ ] SOURCES.md (app, commit SHA, license, every tool/version/dataset) + SIMULATIONS.md
- [ ] Cost and efficiency analysis with assumptions labeled
- [ ] Responsible AI & Security Note
- [ ] Demo video backup + deck (problem > solution > demo > innovation (stretch goals) > roadmap)
- [ ] Confirmation that no Bosch out-of-scope action was performed

---

## 20. Next 5 actions (do right now)
1. Pick and clone the demo app; confirm build + tests locally.
2. Install Trivy, Syft, Cosign, OPA, Docker; test each once.
3. Write the JSON contracts (Sec 4) and repo skeleton (Sec 13).
4. Get Agent 1 producing an SBOM + graph from the lockfile.
5. Query OSV for those purls and print a first findings table.

*Core capabilities demonstrate completeness. Stretch goals demonstrate innovation.*
