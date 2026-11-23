# Guardian evidence report: juice-shop

*Scanned 2026-11-23T11:50:20+00:00 with sscg 0.1.0*

**Repository → SBOM → Dependency graph → Risk detection → Evidence** ✔

## 1. What is in the application

| | |
|---|---|
| Components | 1790 (github-actions 25, url 3, docker 8, npm 1754) |
| Libraries | 1754: 155 direct, 1599 transitive, max depth 9 |
| Container images | 8: node:24, gcr.io/distroless/nodejs24-debian13:latest, nginx:1.28.0-alpine, redis:7.4.4-alpine, mongo:4.4.29, node:20.19.2-bookworm-slim, node:20.19.2-bookworm, alpine:latest |
| CI/CD | 16 workflow(s), 25 distinct actions |
| SBOM | `sbom.cdx.json` (CycloneDX 1.5, 1813 components) |

## 2. What changed

Not analysed (no base commit available, e.g. a shallow clone). See notes.

## 3. What appears risky

**83 findings**: 55 vulnerable components (139 advisories) and 28 supply-chain anomalies.

| Level | Critical | High | Medium | Low | Info |
|---|---|---|---|---|---|
| Findings | 7 | 29 | 27 | 20 | 0 |

*Initial risk = Guardian initial risk (heuristic, 0-10); not a CVSS score. Official severity is shown separately for vulnerabilities.*

| ID | Risk | Type | Finding | Location | New |
|---|---|---|---|---|---|
| F-001 | 🟥 Critical (9.8) | Vulnerable transitive dependency | handlebars@4.7.7: 11 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package.json` |  |
| F-002 | 🟥 Critical (9.8) | Vulnerable direct dependency | sequelize@6.37.3: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package.json` |  |
| F-003 | 🟥 Critical (9.5) | Unsafe CI/CD component | .github/workflows/ci.yml: secret(s) GITHUB_TOKEN are passed to the unpinned action 'coverallsapp/github-action@v2' | `.github/workflows/ci.yml:200` |  |
| F-004 | 🟥 Critical (9.5) | Unsafe CI/CD component | .github/workflows/image_actions.yml: secret(s) GITHUB_TOKEN are passed to the unpinned action 'calibreapp/image-actions@main' | `.github/workflows/image_actions.yml:35` |  |
| F-005 | 🟥 Critical (9.5) | Vulnerable direct dependency | marsdb@0.6.11: 1 known vulnerability (highest CRITICAL) | `package.json` |  |
| F-006 | 🟥 Critical (9.1) | Vulnerable transitive dependency | crypto-js@3.3.0: 2 known vulnerabilities (highest CRITICAL, CVSS 9.1) | `package.json` |  |
| F-007 | 🟥 Critical (9.1) | Vulnerable transitive dependency | lodash@2.4.2: 4 known vulnerabilities (highest CRITICAL, CVSS 9.1) | `package.json` |  |
| F-008 | 🟧 High (8.8) | Vulnerable transitive dependency | tar@6.2.1: 12 known vulnerabilities (highest HIGH, CVSS 8.8) | `package.json` |  |
| F-009 | 🟧 High (8.7) | Vulnerable transitive dependency | jws@0.2.6: 2 known vulnerabilities (highest HIGH, CVSS 8.7) | `package.json` |  |
| F-010 | 🟧 High (8.6) | Vulnerable transitive dependency | @modelcontextprotocol/sdk@1.29.0: 6 known vulnerabilities (highest HIGH, CVSS 8.6) | `frontend/package.json` |  |
| F-011 | 🟧 High (8.1) | Vulnerable transitive dependency | ip@2.0.1: 1 known vulnerability (highest HIGH, CVSS 8.1) | `package.json` |  |
| F-012 | 🟧 High (8.1) | Vulnerable transitive dependency | jsonwebtoken@0.1.0: 4 known vulnerabilities (highest CRITICAL, CVSS 8.1) | `package.json` |  |
| F-013 | 🟧 High (8.1) | Vulnerable direct dependency | jsonwebtoken@0.4.0: 4 known vulnerabilities (highest CRITICAL, CVSS 8.1) | `package.json` |  |
| F-014 | 🟧 High (8.1) | Vulnerable transitive dependency | libxmljs2@0.35.0: 1 known vulnerability (highest HIGH, CVSS 8.1) | `package.json` |  |
| F-015 | 🟧 High (8.1) | Vulnerable direct dependency | lodash-es@4.17.21: 2 known vulnerabilities (highest HIGH, CVSS 8.1) | `frontend/package.json` |  |
| F-016 | 🟧 High (8.1) | Vulnerable transitive dependency | piscina@5.1.4: 2 known vulnerabilities (highest CRITICAL, CVSS 8.1) | `frontend/package.json` |  |
| F-017 | 🟧 High (8.0) | Unsafe install script | .github/workflows/ci.yml: job 'heroku' downloads a script and pipes it into a shell | `.github/workflows/ci.yml:353` |  |
| F-018 | 🟧 High (8.0) | Unsafe CI/CD component | .github/workflows/ci.yml: third-party action 'coverallsapp/github-action@v2' is not pinned to a commit SHA | `.github/workflows/ci.yml:198` |  |
| F-019 | 🟧 High (8.0) | Unsafe CI/CD component | .github/workflows/image_actions.yml: third-party action 'calibreapp/image-actions@main' is not pinned to a commit SHA | `.github/workflows/image_actions.yml:33` |  |
| F-020 | 🟧 High (8.0) | Unsafe CI/CD component | .github/workflows/image_actions.yml: third-party action 'peter-evans/create-pull-request@v8' is not pinned to a commit SHA | `.github/workflows/image_actions.yml:42` |  |
| F-021 | 🟧 High (8.0) | Vulnerable direct dependency | @angular/router@22.0.1: 3 known vulnerabilities (highest HIGH) | `frontend/package.json` |  |
| F-022 | 🟧 High (8.0) | Vulnerable direct dependency | @cyclonedx/cyclonedx-npm@2.0.0: 1 known vulnerability (highest HIGH) | `package.json` |  |
| F-023 | 🟧 High (8.0) | Vulnerable transitive dependency | vite@7.3.2: 7 known vulnerabilities (highest HIGH) | `frontend/package.json` |  |
| F-024 | 🟧 High (7.7) | Vulnerable direct dependency | express-jwt@0.1.3: 1 known vulnerability (highest HIGH, CVSS 7.7) | `package.json` |  |
| F-025 | 🟧 High (7.5) | Vulnerable direct dependency | compression@1.8.1: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package.json` |  |
| F-026 | 🟧 High (7.5) | Vulnerable direct dependency | js-yaml@3.14.0: 5 known vulnerabilities (highest HIGH, CVSS 7.5) | `package.json` |  |
| F-027 | 🟧 High (7.5) | Vulnerable transitive dependency | js-yaml@3.14.1: 5 known vulnerabilities (highest HIGH, CVSS 7.5) | `package.json` |  |
| F-028 | 🟧 High (7.5) | Vulnerable transitive dependency | moment@2.0.0: 3 known vulnerabilities (highest HIGH, CVSS 7.5) | `package.json` |  |
| F-029 | 🟧 High (7.5) | Vulnerable direct dependency | multer@2.4.0: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package.json` |  |
| F-030 | 🟧 High (7.5) | Vulnerable transitive dependency | pacote@21.5.0: 1 known vulnerability (highest HIGH, CVSS 7.5) | `frontend/package.json` |  |
| F-031 | 🟧 High (7.5) | Vulnerable direct dependency | sanitize-html@1.4.2: 10 known vulnerabilities (highest HIGH, CVSS 7.5) | `package.json` |  |
| F-032 | 🟧 High (7.5) | Vulnerable transitive dependency | uuid@8.3.2: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package.json` |  |
| F-033 | 🟧 High (7.5) | Vulnerable transitive dependency | ws@7.4.6: 2 known vulnerabilities (highest HIGH, CVSS 7.5) | `frontend/package.json` |  |
| F-034 | 🟧 High (7.5) | Vulnerable transitive dependency | ws@8.17.1: 2 known vulnerabilities (highest HIGH, CVSS 7.5) | `package.json` |  |
| F-035 | 🟧 High (7.5) | Vulnerable transitive dependency | zod@4.4.2: 1 known vulnerability (highest HIGH, CVSS 7.5) | `frontend/package.json` |  |
| F-036 | 🟧 High (7.5) | Vulnerable direct dependency | zod@4.4.3: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package.json` |  |
| F-037 | 🟨 Medium (6.5) | Vulnerable direct dependency | notevil@1.3.3: 1 known vulnerability (highest MEDIUM, CVSS 6.5) | `package.json` |  |
| F-038 | 🟨 Medium (5.9) | Vulnerable transitive dependency | @vitest/mocker@4.1.1: 2 known vulnerabilities (highest MEDIUM, CVSS 5.9) | `frontend/package.json` |  |
| F-039 | 🟨 Medium (5.9) | Vulnerable transitive dependency | basic-ftp@5.3.1: 3 known vulnerabilities (highest HIGH, CVSS 5.9) | `package.json` |  |
| F-040 | 🟨 Medium (5.9) | Vulnerable direct dependency | vitest@4.1.1: 1 known vulnerability (highest MEDIUM, CVSS 5.9) | `frontend/package.json` |  |
| F-041 | 🟨 Medium (5.6) | Vulnerable transitive dependency | elliptic@6.5.4: 7 known vulnerabilities (highest CRITICAL, CVSS 5.6) | `frontend/package.json` |  |
| F-042 | 🟨 Medium (5.5) | Untrusted image | Dockerfile runs 'npm install' with install scripts enabled | `Dockerfile:4` |  |
| F-043 | 🟨 Medium (5.5) | Untrusted image | Dockerfile runs 'npm install' with install scripts enabled | `Dockerfile:5` |  |
| F-044 | 🟨 Medium (5.5) | Untrusted image | Dockerfile runs 'npm install' with install scripts enabled | `Dockerfile:19` |  |
| F-045 | 🟨 Medium (5.5) | Suspicious package update | frontend/package.json has no lockfile: 61 dependencies use version ranges | `frontend/package.json` |  |
| F-046 | 🟨 Medium (5.5) | Untrusted image | image alpine:latest uses a mutable tag and no digest | `test/smoke/Dockerfile:1` |  |
| F-047 | 🟨 Medium (5.5) | Untrusted image | image gcr.io/distroless/nodejs24-debian13:latest uses a mutable tag and no digest | `Dockerfile:22` |  |
| F-048 | 🟨 Medium (5.5) | Unsafe install script | juice-shop@20.4.0-SNAPSHOT runs a 'postinstall' script on every install: cd frontend && npm install && cd .. && npm run build:frontend && (npm run --silent build:server // cd .) | `package.json:56` |  |
| F-049 | 🟨 Medium (5.5) | Suspicious package update | package.json has no lockfile: 95 dependencies use version ranges | `package.json` |  |
| F-050 | 🟨 Medium (5.5) | Vulnerable direct dependency | @angular/compiler@22.0.1: 1 known vulnerability (highest MEDIUM) | `frontend/package.json` |  |
| F-051 | 🟨 Medium (5.5) | Vulnerable direct dependency | @angular/core@22.0.1: 1 known vulnerability (highest MEDIUM) | `frontend/package.json` |  |
| F-052 | 🟨 Medium (5.5) | Vulnerable transitive dependency | base64url@0.0.6: 1 known vulnerability (highest MEDIUM) | `package.json` |  |
| F-053 | 🟨 Medium (5.5) | Vulnerable transitive dependency | glob@10.5.0: 1 known vulnerability (highest MEDIUM) | `package.json` |  |
| F-054 | 🟨 Medium (5.5) | Vulnerable transitive dependency | glob@13.0.7: 1 known vulnerability (highest MEDIUM) | `frontend/package.json` |  |
| F-055 | 🟨 Medium (5.5) | Vulnerable transitive dependency | minimatch@10.2.6: 1 known vulnerability (highest MEDIUM) | `frontend/package.json` |  |
| F-056 | 🟨 Medium (5.5) | Vulnerable transitive dependency | minimatch@9.0.9: 1 known vulnerability (highest MEDIUM) | `frontend/package.json` |  |
| F-057 | 🟨 Medium (5.3) | Vulnerable transitive dependency | @hono/node-server@1.19.18: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `frontend/package.json` |  |
| F-058 | 🟨 Medium (5.3) | Vulnerable direct dependency | file-type@16.5.4: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package.json` |  |
| F-059 | 🟨 Medium (5.3) | Vulnerable direct dependency | morgan@1.10.0: 3 known vulnerabilities (highest MEDIUM, CVSS 5.3) | `package.json` |  |
| F-060 | 🟨 Medium (5.3) | Vulnerable transitive dependency | qs@6.14.3: 4 known vulnerabilities (highest MEDIUM, CVSS 5.3) | `package.json` |  |
| F-061 | 🟨 Medium (4.3) | Vulnerable transitive dependency | @ai-sdk/provider-utils@4.0.19: 1 known vulnerability (highest MEDIUM, CVSS 4.3) | `package.json` |  |
| F-062 | 🟨 Medium (4.0) | Vulnerable direct dependency | @angular/common@22.0.1: 2 known vulnerabilities (highest HIGH, CVSS 4.0) | `frontend/package.json` |  |
| F-063 | 🟨 Medium (4.0) | Vulnerable direct dependency | hbs@4.2.0: 1 known vulnerability (highest MEDIUM, CVSS 4.0) | `package.json` |  |
| F-064 | 🟦 Low (3.4) | Vulnerable transitive dependency | on-headers@1.0.2: 1 known vulnerability (highest LOW, CVSS 3.4) | `package.json` |  |
| F-065 | 🟦 Low (3.3) | Vulnerable transitive dependency | @tootallnate/once@1.1.2: 1 known vulnerability (highest LOW, CVSS 3.3) | `package.json` |  |
| F-066 | 🟦 Low (3.2) | Vulnerable transitive dependency | @babel/core@7.29.0: 1 known vulnerability (highest LOW, CVSS 3.2) | `frontend/package.json` |  |
| F-067 | 🟦 Low (3.0) | Unsafe CI/CD component | .github/workflows/ci.yml: no top-level 'permissions:' (token gets the repository default, often read/write) | `.github/workflows/ci.yml` |  |
| F-068 | 🟦 Low (3.0) | Unsafe CI/CD component | .github/workflows/codeql-analysis.yml: no top-level 'permissions:' (token gets the repository default, often read/write) | `.github/workflows/codeql-analysis.yml` |  |
| F-069 | 🟦 Low (3.0) | Unsafe CI/CD component | .github/workflows/frontend-bundle-analysis.yml: no top-level 'permissions:' (token gets the repository default, often read/write) | `.github/workflows/frontend-bundle-analysis.yml` |  |
| F-070 | 🟦 Low (3.0) | Unsafe CI/CD component | .github/workflows/image_actions.yml: no top-level 'permissions:' (token gets the repository default, often read/write) | `.github/workflows/image_actions.yml` |  |
| F-071 | 🟦 Low (3.0) | Unsafe CI/CD component | .github/workflows/lint-fixer.yml: no top-level 'permissions:' (token gets the repository default, often read/write) | `.github/workflows/lint-fixer.yml` |  |
| F-072 | 🟦 Low (3.0) | Unsafe CI/CD component | .github/workflows/rebase.yml: no top-level 'permissions:' (token gets the repository default, often read/write) | `.github/workflows/rebase.yml` |  |
| F-073 | 🟦 Low (3.0) | Unsafe CI/CD component | .github/workflows/release.yml: no top-level 'permissions:' (token gets the repository default, often read/write) | `.github/workflows/release.yml` |  |
| F-074 | 🟦 Low (3.0) | Unsafe CI/CD component | .github/workflows/stale.yml: no top-level 'permissions:' (token gets the repository default, often read/write) | `.github/workflows/stale.yml` |  |
| F-075 | 🟦 Low (3.0) | Unsafe CI/CD component | .github/workflows/update-challenges-ebook.yml: no top-level 'permissions:' (token gets the repository default, often read/write) | `.github/workflows/update-challenges-ebook.yml` |  |
| F-076 | 🟦 Low (3.0) | Unsafe CI/CD component | .github/workflows/update-challenges-www-legacy.yml: no top-level 'permissions:' (token gets the repository default, often read/write) | `.github/workflows/update-challenges-www-legacy.yml` |  |
| F-077 | 🟦 Low (3.0) | Unsafe CI/CD component | .github/workflows/update-challenges-www.yml: no top-level 'permissions:' (token gets the repository default, often read/write) | `.github/workflows/update-challenges-www.yml` |  |
| F-078 | 🟦 Low (3.0) | Unsafe CI/CD component | .github/workflows/update-news-www-legacy.yml: no top-level 'permissions:' (token gets the repository default, often read/write) | `.github/workflows/update-news-www-legacy.yml` |  |
| F-079 | 🟦 Low (3.0) | Unsafe CI/CD component | .github/workflows/update-news-www.yml: no top-level 'permissions:' (token gets the repository default, often read/write) | `.github/workflows/update-news-www.yml` |  |
| F-080 | 🟦 Low (3.0) | Untrusted image | test/smoke/Dockerfile sets no USER: the container runs as the base image's default user (usually root) | `test/smoke/Dockerfile` |  |
| F-081 | 🟦 Low (3.0) | Vulnerable transitive dependency | messageformat@2.3.0: 1 known vulnerability (highest LOW) | `package.json` |  |
| F-082 | 🟦 Low (2.5) | Vulnerable transitive dependency | esbuild@0.27.7: 1 known vulnerability (highest LOW, CVSS 2.5) | `frontend/package.json` |  |
| F-083 | 🟦 Low (2.5) | Vulnerable transitive dependency | esbuild@0.28.0: 1 known vulnerability (highest LOW, CVSS 2.5) | `frontend/package.json` |  |

## 4. Evidence per finding

### F-001 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** handlebars@4.7.7: 11 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `handlebars@4.7.7` (npm, scope prod, transitive), purl `pkg:npm/handlebars@4.7.7`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → hbs@4.2.0 → handlebars@4.7.7
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 4.7.10
- **Evidence:**
  - [GHSA-2w6w-674q-4c4q](https://osv.dev/vulnerability/GHSA-2w6w-674q-4c4q) (CVE-2026-33937): CRITICAL, CVSS 9.8, fixed in 4.7.9. Handlebars.js has JavaScript Injection via AST Type Confusion
  - [GHSA-8r5x-fm3f-whwj](https://osv.dev/vulnerability/GHSA-8r5x-fm3f-whwj) (CVE-2026-106446): CRITICAL, CVSS 9.8, fixed in 4.7.10. Handlebars: JavaScript Injection via AST Type Confusion in compile (bypass of CVE-2026-33937)
  - [GHSA-p8wg-vrv2-v86f](https://osv.dev/vulnerability/GHSA-p8wg-vrv2-v86f) (CVE-2026-106445): CRITICAL, fixed in 4.7.10. Handlebars: JavaScript Injection via Own Property Check Bypass
  - [GHSA-xjpj-3mr7-gcpf](https://osv.dev/vulnerability/GHSA-xjpj-3mr7-gcpf) (CVE-2026-33941): HIGH, CVSS 8.2, fixed in 4.7.9. Handlebars.js has JavaScript Injection in CLI Precompiler via Unescaped Names and Options
  - [GHSA-3mfm-83xf-c92r](https://osv.dev/vulnerability/GHSA-3mfm-83xf-c92r) (CVE-2026-33938): HIGH, CVSS 8.1, fixed in 4.7.9. Handlebars.js has JavaScript Injection via AST Type Confusion by tampering @partial-block
  - [GHSA-xhpv-hc6g-r9c6](https://osv.dev/vulnerability/GHSA-xhpv-hc6g-r9c6) (CVE-2026-33940): HIGH, CVSS 8.1, fixed in 4.7.9. Handlebars.js has JavaScript Injection via AST Type Confusion when passing an object as dynamic partial
  - [GHSA-9cx6-37pm-9jff](https://osv.dev/vulnerability/GHSA-9cx6-37pm-9jff) (CVE-2026-33939): HIGH, CVSS 7.5, fixed in 4.7.9. Handlebars.js has Denial of Service via Malformed Decorator Syntax in Template Compilation
  - [GHSA-7rx3-28cr-v5wh](https://osv.dev/vulnerability/GHSA-7rx3-28cr-v5wh): MEDIUM, CVSS 4.8, fixed in 4.7.9. Handlebars.js has a Prototype Method Access Control Gap via Missing __lookupSetter__ Blocklist Entry
  - [GHSA-2qvq-rjwj-gvw9](https://osv.dev/vulnerability/GHSA-2qvq-rjwj-gvw9) (CVE-2026-33916): MEDIUM, CVSS 4.7, fixed in 4.7.9. Handlebars.js has Prototype Pollution Leading to XSS through Partial Template Injection
  - [GHSA-xw65-4hp5-5hc7](https://osv.dev/vulnerability/GHSA-xw65-4hp5-5hc7) (CVE-2026-106444): MEDIUM, CVSS 4.7, fixed in 4.7.10. Handlebars: JavaScript Injection via Unsafe Inline Embedding of Precompiled Templates
  - [GHSA-442j-39wm-28r2](https://osv.dev/vulnerability/GHSA-442j-39wm-28r2): LOW, CVSS 3.7, fixed in 4.7.9. Handlebars.js has a Property Access Validation Bypass in container.lookup
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-002 · 🟥 Critical (9.8) · Vulnerable direct dependency

- **What:** sequelize@6.37.3: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `sequelize@6.37.3` (npm, scope prod, direct), purl `pkg:npm/sequelize@6.37.3`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → sequelize@6.37.3
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 6.37.8
- **Evidence:**
  - [GHSA-v8fg-2rw7-q452](https://osv.dev/vulnerability/GHSA-v8fg-2rw7-q452) (CVE-2026-69240): CRITICAL, CVSS 9.8, fixed in 6.37.4. Sequelize: SQL Injection (Oracle DB)
  - [GHSA-6457-6jrx-69cr](https://osv.dev/vulnerability/GHSA-6457-6jrx-69cr) (CVE-2026-30951): HIGH, CVSS 7.5, fixed in 6.37.8. Sequelize v6 Vulnerable to SQL Injection via JSON Column Cast Type
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-003 · 🟥 Critical (9.5) · Unsafe CI/CD component

- **What:** .github/workflows/ci.yml: secret(s) GITHUB_TOKEN are passed to the unpinned action 'coverallsapp/github-action@v2'
- **Where:** `.github/workflows/ci.yml:200`
- **Evidence:**
  - `.github/workflows/ci.yml:200`: `github-token: ${{ secrets.GITHUB_TOKEN }}`
- **Initial risk:** Critical (9.5): R17_CI_SECRET_EXPOSURE default level Critical
- **Why it matters:** A secret is handed to code that was downloaded at run time or comes from a mutable third-party action.
- **Basis:** verified fact, confidence high

### F-004 · 🟥 Critical (9.5) · Unsafe CI/CD component

- **What:** .github/workflows/image_actions.yml: secret(s) GITHUB_TOKEN are passed to the unpinned action 'calibreapp/image-actions@main'
- **Where:** `.github/workflows/image_actions.yml:35`
- **Evidence:**
  - `.github/workflows/image_actions.yml:35`: `githubToken: ${{ secrets.GITHUB_TOKEN }}`
- **Initial risk:** Critical (9.5): R17_CI_SECRET_EXPOSURE default level Critical
- **Why it matters:** A secret is handed to code that was downloaded at run time or comes from a mutable third-party action.
- **Basis:** verified fact, confidence high

### F-005 · 🟥 Critical (9.5) · Vulnerable direct dependency

- **What:** marsdb@0.6.11: 1 known vulnerability (highest CRITICAL)
- **Component:** `marsdb@0.6.11` (npm, scope prod, direct), purl `pkg:npm/marsdb@0.6.11`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → marsdb@0.6.11
- **Official severity:** CRITICAL (advisory severity label (OSV))
- **Fix available:** no fixed version published
- **Evidence:**
  - [GHSA-5mrr-rgp6-x4gr](https://osv.dev/vulnerability/GHSA-5mrr-rgp6-x4gr): CRITICAL, no fix published. Command Injection in marsdb
- **Initial risk:** Critical (9.5): highest advisory severity CRITICAL; 1 advisory(ies) without a published fix; version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-006 · 🟥 Critical (9.1) · Vulnerable transitive dependency

- **What:** crypto-js@3.3.0: 2 known vulnerabilities (highest CRITICAL, CVSS 9.1)
- **Component:** `crypto-js@3.3.0` (npm, scope prod, transitive), purl `pkg:npm/crypto-js@3.3.0`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → pdfkit@0.11.0 → crypto-js@3.3.0
- **Official severity:** CRITICAL, CVSS 9.1 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 4.2.0
- **Evidence:**
  - [GHSA-xwcq-pm8m-c4vf](https://osv.dev/vulnerability/GHSA-xwcq-pm8m-c4vf) (CVE-2023-46233): CRITICAL, CVSS 9.1, fixed in 4.2.0. crypto-js PBKDF2 1,000 times weaker than specified in 1993 and 1.3M times weaker than current standard
  - [GHSA-rg76-677x-56q9](https://osv.dev/vulnerability/GHSA-rg76-677x-56q9) (CVE-2026-71851): CRITICAL, CVSS 9.0, fixed in 4.0.0. crypto-js: Insufficient Entropy in Cryptographic Secret Generation via Vulnerable CryptoJS Dependency Chain
- **Initial risk:** Critical (9.1): highest advisory severity CRITICAL (CVSS 9.1); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-007 · 🟥 Critical (9.1) · Vulnerable transitive dependency

- **What:** lodash@2.4.2: 4 known vulnerabilities (highest CRITICAL, CVSS 9.1)
- **Component:** `lodash@2.4.2` (npm, scope prod, transitive), purl `pkg:npm/lodash@2.4.2`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → sanitize-html@1.4.2 → lodash@2.4.2
- **Official severity:** CRITICAL, CVSS 9.1 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 4.17.21
- **Evidence:**
  - [GHSA-jf85-cpcp-j695](https://osv.dev/vulnerability/GHSA-jf85-cpcp-j695) (CVE-2019-10744): CRITICAL, CVSS 9.1, fixed in 4.17.12. Prototype Pollution in lodash
  - [GHSA-4xc9-xhrj-v574](https://osv.dev/vulnerability/GHSA-4xc9-xhrj-v574) (CVE-2018-16487): HIGH, fixed in 4.17.11. Prototype Pollution in lodash
  - [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) (CVE-2021-23337): HIGH, CVSS 7.2, fixed in 4.17.21. Command Injection in lodash
  - [GHSA-fvqr-27wr-82fm](https://osv.dev/vulnerability/GHSA-fvqr-27wr-82fm) (CVE-2018-3721): MEDIUM, CVSS 6.5, fixed in 4.17.5. Prototype Pollution in lodash
- **Initial risk:** Critical (9.1): highest advisory severity CRITICAL (CVSS 9.1); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-008 · 🟧 High (8.8) · Vulnerable transitive dependency

- **What:** tar@6.2.1: 12 known vulnerabilities (highest HIGH, CVSS 8.8)
- **Component:** `tar@6.2.1` (npm, scope prod, transitive), purl `pkg:npm/tar@6.2.1`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → sqlite3@5.1.7 → tar@6.2.1 ; juice-shop@20.4.0-SNAPSHOT → sqlite3@5.1.7 → node-gyp@8.4.1 → tar@6.2.1 ; juice-shop@20.4.0-SNAPSHOT → @cyclonedx/cyclonedx-npm@2.0.0 → @cyclonedx/cyclonedx-library@7.1.0 → libxmljs2@0.35.0 → node-gyp@10.3.1 → tar@6.2.1
- **Official severity:** HIGH, CVSS 8.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 7.5.21
- **Evidence:**
  - [GHSA-r6q2-hw4h-h46w](https://osv.dev/vulnerability/GHSA-r6q2-hw4h-h46w) (CVE-2026-23950): HIGH, CVSS 8.8, fixed in 7.5.4. Race Condition in node-tar Path Reservations via Unicode Ligature Collisions on macOS APFS
  - [GHSA-34x7-hfp2-rc4v](https://osv.dev/vulnerability/GHSA-34x7-hfp2-rc4v) (CVE-2026-24842): HIGH, CVSS 8.2, fixed in 7.5.7. node-tar Vulnerable to Arbitrary File Creation/Overwrite via Hardlink Path Traversal
  - [GHSA-8qq5-rm4j-mr97](https://osv.dev/vulnerability/GHSA-8qq5-rm4j-mr97) (CVE-2026-23745): HIGH, fixed in 7.5.3. node-tar is Vulnerable to Arbitrary File Overwrite and Symlink Poisoning via Insufficient Path Sanitization
  - [GHSA-9ppj-qmqm-q256](https://osv.dev/vulnerability/GHSA-9ppj-qmqm-q256) (CVE-2026-31802): HIGH, fixed in 7.5.11. node-tar Symlink Path Traversal via Drive-Relative Linkpath
  - [GHSA-qffp-2rhf-9h96](https://osv.dev/vulnerability/GHSA-qffp-2rhf-9h96) (CVE-2026-29786): HIGH, fixed in 7.5.10. tar has Hardlink Path Traversal via Drive-Relative Linkpath
  - [GHSA-23hp-3jrh-7fpw](https://osv.dev/vulnerability/GHSA-23hp-3jrh-7fpw) (CVE-2026-59873): HIGH, CVSS 7.5, fixed in 7.5.19. node-tar: Decompression/parse DoS via unlimited input
  - [GHSA-8x88-c5mf-7j5w](https://osv.dev/vulnerability/GHSA-8x88-c5mf-7j5w) (CVE-2026-59874): HIGH, CVSS 7.5, fixed in 7.5.18. node-tar: Negative tar entry size causes infinite loop in archive replace
  - [GHSA-r292-9mhp-454m](https://osv.dev/vulnerability/GHSA-r292-9mhp-454m) (CVE-2026-73566): HIGH, CVSS 7.5, fixed in 7.5.21. node-tar: Uncontrolled recursion in mapHas/filesFilter allows uncatchable stack-overflow DoS via crafted long-path tar with member selection
  - [GHSA-83g3-92jg-28cx](https://osv.dev/vulnerability/GHSA-83g3-92jg-28cx) (CVE-2026-26960): HIGH, CVSS 7.1, fixed in 7.5.8. Arbitrary File Read/Write via Hardlink Target Escape Through Symlink Chain in node-tar Extraction
  - [GHSA-vmf3-w455-68vh](https://osv.dev/vulnerability/GHSA-vmf3-w455-68vh) (CVE-2026-53655): MEDIUM, fixed in 7.5.16. node-tar applies PAX size override to intermediary GNU long-name/long-link headers, causing tar parser interpretation differential (file smuggling)
  - [GHSA-gvwx-54wh-qm9j](https://osv.dev/vulnerability/GHSA-gvwx-54wh-qm9j) (CVE-2026-59875): MEDIUM, CVSS 5.3, fixed in 7.5.17. node-tar: Uncaught Exception DoS via NUL byte in PAX path/linkpath records
  - [GHSA-w8wr-v893-vjvp](https://osv.dev/vulnerability/GHSA-w8wr-v893-vjvp) (CVE-2026-59871): MEDIUM, CVSS 5.3, fixed in 7.5.18. node-tar: Process crash via PAX numeric path type confusion
- **Initial risk:** High (8.8): highest advisory severity HIGH (CVSS 8.8); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-009 · 🟧 High (8.7) · Vulnerable transitive dependency

- **What:** jws@0.2.6: 2 known vulnerabilities (highest HIGH, CVSS 8.7)
- **Component:** `jws@0.2.6` (npm, scope prod, transitive), purl `pkg:npm/jws@0.2.6`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → jsonwebtoken@0.4.0 → jws@0.2.6 ; juice-shop@20.4.0-SNAPSHOT → express-jwt@0.1.3 → jsonwebtoken@0.1.0 → jws@0.2.6
- **Official severity:** HIGH, CVSS 8.7 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 3.2.3
- **Evidence:**
  - [GHSA-gjcw-v447-2w7q](https://osv.dev/vulnerability/GHSA-gjcw-v447-2w7q) (CVE-2016-1000223): HIGH, CVSS 8.7, fixed in 3.0.0. Forgeable Public/Private Tokens in jws
  - [GHSA-869p-cjfg-cm3x](https://osv.dev/vulnerability/GHSA-869p-cjfg-cm3x) (CVE-2025-65945): HIGH, CVSS 7.5, fixed in 3.2.3. auth0/node-jws Improperly Verifies HMAC Signature
- **Initial risk:** High (8.7): highest advisory severity HIGH (CVSS 8.7); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-010 · 🟧 High (8.6) · Vulnerable transitive dependency

- **What:** @modelcontextprotocol/sdk@1.29.0: 6 known vulnerabilities (highest HIGH, CVSS 8.6)
- **Component:** `@modelcontextprotocol/sdk@1.29.0` (npm, scope prod, transitive), purl `pkg:npm/%40modelcontextprotocol/sdk@1.29.0`
- **Where:** `frontend/package.json`
- **Dependency path:** frontend@20.4.0-SNAPSHOT → @angular/cli@22.0.1 → @modelcontextprotocol/sdk@1.29.0
- **Official severity:** HIGH, CVSS 8.6 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.32.0
- **Evidence:**
  - [GHSA-22jm-h49p-29qw](https://osv.dev/vulnerability/GHSA-22jm-h49p-29qw) (CVE-2026-111767): HIGH, CVSS 8.6, fixed in 1.32.0. MCP TypeScript SDK: Experimental tasks were not tied to the session that created them
  - [GHSA-46jr-4wx8-v453](https://osv.dev/vulnerability/GHSA-46jr-4wx8-v453) (CVE-2026-111768): HIGH, CVSS 7.5, fixed in 1.32.0. MCP TypeScript SDK: One HTTP request within the default size limit could exhaust server memory during validation
  - [GHSA-6qxp-vccf-f47h](https://osv.dev/vulnerability/GHSA-6qxp-vccf-f47h) (CVE-2026-104850): HIGH, CVSS 7.5, fixed in 1.31.0. MCP TypeScript SDK: OAuth client could send credentials to an authorization server chosen by the MCP server
  - [GHSA-f897-62hf-6gxq](https://osv.dev/vulnerability/GHSA-f897-62hf-6gxq): HIGH, CVSS 7.5, fixed in 1.30.1. MCP TypeScript SDK: HTTP server transports and handlers did not limit request body size or JSON-RPC batch length
  - [GHSA-rvq5-wwqv-78pq](https://osv.dev/vulnerability/GHSA-rvq5-wwqv-78pq) (CVE-2026-111771): MEDIUM, CVSS 6.8, fixed in 1.32.0. MCP TypeScript SDK: Server bearer authentication accepted tokens issued for another service
  - [GHSA-6prh-2h8m-c8cw](https://osv.dev/vulnerability/GHSA-6prh-2h8m-c8cw) (CVE-2026-111769): MEDIUM, CVSS 6.5, fixed in 1.32.0. MCP TypeScript client SDK: HTTP client transports and OAuth requests followed cross-origin redirects and re-sent custom headers and request bodies
- **Initial risk:** High (8.6): highest advisory severity HIGH (CVSS 8.6); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-011 · 🟧 High (8.1) · Vulnerable transitive dependency

- **What:** ip@2.0.1: 1 known vulnerability (highest HIGH, CVSS 8.1)
- **Component:** `ip@2.0.1` (npm, scope prod, transitive), purl `pkg:npm/ip@2.0.1`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → express-ipfilter@1.3.2 → ip@2.0.1
- **Official severity:** HIGH, CVSS 8.1 (OSV CVSS v3 vector (score computed))
- **Fix available:** no fixed version published
- **Evidence:**
  - [GHSA-2p57-rm9w-gvfp](https://osv.dev/vulnerability/GHSA-2p57-rm9w-gvfp) (CVE-2024-29415): HIGH, CVSS 8.1, no fix published. ip SSRF improper categorization in isPublic
- **Initial risk:** High (8.1): highest advisory severity HIGH (CVSS 8.1); 1 advisory(ies) without a published fix; version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-012 · 🟧 High (8.1) · Vulnerable transitive dependency

- **What:** jsonwebtoken@0.1.0: 4 known vulnerabilities (highest CRITICAL, CVSS 8.1)
- **Component:** `jsonwebtoken@0.1.0` (npm, scope prod, transitive), purl `pkg:npm/jsonwebtoken@0.1.0`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → express-jwt@0.1.3 → jsonwebtoken@0.1.0
- **Official severity:** CRITICAL, CVSS 8.1 (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 9.0.0
- **Evidence:**
  - [GHSA-c7hr-j4mj-j2w6](https://osv.dev/vulnerability/GHSA-c7hr-j4mj-j2w6) (CVE-2015-9235): CRITICAL, fixed in 4.2.2. Verification Bypass in jsonwebtoken
  - [GHSA-8cf7-32gw-wr33](https://osv.dev/vulnerability/GHSA-8cf7-32gw-wr33) (CVE-2022-23539): HIGH, CVSS 8.1, fixed in 9.0.0. jsonwebtoken unrestricted key type could lead to legacy keys usage 
  - [GHSA-qwph-4952-7xr6](https://osv.dev/vulnerability/GHSA-qwph-4952-7xr6) (CVE-2022-23540): MEDIUM, CVSS 6.4, fixed in 9.0.0. jsonwebtoken vulnerable to signature validation bypass due to insecure default algorithm in jwt.verify()
  - [GHSA-hjrf-2m68-5959](https://osv.dev/vulnerability/GHSA-hjrf-2m68-5959) (CVE-2022-23541): MEDIUM, CVSS 5.0, fixed in 9.0.0. jsonwebtoken's insecure implementation of key retrieval function could lead to Forgeable Public/Private Tokens from RSA to HMAC
- **Initial risk:** High (8.1): highest advisory severity CRITICAL (CVSS 8.1); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-013 · 🟧 High (8.1) · Vulnerable direct dependency

- **What:** jsonwebtoken@0.4.0: 4 known vulnerabilities (highest CRITICAL, CVSS 8.1)
- **Component:** `jsonwebtoken@0.4.0` (npm, scope prod, direct), purl `pkg:npm/jsonwebtoken@0.4.0`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → jsonwebtoken@0.4.0
- **Official severity:** CRITICAL, CVSS 8.1 (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 9.0.0
- **Evidence:**
  - [GHSA-c7hr-j4mj-j2w6](https://osv.dev/vulnerability/GHSA-c7hr-j4mj-j2w6) (CVE-2015-9235): CRITICAL, fixed in 4.2.2. Verification Bypass in jsonwebtoken
  - [GHSA-8cf7-32gw-wr33](https://osv.dev/vulnerability/GHSA-8cf7-32gw-wr33) (CVE-2022-23539): HIGH, CVSS 8.1, fixed in 9.0.0. jsonwebtoken unrestricted key type could lead to legacy keys usage 
  - [GHSA-qwph-4952-7xr6](https://osv.dev/vulnerability/GHSA-qwph-4952-7xr6) (CVE-2022-23540): MEDIUM, CVSS 6.4, fixed in 9.0.0. jsonwebtoken vulnerable to signature validation bypass due to insecure default algorithm in jwt.verify()
  - [GHSA-hjrf-2m68-5959](https://osv.dev/vulnerability/GHSA-hjrf-2m68-5959) (CVE-2022-23541): MEDIUM, CVSS 5.0, fixed in 9.0.0. jsonwebtoken's insecure implementation of key retrieval function could lead to Forgeable Public/Private Tokens from RSA to HMAC
- **Initial risk:** High (8.1): highest advisory severity CRITICAL (CVSS 8.1); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-014 · 🟧 High (8.1) · Vulnerable transitive dependency

- **What:** libxmljs2@0.35.0: 1 known vulnerability (highest HIGH, CVSS 8.1)
- **Component:** `libxmljs2@0.35.0` (npm, scope dev, transitive), purl `pkg:npm/libxmljs2@0.35.0`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → @cyclonedx/cyclonedx-npm@2.0.0 → @cyclonedx/cyclonedx-library@7.1.0 → libxmljs2@0.35.0
- **Official severity:** HIGH, CVSS 8.1 (OSV CVSS v3 vector (score computed))
- **Fix available:** no fixed version published
- **Evidence:**
  - [GHSA-78h3-pg4x-j8cv](https://osv.dev/vulnerability/GHSA-78h3-pg4x-j8cv) (CVE-2024-34394): HIGH, CVSS 8.1, no fix published. libxmljs2 vulnerable to type confusion when parsing specially crafted XML
- **Initial risk:** High (8.1): highest advisory severity HIGH (CVSS 8.1); 1 advisory(ies) without a published fix; version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-015 · 🟧 High (8.1) · Vulnerable direct dependency

- **What:** lodash-es@4.17.21: 2 known vulnerabilities (highest HIGH, CVSS 8.1)
- **Component:** `lodash-es@4.17.21` (npm, scope prod, direct), purl `pkg:npm/lodash-es@4.17.21`
- **Where:** `frontend/package.json`
- **Dependency path:** frontend@20.4.0-SNAPSHOT → lodash-es@4.17.21
- **Official severity:** HIGH, CVSS 8.1 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 4.18.0
- **Evidence:**
  - [GHSA-r5fr-rjxr-66jc](https://osv.dev/vulnerability/GHSA-r5fr-rjxr-66jc) (CVE-2026-4800): HIGH, CVSS 8.1, fixed in 4.18.0. lodash vulnerable to Code Injection via `_.template` imports key names
  - [GHSA-xxjr-mmjv-4gpg](https://osv.dev/vulnerability/GHSA-xxjr-mmjv-4gpg) (CVE-2025-13465): MEDIUM, CVSS 6.5, fixed in 4.17.23. Lodash has Prototype Pollution Vulnerability in `_.unset`, `_.omit`, and `_.pullAt` functions
- **Initial risk:** High (8.1): highest advisory severity HIGH (CVSS 8.1); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-016 · 🟧 High (8.1) · Vulnerable transitive dependency

- **What:** piscina@5.1.4: 2 known vulnerabilities (highest CRITICAL, CVSS 8.1)
- **Component:** `piscina@5.1.4` (npm, scope prod, transitive), purl `pkg:npm/piscina@5.1.4`
- **Where:** `frontend/package.json`
- **Dependency path:** frontend@20.4.0-SNAPSHOT → @angular/build@22.0.1 → piscina@5.1.4
- **Official severity:** CRITICAL, CVSS 8.1 (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 5.3.2
- **Evidence:**
  - [GHSA-67c8-pqhq-4rmx](https://osv.dev/vulnerability/GHSA-67c8-pqhq-4rmx) (CVE-2026-102992): CRITICAL, fixed in 5.3.2. piscina: Prototype-pollution gadget in ThreadPool.options allows RCE via execArgv / loadBalancer / env
  - [GHSA-x9g3-xrwr-cwfg](https://osv.dev/vulnerability/GHSA-x9g3-xrwr-cwfg) (CVE-2026-55388): HIGH, CVSS 8.1, fixed in 5.2.0. piscina: Prototype Pollution Gadget → RCE via inherited options.filename
- **Initial risk:** High (8.1): highest advisory severity CRITICAL (CVSS 8.1); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-017 · 🟧 High (8.0) · Unsafe install script

- **What:** .github/workflows/ci.yml: job 'heroku' downloads a script and pipes it into a shell
- **Where:** `.github/workflows/ci.yml:353`
- **Evidence:**
  - `.github/workflows/ci.yml:353`: `run: curl https://cli-assets.heroku.com/install.sh | sh`
- **Initial risk:** High (8.0): R12_REMOTE_SCRIPT_EXEC default level High
- **Why it matters:** A script is downloaded and executed without any integrity check.
- **Basis:** verified fact, confidence high

### F-018 · 🟧 High (8.0) · Unsafe CI/CD component

- **What:** .github/workflows/ci.yml: third-party action 'coverallsapp/github-action@v2' is not pinned to a commit SHA
- **Component:** `coverallsapp/github-action@v2` (github-actions, scope ci, direct), purl `pkg:github/coverallsapp/github-action@v2`
- **Where:** `.github/workflows/ci.yml:198`
- **Dependency path:** CI/CD Pipeline → coverallsapp/github-action@v2
- **Evidence:**
  - `.github/workflows/ci.yml:198`: `uses: coverallsapp/github-action@v2`
- **Initial risk:** High (8.0): R15_CI_UNPINNED_ACTION default level High
- **Why it matters:** A third-party action referenced by tag/branch can be changed by its owner at any time.
- **Basis:** verified fact, confidence high

### F-019 · 🟧 High (8.0) · Unsafe CI/CD component

- **What:** .github/workflows/image_actions.yml: third-party action 'calibreapp/image-actions@main' is not pinned to a commit SHA
- **Component:** `calibreapp/image-actions@main` (github-actions, scope ci, direct), purl `pkg:github/calibreapp/image-actions@main`
- **Where:** `.github/workflows/image_actions.yml:33`
- **Dependency path:** Compress images → calibreapp/image-actions@main
- **Evidence:**
  - `.github/workflows/image_actions.yml:33`: `uses: calibreapp/image-actions@main`
- **Initial risk:** High (8.0): R15_CI_UNPINNED_ACTION default level High
- **Why it matters:** A third-party action referenced by tag/branch can be changed by its owner at any time.
- **Basis:** verified fact, confidence high

### F-020 · 🟧 High (8.0) · Unsafe CI/CD component

- **What:** .github/workflows/image_actions.yml: third-party action 'peter-evans/create-pull-request@v8' is not pinned to a commit SHA
- **Component:** `peter-evans/create-pull-request@v8` (github-actions, scope ci, direct), purl `pkg:github/peter-evans/create-pull-request@v8`
- **Where:** `.github/workflows/image_actions.yml:42`
- **Dependency path:** Compress images → peter-evans/create-pull-request@v8
- **Evidence:**
  - `.github/workflows/image_actions.yml:42`: `uses: peter-evans/create-pull-request@v8`
- **Initial risk:** High (8.0): R15_CI_UNPINNED_ACTION default level High
- **Why it matters:** A third-party action referenced by tag/branch can be changed by its owner at any time.
- **Basis:** verified fact, confidence high

### F-021 · 🟧 High (8.0) · Vulnerable direct dependency

- **What:** @angular/router@22.0.1: 3 known vulnerabilities (highest HIGH)
- **Component:** `@angular/router@22.0.1` (npm, scope prod, direct), purl `pkg:npm/%40angular/router@22.0.1`
- **Where:** `frontend/package.json`
- **Dependency path:** frontend@20.4.0-SNAPSHOT → @angular/router@22.0.1
- **Official severity:** HIGH (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 22.2.1
- **Evidence:**
  - [GHSA-57xq-rjx2-v5xh](https://osv.dev/vulnerability/GHSA-57xq-rjx2-v5xh) (CVE-2026-111751): HIGH, fixed in 22.2.1. @angular/router: Denial of Service via RouterLink Query Parameter Retention in Server-Side Rendering (SSR)
  - [GHSA-62vg-58rm-qff7](https://osv.dev/vulnerability/GHSA-62vg-58rm-qff7) (CVE-2026-111752): HIGH, fixed in 22.2.1. @angular/router: Denial of Service via Unmatched Empty-Path Outlet Route Matching in Server-Side Rendering (SSR)
  - [GHSA-ff3f-86qr-9cv3](https://osv.dev/vulnerability/GHSA-ff3f-86qr-9cv3) (CVE-2026-101896): HIGH, fixed in 22.2.0. Angular Server-Side Rendering (SSR): Denial of Service via Numeric URL Matrix Parameters
- **Initial risk:** High (8.0): highest advisory severity HIGH; version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-022 · 🟧 High (8.0) · Vulnerable direct dependency

- **What:** @cyclonedx/cyclonedx-npm@2.0.0: 1 known vulnerability (highest HIGH)
- **Component:** `@cyclonedx/cyclonedx-npm@2.0.0` (npm, scope dev, direct), purl `pkg:npm/%40cyclonedx/cyclonedx-npm@2.0.0`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → @cyclonedx/cyclonedx-npm@2.0.0
- **Official severity:** HIGH (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 6.0.0
- **Evidence:**
  - [GHSA-q69g-4hcv-6jg4](https://osv.dev/vulnerability/GHSA-q69g-4hcv-6jg4) (CVE-2026-71538): HIGH, fixed in 6.0.0. @cyclonedx/cyclonedx-npm: Shell Injection via Unsanitized --workspace Argument on Windows
- **Initial risk:** High (8.0): highest advisory severity HIGH; version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-023 · 🟧 High (8.0) · Vulnerable transitive dependency

- **What:** vite@7.3.2: 7 known vulnerabilities (highest HIGH)
- **Component:** `vite@7.3.2` (npm, scope prod, transitive), purl `pkg:npm/vite@7.3.2`
- **Where:** `frontend/package.json`
- **Dependency path:** frontend@20.4.0-SNAPSHOT → @angular/build@22.0.1 → vite@7.3.2
- **Official severity:** HIGH (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 7.3.7
- **Evidence:**
  - [GHSA-587h-7wmj-h5pm](https://osv.dev/vulnerability/GHSA-587h-7wmj-h5pm) (CVE-2026-112942): HIGH, fixed in 7.3.7. launch-editor: `fs.existsSync()` existence check can be bypassed on Windows
  - [GHSA-698v-4r3x-3vcv](https://osv.dev/vulnerability/GHSA-698v-4r3x-3vcv) (CVE-2026-112943): MEDIUM, fixed in 7.3.7. launch-editor: escapeCmdArgs() omits % escaping on Windows
  - [GHSA-fx2h-pf6j-xcff](https://osv.dev/vulnerability/GHSA-fx2h-pf6j-xcff) (CVE-2026-53571): MEDIUM, fixed in 7.3.5. vite: `server.fs.deny` bypass on Windows alternate paths
  - [GHSA-r825-w8mm-5pxw](https://osv.dev/vulnerability/GHSA-r825-w8mm-5pxw) (CVE-2026-112944): MEDIUM, fixed in 7.3.7. launch-editor: Editor CLI flag misinterpretation causing arbitrary command execution for some editors
  - [GHSA-rq7h-c2jc-7f22](https://osv.dev/vulnerability/GHSA-rq7h-c2jc-7f22) (CVE-2026-112946): MEDIUM, fixed in 7.3.7. Vite: Files outside `server.fs.allow` could be served when project paths match system paths on non-Windows machine
  - [GHSA-v6wh-96g9-6wx3](https://osv.dev/vulnerability/GHSA-v6wh-96g9-6wx3) (CVE-2026-53632): MEDIUM, fixed in 7.3.5. launch-editor: NTLMv2 hash disclosure via UNC path handling on Windows
  - [GHSA-9jrq-w75r-8gcw](https://osv.dev/vulnerability/GHSA-9jrq-w75r-8gcw) (CVE-2026-112945): LOW, fixed in 7.3.7. Vite: Cross origin script execution through Vite custom middleware
- **Initial risk:** High (8.0): highest advisory severity HIGH; version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-024 · 🟧 High (7.7) · Vulnerable direct dependency

- **What:** express-jwt@0.1.3: 1 known vulnerability (highest HIGH, CVSS 7.7)
- **Component:** `express-jwt@0.1.3` (npm, scope prod, direct), purl `pkg:npm/express-jwt@0.1.3`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → express-jwt@0.1.3
- **Official severity:** HIGH, CVSS 7.7 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 6.0.0
- **Evidence:**
  - [GHSA-6g6m-m6h5-w9gf](https://osv.dev/vulnerability/GHSA-6g6m-m6h5-w9gf) (CVE-2020-15084): HIGH, CVSS 7.7, fixed in 6.0.0. Authorization bypass in express-jwt
- **Initial risk:** High (7.7): highest advisory severity HIGH (CVSS 7.7); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-025 · 🟧 High (7.5) · Vulnerable direct dependency

- **What:** compression@1.8.1: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `compression@1.8.1` (npm, scope prod, direct), purl `pkg:npm/compression@1.8.1`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → compression@1.8.1
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.8.2
- **Evidence:**
  - [GHSA-vc2v-76pw-4v95](https://osv.dev/vulnerability/GHSA-vc2v-76pw-4v95) (CVE-2026-87776): HIGH, CVSS 7.5, fixed in 1.8.2. compression vulnerable to Denial of Service via memory leak on premature response close
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-026 · 🟧 High (7.5) · Vulnerable direct dependency

- **What:** js-yaml@3.14.0: 5 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `js-yaml@3.14.0` (npm, scope prod, direct), purl `pkg:npm/js-yaml@3.14.0`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → js-yaml@3.14.0
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 3.15.2
- **Evidence:**
  - [GHSA-2883-xcg3-v3hh](https://osv.dev/vulnerability/GHSA-2883-xcg3-v3hh) (CVE-2026-84375): HIGH, CVSS 7.5, fixed in 3.15.2. js-yaml: maxTotalMergeKeys does not limit CPU use for empty merge sources
  - [GHSA-52cp-r559-cp3m](https://osv.dev/vulnerability/GHSA-52cp-r559-cp3m) (CVE-2026-59869): HIGH, CVSS 7.5, fixed in 3.15.0. js-yaml: YAML merge-key chains can force quadratic CPU consumption
  - [GHSA-5p4m-2wfm-xmqj](https://osv.dev/vulnerability/GHSA-5p4m-2wfm-xmqj): HIGH, CVSS 7.5, fixed in 3.15.1. JS-YAML: Quadratic CPU consumption in !!omap resolution (3.x and 4.x) — CVE-2026-59870 fix not backported
  - [GHSA-h67p-54hq-rp68](https://osv.dev/vulnerability/GHSA-h67p-54hq-rp68) (CVE-2026-53550): MEDIUM, CVSS 5.3, fixed in 3.15.0. JS-YAML: Quadratic-complexity DoS in merge key handling via repeated aliases
  - [GHSA-mh29-5h37-fv8m](https://osv.dev/vulnerability/GHSA-mh29-5h37-fv8m) (CVE-2025-64718): MEDIUM, CVSS 5.3, fixed in 3.14.2. js-yaml has prototype pollution in merge (<<)
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-027 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** js-yaml@3.14.1: 5 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `js-yaml@3.14.1` (npm, scope dev, transitive), purl `pkg:npm/js-yaml@3.14.1`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → @cyclonedx/cyclonedx-npm@2.0.0 → xmlbuilder2@3.1.1 → js-yaml@3.14.1 ; juice-shop@20.4.0-SNAPSHOT → @cyclonedx/cyclonedx-npm@2.0.0 → @cyclonedx/cyclonedx-library@7.1.0 → xmlbuilder2@3.1.1 → js-yaml@3.14.1
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 3.15.2
- **Evidence:**
  - [GHSA-2883-xcg3-v3hh](https://osv.dev/vulnerability/GHSA-2883-xcg3-v3hh) (CVE-2026-84375): HIGH, CVSS 7.5, fixed in 3.15.2. js-yaml: maxTotalMergeKeys does not limit CPU use for empty merge sources
  - [GHSA-52cp-r559-cp3m](https://osv.dev/vulnerability/GHSA-52cp-r559-cp3m) (CVE-2026-59869): HIGH, CVSS 7.5, fixed in 3.15.0. js-yaml: YAML merge-key chains can force quadratic CPU consumption
  - [GHSA-5p4m-2wfm-xmqj](https://osv.dev/vulnerability/GHSA-5p4m-2wfm-xmqj): HIGH, CVSS 7.5, fixed in 3.15.1. JS-YAML: Quadratic CPU consumption in !!omap resolution (3.x and 4.x) — CVE-2026-59870 fix not backported
  - [GHSA-h67p-54hq-rp68](https://osv.dev/vulnerability/GHSA-h67p-54hq-rp68) (CVE-2026-53550): MEDIUM, CVSS 5.3, fixed in 3.15.0. JS-YAML: Quadratic-complexity DoS in merge key handling via repeated aliases
  - [GHSA-mh29-5h37-fv8m](https://osv.dev/vulnerability/GHSA-mh29-5h37-fv8m) (CVE-2025-64718): MEDIUM, CVSS 5.3, fixed in 3.14.2. js-yaml has prototype pollution in merge (<<)
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-028 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** moment@2.0.0: 3 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `moment@2.0.0` (npm, scope prod, transitive), purl `pkg:npm/moment@2.0.0`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → express-jwt@0.1.3 → jsonwebtoken@0.1.0 → moment@2.0.0
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 2.29.2
- **Evidence:**
  - [GHSA-446m-mv8f-q348](https://osv.dev/vulnerability/GHSA-446m-mv8f-q348) (CVE-2017-18214): HIGH, CVSS 7.5, fixed in 2.19.3. Regular Expression Denial of Service in moment
  - [GHSA-8hfj-j24r-96c4](https://osv.dev/vulnerability/GHSA-8hfj-j24r-96c4) (CVE-2022-24785): HIGH, CVSS 7.5, fixed in 2.29.2. Path Traversal: 'dir/../../filename' in moment.locale
  - [GHSA-87vv-r9j6-g5qv](https://osv.dev/vulnerability/GHSA-87vv-r9j6-g5qv) (CVE-2016-4055): MEDIUM, CVSS 6.5, fixed in 2.11.2. Regular Expression Denial of Service in moment
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-029 · 🟧 High (7.5) · Vulnerable direct dependency

- **What:** multer@2.4.0: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `multer@2.4.0` (npm, scope prod, direct), purl `pkg:npm/multer@2.4.0`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → multer@2.4.0
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 2.5.0
- **Evidence:**
  - [GHSA-q7qp-rjg7-q26m](https://osv.dev/vulnerability/GHSA-q7qp-rjg7-q26m) (CVE-2026-113872): HIGH, CVSS 7.5, fixed in 2.5.0. multer vulnerable to Denial of Service via a pending asynchronous fileFilter after request teardown
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-030 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** pacote@21.5.0: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `pacote@21.5.0` (npm, scope prod, transitive), purl `pkg:npm/pacote@21.5.0`
- **Where:** `frontend/package.json`
- **Dependency path:** frontend@20.4.0-SNAPSHOT → @angular/cli@22.0.1 → pacote@21.5.0
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 21.5.1
- **Evidence:**
  - [GHSA-w4pp-8pjf-rmxw](https://osv.dev/vulnerability/GHSA-w4pp-8pjf-rmxw) (CVE-2026-9496): HIGH, CVSS 7.5, fixed in 21.5.1. pacote is vulnerable to Denial of Service (DoS) via the addGitSha function
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-031 · 🟧 High (7.5) · Vulnerable direct dependency

- **What:** sanitize-html@1.4.2: 10 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `sanitize-html@1.4.2` (npm, scope prod, direct), purl `pkg:npm/sanitize-html@1.4.2`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → sanitize-html@1.4.2
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 2.18.0
- **Evidence:**
  - [GHSA-cgfm-xwp7-2cvr](https://osv.dev/vulnerability/GHSA-cgfm-xwp7-2cvr) (CVE-2022-25887): HIGH, CVSS 7.5, fixed in 2.7.1. Sanitize-html Vulnerable To REDoS Attacks
  - [GHSA-3j7m-hmh3-9jmp](https://osv.dev/vulnerability/GHSA-3j7m-hmh3-9jmp) (CVE-2016-1000237): MEDIUM, CVSS 6.1, fixed in 1.4.3. Cross-Site Scripting in sanitize-html
  - [GHSA-jxwj-j7wr-gfrw](https://osv.dev/vulnerability/GHSA-jxwj-j7wr-gfrw) (CVE-2026-63670): MEDIUM, CVSS 6.1, fixed in 2.17.6. ApostropheCMS: Mutation-XSS / allowedTags bypass via literal `</textarea/>` solidus close
  - [GHSA-qhxp-v273-g94h](https://osv.dev/vulnerability/GHSA-qhxp-v273-g94h) (CVE-2019-25225): MEDIUM, CVSS 6.1, fixed in 2.0.0-beta. sanitize-html is vulnerable to XSS through incomprehensive sanitization
  - [GHSA-x3q4-9hxx-gx8m](https://osv.dev/vulnerability/GHSA-x3q4-9hxx-gx8m) (CVE-2026-113654): MEDIUM, fixed in 2.18.0. ApostropheCMS sanitize-html: nonTextTags discard region ends early on an implied close, letting <noscript> content render
  - [GHSA-xc6g-ggrc-qq4r](https://osv.dev/vulnerability/GHSA-xc6g-ggrc-qq4r) (CVE-2017-16016): MEDIUM, fixed in 1.11.4. Cross-Site Scripting in sanitize-html
  - [GHSA-cv27-6wvh-8x7j](https://osv.dev/vulnerability/GHSA-cv27-6wvh-8x7j) (CVE-2026-113661): MEDIUM, CVSS 5.4, fixed in 2.18.0. ApostropheCMS: Incomplete CVE-2026-53606: `meta http-equiv=refresh` `content` still ships `javascript:` / `data:` URLs
  - [GHSA-mjxr-4v3x-q3m4](https://osv.dev/vulnerability/GHSA-mjxr-4v3x-q3m4) (CVE-2021-26540): MEDIUM, CVSS 5.3, fixed in 2.3.2. Improper Input Validation in sanitize-html
  - [GHSA-rjqq-98f6-6j3r](https://osv.dev/vulnerability/GHSA-rjqq-98f6-6j3r) (CVE-2021-26539): MEDIUM, CVSS 5.3, fixed in 2.3.1. Improper Input Validation in sanitize-html
  - [GHSA-rm97-x556-q36h](https://osv.dev/vulnerability/GHSA-rm97-x556-q36h) (CVE-2024-21501): MEDIUM, CVSS 5.3, fixed in 2.12.1. sanitize-html Information Exposure vulnerability
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-032 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** uuid@8.3.2: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `uuid@8.3.2` (npm, scope prod, transitive), purl `pkg:npm/uuid@8.3.2`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → sequelize@6.37.3 → uuid@8.3.2 ; juice-shop@20.4.0-SNAPSHOT → nyc@15.1.0 → istanbul-lib-processinfo@2.0.3 → uuid@8.3.2
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 11.1.1
- **Evidence:**
  - [GHSA-w5hq-g745-h8pq](https://osv.dev/vulnerability/GHSA-w5hq-g745-h8pq) (CVE-2026-41907, CVE-2026-41988): HIGH, CVSS 7.5, fixed in 11.1.1. uuid: Missing buffer bounds check in v3/v5/v6 when buf is provided
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-033 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** ws@7.4.6: 2 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `ws@7.4.6` (npm, scope prod, transitive), purl `pkg:npm/ws@7.4.6`
- **Where:** `frontend/package.json`
- **Dependency path:** frontend@20.4.0-SNAPSHOT → ethers@5.7.2 → @ethersproject/providers@5.7.2 → ws@7.4.6
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 7.5.11
- **Evidence:**
  - [GHSA-3h5v-q93c-6h6q](https://osv.dev/vulnerability/GHSA-3h5v-q93c-6h6q) (CVE-2024-37890): HIGH, CVSS 7.5, fixed in 7.5.10. ws affected by a DoS when handling a request with many HTTP headers
  - [GHSA-96hv-2xvq-fx4p](https://osv.dev/vulnerability/GHSA-96hv-2xvq-fx4p) (CVE-2026-48779): HIGH, CVSS 7.5, fixed in 7.5.11. ws: Memory exhaustion DoS from tiny fragments and data chunks
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-034 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** ws@8.17.1: 2 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `ws@8.17.1` (npm, scope prod, transitive), purl `pkg:npm/ws@8.17.1`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → ethers@6.16.0 → ws@8.17.1
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 8.21.0
- **Evidence:**
  - [GHSA-96hv-2xvq-fx4p](https://osv.dev/vulnerability/GHSA-96hv-2xvq-fx4p) (CVE-2026-48779): HIGH, CVSS 7.5, fixed in 8.21.0. ws: Memory exhaustion DoS from tiny fragments and data chunks
  - [GHSA-58qx-3vcg-4xpx](https://osv.dev/vulnerability/GHSA-58qx-3vcg-4xpx) (CVE-2026-45736): MEDIUM, CVSS 4.4, fixed in 8.20.1. ws: Uninitialized memory disclosure
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-035 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** zod@4.4.2: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `zod@4.4.2` (npm, scope prod, transitive), purl `pkg:npm/zod@4.4.2`
- **Where:** `frontend/package.json`
- **Dependency path:** frontend@20.4.0-SNAPSHOT → @angular/cli@22.0.1 → zod@4.4.2 ; frontend@20.4.0-SNAPSHOT → @angular/cli@22.0.1 → @modelcontextprotocol/sdk@1.29.0 → zod@4.4.2
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 4.6.6
- **Evidence:**
  - [GHSA-mrhx-c7xc-m3w5](https://osv.dev/vulnerability/GHSA-mrhx-c7xc-m3w5) (CVE-2023-54404): HIGH, CVSS 7.5, fixed in 4.6.6. Zod can exhaust memory while validating oversized constrained collections
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-036 · 🟧 High (7.5) · Vulnerable direct dependency

- **What:** zod@4.4.3: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `zod@4.4.3` (npm, scope prod, direct), purl `pkg:npm/zod@4.4.3`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → zod@4.4.3
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 4.6.6
- **Evidence:**
  - [GHSA-mrhx-c7xc-m3w5](https://osv.dev/vulnerability/GHSA-mrhx-c7xc-m3w5) (CVE-2023-54404): HIGH, CVSS 7.5, fixed in 4.6.6. Zod can exhaust memory while validating oversized constrained collections
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-037 · 🟨 Medium (6.5) · Vulnerable direct dependency

- **What:** notevil@1.3.3: 1 known vulnerability (highest MEDIUM, CVSS 6.5)
- **Component:** `notevil@1.3.3` (npm, scope prod, direct), purl `pkg:npm/notevil@1.3.3`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → notevil@1.3.3
- **Official severity:** MEDIUM, CVSS 6.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** no fixed version published
- **Evidence:**
  - [GHSA-8g4m-cjm2-96wq](https://osv.dev/vulnerability/GHSA-8g4m-cjm2-96wq) (CVE-2021-23771): MEDIUM, CVSS 6.5, no fix published. Sandbox escape in notevil and argencoders-notevil
- **Initial risk:** Medium (6.5): highest advisory severity MEDIUM (CVSS 6.5); 1 advisory(ies) without a published fix; version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-038 · 🟨 Medium (5.9) · Vulnerable transitive dependency

- **What:** @vitest/mocker@4.1.1: 2 known vulnerabilities (highest MEDIUM, CVSS 5.9)
- **Component:** `@vitest/mocker@4.1.1` (npm, scope dev, transitive), purl `pkg:npm/%40vitest/mocker@4.1.1`
- **Where:** `frontend/package.json`
- **Dependency path:** frontend@20.4.0-SNAPSHOT → vitest@4.1.1 → @vitest/mocker@4.1.1
- **Official severity:** MEDIUM, CVSS 5.9 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 4.1.12
- **Evidence:**
  - [GHSA-82fw-gwwq-j7x9](https://osv.dev/vulnerability/GHSA-82fw-gwwq-j7x9) (CVE-2026-84373): MEDIUM, CVSS 5.9, fixed in 4.1.11. Vitest: Path Traversal / Arbitrary File Read via @vitest/mocker Redirect Mock
  - [GHSA-qxg6-89mg-rqv8](https://osv.dev/vulnerability/GHSA-qxg6-89mg-rqv8) (CVE-2026-112949): MEDIUM, CVSS 4.7, fixed in 4.1.12. Vitest: Code injection via unauthenticated manual mock registration
- **Initial risk:** Medium (5.9): highest advisory severity MEDIUM (CVSS 5.9); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-039 · 🟨 Medium (5.9) · Vulnerable transitive dependency

- **What:** basic-ftp@5.3.1: 3 known vulnerabilities (highest HIGH, CVSS 5.9)
- **Component:** `basic-ftp@5.3.1` (npm, scope prod, transitive), purl `pkg:npm/basic-ftp@5.3.1`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → proxy-agent@8.0.2 → pac-proxy-agent@9.1.0 → get-uri@8.0.1 → basic-ftp@5.3.1
- **Official severity:** HIGH, CVSS 5.9 (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 6.2.4
- **Evidence:**
  - [GHSA-c475-qrg2-pj4r](https://osv.dev/vulnerability/GHSA-c475-qrg2-pj4r) (CVE-2026-102990): HIGH, fixed in 6.2.1. basic-ftp: Quadratic-time CPU denial of service in Client.list() Unix directory-listing parser (RE_LINE backtracking)
  - [GHSA-r4jh-29pc-gfqr](https://osv.dev/vulnerability/GHSA-r4jh-29pc-gfqr) (CVE-2026-126346): MEDIUM, CVSS 5.9, fixed in 6.2.3. basic-ftp: Uncaught exception crashes the Node.js process when a password (or resumed-download path) contains CR/LF
  - [GHSA-5pm8-86m8-9m6r](https://osv.dev/vulnerability/GHSA-5pm8-86m8-9m6r) (CVE-2026-126345): MEDIUM, CVSS 5.3, fixed in 6.2.4. basic-ftp: Uncaught TypeError in MLSD directory-listing parser via __proto__ fact name causes DoS in Client.list()
- **Initial risk:** Medium (5.9): highest advisory severity HIGH (CVSS 5.9); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-040 · 🟨 Medium (5.9) · Vulnerable direct dependency

- **What:** vitest@4.1.1: 1 known vulnerability (highest MEDIUM, CVSS 5.9)
- **Component:** `vitest@4.1.1` (npm, scope dev, direct), purl `pkg:npm/vitest@4.1.1`
- **Where:** `frontend/package.json`
- **Dependency path:** frontend@20.4.0-SNAPSHOT → vitest@4.1.1
- **Official severity:** MEDIUM, CVSS 5.9 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 4.1.11
- **Evidence:**
  - [GHSA-82fw-gwwq-j7x9](https://osv.dev/vulnerability/GHSA-82fw-gwwq-j7x9) (CVE-2026-84373): MEDIUM, CVSS 5.9, fixed in 4.1.11. Vitest: Path Traversal / Arbitrary File Read via @vitest/mocker Redirect Mock
- **Initial risk:** Medium (5.9): highest advisory severity MEDIUM (CVSS 5.9); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-041 · 🟨 Medium (5.6) · Vulnerable transitive dependency

- **What:** elliptic@6.5.4: 7 known vulnerabilities (highest CRITICAL, CVSS 5.6)
- **Component:** `elliptic@6.5.4` (npm, scope prod, transitive), purl `pkg:npm/elliptic@6.5.4`
- **Where:** `frontend/package.json`
- **Dependency path:** frontend@20.4.0-SNAPSHOT → ethers@5.7.2 → @ethersproject/signing-key@5.7.0 → elliptic@6.5.4 ; frontend@20.4.0-SNAPSHOT → ethers@5.7.2 → @ethersproject/hdnode@5.7.0 → @ethersproject/signing-key@5.7.0 → elliptic@6.5.4 ; frontend@20.4.0-SNAPSHOT → ethers@5.7.2 → @ethersproject/transactions@5.7.0 → @ethersproject/signing-key@5.7.0 → elliptic@6.5.4
- **Official severity:** CRITICAL, CVSS 5.6 (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 6.6.1; no fix for GHSA-848j-6mx2-7j84
- **Evidence:**
  - [GHSA-vjh7-7g9h-fjfh](https://osv.dev/vulnerability/GHSA-vjh7-7g9h-fjfh): CRITICAL, fixed in 6.6.1. Elliptic's private key extraction in ECDSA upon signing a malformed input (e.g. a string)
  - [GHSA-848j-6mx2-7j84](https://osv.dev/vulnerability/GHSA-848j-6mx2-7j84) (CVE-2025-14505): MEDIUM, CVSS 5.6, no fix published. Elliptic Uses a Cryptographic Primitive with a Risky Implementation
  - [GHSA-434g-2637-qmqr](https://osv.dev/vulnerability/GHSA-434g-2637-qmqr) (CVE-2024-48949): MEDIUM, CVSS 5.3, fixed in 6.5.6. Elliptic's verify function omits uniqueness validation
  - [GHSA-49q7-c7j4-3p7m](https://osv.dev/vulnerability/GHSA-49q7-c7j4-3p7m) (CVE-2024-42461): MEDIUM, CVSS 5.3, fixed in 6.5.7. Elliptic allows BER-encoded signatures
  - [GHSA-977x-g7h5-7qgw](https://osv.dev/vulnerability/GHSA-977x-g7h5-7qgw) (CVE-2024-42460): MEDIUM, CVSS 5.3, fixed in 6.5.7. Elliptic's ECDSA missing check for whether leading bit of r and s is zero
  - [GHSA-f7q4-pwc6-w24p](https://osv.dev/vulnerability/GHSA-f7q4-pwc6-w24p) (CVE-2024-42459): MEDIUM, CVSS 5.3, fixed in 6.5.7. Elliptic's EDDSA missing signature length check
  - [GHSA-fc9h-whq2-v747](https://osv.dev/vulnerability/GHSA-fc9h-whq2-v747) (CVE-2024-48948): MEDIUM, CVSS 4.8, fixed in 6.6.0. Valid ECDSA signatures erroneously rejected in Elliptic
- **Initial risk:** Medium (5.6): highest advisory severity CRITICAL (CVSS 5.6); 1 advisory(ies) without a published fix; version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-042 · 🟨 Medium (5.5) · Untrusted image

- **What:** Dockerfile runs 'npm install' with install scripts enabled
- **Where:** `Dockerfile:4`
- **Evidence:**
  - `Dockerfile:4`: `RUN npm install -g typescript@^6.0.3`
- **Initial risk:** Medium (5.5): R13_CONTAINER_HARDENING default level Medium
- **Why it matters:** The container build or runtime is less isolated than it could be.
- **Basis:** verified fact, confidence high

### F-043 · 🟨 Medium (5.5) · Untrusted image

- **What:** Dockerfile runs 'npm install' with install scripts enabled
- **Where:** `Dockerfile:5`
- **Evidence:**
  - `Dockerfile:5`: `RUN npm install --omit=dev`
- **Initial risk:** Medium (5.5): R13_CONTAINER_HARDENING default level Medium
- **Why it matters:** The container build or runtime is less isolated than it could be.
- **Basis:** verified fact, confidence high

### F-044 · 🟨 Medium (5.5) · Untrusted image

- **What:** Dockerfile runs 'npm install' with install scripts enabled
- **Where:** `Dockerfile:19`
- **Evidence:**
  - `Dockerfile:19`: `RUN npm install -g @cyclonedx/cyclonedx-npm@$CYCLONEDX_NPM_VERSION`
- **Initial risk:** Medium (5.5): R13_CONTAINER_HARDENING default level Medium
- **Why it matters:** The container build or runtime is less isolated than it could be.
- **Basis:** verified fact, confidence high

### F-045 · 🟨 Medium (5.5) · Suspicious package update

- **What:** frontend/package.json has no lockfile: 61 dependencies use version ranges
- **Where:** `frontend/package.json`
- **Evidence:**
  - no package-lock.json / yarn.lock next to frontend/package.json; ranged: @angular/animations, @angular/build, @angular/cdk, @angular/cli, @angular/common, @angular/compiler, @angular/compiler-cli, @angular/core, @angular/forms, @angular/material, @angular/platform-browser, @angular/router, @codemirror/lang-javascript, @codemirror/lang-json, @codemirror/lang-yaml ...
- **Initial risk:** Medium (5.5): R09_UNPINNED_DEPENDENCY default level Medium
- **Why it matters:** Without an exact version, a future (possibly compromised) release is installed silently.
- **Basis:** verified fact, confidence high

### F-046 · 🟨 Medium (5.5) · Untrusted image

- **What:** image alpine:latest uses a mutable tag and no digest
- **Component:** `alpine:latest` (docker, scope prod, direct), purl `pkg:docker/library/alpine@latest?repository_url=docker.io`
- **Where:** `test/smoke/Dockerfile:1`
- **Dependency path:** test/smoke/Dockerfile → alpine:latest
- **Evidence:**
  - `test/smoke/Dockerfile:1`: `FROM alpine`
- **Initial risk:** Medium (5.5): R11_MUTABLE_IMAGE_TAG default level Medium
- **Why it matters:** A 'latest' / missing tag without a digest can point to different content tomorrow.
- **Basis:** verified fact, confidence high

### F-047 · 🟨 Medium (5.5) · Untrusted image

- **What:** image gcr.io/distroless/nodejs24-debian13:latest uses a mutable tag and no digest
- **Component:** `gcr.io/distroless/nodejs24-debian13:latest` (docker, scope prod, direct), purl `pkg:docker/distroless/nodejs24-debian13@latest?repository_url=gcr.io`
- **Where:** `Dockerfile:22`
- **Dependency path:** Dockerfile → gcr.io/distroless/nodejs24-debian13:latest
- **Evidence:**
  - `Dockerfile:22`: `FROM gcr.io/distroless/nodejs24-debian13`
- **Initial risk:** Medium (5.5): R11_MUTABLE_IMAGE_TAG default level Medium
- **Why it matters:** A 'latest' / missing tag without a digest can point to different content tomorrow.
- **Basis:** verified fact, confidence high

### F-048 · 🟨 Medium (5.5) · Unsafe install script

- **What:** juice-shop@20.4.0-SNAPSHOT runs a 'postinstall' script on every install: cd frontend && npm install && cd .. && npm run build:frontend && (npm run --silent build:server || cd .)
- **Where:** `package.json:56`
- **Evidence:**
  - `package.json:56`: `"postinstall": "cd frontend && npm install && cd .. && npm run build:frontend && (npm run --silent build:server || cd .)",`
- **Initial risk:** Medium (5.5): R03_INSTALL_SCRIPT default level Medium
- **Why it matters:** Install scripts run arbitrary code on every machine that installs the package, including CI.
- **Basis:** verified fact, confidence high

### F-049 · 🟨 Medium (5.5) · Suspicious package update

- **What:** package.json has no lockfile: 95 dependencies use version ranges
- **Where:** `package.json`
- **Evidence:**
  - no package-lock.json / yarn.lock next to package.json; ranged: @ai-sdk/openai-compatible, @fontsource/roboto, @simplewebauthn/server, ai, beercss, clarinet, compression, config, cookie-parser, cookieconsent, cors, errorhandler, ethers, express, express-ipfilter ...
- **Initial risk:** Medium (5.5): R09_UNPINNED_DEPENDENCY default level Medium
- **Why it matters:** Without an exact version, a future (possibly compromised) release is installed silently.
- **Basis:** verified fact, confidence high

### F-050 · 🟨 Medium (5.5) · Vulnerable direct dependency

- **What:** @angular/compiler@22.0.1: 1 known vulnerability (highest MEDIUM)
- **Component:** `@angular/compiler@22.0.1` (npm, scope prod, direct), purl `pkg:npm/%40angular/compiler@22.0.1`
- **Where:** `frontend/package.json`
- **Dependency path:** frontend@20.4.0-SNAPSHOT → @angular/compiler@22.0.1
- **Official severity:** MEDIUM (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 22.1.0
- **Evidence:**
  - [GHSA-hh8m-fm6v-7cvg](https://osv.dev/vulnerability/GHSA-hh8m-fm6v-7cvg) (CVE-2026-88057): MEDIUM, fixed in 22.1.0. Angular: Sanitization bypass via directive host bindings on concrete host elements in @angular/core and @angular/compiler
- **Initial risk:** Medium (5.5): highest advisory severity MEDIUM; version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-051 · 🟨 Medium (5.5) · Vulnerable direct dependency

- **What:** @angular/core@22.0.1: 1 known vulnerability (highest MEDIUM)
- **Component:** `@angular/core@22.0.1` (npm, scope prod, direct), purl `pkg:npm/%40angular/core@22.0.1`
- **Where:** `frontend/package.json`
- **Dependency path:** frontend@20.4.0-SNAPSHOT → @angular/core@22.0.1
- **Official severity:** MEDIUM (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 22.1.0
- **Evidence:**
  - [GHSA-hh8m-fm6v-7cvg](https://osv.dev/vulnerability/GHSA-hh8m-fm6v-7cvg) (CVE-2026-88057): MEDIUM, fixed in 22.1.0. Angular: Sanitization bypass via directive host bindings on concrete host elements in @angular/core and @angular/compiler
- **Initial risk:** Medium (5.5): highest advisory severity MEDIUM; version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-052 · 🟨 Medium (5.5) · Vulnerable transitive dependency

- **What:** base64url@0.0.6: 1 known vulnerability (highest MEDIUM)
- **Component:** `base64url@0.0.6` (npm, scope prod, transitive), purl `pkg:npm/base64url@0.0.6`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → jsonwebtoken@0.4.0 → jws@0.2.6 → base64url@0.0.6 ; juice-shop@20.4.0-SNAPSHOT → express-jwt@0.1.3 → jsonwebtoken@0.1.0 → jws@0.2.6 → base64url@0.0.6 ; juice-shop@20.4.0-SNAPSHOT → jsonwebtoken@0.4.0 → jws@0.2.6 → jwa@0.0.1 → base64url@0.0.6
- **Official severity:** MEDIUM (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 3.0.0
- **Evidence:**
  - [GHSA-rvg8-pwq2-xj7q](https://osv.dev/vulnerability/GHSA-rvg8-pwq2-xj7q): MEDIUM, fixed in 3.0.0. Out-of-bounds Read in base64url
- **Initial risk:** Medium (5.5): highest advisory severity MEDIUM; version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-053 · 🟨 Medium (5.5) · Vulnerable transitive dependency

- **What:** glob@10.5.0: 1 known vulnerability (highest MEDIUM)
- **Component:** `glob@10.5.0` (npm, scope dev, transitive), purl `pkg:npm/glob@10.5.0`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → @cyclonedx/cyclonedx-npm@2.0.0 → @cyclonedx/cyclonedx-library@7.1.0 → libxmljs2@0.35.0 → node-gyp@10.3.1 → glob@10.5.0 ; juice-shop@20.4.0-SNAPSHOT → @cyclonedx/cyclonedx-npm@2.0.0 → @cyclonedx/cyclonedx-library@7.1.0 → libxmljs2@0.35.0 → node-gyp@10.3.1 → make-fetch-happen@13.0.1 → cacache@18.0.4 → glob@10.5.0
- **Official severity:** MEDIUM (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 14.0.2
- **Evidence:**
  - [GHSA-3g3m-2fjr-6pw4](https://osv.dev/vulnerability/GHSA-3g3m-2fjr-6pw4) (CVE-2026-118773): MEDIUM, fixed in 14.0.2. Glob: AbortSignal cancellation bypass allows post-timeout filesystem traversal
- **Initial risk:** Medium (5.5): highest advisory severity MEDIUM; version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-054 · 🟨 Medium (5.5) · Vulnerable transitive dependency

- **What:** glob@13.0.7: 1 known vulnerability (highest MEDIUM)
- **Component:** `glob@13.0.7` (npm, scope prod, transitive), purl `pkg:npm/glob@13.0.7`
- **Where:** `frontend/package.json`
- **Dependency path:** frontend@20.4.0-SNAPSHOT → @angular/cli@22.0.1 → pacote@21.5.0 → @npmcli/package-json@7.0.5 → glob@13.0.7 ; frontend@20.4.0-SNAPSHOT → @angular/cli@22.0.1 → pacote@21.5.0 → cacache@20.0.4 → glob@13.0.7 ; frontend@20.4.0-SNAPSHOT → @angular/cli@22.0.1 → pacote@21.5.0 → @npmcli/run-script@10.0.4 → @npmcli/package-json@7.0.5 → glob@13.0.7
- **Official severity:** MEDIUM (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 14.0.2
- **Evidence:**
  - [GHSA-3g3m-2fjr-6pw4](https://osv.dev/vulnerability/GHSA-3g3m-2fjr-6pw4) (CVE-2026-118773): MEDIUM, fixed in 14.0.2. Glob: AbortSignal cancellation bypass allows post-timeout filesystem traversal
- **Initial risk:** Medium (5.5): highest advisory severity MEDIUM; version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-055 · 🟨 Medium (5.5) · Vulnerable transitive dependency

- **What:** minimatch@10.2.6: 1 known vulnerability (highest MEDIUM)
- **Component:** `minimatch@10.2.6` (npm, scope prod, transitive), purl `pkg:npm/minimatch@10.2.6`
- **Where:** `frontend/package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → typescript-eslint@8.57.1 → @typescript-eslint/typescript-estree@8.57.1 → minimatch@10.2.6 ; frontend@20.4.0-SNAPSHOT → angular-eslint@22.0.0 → @typescript-eslint/utils@8.72.2 → @typescript-eslint/typescript-estree@8.72.2 → minimatch@10.2.6 ; juice-shop@20.4.0-SNAPSHOT → neostandard@0.13.0 → typescript-eslint@8.72.2 → @typescript-eslint/typescript-estree@8.72.2 → minimatch@10.2.6
- **Official severity:** MEDIUM (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 11.0.1
- **Evidence:**
  - [GHSA-g3hv-75wg-m249](https://osv.dev/vulnerability/GHSA-g3hv-75wg-m249) (CVE-2026-118764): MEDIUM, fixed in 11.0.1. minimatch has potential denial of service via globparts amplification
- **Initial risk:** Medium (5.5): highest advisory severity MEDIUM; version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-056 · 🟨 Medium (5.5) · Vulnerable transitive dependency

- **What:** minimatch@9.0.9: 1 known vulnerability (highest MEDIUM)
- **Component:** `minimatch@9.0.9` (npm, scope dev, transitive), purl `pkg:npm/minimatch@9.0.9`
- **Where:** `frontend/package.json`
- **Dependency path:** frontend@20.4.0-SNAPSHOT → typescript-eslint@8.42.0 → @typescript-eslint/typescript-estree@8.42.0 → minimatch@9.0.9 ; frontend@20.4.0-SNAPSHOT → typescript-eslint@8.42.0 → @typescript-eslint/parser@8.42.0 → @typescript-eslint/typescript-estree@8.42.0 → minimatch@9.0.9 ; frontend@20.4.0-SNAPSHOT → typescript-eslint@8.42.0 → @typescript-eslint/utils@8.42.0 → @typescript-eslint/typescript-estree@8.42.0 → minimatch@9.0.9
- **Official severity:** MEDIUM (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 11.0.1
- **Evidence:**
  - [GHSA-g3hv-75wg-m249](https://osv.dev/vulnerability/GHSA-g3hv-75wg-m249) (CVE-2026-118764): MEDIUM, fixed in 11.0.1. minimatch has potential denial of service via globparts amplification
- **Initial risk:** Medium (5.5): highest advisory severity MEDIUM; version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-057 · 🟨 Medium (5.3) · Vulnerable transitive dependency

- **What:** @hono/node-server@1.19.18: 1 known vulnerability (highest MEDIUM, CVSS 5.3)
- **Component:** `@hono/node-server@1.19.18` (npm, scope prod, transitive), purl `pkg:npm/%40hono/node-server@1.19.18`
- **Where:** `frontend/package.json`
- **Dependency path:** frontend@20.4.0-SNAPSHOT → @angular/cli@22.0.1 → @modelcontextprotocol/sdk@1.29.0 → @hono/node-server@1.19.18
- **Official severity:** MEDIUM, CVSS 5.3 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 2.1.3
- **Evidence:**
  - [GHSA-rmxm-3fg6-px4f](https://osv.dev/vulnerability/GHSA-rmxm-3fg6-px4f) (CVE-2026-118663): MEDIUM, CVSS 5.3, fixed in 2.1.3. @hono/node-server: `serveStatic` decodes the request path a second time, leading to bypass of middleware on static paths
- **Initial risk:** Medium (5.3): highest advisory severity MEDIUM (CVSS 5.3); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-058 · 🟨 Medium (5.3) · Vulnerable direct dependency

- **What:** file-type@16.5.4: 1 known vulnerability (highest MEDIUM, CVSS 5.3)
- **Component:** `file-type@16.5.4` (npm, scope prod, direct), purl `pkg:npm/file-type@16.5.4`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → file-type@16.5.4
- **Official severity:** MEDIUM, CVSS 5.3 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 21.3.1
- **Evidence:**
  - [GHSA-5v7r-6r5c-r473](https://osv.dev/vulnerability/GHSA-5v7r-6r5c-r473) (CVE-2026-31808): MEDIUM, CVSS 5.3, fixed in 21.3.1. file-type affected by infinite loop in ASF parser on malformed input with zero-size sub-header
- **Initial risk:** Medium (5.3): highest advisory severity MEDIUM (CVSS 5.3); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-059 · 🟨 Medium (5.3) · Vulnerable direct dependency

- **What:** morgan@1.10.0: 3 known vulnerabilities (highest MEDIUM, CVSS 5.3)
- **Component:** `morgan@1.10.0` (npm, scope prod, direct), purl `pkg:npm/morgan@1.10.0`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → morgan@1.10.0
- **Official severity:** MEDIUM, CVSS 5.3 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.12.1
- **Evidence:**
  - [GHSA-4vj7-5mj6-jm8m](https://osv.dev/vulnerability/GHSA-4vj7-5mj6-jm8m) (CVE-2026-5078): MEDIUM, CVSS 5.3, fixed in 1.11.0. morgan vulnerable to Log Forging via unneutralized control characters in :remote-user
  - [GHSA-9f6g-j8ch-79g4](https://osv.dev/vulnerability/GHSA-9f6g-j8ch-79g4) (CVE-2026-87859): MEDIUM, CVSS 5.3, fixed in 1.12.1. morgan vulnerable to Log Injection via unescaped double quote in quoted log fields
  - [GHSA-jxfw-x594-9x9m](https://osv.dev/vulnerability/GHSA-jxfw-x594-9x9m) (CVE-2026-15603): MEDIUM, CVSS 5.3, fixed in 1.12.0. morgan vulnerable to Log Forging via unescaped Unicode line separators
- **Initial risk:** Medium (5.3): highest advisory severity MEDIUM (CVSS 5.3); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

### F-060 · 🟨 Medium (5.3) · Vulnerable transitive dependency

- **What:** qs@6.14.3: 4 known vulnerabilities (highest MEDIUM, CVSS 5.3)
- **Component:** `qs@6.14.3` (npm, scope prod, transitive), purl `pkg:npm/qs@6.14.3`
- **Where:** `package.json`
- **Dependency path:** juice-shop@20.4.0-SNAPSHOT → express@4.22.1 → qs@6.14.3
- **Official severity:** MEDIUM, CVSS 5.3 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 6.16.1
- **Evidence:**
  - [GHSA-4mjr-xmp4-gh2g](https://osv.dev/vulnerability/GHSA-4mjr-xmp4-gh2g) (CVE-2026-82417): MEDIUM, CVSS 5.3, fixed in 6.16.0. qs: Denial of Service via Attacker Controlled isBuffer
  - [GHSA-6pq8-jhm2-2vcw](https://osv.dev/vulnerability/GHSA-6pq8-jhm2-2vcw) (CVE-2026-110816): MEDIUM, CVSS 5.3, fixed in 6.16.1. qs : qs.stringify with arrayFormat 'comma' throws an uncaught TypeError on array elements carrying a non-callable own toString (DoS)
  - [GHSA-q8mj-m7cp-5q26](https://osv.dev/vulnerability/GHSA-q8mj-m7cp-5q26) (CVE-2026-8723): MEDIUM, CVSS 5.3, fixed in 6.15.2. qs has a remotely triggerable DoS: qs.stringify crashes with TypeError on null/undefined entries in comma-format arrays when encodeValuesOnly is set
  - [GHSA-x5fp-wj9c-mxmx](https://osv.dev/vulnerability/GHSA-x5fp-wj9c-mxmx) (CVE-2026-82562): LOW, CVSS 3.7, fixed in 6.16.0. qs array-limit bypass via bracket-key comma parsing
- **Initial risk:** Medium (5.3): highest advisory severity MEDIUM (CVSS 5.3); version estimated without a lockfile (deps.dev)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence medium

*23 more findings: full evidence in `findings.json`.*

## 5. Notes and limits

- frontend/package.json: no lockfile -> transitive deps resolved via deps.dev (approximate)
- package.json: no lockfile -> transitive deps resolved via deps.dev (approximate)
- what changed: base revision 'HEAD~1' not found (shallow clone or first commit), change analysis skipped
- graph.html limited to depth 2 + vulnerable paths (1814 nodes); use --focus/--max-depth
- Day 1 scope: visibility and detection. Reachability, exploitability (KEV/EPSS) and remediation are Day 2.
- Typosquat results are heuristic (name similarity) and need human review.
