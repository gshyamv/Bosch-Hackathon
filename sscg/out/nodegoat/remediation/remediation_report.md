# Guardian remediation report: nodegoat

*Run `ec853aa0ea2f` · 2026-11-24T06:04:58+00:00 · AI engine deepseek:deepseek-flash*

**Prioritized risk → Recommended fix → Human approval → Build & test → Rescan → Verification: partially verified**

## 1. Summary

- **Verdict:** **PARTIALLY VERIFIED** (confidence medium)
  - 6 targeted vulnerability finding(s) NOT resolved: the same advisories remain on the new version: F-071 qs@5.2.1 (GHSA-4mjr-xmp4-gh2g, GHSA-6rw7-vpxm-498p, GHSA-gqgv-6jq5-jjj9); F-008 minimist@0.0.10 (GHSA-vh95-rmgr-6w4m, GHSA-xvch-5gv4-984h); F-011 minimist@1.2.5 (GHSA-xvch-5gv4-984h); F-074 qs@6.5.2 (GHSA-4mjr-xmp4-gh2g, GHSA-6rw7-vpxm-498p, GHSA-hrpp-h998-j3pp)
  - 7/22 targeted finding(s) still present: F-009, F-010, F-025, F-026, F-092, F-031
- **Measured (rescan):** 141 findings before → 127 after · resolved 9 · new 1 · by level before/after: Critical 22→13, High 72→66, Medium 32→33, Low 15→15
- **Proposals:** 14 · pending 2 · approved 12
- **Validated patch:** `remediation.patch` (sha256 `8c7cf199a525acd8…`, validated 2026-11-24T11:34:58+0530): the exact change that was built and rescanned, including regenerated lockfiles

## 2. Prioritized risks

*Initial risk + signed points for exploitability (CISA KEV, EPSS), static reachability, exposure indicators and the triage verdict. Deterministic: the same input gives the same order. Confidence drops for every missing or weak signal.*

| Priority | Score | Finding | Component | Why | Confidence |
|---|---|---|---|---|---|
| P0 URGENT | 10.0 | F-001 fsevents@1.2.9 is a documented malicious package | fsevents@1.2.9 | install-time risk: runs on every install, whether or not code imports it | high |
| P0 | 10.8 | F-016 underscore@1.9.1: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | underscore@1.9.1 | EPSS 0.042 for CVE-2021-23358 (91% percentile); imported by application code: potentially reachable (config/config.js:1) (+0.5); production dependency; network-service indicators in the app (server.js:15 (Node HTTP server), Dockerfile:… | high |
| P1 | 10.3 | F-002 bson@1.0.9: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | bson@1.0.9 | EPSS 0.023 for CVE-2020-7610 (84% percentile); pulled in by an imported dependency: potentially reachable; production dependency; network-service indicators in the app (server.js:15 (Node HTTP server), Dockerfile: EXPOSE 4000) (+0.5) | high |
| P1 | 10.3 | F-008 minimist@0.0.10: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | minimist@0.0.10 | EPSS 0.046 for CVE-2021-44906 (92% percentile); pulled in by an imported dependency: potentially reachable; production dependency; network-service indicators in the app (server.js:15 (Node HTTP server), Dockerfile: EXPOSE 4000) (+0.5) | high |
| P1 | 10.3 | F-009 minimist@0.0.8: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | minimist@0.0.8 | EPSS 0.046 for CVE-2021-44906 (92% percentile); pulled in by an imported dependency: potentially reachable; production dependency; network-service indicators in the app (server.js:15 (Node HTTP server), Dockerfile: EXPOSE 4000) (+0.5) | high |
| P1 | 10.3 | F-013 set-value@0.4.3: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | set-value@0.4.3 | EPSS 0.025 for CVE-2019-10747 (85% percentile); pulled in by an imported dependency: potentially reachable; production dependency; network-service indicators in the app (server.js:15 (Node HTTP server), Dockerfile: EXPOSE 4000) (+0.5) | high |
| P1 | 10.3 | F-014 set-value@2.0.0: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | set-value@2.0.0 | EPSS 0.025 for CVE-2019-10747 (85% percentile); pulled in by an imported dependency: potentially reachable; production dependency; network-service indicators in the app (server.js:15 (Node HTTP server), Dockerfile: EXPOSE 4000) (+0.5) | high |
| P1 | 9.3 | F-003 fsevents@1.2.9: 1 known vulnerability (highest CRITICAL, CVSS 9.8) | fsevents@1.2.9 | EPSS 0.017 for CVE-2023-45311 (78% percentile); no import found in application code (static check; it may still be loaded dynamically or by build tools) (-1); production dependency; network-service indicators in the app (server.js:15… | high |
| P1 | 9.3 | F-011 minimist@1.2.5: 1 known vulnerability (highest CRITICAL, CVSS 9.8) | minimist@1.2.5 | EPSS 0.046 for CVE-2021-44906 (92% percentile); no import found in application code (static check; it may still be loaded dynamically or by build tools) (-1); production dependency; network-service indicators in the app (server.js:15… | high |
| P1 | 9.3 | F-012 mixin-deep@1.3.1: 1 known vulnerability (highest CRITICAL, CVSS 9.8) | mixin-deep@1.3.1 | EPSS 0.037 for CVE-2019-10746 (90% percentile); no import found in application code (static check; it may still be loaded dynamically or by build tools) (-1); production dependency; network-service indicators in the app (server.js:15… | high |
| P1 | 9.1 | F-022 proxy-addr@2.0.4: 1 known vulnerability (highest CRITICAL, CVSS 9.1) | proxy-addr@2.0.4 | EPSS 0.003 for CVE-2026-90711 (18% percentile) (-0.5); pulled in by an imported dependency: potentially reachable; production dependency; network-service indicators in the app (server.js:15 (Node HTTP server), Dockerfile: EXPOSE 4000)… | high |
| P1 | 9.0 | F-033 mongodb@2.2.36: 1 known vulnerability (highest HIGH) | mongodb@2.2.36 | no CVE alias: exploitability data not available; imported by application code: potentially reachable (server.js:11, artifacts/db-reset.js:9) (+0.5); production dependency; network-service indicators in the app (server.js:15 (Node HTTP… | medium (no CVE) |
| P1 | 8.8 | F-015 underscore@1.8.3: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | underscore@1.8.3 | EPSS 0.042 for CVE-2021-23358 (91% percentile); imported by application code: potentially reachable (config/config.js:1) (+0.5); dev-only dependency: not shipped, but it runs on developer / CI machines (-1.5) | high |
| P1 | 8.8 | F-026 tar@4.4.8: 18 known vulnerabilities (highest HIGH, CVSS 8.8) | tar@4.4.8 | EPSS 0.151 for CVE-2021-32804 (97% percentile) (+0.5); no import found in application code (static check; it may still be loaded dynamically or by build tools) (-1); production dependency; network-service indicators in the app… | high |
| P1 | 8.8 | F-092 y18n@3.2.1: 1 known vulnerability (highest HIGH, CVSS 7.3) | y18n@3.2.1 | EPSS 0.696 for CVE-2020-7774 (99% percentile) (+1); pulled in by an imported dependency: potentially reachable; production dependency; network-service indicators in the app (server.js:15 (Node HTTP server), Dockerfile: EXPOSE 4000) (+0.5) | high |
| P1 | 8.5 | F-031 grunt-if@0.2.0 is downloaded from github.com, not the npm registry | grunt-if@0.2.0 | install-time risk: runs on every install, whether or not code imports it; triage: suspicious, medium confidence (AI inference) (+0.5) | high |
| P1 | 8.5 | F-061 marked@0.3.5: 6 known vulnerabilities (highest HIGH, CVSS 7.5) | marked@0.3.5 | EPSS 0.030 for CVE-2022-21680 (88% percentile); imported by application code: potentially reachable (server.js:13) (+0.5); production dependency; network-service indicators in the app (server.js:15 (Node HTTP server), Dockerfile: EXPOSE… | high |
| P1 | 8.5 | F-074 qs@6.5.2: 3 known vulnerabilities (highest HIGH, CVSS 7.5) | qs@6.5.2 | EPSS 0.200 for CVE-2022-24999 (98% percentile) (+0.5); pulled in by an imported dependency: potentially reachable; production dependency; network-service indicators in the app (server.js:15 (Node HTTP server), Dockerfile: EXPOSE 4000)… | high |
| P1 | 8.5 | F-079 swig@1.4.2: 1 known vulnerability (highest HIGH, CVSS 7.5) | swig@1.4.2 | EPSS 0.011 for CVE-2023-25345 (65% percentile); imported by application code: potentially reachable (server.js:9) (+0.5); production dependency; network-service indicators in the app (server.js:15 (Node HTTP server), Dockerfile: EXPOSE… | high |
| P2 | 8.3 | F-006 handlebars@4.0.5: 20 known vulnerabilities (highest CRITICAL, CVSS 9.8) | handlebars@4.0.5 | EPSS 0.071 for CVE-2019-19919 (94% percentile); pulled in by an imported dependency: potentially reachable; dev-only dependency: not shipped, but it runs on developer / CI machines (-1.5) | high |
| | | *121 more in remediation.json* | | | |

## 3. Recommended fixes and decisions

*The diff under each proposal is what the reviewer approved (manifest and file edits). Lockfiles are regenerated from the official registry during validation; the validated patch (section 4) contains them.*

### P-001 · PENDING · remove · fsevents@1.2.9

- **Findings:** F-001 fsevents@1.2.9 is a documented malicious package; F-003 fsevents@1.2.9: 1 known vulnerability (highest CRITICAL, CVSS 9.8); F-135 fsevents@1.2.9 runs an install script (code not inspected)
- **Change:** 1.2.9 → - in `package.json`
- **Why (verified facts):** fsevents@1.2.9 is a documented malicious package; remove it.
- **Advisor (AI inference):** P-001 removes fsevents@1.2.9 because F-001 documents it as a malicious package, F-003 reports a critical vulnerability, and F-135 flags an uninspected install script. The packet rates compatibility as low since fsevents is not imported by application code, and residual_status is checked with no residual advisories listed. The trade-off is that rollback must never restore the removed package, so any build break should be handled without reintroducing fsevents@1.2.9.
- **Reviewer checklist (AI inference):** Confirm no application code imports or requires fsevents and that the build succeeds without it. · Verify fsevents@1.2.9 is absent from package.json and the regenerated package-lock.json, and that no install script from it remains. · Ensure any rollback follows the packet guidance and never restores fsevents@1.2.9.
- **Expected risk reduction (estimate before validation):** removes the malicious / typosquatted package and its install-time code; resolves 3 finding(s)
- **Compatibility:** low: fsevents is not imported by application code
- **Rollback:** do NOT roll back to the removed package; revert only if the replacement breaks the build
- **Decision:** defer by user1 at 2026-11-24T06:03:40+00:00: not decided (proposal sha256 `6ec873523d12…`)

```diff
# + package-lock.json regenerated from the registry during validation (npm --package-lock-only)
```

### P-002 · APPROVED · upgrade · underscore@1.8.3, 1.9.1

- **Findings:** F-015 underscore@1.8.3: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8); F-016 underscore@1.9.1: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Change:** 1.8.3, 1.9.1 → 1.13.8 in `package.json`
- **Why (verified facts):** Upgrade and make the transitive copies use the direct dependency's version underscore 1.8.3, 1.9.1 -> 1.13.8: fixes the 2 published advisories on 1.8.3, 1.9.1; no known advisories remain on the target.
- **Advisor (AI inference):** P-002 upgrades underscore from 1.8.3 and 1.9.1 to 1.13.8, addressing F-015 on the transitive copy and F-016 on the direct dependency. The packet rates compatibility as medium for the minor version change and states residual_status is checked with no residual advisories on the target. The main trade-off is validating that both the direct dependency and overridden transitive copies behave correctly at 1.13.8.
- **Reviewer checklist (AI inference):** Run the test suite with attention to code paths that use underscore, since this is a medium-compatibility minor upgrade. · Verify package.json pins underscore to 1.13.8 with the "$underscore" override and that the regenerated lockfile resolves both former versions to 1.13.8. · Confirm no known residual advisories remain after the lockfile regeneration, per the packet's checked residual_status.
- **Expected risk reduction (estimate before validation):** expected: the 2 advisories of 1.8.3, 1.9.1 are fixed in 1.13.8; 0 other advisory(ies) on 1.13.8 · targets 2 finding(s)
- **Compatibility:** medium: minor version change (1.8.3, 1.9.1 -> 1.13.8)
- **Rollback:** restore underscore 1.8.3, 1.9.1 in package.json (and the lockfile) by reverting the remediation commit
- **Decision:** approve by user1 at 2026-11-24T06:03:40+00:00: decided in the dashboard (proposal sha256 `619296ad5ea8…`)
- **Validation (measured):** resolved (2/2 targeted findings resolved) · execution: tested

```diff
--- a/package.json
+++ b/package.json
@@ -20,7 +20,7 @@
     "node-esapi": "0.0.1",
     "serve-favicon": "^2.3.0",
     "swig": "^1.4.2",
-    "underscore": "^1.8.3"
+    "underscore": "1.13.8"
   },
   "comments": {
     "//": "a9 insecure components"
@@ -61,5 +61,8 @@
     "zaproxy": "^0.2.0"
   },
   "repository": "https://github.com/OWASP/NodejsGoat",
-  "license": "Apache 2.0"
+  "license": "Apache 2.0",
+  "overrides": {
+    "underscore": "$underscore"
+  }
 }
# + package-lock.json regenerated from the registry during validation (npm --package-lock-only)
```

### P-003 · APPROVED · upgrade · bson@1.0.9

- **Findings:** F-002 bson@1.0.9: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Change:** 1.0.9 → 1.1.4 in `package.json`
- **Why (verified facts):** Override the transitive copies bson 1.0.9 -> 1.1.4: fixes the 2 published advisories on 1.0.9; no known advisories remain on the target.
- **Advisor (AI inference):** P-003 upgrades bson from 1.0.9 to 1.1.4 to address F-002, which reports two known vulnerabilities with a critical CVSS of 9.8. The packet rates compatibility as medium for the minor version change and records residual_status as checked with no residual advisories. The trade-off is that callers consuming bson must be exercised to catch any minor-version behavior changes.
- **Reviewer checklist (AI inference):** Run tests covering code paths that consume bson, especially serialization and deserialization behavior. · Verify the override pins bson to 1.1.4 and that the regenerated lockfile no longer contains bson@1.0.9. · Confirm the post-upgrade lockfile shows no known residual advisories for bson, consistent with the packet's checked residual_status.
- **Expected risk reduction (estimate before validation):** expected: the 2 advisories of 1.0.9 are fixed in 1.1.4; 0 other advisory(ies) on 1.1.4 · targets 1 finding(s)
- **Compatibility:** medium: minor version change (1.0.9 -> 1.1.4)
- **Rollback:** restore bson 1.0.9 in package.json (and the lockfile) by reverting the remediation commit
- **Decision:** approve by user1 at 2026-11-24T06:03:40+00:00: decided in the dashboard (proposal sha256 `3f392c92a902…`)
- **Validation (measured):** resolved (1/1 targeted findings resolved) · execution: tested

```diff
--- a/package.json
+++ b/package.json
@@ -61,5 +61,8 @@
     "zaproxy": "^0.2.0"
   },
   "repository": "https://github.com/OWASP/NodejsGoat",
-  "license": "Apache 2.0"
+  "license": "Apache 2.0",
+  "overrides": {
+    "bson": "1.1.4"
+  }
 }
# + package-lock.json regenerated from the registry during validation (npm --package-lock-only)
```

### P-004 · APPROVED · upgrade · minimist@0.0.8, 0.0.10, 1.2.0, 1.2.5

- **Findings:** F-008 minimist@0.0.10: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8); F-009 minimist@0.0.8: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8); F-010 minimist@1.2.0: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8); F-011 minimist@1.2.5: 1 known vulnerability (highest CRITICAL, CVSS 9.8)
- **Change:** 0.0.8, 0.0.10, 1.2.0, 1.2.5 → 1.2.6 in `package.json`
- **Why (verified facts):** Override the transitive copies minimist 0.0.8, 0.0.10, 1.2.0, 1.2.5 -> 1.2.6: fixes the 2 published advisories on 0.0.8, 0.0.10, 1.2.0, 1.2.5; no known advisories remain on the target.
- **Advisor (AI inference):** P-004 overrides minimist 0.0.8, 0.0.10, 1.2.0, and 1.2.5 to 1.2.6, addressing F-008, F-009, F-010, and F-011. The packet flags this as high compatibility risk because it spans major versions, while residual_status is checked with no residual advisories listed on the target. The trade-off is accepting possible breaking API behavior in exchange for removing the vulnerable copies.
- **Reviewer checklist (AI inference):** Run the full test suite and specifically exercise code paths that consume minimist, because the packet rates compatibility as high with possible breaking API changes. · Verify the override pins minimist to 1.2.6 and that the regenerated lockfile resolves all four former versions to 1.2.6. · Confirm no known residual advisories remain after regeneration, per the packet's checked residual_status.
- **Expected risk reduction (estimate before validation):** expected: the 2 advisories of 0.0.8, 0.0.10, 1.2.0, 1.2.5 are fixed in 1.2.6; 0 other advisory(ies) on 1.2.6 · targets 4 finding(s)
- **Compatibility:** high: major version change (0.0.8, 0.0.10, 1.2.0, 1.2.5 -> 1.2.6): breaking API changes are possible, run the tests
- **Rollback:** restore minimist 0.0.8, 0.0.10, 1.2.0, 1.2.5 in package.json (and the lockfile) by reverting the remediation commit
- **Notes:** some copies of minimist are bundled inside fsevents, rc, mkdirp (bundleDependencies): npm overrides cannot change them; upgrade fsevents (or the package that pulls it in)
- **Decision:** approve by user1 at 2026-11-24T06:03:40+00:00: decided in the dashboard (proposal sha256 `7cda233a8666…`)
- **Validation (measured):** not resolved (0/4 targeted findings resolved) · execution: tested; advisories still present on the new version: F-008 GHSA-vh95-rmgr-6w4m, GHSA-xvch-5gv4-984h; F-011 GHSA-xvch-5gv4-984h

```diff
--- a/package.json
+++ b/package.json
@@ -61,5 +61,8 @@
     "zaproxy": "^0.2.0"
   },
   "repository": "https://github.com/OWASP/NodejsGoat",
-  "license": "Apache 2.0"
+  "license": "Apache 2.0",
+  "overrides": {
+    "minimist": "1.2.6"
+  }
 }
# + package-lock.json regenerated from the registry during validation (npm --package-lock-only)
```

### P-005 · APPROVED · upgrade · set-value@0.4.3, 2.0.0

- **Findings:** F-013 set-value@0.4.3: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8); F-014 set-value@2.0.0: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Change:** 0.4.3, 2.0.0 → 2.0.1 in `package.json`
- **Why (verified facts):** Override the transitive copies set-value 0.4.3, 2.0.0 -> 2.0.1: fixes the 2 published advisories on 0.4.3, 2.0.0; no known advisories remain on the target.
- **Advisor (AI inference):** P-005 upgrades set-value from 0.4.3 and 2.0.0 to 2.0.1, addressing F-013 and F-014. The packet rates compatibility as high because 0.4.3 moves across major versions to 2.0.1 and residual_status is checked with no residual advisories listed. The trade-off is that breaking API changes are possible and must be covered by testing.
- **Reviewer checklist (AI inference):** Run tests for code paths that consume set-value, with extra attention to behavior changed by the major-version jump from 0.4.3 to 2.0.1. · Verify the override pins set-value to 2.0.1 and that the regenerated lockfile no longer contains 0.4.3 or 2.0.0. · Confirm no known residual advisories remain after regeneration, per the packet's checked residual_status.
- **Expected risk reduction (estimate before validation):** expected: the 2 advisories of 0.4.3, 2.0.0 are fixed in 2.0.1; 0 other advisory(ies) on 2.0.1 · targets 2 finding(s)
- **Compatibility:** high: major version change (0.4.3, 2.0.0 -> 2.0.1): breaking API changes are possible, run the tests
- **Rollback:** restore set-value 0.4.3, 2.0.0 in package.json (and the lockfile) by reverting the remediation commit
- **Decision:** approve by user1 at 2026-11-24T06:03:40+00:00: decided in the dashboard (proposal sha256 `cbeb33a7070b…`)
- **Validation (measured):** resolved (2/2 targeted findings resolved) · execution: tested

```diff
--- a/package.json
+++ b/package.json
@@ -61,5 +61,8 @@
     "zaproxy": "^0.2.0"
   },
   "repository": "https://github.com/OWASP/NodejsGoat",
-  "license": "Apache 2.0"
+  "license": "Apache 2.0",
+  "overrides": {
+    "set-value": "2.0.1"
+  }
 }
# + package-lock.json regenerated from the registry during validation (npm --package-lock-only)
```

### P-006 · APPROVED · upgrade · mixin-deep@1.3.1

- **Findings:** F-012 mixin-deep@1.3.1: 1 known vulnerability (highest CRITICAL, CVSS 9.8)
- **Change:** 1.3.1 → 1.3.2 in `package.json`
- **Why (verified facts):** Override the transitive copies mixin-deep 1.3.1 -> 1.3.2: fixes the 1 published advisories on 1.3.1; no known advisories remain on the target.
- **Advisor (AI inference):** P-006 upgrades mixin-deep from 1.3.1 to 1.3.2 to address F-012. The packet rates compatibility as low for this patch version change and records residual_status as checked with no residual advisories on the target. The trade-off is minimal, but the override and regenerated lockfile should still be validated.
- **Reviewer checklist (AI inference):** Run the test suite, focusing on code paths that consume mixin-deep, even though this is a low-risk patch upgrade. · Verify the override pins mixin-deep to 1.3.2 and that the regenerated lockfile no longer contains mixin-deep@1.3.1. · Confirm no known residual advisories remain after regeneration, per the packet's checked residual_status.
- **Expected risk reduction (estimate before validation):** expected: the 1 advisories of 1.3.1 are fixed in 1.3.2; 0 other advisory(ies) on 1.3.2 · targets 1 finding(s)
- **Compatibility:** low: patch version change (1.3.1 -> 1.3.2)
- **Rollback:** restore mixin-deep 1.3.1 in package.json (and the lockfile) by reverting the remediation commit
- **Decision:** approve by user1 at 2026-11-24T06:03:40+00:00: decided in the dashboard (proposal sha256 `501f2b49aa67…`)
- **Validation (measured):** resolved (1/1 targeted findings resolved) · execution: tested

```diff
--- a/package.json
+++ b/package.json
@@ -61,5 +61,8 @@
     "zaproxy": "^0.2.0"
   },
   "repository": "https://github.com/OWASP/NodejsGoat",
-  "license": "Apache 2.0"
+  "license": "Apache 2.0",
+  "overrides": {
+    "mixin-deep": "1.3.2"
+  }
 }
# + package-lock.json regenerated from the registry during validation (npm --package-lock-only)
```

### P-007 · APPROVED · upgrade · proxy-addr@2.0.4

- **Findings:** F-022 proxy-addr@2.0.4: 1 known vulnerability (highest CRITICAL, CVSS 9.1)
- **Change:** 2.0.4 → 2.0.8 in `package.json`
- **Why (verified facts):** Override the transitive copies proxy-addr 2.0.4 -> 2.0.8: fixes the 1 published advisories on 2.0.4; no known advisories remain on the target.
- **Advisor (AI inference):** P-007 upgrades the transitive copy of proxy-addr 2.0.4 to 2.0.8 via a package.json override, addressing the one critical advisory on 2.0.4 reported in F-022 (CVSS 9.1). The change is a patch-level bump with low compatibility risk and the planner reports no residual advisories on 2.0.8 (residual_status checked). The trade-off is minimal, though the override pins all transitive consumers of proxy-addr to 2.0.8 regardless of their declared ranges.
- **Reviewer checklist (AI inference):** Confirm the regenerated package-lock.json resolves proxy-addr to 2.0.8 for every dependent path, not just the top-level entry. · Run the test suite and smoke-test HTTP request handling through Express, since proxy-addr parses forwarded headers. · Verify no other override or dependency expects a proxy-addr version incompatible with the 2.0.x line.
- **Expected risk reduction (estimate before validation):** expected: the 1 advisories of 2.0.4 are fixed in 2.0.8; 0 other advisory(ies) on 2.0.8 · targets 1 finding(s)
- **Compatibility:** low: patch version change (2.0.4 -> 2.0.8)
- **Rollback:** restore proxy-addr 2.0.4 in package.json (and the lockfile) by reverting the remediation commit
- **Decision:** approve by user1 at 2026-11-24T06:03:40+00:00: decided in the dashboard (proposal sha256 `9049b53c8942…`)
- **Validation (measured):** resolved (1/1 targeted findings resolved) · execution: tested

```diff
--- a/package.json
+++ b/package.json
@@ -61,5 +61,8 @@
     "zaproxy": "^0.2.0"
   },
   "repository": "https://github.com/OWASP/NodejsGoat",
-  "license": "Apache 2.0"
+  "license": "Apache 2.0",
+  "overrides": {
+    "proxy-addr": "2.0.8"
+  }
 }
# + package-lock.json regenerated from the registry during validation (npm --package-lock-only)
```

### P-008 · APPROVED · upgrade · mongodb@2.2.36

- **Findings:** F-033 mongodb@2.2.36: 1 known vulnerability (highest HIGH)
- **Change:** 2.2.36 → 3.1.13 in `package.json`
- **Why (verified facts):** Upgrade mongodb 2.2.36 -> 3.1.13: fixes the 1 published advisories on 2.2.36; no known advisories remain on the target.
- **Advisor (AI inference):** P-008 upgrades the direct dependency mongodb 2.2.36 to 3.1.13 to clear the single HIGH advisory cited in F-033, with no known residual advisories on the target. This is a major version jump flagged as high compatibility risk, so breaking driver API changes are plausible and test coverage is the main safeguard. The trade-off is accepting migration work in exchange for removing the known vulnerability from a directly used library.
- **Reviewer checklist (AI inference):** Run the full test suite and exercise all database connection, query and write paths used by the application against the 3.x driver. · Check application code for driver 2.x API usage (e.g. connection options, collection/cursor APIs) that changed in 3.x. · Verify the application still connects to the deployed MongoDB server version with the 3.1.13 driver in a staging environment.
- **Expected risk reduction (estimate before validation):** expected: the 1 advisories of 2.2.36 are fixed in 3.1.13; 0 other advisory(ies) on 3.1.13 · targets 1 finding(s)
- **Compatibility:** high: major version change (2.2.36 -> 3.1.13): breaking API changes are possible, run the tests
- **Rollback:** restore mongodb 2.2.36 in package.json (and the lockfile) by reverting the remediation commit
- **Decision:** approve by user1 at 2026-11-24T06:03:40+00:00: decided in the dashboard (proposal sha256 `608da7cc28ee…`)
- **Validation (measured):** resolved (1/1 targeted findings resolved) · execution: tested

```diff
--- a/package.json
+++ b/package.json
@@ -15,7 +15,7 @@
     "forever": "^2.0.0",
     "helmet": "^2.0.0",
     "marked": "0.3.5",
-    "mongodb": "^2.1.18",
+    "mongodb": "3.1.13",
     "needle": "2.2.4",
     "node-esapi": "0.0.1",
     "serve-favicon": "^2.3.0",
# + package-lock.json regenerated from the registry during validation (npm --package-lock-only)
```

### P-009 · APPROVED · upgrade · tar@2.2.1, 4.4.8

- **Findings:** F-025 tar@2.2.1: 16 known vulnerabilities (highest HIGH, CVSS 8.8); F-026 tar@4.4.8: 18 known vulnerabilities (highest HIGH, CVSS 8.8)
- **Change:** 2.2.1, 4.4.8 → 7.5.21 in `package.json`
- **Why (verified facts):** Override the transitive copies tar 2.2.1, 4.4.8 -> 7.5.21: fixes the 19 published advisories on 2.2.1, 4.4.8; no known advisories remain on the target.
- **Advisor (AI inference):** P-009 resolves both transitive tar copies (2.2.1 and 4.4.8) to 7.5.21 through an override, clearing the numerous advisories in F-025 and F-026 (highest HIGH, CVSS 8.8) with no known residual advisories on the target. This is a multi-major jump flagged as high compatibility risk, and tar is typically consumed by build/install tooling, so the trade-off is possible breakage in packaging-related scripts. The override forces all transitive consumers onto 7.5.21 regardless of their declared ranges.
- **Reviewer checklist (AI inference):** Confirm the regenerated lockfile no longer contains tar 2.2.1 or 4.4.8 anywhere in the dependency tree. · Exercise any build, archive or packaging scripts that depend on tar (including npm install behavior) to confirm they still work with 7.x. · Verify no dependent package's code relies on tar APIs removed between 2.x/4.x and 7.x.
- **Expected risk reduction (estimate before validation):** expected: the 19 advisories of 2.2.1, 4.4.8 are fixed in 7.5.21; 0 other advisory(ies) on 7.5.21 · targets 2 finding(s)
- **Compatibility:** high: major version change (2.2.1, 4.4.8 -> 7.5.21): breaking API changes are possible, run the tests
- **Rollback:** restore tar 2.2.1, 4.4.8 in package.json (and the lockfile) by reverting the remediation commit
- **Notes:** some copies of tar are bundled inside fsevents, npm (bundleDependencies): npm overrides cannot change them; upgrade fsevents (or the package that pulls it in)
- **Decision:** approve by user1 at 2026-11-24T06:03:40+00:00: decided in the dashboard (proposal sha256 `dd295433c9a7…`)
- **Validation (measured):** not resolved (0/2 targeted findings resolved) · execution: tested

```diff
--- a/package.json
+++ b/package.json
@@ -61,5 +61,8 @@
     "zaproxy": "^0.2.0"
   },
   "repository": "https://github.com/OWASP/NodejsGoat",
-  "license": "Apache 2.0"
+  "license": "Apache 2.0",
+  "overrides": {
+    "tar": "7.5.21"
+  }
 }
# + package-lock.json regenerated from the registry during validation (npm --package-lock-only)
```

### P-010 · APPROVED · upgrade · y18n@3.2.1

- **Findings:** F-092 y18n@3.2.1: 1 known vulnerability (highest HIGH, CVSS 7.3)
- **Change:** 3.2.1 → 3.2.2 in `package.json`
- **Why (verified facts):** Override the transitive copies y18n 3.2.1 -> 3.2.2: fixes the 1 published advisories on 3.2.1; no known advisories remain on the target.
- **Advisor (AI inference):** P-010 overrides the transitive y18n 3.2.1 to 3.2.2, a patch-level change that fixes the single HIGH advisory in F-092 (CVSS 7.3), and the planner reports no known residual advisories on the target. Compatibility risk is low because the API surface is unchanged across the patch, and y18n is typically pulled in via CLI tooling rather than application runtime code. The trade-off is limited to pinning transitive consumers to 3.2.2.
- **Reviewer checklist (AI inference):** Confirm the regenerated lockfile resolves y18n to 3.2.2 for all dependents and no 3.2.1 copy remains. · Run the test suite and any CLI tooling that uses y18n to confirm output and locale handling are unaffected. · Check that no dependent requires a y18n version outside the 3.2.x line that the override would conflict with.
- **Expected risk reduction (estimate before validation):** expected: the 1 advisories of 3.2.1 are fixed in 3.2.2; 0 other advisory(ies) on 3.2.2 · targets 1 finding(s)
- **Compatibility:** low: patch version change (3.2.1 -> 3.2.2)
- **Rollback:** restore y18n 3.2.1 in package.json (and the lockfile) by reverting the remediation commit
- **Notes:** some copies of y18n are bundled inside nyc (bundleDependencies): npm overrides cannot change them; upgrade nyc (or the package that pulls it in)
- **Decision:** approve by user1 at 2026-11-24T06:03:40+00:00: decided in the dashboard (proposal sha256 `7dd4f2dde036…`)
- **Validation (measured):** not resolved (0/1 targeted findings resolved) · execution: tested

```diff
--- a/package.json
+++ b/package.json
@@ -61,5 +61,8 @@
     "zaproxy": "^0.2.0"
   },
   "repository": "https://github.com/OWASP/NodejsGoat",
-  "license": "Apache 2.0"
+  "license": "Apache 2.0",
+  "overrides": {
+    "y18n": "3.2.2"
+  }
 }
# + package-lock.json regenerated from the registry during validation (npm --package-lock-only)
```

### P-011 · APPROVED · pin · grunt-if@0.2.0

- **Findings:** F-031 grunt-if@0.2.0 is downloaded from github.com, not the npm registry
- **Change:** 0.2.0 → 0.2.0 in `package-lock.json`
- **Why (verified facts):** grunt-if@0.2.0: restore the base commit's lockfile entry (https://github.com/binarymist/grunt-if/tarball/master), so the verified tarball is installed again.
- **Advisor (AI inference):** P-011 is a pin rather than a version change: it restores the base-commit lockfile entry for grunt-if 0.2.0 so the verified tarball from github.com is installed again, addressing the modified-lockfile finding F-031. Because the version is unchanged, there is no code change and no residual advisories are recorded (residual_status checked). The trade-off is that the dependency continues to be sourced from GitHub rather than the npm registry, which the approver should be aware of.
- **Reviewer checklist (AI inference):** Confirm the lockfile entry for grunt-if again points to https://github.com/binarymist/grunt-if/tarball/master and matches the base commit. · Verify a clean install (npm ci) fetches the expected tarball and that the resolved integrity hash is stable. · Note for the approver: this package is still sourced from GitHub, not the npm registry, so future lockfile drift should be monitored.
- **Expected risk reduction (estimate before validation):** resolves 1 finding(s)
- **Compatibility:** low: same version, verified source: no code change
- **Rollback:** none needed (same version)
- **Decision:** approve by user1 at 2026-11-24T06:03:40+00:00: decided in the dashboard (proposal sha256 `5eae328e2868…`)
- **Validation (measured):** not resolved (0/1 targeted findings resolved) · execution: tested

### P-012 · APPROVED · upgrade · marked@0.3.5

- **Findings:** F-061 marked@0.3.5: 6 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Change:** 0.3.5 → 4.0.10 in `package.json`
- **Why (verified facts):** Upgrade marked 0.3.5 -> 4.0.10: fixes the 6 published advisories on 0.3.5; no known advisories remain on the target.
- **Advisor (AI inference):** P-012 upgrades the direct dependency marked 0.3.5 to 4.0.10, clearing the six advisories reported in F-061 (highest HIGH, CVSS 7.5); the planner reports no known residual advisories on the target. This is a major version change with high compatibility risk, since marked's API and rendering behavior changed substantially across versions. The trade-off is potential rendering differences or code changes in exchange for removing the known vulnerabilities.
- **Reviewer checklist (AI inference):** Run the test suite and exercise every place the application renders Markdown with marked, checking output for API or formatting changes. · Review application code for marked 0.x API usage (options, renderer callbacks) that changed in 4.x. · Sanity-check that any user-supplied Markdown rendering paths still behave correctly and securely after the upgrade.
- **Expected risk reduction (estimate before validation):** expected: the 6 advisories of 0.3.5 are fixed in 4.0.10; 0 other advisory(ies) on 4.0.10 · targets 1 finding(s)
- **Compatibility:** high: major version change (0.3.5 -> 4.0.10): breaking API changes are possible, run the tests
- **Rollback:** restore marked 0.3.5 in package.json (and the lockfile) by reverting the remediation commit
- **Decision:** approve by user1 at 2026-11-24T06:03:40+00:00: decided in the dashboard (proposal sha256 `ddbf59e2f403…`)
- **Validation (measured):** resolved (1/1 targeted findings resolved) · execution: tested

```diff
--- a/package.json
+++ b/package.json
@@ -14,7 +14,7 @@
     "express-session": "^1.13.0",
     "forever": "^2.0.0",
     "helmet": "^2.0.0",
-    "marked": "0.3.5",
+    "marked": "4.0.10",
     "mongodb": "^2.1.18",
     "needle": "2.2.4",
     "node-esapi": "0.0.1",
# + package-lock.json regenerated from the registry during validation (npm --package-lock-only)
```

### P-013 · APPROVED · upgrade · qs@0.6.6, 5.2.1, 6.2.1, 6.3.2, 6.5.2

- **Findings:** F-070 qs@0.6.6: 5 known vulnerabilities (highest HIGH, CVSS 7.5); F-071 qs@5.2.1: 4 known vulnerabilities (highest HIGH, CVSS 7.5); F-072 qs@6.2.1: 4 known vulnerabilities (highest HIGH, CVSS 7.5); F-073 qs@6.3.2: 3 known vulnerabilities (highest HIGH, CVSS 7.5); F-074 qs@6.5.2: 3 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Change:** 0.6.6, 5.2.1, 6.2.1, 6.3.2, 6.5.2 → 6.16.1 in `package.json`
- **Why (verified facts):** Override the transitive copies qs 0.6.6, 5.2.1, 6.2.1, 6.3.2, 6.5.2 -> 6.16.1: fixes the 6 published advisories on 0.6.6, 5.2.1, 6.2.1, 6.3.2, 6.5.2; no known advisories remain on the target.
- **Advisor (AI inference):** P-013 consolidates five vulnerable transitive copies of qs (0.6.6, 5.2.1, 6.2.1, 6.3.2, 6.5.2) to a single 6.16.1 via a package.json overrides entry; this directly addresses findings F-070 through F-074, each reporting HIGH-severity advisories (CVSS 7.5) on those copies. The planner records residual_advisories as empty with residual_status "checked", so no known advisories remain on the target. The trade-off is a major-version jump for several of these copies, so breaking API changes are possible and the existing test suite must confirm behavior before merge.
- **Reviewer checklist (AI inference):** Run the full test suite (and any integration tests exercising libraries that consumed qs 0.6.6/5.2.1/6.2.1/6.3.2/6.5.2) to catch breaking API changes from the major-version jump described in the compa · Verify the regenerated package-lock.json actually resolves every former copy to 6.16.1 and that no nested qs@0.6.6/5.2.1/6.2.1/6.3.2/6.5.2 remains installed (npm ls qs). · Confirm the override does not break other direct or transitive consumers of qs, and confirm the rollback path (reverting the remediation commit to restore the prior qs versions in package.json and the
- **Expected risk reduction (estimate before validation):** expected: the 6 advisories of 0.6.6, 5.2.1, 6.2.1, 6.3.2, 6.5.2 are fixed in 6.16.1; 0 other advisory(ies) on 6.16.1 · targets 5 finding(s)
- **Compatibility:** high: major version change (0.6.6, 5.2.1, 6.2.1, 6.3.2, 6.5.2 -> 6.16.1): breaking API changes are possible, run the tests
- **Rollback:** restore qs 0.6.6, 5.2.1, 6.2.1, 6.3.2, 6.5.2 in package.json (and the lockfile) by reverting the remediation commit
- **Notes:** some copies of qs are bundled inside request (bundleDependencies): npm overrides cannot change them; upgrade request (or the package that pulls it in)
- **Decision:** approve by user1 at 2026-11-24T06:03:40+00:00: decided in the dashboard (proposal sha256 `6ed6513ca165…`)
- **Validation (measured):** not resolved (0/5 targeted findings resolved) · execution: tested; advisories still present on the new version: F-071 GHSA-4mjr-xmp4-gh2g, GHSA-6rw7-vpxm-498p, GHSA-gqgv-6jq5-jjj9; F-074 GHSA-4mjr-xmp4-gh2g, GHSA-6rw7-vpxm-498p, GHSA-hrpp-h998-j3pp; F-070 GHSA-6rw7-vpxm-498p, GHSA-gqgv-6jq5-jjj9, GHSA-hrpp-h998-j3pp; F-073 GHSA-4mjr-xmp4-gh2g, GHSA-6rw7-vpxm-498p, GHSA-hrpp-h998-j3pp

```diff
--- a/package.json
+++ b/package.json
@@ -61,5 +61,8 @@
     "zaproxy": "^0.2.0"
   },
   "repository": "https://github.com/OWASP/NodejsGoat",
-  "license": "Apache 2.0"
+  "license": "Apache 2.0",
+  "overrides": {
+    "qs": "6.16.1"
+  }
 }
# + package-lock.json regenerated from the registry during validation (npm --package-lock-only)
```

### P-014 · PENDING · escalate review · swig@1.4.2

- **Findings:** F-079 swig@1.4.2: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Change:** 1.4.2 → - in `package.json`
- **Why (verified facts):** No safe version of swig could be determined (no version list from the npm registry (offline or unknown package)): mitigate in code or replace the library.
- **Expected risk reduction (estimate before validation):** -
- **Compatibility:** low: -
- **Rollback:** -
- **Notes:** no version list from the npm registry (offline or unknown package)
- **Decision:** defer by user1 at 2026-11-24T06:03:40+00:00: not decided (proposal sha256 `70569f466618…`)

## 4. Validation: build, test and rescan

- **Where:** a temporary copy `C:\Users\VICTUS\AppData\Local\Temp\sscg-validate-ec853aa0ea2f` of the repository with the approved edits. Commands run as local processes with secrets removed from the environment and npm install scripts disabled; this is not an isolated sandbox.
- **Docker:** engine running: images were built (and removed afterwards)
- **What was rescanned:** source of the remediated copy: manifests, lockfiles, Dockerfiles and CI workflows, with the same detection pipeline as the original scan. The built container image itself is not scanned.
- **Vulnerability lookup in the rescan:** complete

| Step | Kind | Before (unchanged) | After (remediated) | Compared with the baseline | Time |
|---|---|---|---|---|---|
| regenerate lockfile (.) | relock | - | ok | ok | 4.2s |
| docker build (./Dockerfile) | image | ok | ok | ok | 21.2s |
| npm ci (.) | install | ok | ok | ok | 16.9s |
| npm test (.) | test | ok | ok | ok | 2.0s |

**SBOM before → after:** 19 changed · 17 added · 1 removed

- changed: npm:bson 1.0.9 -> 1.1.4
- changed: npm:forwarded 0.1.2 -> 0.2.0
- changed: npm:function-bind 1.1.1 -> 1.1.2
- changed: npm:has-symbols 1.0.1 -> 1.1.0
- changed: npm:ipaddr.js 1.8.0 -> 1.9.1
- changed: npm:marked 0.3.5 -> 4.0.10
- changed: npm:minimist 0.0.10/0.0.8/1.2.0/1.2.5 -> 0.0.8/1.2.0/1.2.6
- changed: npm:mixin-deep 1.3.1 -> 1.3.2
- changed: npm:mongodb 2.2.36 -> 3.1.13
- changed: npm:mongodb-core 2.1.20 -> 3.1.11
- changed: npm:object-inspect 1.7.0 -> 1.14.0
- changed: npm:proxy-addr 2.0.4 -> 2.0.8
- changed: npm:qs 0.6.6/5.2.1/6.2.1/6.3.2/6.5.2 -> 6.16.1/6.2.1
- changed: npm:readable-stream 1.1.14/2.0.6/2.1.5/2.2.7/2.3.6 -> 1.1.14/2.0.6/2.1.5/2.3.6
- changed: npm:set-value 0.4.3/2.0.0 -> 2.0.1
- changed: npm:side-channel 1.0.2 -> 1.1.1
- changed: npm:string_decoder 0.10.31/1.0.3/1.1.1 -> 0.10.31/1.1.1
- changed: npm:underscore 1.8.3/1.9.1 -> 1.13.8
- changed: npm:y18n 3.2.1 -> 3.2.1/3.2.2
- added: npm:call-bind-apply-helpers@1.0.2
- added: npm:call-bound@1.0.4
- added: npm:dunder-proto@1.0.1
- added: npm:es-define-property@1.0.1
- added: npm:es-errors@1.3.0
- added: npm:es-object-atoms@1.1.2
- added: npm:get-intrinsic@1.3.0
- added: npm:get-proto@1.0.1
- added: npm:gopd@1.2.0
- added: npm:hasown@2.0.4
- added: npm:math-intrinsics@1.1.0
- added: npm:memory-pager@1.5.0
- added: npm:saslprep@1.0.3
- added: npm:side-channel-list@1.0.1
- added: npm:side-channel-map@1.0.1
- removed: npm:es6-promise@3.2.1

**Resolved findings:** F-002, F-012, F-013, F-014, F-015, F-016, F-022, F-033, F-061

**Vulnerabilities NOT resolved: the package moved to a new version that keeps the same advisories:**

- F-071 qs@5.2.1: GHSA-4mjr-xmp4-gh2g, GHSA-6rw7-vpxm-498p, GHSA-gqgv-6jq5-jjj9, GHSA-hrpp-h998-j3pp
- F-008 minimist@0.0.10: GHSA-vh95-rmgr-6w4m, GHSA-xvch-5gv4-984h
- F-011 minimist@1.2.5: GHSA-xvch-5gv4-984h
- F-074 qs@6.5.2: GHSA-4mjr-xmp4-gh2g, GHSA-6rw7-vpxm-498p, GHSA-hrpp-h998-j3pp
- F-070 qs@0.6.6: GHSA-6rw7-vpxm-498p, GHSA-gqgv-6jq5-jjj9, GHSA-hrpp-h998-j3pp
- F-073 qs@6.3.2: GHSA-4mjr-xmp4-gh2g, GHSA-6rw7-vpxm-498p, GHSA-hrpp-h998-j3pp

**Findings that exist only after the change:**

- expected (e.g. the replacement package) · Medium: new prod dependency underscore@1.13.8 added in package.json (R08_UNEXPECTED_DEPENDENCY)

**Machine-readable evidence:** before: `findings.json`, `sbom.cdx.json` · after: `remediation/after/findings.json`, `remediation/after/sbom.cdx.json` · validation details: `remediation/remediation.json`

## 5. Remaining and accepted risk

Measured after the change: **127 finding(s)** = 132 original finding(s) still present + 1 finding(s) that only exist after the change (section 4). Highest remaining: F-001 (P0), F-008 (P1), F-009 (P1), F-003 (P1), F-011 (P1), F-026 (P1), F-092 (P1), F-031 (P1).
- pending: P-001 remove fsevents@1.2.9 (not decided)
- pending: P-014 escalate review swig@1.4.2 (not decided)

**Next step (retry):** a finished run cannot be approved again. Start a new run and decide again:

```
python -m sscg agent C:\Users\VICTUS\Desktop\Bosch Hack\sscg\repos\nodegoat --remediate --decisions later
python -m sscg approve C:\Users\VICTUS\Desktop\Bosch Hack\sscg\repos\nodegoat --approve <ids> --by "<name>"
```

## 6. Audit trail

- Knowledge base `7f4bce14289a` · AI engine deepseek:deepseek-flash · nothing was merged, deployed or released; the original repository was not modified.
- Approvals are bound to a fingerprint of the reviewed files (manifests, lockfiles, Dockerfiles, workflows, edited files): a changed repository is refused at resume. Source fingerprint `8f99a1c14c969abd…`.

| Agent / step | Kind | Status | Seconds | Tokens in/out |
|---|---|---|---|---|
| Orchestrator | deterministic | ok | 0.08 | 0/0 |
| Discovery | deterministic | ok | 0.1 | 0/0 |
| Vulnerability Intel | deterministic | ok | 0.1 | 0/0 |
| Detection | deterministic | ok | 0.69 | 0/0 |
| Evidence Gatherer | deterministic | ok | 0.08 | 0/0 |
| Triage | llm | ok | 10.25 | 2390/1628 |
| Triage | llm | ok | 5.38 | 1815/911 |
| Triage | llm | ok | 8.78 | 1841/891 |
| Triage | llm | ok | 14.29 | 2406/1416 |
| Triage | llm | ok | 18.29 | 2722/3320 |
| Triage | llm | ok | 4.78 | 2399/783 |
| Triage | deterministic | ok | 0.0 | 0/0 |
| Evidence Gatherer | deterministic | ok | 0.01 | 0/0 |
| Triage | llm | ok | 18.07 | 2807/1688 |
| Triage | llm | ok | 5.97 | 2093/968 |
| Triage | llm | ok | 8.89 | 2119/1282 |
| Triage | deterministic | ok | 0.0 | 0/0 |
| Narrator | llm | ok | 11.54 | 4123/1394 |
| Reporter | deterministic | ok | 1.74 | 0/0 |
| Exploit Intel | deterministic | ok | 0.01 | 0/0 |
| Reachability | deterministic | ok | 0.39 | 0/0 |
| Prioritizer | deterministic | ok | 0.0 | 0/0 |
| Remediation | deterministic | ok | 2.02 | 0/0 |
| Remediation Advisor | llm | ok | 24.89 | 7595/3758 |
| Human Approval | human | ok | 0.06 | 0/0 |
| Validation | deterministic | ok | 77.66 | 0/0 |
| Human approval | human | approve P-002 by user1 | 2026-11-24T06:03:40+00:00 | |
| Human approval | human | approve P-003 by user1 | 2026-11-24T06:03:40+00:00 | |
| Human approval | human | approve P-004 by user1 | 2026-11-24T06:03:40+00:00 | |
| Human approval | human | approve P-005 by user1 | 2026-11-24T06:03:40+00:00 | |
| Human approval | human | approve P-006 by user1 | 2026-11-24T06:03:40+00:00 | |
| Human approval | human | approve P-007 by user1 | 2026-11-24T06:03:40+00:00 | |
| Human approval | human | approve P-008 by user1 | 2026-11-24T06:03:40+00:00 | |
| Human approval | human | approve P-009 by user1 | 2026-11-24T06:03:40+00:00 | |
| Human approval | human | approve P-010 by user1 | 2026-11-24T06:03:40+00:00 | |
| Human approval | human | approve P-011 by user1 | 2026-11-24T06:03:40+00:00 | |
| Human approval | human | approve P-012 by user1 | 2026-11-24T06:03:40+00:00 | |
| Human approval | human | approve P-013 by user1 | 2026-11-24T06:03:40+00:00 | |
| Human approval | human | defer P-001 by user1 | 2026-11-24T06:03:40+00:00 | |
| Human approval | human | defer P-014 by user1 | 2026-11-24T06:03:40+00:00 | |
