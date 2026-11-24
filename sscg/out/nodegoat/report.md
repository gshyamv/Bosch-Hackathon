# Guardian evidence report: nodegoat

*Scanned 2026-11-24T05:59:37+00:00 with sscg 0.1.0* · HEAD `c5cb68a`

**Repository → SBOM → Dependency graph → Risk detection → Evidence** ✔

## 1. What is in the application

| | |
|---|---|
| Components | 1097 (github-actions 4, docker 2, npm 1091) |
| Libraries | 1091: 36 direct, 1055 transitive, max depth 13 |
| Container images | 2: mongo:4.4, node:12-alpine |
| CI/CD | 2 workflow(s), 4 distinct actions |
| SBOM | `sbom.cdx.json` (CycloneDX 1.5, 1102 components) |

## 2. What changed

Base `5e71697` (fix: travel path vulnerability on tutorial pages, merge pull request #233 from rcowsill/fix/path-traversal) → HEAD `c5cb68a` (Merge pull request #290 from za/add-blank-space)

- Author of HEAD: Liran Tal <liran.tal@gmail.com>, first-time contributor: no
- Files changed: M `app/views/contributions.html`
- Components added: none
- Components removed: none
- Components changed: none
- **New findings introduced by this change: 1**

## 3. What appears risky

**141 findings**: 131 vulnerable components (310 advisories) and 10 supply-chain anomalies.

| Level | Critical | High | Medium | Low | Info |
|---|---|---|---|---|---|
| Findings | 22 | 72 | 32 | 15 | 0 |

*Initial risk = Guardian initial risk (heuristic, 0-10); not a CVSS score. Official severity is shown separately for vulnerabilities.*

| ID | Risk | Type | Finding | Location | New |
|---|---|---|---|---|---|
| F-001 | 🟥 Critical (10.0) | Typosquatted package | fsevents@1.2.9 is a documented malicious package | `package-lock.json` | 🆕 |
| F-002 | 🟥 Critical (9.8) | Vulnerable transitive dependency | bson@1.0.9: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-003 | 🟥 Critical (9.8) | Vulnerable transitive dependency | fsevents@1.2.9: 1 known vulnerability (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-004 | 🟥 Critical (9.8) | Vulnerable transitive dependency | getobject@0.1.0: 1 known vulnerability (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-005 | 🟥 Critical (9.8) | Vulnerable transitive dependency | growl@1.9.2: 1 known vulnerability (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-006 | 🟥 Critical (9.8) | Vulnerable transitive dependency | handlebars@4.0.5: 20 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-007 | 🟥 Critical (9.8) | Vulnerable transitive dependency | json-schema@0.2.3: 1 known vulnerability (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-008 | 🟥 Critical (9.8) | Vulnerable transitive dependency | minimist@0.0.10: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-009 | 🟥 Critical (9.8) | Vulnerable transitive dependency | minimist@0.0.8: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-010 | 🟥 Critical (9.8) | Vulnerable transitive dependency | minimist@1.2.0: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-011 | 🟥 Critical (9.8) | Vulnerable transitive dependency | minimist@1.2.5: 1 known vulnerability (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-012 | 🟥 Critical (9.8) | Vulnerable transitive dependency | mixin-deep@1.3.1: 1 known vulnerability (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-013 | 🟥 Critical (9.8) | Vulnerable transitive dependency | set-value@0.4.3: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-014 | 🟥 Critical (9.8) | Vulnerable transitive dependency | set-value@2.0.0: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-015 | 🟥 Critical (9.8) | Vulnerable transitive dependency | underscore@1.8.3: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-016 | 🟥 Critical (9.8) | Vulnerable direct dependency | underscore@1.9.1: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-017 | 🟥 Critical (9.5) | Vulnerable transitive dependency | websocket-driver@0.7.0: 2 known vulnerabilities (highest CRITICAL) | `package-lock.json` |  |
| F-018 | 🟥 Critical (9.3) | Vulnerable transitive dependency | babel-traverse@6.11.4: 1 known vulnerability (highest CRITICAL, CVSS 9.3) | `package-lock.json` |  |
| F-019 | 🟥 Critical (9.1) | Vulnerable transitive dependency | lodash@2.4.2: 4 known vulnerabilities (highest CRITICAL, CVSS 9.1) | `package-lock.json` |  |
| F-020 | 🟥 Critical (9.1) | Vulnerable transitive dependency | lodash@4.13.1: 9 known vulnerabilities (highest CRITICAL, CVSS 9.1) | `package-lock.json` |  |
| F-021 | 🟥 Critical (9.1) | Vulnerable transitive dependency | lodash@4.17.11: 6 known vulnerabilities (highest CRITICAL, CVSS 9.1) | `package-lock.json` |  |
| F-022 | 🟥 Critical (9.1) | Vulnerable transitive dependency | proxy-addr@2.0.4: 1 known vulnerability (highest CRITICAL, CVSS 9.1) | `package-lock.json` |  |
| F-023 | 🟧 High (8.8) | Vulnerable transitive dependency | hoek@0.9.1: 2 known vulnerabilities (highest HIGH, CVSS 8.8) | `package-lock.json` |  |
| F-024 | 🟧 High (8.8) | Vulnerable transitive dependency | hoek@2.16.3: 2 known vulnerabilities (highest HIGH, CVSS 8.8) | `package-lock.json` |  |
| F-025 | 🟧 High (8.8) | Vulnerable transitive dependency | tar@2.2.1: 16 known vulnerabilities (highest HIGH, CVSS 8.8) | `package-lock.json` |  |
| F-026 | 🟧 High (8.8) | Vulnerable transitive dependency | tar@4.4.8: 18 known vulnerabilities (highest HIGH, CVSS 8.8) | `package-lock.json` |  |
| F-027 | 🟧 High (8.2) | Vulnerable transitive dependency | websocket-extensions@0.1.3: 1 known vulnerability (highest HIGH, CVSS 8.2) | `package-lock.json` |  |
| F-028 | 🟧 High (8.1) | Vulnerable transitive dependency | extract-zip@1.6.7: 2 known vulnerabilities (highest HIGH, CVSS 8.1) | `package-lock.json` |  |
| F-029 | 🟧 High (8.1) | Vulnerable transitive dependency | lodash@4.17.20: 4 known vulnerabilities (highest HIGH, CVSS 8.1) | `package-lock.json` |  |
| F-030 | 🟧 High (8.1) | Vulnerable transitive dependency | lodash@4.17.21: 2 known vulnerabilities (highest HIGH, CVSS 8.1) | `package-lock.json` |  |
| F-031 | 🟧 High (8.0) | Modified lockfile | grunt-if@0.2.0 is downloaded from github.com, not the npm registry | `package-lock.json:39` |  |
| F-032 | 🟧 High (8.0) | Vulnerable transitive dependency | diff@1.4.0: 2 known vulnerabilities (highest HIGH) | `package-lock.json` |  |
| F-033 | 🟧 High (8.0) | Vulnerable direct dependency | mongodb@2.2.36: 1 known vulnerability (highest HIGH) | `package-lock.json` |  |
| F-034 | 🟧 High (7.8) | Vulnerable direct dependency | async@2.6.1: 1 known vulnerability (highest HIGH, CVSS 7.8) | `package-lock.json` |  |
| F-035 | 🟧 High (7.8) | Vulnerable transitive dependency | npm@3.10.10: 5 known vulnerabilities (highest HIGH, CVSS 7.8) | `package-lock.json` |  |
| F-036 | 🟧 High (7.5) | Vulnerable transitive dependency | adm-zip@0.4.4: 8 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-037 | 🟧 High (7.5) | Vulnerable transitive dependency | ansi-regex@3.0.0: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-038 | 🟧 High (7.5) | Vulnerable direct dependency | body-parser@1.18.3: 3 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-039 | 🟧 High (7.5) | Vulnerable transitive dependency | brace-expansion@1.1.11: 8 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-040 | 🟧 High (7.5) | Vulnerable transitive dependency | brace-expansion@1.1.6: 9 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-041 | 🟧 High (7.5) | Vulnerable transitive dependency | braces@1.8.5: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-042 | 🟧 High (7.5) | Vulnerable transitive dependency | braces@2.3.2: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-043 | 🟧 High (7.5) | Vulnerable transitive dependency | cross-spawn@4.0.0: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-044 | 🟧 High (7.5) | Vulnerable transitive dependency | cross-spawn@4.0.2: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-045 | 🟧 High (7.5) | Vulnerable transitive dependency | cross-spawn@5.1.0: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-046 | 🟧 High (7.5) | Vulnerable transitive dependency | cross-spawn@6.0.5: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-047 | 🟧 High (7.5) | Vulnerable transitive dependency | cross-spawn@7.0.3: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-048 | 🟧 High (7.5) | Vulnerable transitive dependency | debug@2.2.0: 2 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-049 | 🟧 High (7.5) | Vulnerable transitive dependency | decode-uri-component@0.2.0: 3 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-050 | 🟧 High (7.5) | Vulnerable transitive dependency | form-data@0.1.4: 2 known vulnerabilities (highest CRITICAL, CVSS 7.5) | `package-lock.json` |  |
| F-051 | 🟧 High (7.5) | Vulnerable transitive dependency | form-data@1.0.1: 2 known vulnerabilities (highest CRITICAL, CVSS 7.5) | `package-lock.json` |  |
| F-052 | 🟧 High (7.5) | Vulnerable transitive dependency | form-data@2.0.0: 2 known vulnerabilities (highest CRITICAL, CVSS 7.5) | `package-lock.json` |  |
| F-053 | 🟧 High (7.5) | Vulnerable transitive dependency | form-data@2.1.4: 2 known vulnerabilities (highest CRITICAL, CVSS 7.5) | `package-lock.json` |  |
| F-054 | 🟧 High (7.5) | Vulnerable transitive dependency | form-data@2.3.3: 2 known vulnerabilities (highest CRITICAL, CVSS 7.5) | `package-lock.json` |  |
| F-055 | 🟧 High (7.5) | Vulnerable transitive dependency | fstream@1.0.10: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-056 | 🟧 High (7.5) | Vulnerable transitive dependency | hawk@1.0.0: 2 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-057 | 🟧 High (7.5) | Vulnerable transitive dependency | i@0.3.6: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-058 | 🟧 High (7.5) | Vulnerable transitive dependency | js-yaml@3.5.5: 7 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-059 | 🟧 High (7.5) | Vulnerable transitive dependency | js-yaml@3.6.1: 7 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-060 | 🟧 High (7.5) | Vulnerable transitive dependency | kind-of@6.0.2: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-061 | 🟧 High (7.5) | Vulnerable direct dependency | marked@0.3.5: 6 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-062 | 🟧 High (7.5) | Vulnerable transitive dependency | mime@1.2.11: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-063 | 🟧 High (7.5) | Vulnerable transitive dependency | minimatch@0.3.0: 5 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-064 | 🟧 High (7.5) | Vulnerable transitive dependency | minimatch@3.0.2: 4 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-065 | 🟧 High (7.5) | Vulnerable transitive dependency | minimatch@3.0.3: 4 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-066 | 🟧 High (7.5) | Vulnerable transitive dependency | minimatch@3.0.4: 4 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-067 | 🟧 High (7.5) | Vulnerable transitive dependency | moment@2.24.0: 2 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-068 | 🟧 High (7.5) | Vulnerable transitive dependency | npm-user-validate@0.1.5: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-069 | 🟧 High (7.5) | Vulnerable transitive dependency | path-to-regexp@0.1.7: 2 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-070 | 🟧 High (7.5) | Vulnerable transitive dependency | qs@0.6.6: 5 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-071 | 🟧 High (7.5) | Vulnerable transitive dependency | qs@5.2.1: 4 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-072 | 🟧 High (7.5) | Vulnerable transitive dependency | qs@6.2.1: 4 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-073 | 🟧 High (7.5) | Vulnerable transitive dependency | qs@6.3.2: 3 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-074 | 🟧 High (7.5) | Vulnerable transitive dependency | qs@6.5.2: 3 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-075 | 🟧 High (7.5) | Vulnerable transitive dependency | semver@5.3.0: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-076 | 🟧 High (7.5) | Vulnerable transitive dependency | semver@5.6.0: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-077 | 🟧 High (7.5) | Vulnerable transitive dependency | semver@5.7.0: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-078 | 🟧 High (7.5) | Vulnerable transitive dependency | sshpk@1.10.1: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-079 | 🟧 High (7.5) | Vulnerable direct dependency | swig@1.4.2: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-080 | 🟧 High (7.5) | Vulnerable transitive dependency | tough-cookie@2.2.2: 3 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-081 | 🟧 High (7.5) | Vulnerable transitive dependency | tough-cookie@2.3.1: 2 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-082 | 🟧 High (7.5) | Vulnerable transitive dependency | trim-newlines@1.0.0: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-083 | 🟧 High (7.5) | Vulnerable transitive dependency | uglify-js@2.4.24: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-084 | 🟧 High (7.5) | Vulnerable transitive dependency | uuid@3.3.2: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-085 | 🟧 High (7.5) | Vulnerable transitive dependency | ws@1.1.5: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-086 | 🟧 High (7.4) | Vulnerable transitive dependency | hawk@3.1.3: 1 known vulnerability (highest HIGH, CVSS 7.4) | `package-lock.json` |  |
| F-087 | 🟧 High (7.3) | Vulnerable transitive dependency | dot-prop@4.2.0: 1 known vulnerability (highest HIGH, CVSS 7.3) | `package-lock.json` |  |
| F-088 | 🟧 High (7.3) | Vulnerable transitive dependency | ini@1.3.4: 1 known vulnerability (highest HIGH, CVSS 7.3) | `package-lock.json` |  |
| F-089 | 🟧 High (7.3) | Vulnerable transitive dependency | ini@1.3.5: 1 known vulnerability (highest HIGH, CVSS 7.3) | `package-lock.json` |  |
| F-090 | 🟧 High (7.3) | Vulnerable transitive dependency | nconf@0.10.0: 1 known vulnerability (highest HIGH, CVSS 7.3) | `package-lock.json` |  |
| F-091 | 🟧 High (7.3) | Vulnerable transitive dependency | nconf@0.6.9: 1 known vulnerability (highest HIGH, CVSS 7.3) | `package-lock.json` |  |
| F-092 | 🟧 High (7.3) | Vulnerable transitive dependency | y18n@3.2.1: 1 known vulnerability (highest HIGH, CVSS 7.3) | `package-lock.json` |  |
| F-093 | 🟧 High (7.1) | Vulnerable direct dependency | grunt@1.0.3: 3 known vulnerabilities (highest HIGH, CVSS 7.1) | `package-lock.json` |  |
| F-094 | 🟧 High (7.1) | Vulnerable transitive dependency | shelljs@0.3.0: 2 known vulnerabilities (highest HIGH, CVSS 7.1) | `package-lock.json` |  |
| F-095 | 🟨 Medium (6.5) | Vulnerable transitive dependency | bl@1.0.3: 1 known vulnerability (highest MEDIUM, CVSS 6.5) | `package-lock.json` |  |
| F-096 | 🟨 Medium (6.5) | Vulnerable transitive dependency | bl@1.1.2: 1 known vulnerability (highest MEDIUM, CVSS 6.5) | `package-lock.json` |  |
| F-097 | 🟨 Medium (6.5) | Vulnerable transitive dependency | helmet-csp@1.2.2: 1 known vulnerability (highest MEDIUM, CVSS 6.5) | `package-lock.json` |  |
| F-098 | 🟨 Medium (6.5) | Vulnerable transitive dependency | tough-cookie@2.3.4: 1 known vulnerability (highest MEDIUM, CVSS 6.5) | `package-lock.json` |  |
| F-099 | 🟨 Medium (6.5) | Vulnerable transitive dependency | tough-cookie@2.4.3: 1 known vulnerability (highest MEDIUM, CVSS 6.5) | `package-lock.json` |  |
| F-100 | 🟨 Medium (6.3) | Vulnerable transitive dependency | undefsafe@2.0.2: 1 known vulnerability (highest MEDIUM, CVSS 6.3) | `package-lock.json` |  |
| F-101 | 🟨 Medium (6.1) | Vulnerable direct dependency | express@4.16.4: 2 known vulnerabilities (highest MEDIUM, CVSS 6.1) | `package-lock.json` |  |
| F-102 | 🟨 Medium (6.1) | Vulnerable transitive dependency | request@2.36.0: 2 known vulnerabilities (highest MEDIUM, CVSS 6.1) | `package-lock.json` |  |
| F-103 | 🟨 Medium (6.1) | Vulnerable transitive dependency | request@2.67.0: 2 known vulnerabilities (highest MEDIUM, CVSS 6.1) | `package-lock.json` |  |
| F-104 | 🟨 Medium (6.1) | Vulnerable transitive dependency | request@2.75.0: 1 known vulnerability (highest MEDIUM, CVSS 6.1) | `package-lock.json` |  |
| F-105 | 🟨 Medium (6.1) | Vulnerable transitive dependency | request@2.79.0: 1 known vulnerability (highest MEDIUM, CVSS 6.1) | `package-lock.json` |  |
| F-106 | 🟨 Medium (6.1) | Vulnerable transitive dependency | request@2.88.0: 1 known vulnerability (highest MEDIUM, CVSS 6.1) | `package-lock.json` |  |
| F-107 | 🟨 Medium (5.6) | Vulnerable transitive dependency | ajv@6.10.0: 2 known vulnerabilities (highest MEDIUM, CVSS 5.6) | `package-lock.json` |  |
| F-108 | 🟨 Medium (5.6) | Vulnerable transitive dependency | jsonpointer@4.0.0: 1 known vulnerability (highest MEDIUM, CVSS 5.6) | `package-lock.json` |  |
| F-109 | 🟨 Medium (5.6) | Vulnerable transitive dependency | jsonpointer@4.0.1: 1 known vulnerability (highest MEDIUM, CVSS 5.6) | `package-lock.json` |  |
| F-110 | 🟨 Medium (5.5) | Untrusted image | Dockerfile runs 'npm install' with install scripts enabled | `Dockerfile:5` |  |
| F-111 | 🟨 Medium (5.5) | Vulnerable transitive dependency | extend@3.0.0: 1 known vulnerability (highest MEDIUM) | `package-lock.json` |  |
| F-112 | 🟨 Medium (5.5) | Vulnerable transitive dependency | stringstream@0.0.5: 1 known vulnerability (highest MEDIUM) | `package-lock.json` |  |
| F-113 | 🟨 Medium (5.5) | Vulnerable transitive dependency | tunnel-agent@0.4.3: 1 known vulnerability (highest MEDIUM) | `package-lock.json` |  |
| F-114 | 🟨 Medium (5.3) | Vulnerable transitive dependency | got@6.7.1: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-115 | 🟨 Medium (5.3) | Vulnerable transitive dependency | hosted-git-info@2.1.5: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-116 | 🟨 Medium (5.3) | Vulnerable transitive dependency | hosted-git-info@2.7.1: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-117 | 🟨 Medium (5.3) | Vulnerable transitive dependency | is-my-json-valid@2.15.0: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-118 | 🟨 Medium (5.3) | Vulnerable transitive dependency | micromatch@2.3.11: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-119 | 🟨 Medium (5.3) | Vulnerable transitive dependency | micromatch@3.1.10: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-120 | 🟨 Medium (5.3) | Vulnerable transitive dependency | ms@0.7.1: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-121 | 🟨 Medium (5.3) | Vulnerable transitive dependency | path-parse@1.0.5: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-122 | 🟨 Medium (5.3) | Vulnerable transitive dependency | randomatic@1.1.5: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-123 | 🟨 Medium (5.3) | Vulnerable transitive dependency | xml2js@0.4.4: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-124 | 🟨 Medium (5.3) | Vulnerable transitive dependency | yargs-parser@2.4.1: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-125 | 🟨 Medium (5.0) | Vulnerable transitive dependency | send@0.16.2: 1 known vulnerability (highest MEDIUM, CVSS 5.0) | `package-lock.json` |  |
| F-126 | 🟨 Medium (5.0) | Vulnerable transitive dependency | serve-static@1.13.2: 1 known vulnerability (highest MEDIUM, CVSS 5.0) | `package-lock.json` |  |
| F-127 | 🟦 Low (3.7) | Vulnerable transitive dependency | debug@3.2.6: 1 known vulnerability (highest LOW, CVSS 3.7) | `package-lock.json` |  |
| F-128 | 🟦 Low (3.7) | Vulnerable transitive dependency | debug@4.1.1: 1 known vulnerability (highest LOW, CVSS 3.7) | `package-lock.json` |  |
| F-129 | 🟦 Low (3.4) | Vulnerable transitive dependency | on-headers@1.0.1: 1 known vulnerability (highest LOW, CVSS 3.4) | `package-lock.json` |  |
| F-130 | 🟦 Low (3.0) | Suspicious package update | 'grunt-env' is requested as 'latest' in package.json | `package.json:50` |  |
| F-131 | 🟦 Low (3.0) | Suspicious package update | 'grunt-if' is requested as 'https://github.com/binarymist/grunt-if/tarball/master' in package.json | `package.json:51` |  |
| F-132 | 🟦 Low (3.0) | Unsafe CI/CD component | .github/workflows/e2e-test.yml: no top-level 'permissions:' (token gets the repository default, often read/write) | `.github/workflows/e2e-test.yml` |  |
| F-133 | 🟦 Low (3.0) | Unsafe CI/CD component | .github/workflows/lint.yml: no top-level 'permissions:' (token gets the repository default, often read/write) | `.github/workflows/lint.yml` |  |
| F-134 | 🟦 Low (3.0) | Unsafe install script | cypress@3.3.1 runs an install script (code not inspected) | `package-lock.json` |  |
| F-135 | 🟦 Low (3.0) | Unsafe install script | fsevents@1.2.9 runs an install script (code not inspected) | `package-lock.json` |  |
| F-136 | 🟦 Low (3.0) | Unsafe install script | nodemon@1.19.1 runs an install script (code not inspected) | `package-lock.json` |  |
| F-137 | 🟦 Low (3.0) | Vulnerable transitive dependency | cookie@0.3.1: 1 known vulnerability (highest LOW) | `package-lock.json` |  |
| F-138 | 🟦 Low (3.0) | Vulnerable transitive dependency | es5-ext@0.10.12: 1 known vulnerability (highest LOW) | `package-lock.json` |  |
| F-139 | 🟦 Low (2.5) | Vulnerable transitive dependency | chownr@1.0.1: 1 known vulnerability (highest LOW, CVSS 2.5) | `package-lock.json` |  |
| F-140 | 🟦 Low (2.5) | Vulnerable transitive dependency | tmp@0.0.24: 2 known vulnerabilities (highest HIGH, CVSS 2.5) | `package-lock.json` |  |
| F-141 | 🟦 Low (2.5) | Vulnerable transitive dependency | tmp@0.1.0: 2 known vulnerabilities (highest HIGH, CVSS 2.5) | `package-lock.json` |  |

## 4. Evidence per finding

### F-001 · 🟥 Critical (10.0) · Typosquatted package · 🆕 new in this change

- **What:** fsevents@1.2.9 is a documented malicious package
- **Component:** `fsevents@1.2.9` (npm, scope optional, transitive), purl `pkg:npm/fsevents@1.2.9`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → nodemon@1.19.1 → chokidar@2.1.6 → fsevents@1.2.9 ; owasp-nodejs-goat@1.3.0 → forever@2.0.0 → forever-monitor@2.0.0 → chokidar@2.1.8 → fsevents@1.2.9
- **Evidence:**
  - [MAL-2023-462](https://osv.dev/vulnerability/MAL-2023-462): . Malicious code in fsevents (npm)
- **Initial risk:** Critical (10.0): R02_KNOWN_MALICIOUS default level Critical; introduced in the latest change
- **Why it matters:** This package (version) is publicly documented as malicious.
- **Basis:** verified fact, confidence high

### F-002 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** bson@1.0.9: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `bson@1.0.9` (npm, scope prod, transitive), purl `pkg:npm/bson@1.0.9`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → mongodb@2.2.36 → mongodb-core@2.1.20 → bson@1.0.9
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.1.4
- **Evidence:**
  - [GHSA-v8w9-2789-6hhr](https://osv.dev/vulnerability/GHSA-v8w9-2789-6hhr) (CVE-2020-7610): CRITICAL, CVSS 9.8, fixed in 1.1.4. Deserialization of Untrusted Data in bson
  - [GHSA-4jwp-vfvf-657p](https://osv.dev/vulnerability/GHSA-4jwp-vfvf-657p) (CVE-2019-2391): MEDIUM, CVSS 5.4, fixed in 1.1.4. Deserialization of Untrusted Data in bson
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-003 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** fsevents@1.2.9: 1 known vulnerability (highest CRITICAL, CVSS 9.8)
- **Component:** `fsevents@1.2.9` (npm, scope optional, transitive), purl `pkg:npm/fsevents@1.2.9`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → nodemon@1.19.1 → chokidar@2.1.6 → fsevents@1.2.9 ; owasp-nodejs-goat@1.3.0 → forever@2.0.0 → forever-monitor@2.0.0 → chokidar@2.1.8 → fsevents@1.2.9
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.2.11
- **Evidence:**
  - [GHSA-8r6j-v8pm-fqw3](https://osv.dev/vulnerability/GHSA-8r6j-v8pm-fqw3) (CVE-2023-45311): CRITICAL, CVSS 9.8, fixed in 1.2.11. Code injection in fsevents
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-004 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** getobject@0.1.0: 1 known vulnerability (highest CRITICAL, CVSS 9.8)
- **Component:** `getobject@0.1.0` (npm, scope dev, transitive), purl `pkg:npm/getobject@0.1.0`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt@1.0.3 → grunt-legacy-util@1.1.1 → getobject@0.1.0 ; owasp-nodejs-goat@1.3.0 → grunt-if@0.2.0 → grunt@1.0.3 → grunt-legacy-util@1.1.1 → getobject@0.1.0 ; owasp-nodejs-goat@1.3.0 → grunt-jsbeautifier@0.2.13 → grunt@1.0.3 → grunt-legacy-util@1.1.1 → getobject@0.1.0
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.0.0
- **Evidence:**
  - [GHSA-957j-59c2-j692](https://osv.dev/vulnerability/GHSA-957j-59c2-j692) (CVE-2020-28282): CRITICAL, CVSS 9.8, fixed in 1.0.0. Prototype pollution in getobject
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-005 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** growl@1.9.2: 1 known vulnerability (highest CRITICAL, CVSS 9.8)
- **Component:** `growl@1.9.2` (npm, scope dev, transitive), purl `pkg:npm/growl@1.9.2`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → mocha@2.5.3 → growl@1.9.2
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.10.0
- **Evidence:**
  - [GHSA-qh2h-chj9-jffq](https://osv.dev/vulnerability/GHSA-qh2h-chj9-jffq) (CVE-2017-16042): CRITICAL, CVSS 9.8, fixed in 1.10.0. Growl before 1.10.0 vulnerable to Command Injection
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-006 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** handlebars@4.0.5: 20 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `handlebars@4.0.5` (npm, scope dev, transitive), purl `pkg:npm/handlebars@4.0.5`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt-if@0.2.0 → grunt-contrib-nodeunit@1.0.0 → nodeunit@0.9.5 → tap@7.1.2 → nyc@7.1.0 → istanbul-reports@1.0.0-alpha.8 → handlebars@4.0.5
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 4.7.10
- **Evidence:**
  - [GHSA-2w6w-674q-4c4q](https://osv.dev/vulnerability/GHSA-2w6w-674q-4c4q) (CVE-2026-33937): CRITICAL, CVSS 9.8, fixed in 4.7.9. Handlebars.js has JavaScript Injection via AST Type Confusion
  - [GHSA-765h-qjxv-5f44](https://osv.dev/vulnerability/GHSA-765h-qjxv-5f44) (CVE-2021-23383): CRITICAL, CVSS 9.8, fixed in 4.7.7. Prototype Pollution in handlebars
  - [GHSA-8r5x-fm3f-whwj](https://osv.dev/vulnerability/GHSA-8r5x-fm3f-whwj) (CVE-2026-106446): CRITICAL, CVSS 9.8, fixed in 4.7.10. Handlebars: JavaScript Injection via AST Type Confusion in compile (bypass of CVE-2026-33937)
  - [GHSA-f2jv-r9rf-7988](https://osv.dev/vulnerability/GHSA-f2jv-r9rf-7988) (CVE-2021-23369): CRITICAL, CVSS 9.8, fixed in 4.7.7. Remote code execution in handlebars when compiling templates
  - [GHSA-w457-6q6x-cgp9](https://osv.dev/vulnerability/GHSA-w457-6q6x-cgp9) (CVE-2019-19919): CRITICAL, CVSS 9.8, fixed in 4.3.0. Prototype Pollution in handlebars
  - [GHSA-p8wg-vrv2-v86f](https://osv.dev/vulnerability/GHSA-p8wg-vrv2-v86f) (CVE-2026-106445): CRITICAL, fixed in 4.7.10. Handlebars: JavaScript Injection via Own Property Check Bypass
  - [GHSA-xjpj-3mr7-gcpf](https://osv.dev/vulnerability/GHSA-xjpj-3mr7-gcpf) (CVE-2026-33941): HIGH, CVSS 8.2, fixed in 4.7.9. Handlebars.js has JavaScript Injection in CLI Precompiler via Unescaped Names and Options
  - [GHSA-3cqr-58rm-57f8](https://osv.dev/vulnerability/GHSA-3cqr-58rm-57f8) (CVE-2019-20920): HIGH, CVSS 8.1, fixed in 4.5.3. Arbitrary Code Execution in Handlebars
  - [GHSA-3mfm-83xf-c92r](https://osv.dev/vulnerability/GHSA-3mfm-83xf-c92r) (CVE-2026-33938): HIGH, CVSS 8.1, fixed in 4.7.9. Handlebars.js has JavaScript Injection via AST Type Confusion by tampering @partial-block
  - [GHSA-xhpv-hc6g-r9c6](https://osv.dev/vulnerability/GHSA-xhpv-hc6g-r9c6) (CVE-2026-33940): HIGH, CVSS 8.1, fixed in 4.7.9. Handlebars.js has JavaScript Injection via AST Type Confusion when passing an object as dynamic partial
  - [GHSA-g9r4-xpmj-mj65](https://osv.dev/vulnerability/GHSA-g9r4-xpmj-mj65): HIGH, fixed in 4.5.3. Prototype Pollution in handlebars
  - [GHSA-q2c6-c6pm-g3gh](https://osv.dev/vulnerability/GHSA-q2c6-c6pm-g3gh): HIGH, fixed in 4.5.3. Arbitrary Code Execution in handlebars
  - … 8 more in findings.json
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-007 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** json-schema@0.2.3: 1 known vulnerability (highest CRITICAL, CVSS 9.8)
- **Component:** `json-schema@0.2.3` (npm, scope dev, transitive), purl `pkg:npm/json-schema@0.2.3`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → cypress@3.3.1 → request@2.88.0 → http-signature@1.2.0 → jsprim@1.4.1 → json-schema@0.2.3 ; owasp-nodejs-goat@1.3.0 → grunt-retire@0.3.12 → request@2.67.0 → http-signature@1.1.1 → jsprim@1.4.1 → json-schema@0.2.3 ; owasp-nodejs-goat@1.3.0 → grunt-retire@0.3.12 → request@2.67.0 → http-signature@1.1.1 → jsprim@1.3.1 → json-schema@0.2.3
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 0.4.0
- **Evidence:**
  - [GHSA-896r-f27r-55mw](https://osv.dev/vulnerability/GHSA-896r-f27r-55mw) (CVE-2021-3918): CRITICAL, CVSS 9.8, fixed in 0.4.0. json-schema is vulnerable to Prototype Pollution
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-008 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** minimist@0.0.10: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `minimist@0.0.10` (npm, scope prod, transitive), purl `pkg:npm/minimist@0.0.10`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → forever@2.0.0 → optimist@0.6.1 → minimist@0.0.10 ; owasp-nodejs-goat@1.3.0 → swig@1.4.2 → optimist@0.6.1 → minimist@0.0.10 ; owasp-nodejs-goat@1.3.0 → forever@2.0.0 → flatiron@0.4.3 → optimist@0.6.0 → minimist@0.0.10
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 0.2.4
- **Evidence:**
  - [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) (CVE-2021-44906): CRITICAL, CVSS 9.8, fixed in 0.2.4. Prototype Pollution in minimist
  - [GHSA-vh95-rmgr-6w4m](https://osv.dev/vulnerability/GHSA-vh95-rmgr-6w4m) (CVE-2020-7598): MEDIUM, CVSS 5.6, fixed in 0.2.1. Prototype Pollution in minimist
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-009 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** minimist@0.0.8: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `minimist@0.0.8` (npm, scope prod, transitive), purl `pkg:npm/minimist@0.0.8`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → forever@2.0.0 → mkdirp@0.5.1 → minimist@0.0.8 ; owasp-nodejs-goat@1.3.0 → grunt@1.0.3 → mkdirp@0.5.1 → minimist@0.0.8 ; owasp-nodejs-goat@1.3.0 → forever@2.0.0 → optimist@0.6.1 → minimist@0.0.8
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 0.2.4
- **Evidence:**
  - [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) (CVE-2021-44906): CRITICAL, CVSS 9.8, fixed in 0.2.4. Prototype Pollution in minimist
  - [GHSA-vh95-rmgr-6w4m](https://osv.dev/vulnerability/GHSA-vh95-rmgr-6w4m) (CVE-2020-7598): MEDIUM, CVSS 5.6, fixed in 0.2.1. Prototype Pollution in minimist
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-010 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** minimist@1.2.0: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `minimist@1.2.0` (npm, scope dev, transitive), purl `pkg:npm/minimist@1.2.0`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → cypress@3.3.1 → minimist@1.2.0 ; owasp-nodejs-goat@1.3.0 → grunt-jsbeautifier@0.2.13 → rc@1.2.8 → minimist@1.2.0 ; owasp-nodejs-goat@1.3.0 → grunt@1.0.3 → dateformat@1.0.12 → meow@3.7.0 → minimist@1.2.0
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.2.6
- **Evidence:**
  - [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) (CVE-2021-44906): CRITICAL, CVSS 9.8, fixed in 1.2.6. Prototype Pollution in minimist
  - [GHSA-vh95-rmgr-6w4m](https://osv.dev/vulnerability/GHSA-vh95-rmgr-6w4m) (CVE-2020-7598): MEDIUM, CVSS 5.6, fixed in 1.2.3. Prototype Pollution in minimist
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-011 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** minimist@1.2.5: 1 known vulnerability (highest CRITICAL, CVSS 9.8)
- **Component:** `minimist@1.2.5` (npm, scope prod, transitive), purl `pkg:npm/minimist@1.2.5`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → forever@2.0.0 → prettyjson@1.2.1 → minimist@1.2.5
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.2.6
- **Evidence:**
  - [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) (CVE-2021-44906): CRITICAL, CVSS 9.8, fixed in 1.2.6. Prototype Pollution in minimist
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-012 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** mixin-deep@1.3.1: 1 known vulnerability (highest CRITICAL, CVSS 9.8)
- **Component:** `mixin-deep@1.3.1` (npm, scope prod, transitive), purl `pkg:npm/mixin-deep@1.3.1`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → nodemon@1.19.1 → chokidar@2.1.6 → braces@2.3.2 → snapdragon@0.8.2 → base@0.11.2 → mixin-deep@1.3.1 ; owasp-nodejs-goat@1.3.0 → forever@2.0.0 → forever-monitor@2.0.0 → chokidar@2.1.8 → braces@2.3.2 → snapdragon@0.8.2 → base@0.11.2 → mixin-deep@1.3.1 ; owasp-nodejs-goat@1.3.0 → nodemon@1.19.1 → chokidar@2.1.6 → anymatch@2.0.0 → micromatch@3.1.10 → snapdragon@0.8.2 → base@0.11.2 → mixin-deep@1.3.1
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.3.2
- **Evidence:**
  - [GHSA-fhjf-83wg-r2j9](https://osv.dev/vulnerability/GHSA-fhjf-83wg-r2j9) (CVE-2019-10746): CRITICAL, CVSS 9.8, fixed in 1.3.2. Prototype Pollution in mixin-deep
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-013 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** set-value@0.4.3: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `set-value@0.4.3` (npm, scope prod, transitive), purl `pkg:npm/set-value@0.4.3`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → nodemon@1.19.1 → chokidar@2.1.6 → braces@2.3.2 → snapdragon@0.8.2 → base@0.11.2 → cache-base@1.0.1 → union-value@1.0.0 → set-value@0.4.3 ; owasp-nodejs-goat@1.3.0 → forever@2.0.0 → forever-monitor@2.0.0 → chokidar@2.1.8 → braces@2.3.2 → snapdragon@0.8.2 → base@0.11.2 → cache-base@1.0.1 → union-value@1.0.0 → set-value@0.4.3 ; owasp-nodejs-goat@1.3.0 → nodemon@1.19.1 → chokidar@2.1.6 → anymatch@2.0.0 → micromatch@3.1.10 → snapdragon@0.8.2 → base@0.11.2 → cache-base@1.0.1 → union-value@1.0.0 → set-value@0.4.3
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 2.0.1
- **Evidence:**
  - [GHSA-4g88-fppr-53pp](https://osv.dev/vulnerability/GHSA-4g88-fppr-53pp) (CVE-2019-10747): CRITICAL, CVSS 9.8, fixed in 2.0.1. Prototype Pollution in set-value
  - [GHSA-4jqc-8m5r-9rpr](https://osv.dev/vulnerability/GHSA-4jqc-8m5r-9rpr) (CVE-2021-23440): HIGH, CVSS 7.3, fixed in 2.0.1. Prototype Pollution in set-value
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-014 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** set-value@2.0.0: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `set-value@2.0.0` (npm, scope prod, transitive), purl `pkg:npm/set-value@2.0.0`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → nodemon@1.19.1 → chokidar@2.1.6 → braces@2.3.2 → snapdragon@0.8.2 → base@0.11.2 → cache-base@1.0.1 → set-value@2.0.0 ; owasp-nodejs-goat@1.3.0 → forever@2.0.0 → forever-monitor@2.0.0 → chokidar@2.1.8 → braces@2.3.2 → snapdragon@0.8.2 → base@0.11.2 → cache-base@1.0.1 → set-value@2.0.0 ; owasp-nodejs-goat@1.3.0 → nodemon@1.19.1 → chokidar@2.1.6 → anymatch@2.0.0 → micromatch@3.1.10 → snapdragon@0.8.2 → base@0.11.2 → cache-base@1.0.1 → set-value@2.0.0
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 2.0.1
- **Evidence:**
  - [GHSA-4g88-fppr-53pp](https://osv.dev/vulnerability/GHSA-4g88-fppr-53pp) (CVE-2019-10747): CRITICAL, CVSS 9.8, fixed in 2.0.1. Prototype Pollution in set-value
  - [GHSA-4jqc-8m5r-9rpr](https://osv.dev/vulnerability/GHSA-4jqc-8m5r-9rpr) (CVE-2021-23440): HIGH, CVSS 7.3, fixed in 2.0.1. Prototype Pollution in set-value
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-015 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** underscore@1.8.3: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `underscore@1.8.3` (npm, scope dev, transitive), purl `pkg:npm/underscore@1.8.3`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt-retire@0.3.12 → retire@1.1.6 → underscore@1.8.3
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.13.8
- **Evidence:**
  - [GHSA-cf4h-3jhx-xvhq](https://osv.dev/vulnerability/GHSA-cf4h-3jhx-xvhq) (CVE-2021-23358): CRITICAL, CVSS 9.8, fixed in 1.12.1. Arbitrary Code Execution in underscore
  - [GHSA-qpx9-hpmf-5gmw](https://osv.dev/vulnerability/GHSA-qpx9-hpmf-5gmw) (CVE-2026-27601): MEDIUM, CVSS 5.9, fixed in 1.13.8. Underscore has unlimited recursion in _.flatten and _.isEqual, potential for DoS attack
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-016 · 🟥 Critical (9.8) · Vulnerable direct dependency

- **What:** underscore@1.9.1: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `underscore@1.9.1` (npm, scope prod, direct), purl `pkg:npm/underscore@1.9.1`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → underscore@1.9.1
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.13.8
- **Evidence:**
  - [GHSA-cf4h-3jhx-xvhq](https://osv.dev/vulnerability/GHSA-cf4h-3jhx-xvhq) (CVE-2021-23358): CRITICAL, CVSS 9.8, fixed in 1.12.1. Arbitrary Code Execution in underscore
  - [GHSA-qpx9-hpmf-5gmw](https://osv.dev/vulnerability/GHSA-qpx9-hpmf-5gmw) (CVE-2026-27601): MEDIUM, CVSS 5.9, fixed in 1.13.8. Underscore has unlimited recursion in _.flatten and _.isEqual, potential for DoS attack
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-017 · 🟥 Critical (9.5) · Vulnerable transitive dependency

- **What:** websocket-driver@0.7.0: 2 known vulnerabilities (highest CRITICAL)
- **Component:** `websocket-driver@0.7.0` (npm, scope dev, transitive), purl `pkg:npm/websocket-driver@0.7.0`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt-contrib-watch@1.1.0 → tiny-lr@1.1.1 → faye-websocket@0.10.0 → websocket-driver@0.7.0
- **Official severity:** CRITICAL (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 0.7.5
- **Evidence:**
  - [GHSA-xv26-6w52-cph6](https://osv.dev/vulnerability/GHSA-xv26-6w52-cph6) (CVE-2026-54466): CRITICAL, fixed in 0.7.5. websocket-driver: Message corruption via abuse of protocol length headers
  - [GHSA-mp7j-qc5w-4988](https://osv.dev/vulnerability/GHSA-mp7j-qc5w-4988) (CVE-2026-54490): MEDIUM, fixed in 0.7.5. websocket-driver: Resource limit bypass via message compression
- **Initial risk:** Critical (9.5): highest advisory severity CRITICAL
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-018 · 🟥 Critical (9.3) · Vulnerable transitive dependency

- **What:** babel-traverse@6.11.4: 1 known vulnerability (highest CRITICAL, CVSS 9.3)
- **Component:** `babel-traverse@6.11.4` (npm, scope dev, transitive), purl `pkg:npm/babel-traverse@6.11.4`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt-if@0.2.0 → grunt-contrib-nodeunit@1.0.0 → nodeunit@0.9.5 → tap@7.1.2 → nyc@7.1.0 → istanbul-lib-instrument@1.1.0-alpha.4 → babel-traverse@6.11.4 ; owasp-nodejs-goat@1.3.0 → grunt-if@0.2.0 → grunt-contrib-nodeunit@1.0.0 → nodeunit@0.9.5 → tap@7.1.2 → nyc@7.1.0 → istanbul-lib-instrument@1.1.0-alpha.4 → babel-template@6.9.0 → babel-traverse@6.11.4 ; owasp-nodejs-goat@1.3.0 → grunt-if@0.2.0 → grunt-contrib-nodeunit@1.0.0 → nodeunit@0.9.5 → tap@7.1.2 → nyc@7.1.0 → istanbul-lib-instrument@1.1.0-alpha.4 → babel-types@6.11.1 → babel-traverse@6.11.4
- **Official severity:** CRITICAL, CVSS 9.3 (OSV CVSS v3 vector (score computed))
- **Fix available:** no fixed version published
- **Evidence:**
  - [GHSA-67hx-6x53-jw92](https://osv.dev/vulnerability/GHSA-67hx-6x53-jw92) (CVE-2023-45133): CRITICAL, CVSS 9.3, no fix published. Babel vulnerable to arbitrary code execution when compiling specifically crafted malicious code
- **Initial risk:** Critical (9.3): highest advisory severity CRITICAL (CVSS 9.3); 1 advisory(ies) without a published fix
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-019 · 🟥 Critical (9.1) · Vulnerable transitive dependency

- **What:** lodash@2.4.2: 4 known vulnerabilities (highest CRITICAL, CVSS 9.1)
- **Component:** `lodash@2.4.2` (npm, scope dev, transitive), purl `pkg:npm/lodash@2.4.2`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → zaproxy@0.2.0 → lodash@2.4.2
- **Official severity:** CRITICAL, CVSS 9.1 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 4.17.21
- **Evidence:**
  - [GHSA-jf85-cpcp-j695](https://osv.dev/vulnerability/GHSA-jf85-cpcp-j695) (CVE-2019-10744): CRITICAL, CVSS 9.1, fixed in 4.17.12. Prototype Pollution in lodash
  - [GHSA-4xc9-xhrj-v574](https://osv.dev/vulnerability/GHSA-4xc9-xhrj-v574) (CVE-2018-16487): HIGH, fixed in 4.17.11. Prototype Pollution in lodash
  - [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) (CVE-2021-23337): HIGH, CVSS 7.2, fixed in 4.17.21. Command Injection in lodash
  - [GHSA-fvqr-27wr-82fm](https://osv.dev/vulnerability/GHSA-fvqr-27wr-82fm) (CVE-2018-3721): MEDIUM, CVSS 6.5, fixed in 4.17.5. Prototype Pollution in lodash
- **Initial risk:** Critical (9.1): highest advisory severity CRITICAL (CVSS 9.1)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-020 · 🟥 Critical (9.1) · Vulnerable transitive dependency

- **What:** lodash@4.13.1: 9 known vulnerabilities (highest CRITICAL, CVSS 9.1)
- **Component:** `lodash@4.13.1` (npm, scope dev, transitive), purl `pkg:npm/lodash@4.13.1`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt-if@0.2.0 → grunt-contrib-nodeunit@1.0.0 → nodeunit@0.9.5 → tap@7.1.2 → nyc@7.1.0 → istanbul-lib-instrument@1.1.0-alpha.4 → babel-generator@6.11.4 → lodash@4.13.1 ; owasp-nodejs-goat@1.3.0 → grunt-if@0.2.0 → grunt-contrib-nodeunit@1.0.0 → nodeunit@0.9.5 → tap@7.1.2 → nyc@7.1.0 → istanbul-lib-instrument@1.1.0-alpha.4 → babel-template@6.9.0 → lodash@4.13.1 ; owasp-nodejs-goat@1.3.0 → grunt-if@0.2.0 → grunt-contrib-nodeunit@1.0.0 → nodeunit@0.9.5 → tap@7.1.2 → nyc@7.1.0 → istanbul-lib-instrument@1.1.0-alpha.4 → babel-traverse@6.11.4 → lodash@4.13.1
- **Official severity:** CRITICAL, CVSS 9.1 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 4.18.0
- **Evidence:**
  - [GHSA-jf85-cpcp-j695](https://osv.dev/vulnerability/GHSA-jf85-cpcp-j695) (CVE-2019-10744): CRITICAL, CVSS 9.1, fixed in 4.17.12. Prototype Pollution in lodash
  - [GHSA-r5fr-rjxr-66jc](https://osv.dev/vulnerability/GHSA-r5fr-rjxr-66jc) (CVE-2026-4800): HIGH, CVSS 8.1, fixed in 4.18.0. lodash vulnerable to Code Injection via `_.template` imports key names
  - [GHSA-4xc9-xhrj-v574](https://osv.dev/vulnerability/GHSA-4xc9-xhrj-v574) (CVE-2018-16487): HIGH, fixed in 4.17.11. Prototype Pollution in lodash
  - [GHSA-p6mc-m468-83gw](https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw) (CVE-2020-8203): HIGH, CVSS 7.4, fixed in 4.17.19. Prototype Pollution in lodash
  - [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) (CVE-2021-23337): HIGH, CVSS 7.2, fixed in 4.17.21. Command Injection in lodash
  - [GHSA-fvqr-27wr-82fm](https://osv.dev/vulnerability/GHSA-fvqr-27wr-82fm) (CVE-2018-3721): MEDIUM, CVSS 6.5, fixed in 4.17.5. Prototype Pollution in lodash
  - [GHSA-x5rq-j2xg-h7qm](https://osv.dev/vulnerability/GHSA-x5rq-j2xg-h7qm) (CVE-2019-1010266): MEDIUM, CVSS 6.5, fixed in 4.17.11. Regular Expression Denial of Service (ReDoS) in lodash
  - [GHSA-xxjr-mmjv-4gpg](https://osv.dev/vulnerability/GHSA-xxjr-mmjv-4gpg) (CVE-2025-13465): MEDIUM, CVSS 6.5, fixed in 4.17.23. Lodash has Prototype Pollution Vulnerability in `_.unset`, `_.omit`, and `_.pullAt` functions
  - [GHSA-29mw-wpgm-hmr9](https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9) (CVE-2020-28500): MEDIUM, CVSS 5.3, fixed in 4.17.21. Regular Expression Denial of Service (ReDoS) in lodash
- **Initial risk:** Critical (9.1): highest advisory severity CRITICAL (CVSS 9.1)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-021 · 🟥 Critical (9.1) · Vulnerable transitive dependency

- **What:** lodash@4.17.11: 6 known vulnerabilities (highest CRITICAL, CVSS 9.1)
- **Component:** `lodash@4.17.11` (npm, scope dev, transitive), purl `pkg:npm/lodash@4.17.11`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → async@2.6.1 → lodash@4.17.11 ; owasp-nodejs-goat@1.3.0 → cypress@3.3.1 → lodash@4.17.11 ; owasp-nodejs-goat@1.3.0 → grunt-contrib-watch@1.1.0 → lodash@4.17.11
- **Official severity:** CRITICAL, CVSS 9.1 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 4.18.0
- **Evidence:**
  - [GHSA-jf85-cpcp-j695](https://osv.dev/vulnerability/GHSA-jf85-cpcp-j695) (CVE-2019-10744): CRITICAL, CVSS 9.1, fixed in 4.17.12. Prototype Pollution in lodash
  - [GHSA-r5fr-rjxr-66jc](https://osv.dev/vulnerability/GHSA-r5fr-rjxr-66jc) (CVE-2026-4800): HIGH, CVSS 8.1, fixed in 4.18.0. lodash vulnerable to Code Injection via `_.template` imports key names
  - [GHSA-p6mc-m468-83gw](https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw) (CVE-2020-8203): HIGH, CVSS 7.4, fixed in 4.17.19. Prototype Pollution in lodash
  - [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) (CVE-2021-23337): HIGH, CVSS 7.2, fixed in 4.17.21. Command Injection in lodash
  - [GHSA-xxjr-mmjv-4gpg](https://osv.dev/vulnerability/GHSA-xxjr-mmjv-4gpg) (CVE-2025-13465): MEDIUM, CVSS 6.5, fixed in 4.17.23. Lodash has Prototype Pollution Vulnerability in `_.unset`, `_.omit`, and `_.pullAt` functions
  - [GHSA-29mw-wpgm-hmr9](https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9) (CVE-2020-28500): MEDIUM, CVSS 5.3, fixed in 4.17.21. Regular Expression Denial of Service (ReDoS) in lodash
- **Initial risk:** Critical (9.1): highest advisory severity CRITICAL (CVSS 9.1)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-022 · 🟥 Critical (9.1) · Vulnerable transitive dependency

- **What:** proxy-addr@2.0.4: 1 known vulnerability (highest CRITICAL, CVSS 9.1)
- **Component:** `proxy-addr@2.0.4` (npm, scope prod, transitive), purl `pkg:npm/proxy-addr@2.0.4`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → express@4.16.4 → proxy-addr@2.0.4
- **Official severity:** CRITICAL, CVSS 9.1 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 2.0.8
- **Evidence:**
  - [GHSA-jqcg-44mw-7w3h](https://osv.dev/vulnerability/GHSA-jqcg-44mw-7w3h) (CVE-2026-90711): CRITICAL, CVSS 9.1, fixed in 2.0.8. proxy-addr vulnerable to IP spoofing via IPv4-mapped IPv6 trust subnet
- **Initial risk:** Critical (9.1): highest advisory severity CRITICAL (CVSS 9.1)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-023 · 🟧 High (8.8) · Vulnerable transitive dependency

- **What:** hoek@0.9.1: 2 known vulnerabilities (highest HIGH, CVSS 8.8)
- **Component:** `hoek@0.9.1` (npm, scope dev, transitive), purl `pkg:npm/hoek@0.9.1`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → zaproxy@0.2.0 → request@2.36.0 → hawk@1.0.0 → hoek@0.9.1 ; owasp-nodejs-goat@1.3.0 → zaproxy@0.2.0 → request@2.36.0 → hawk@1.0.0 → boom@0.4.2 → hoek@0.9.1 ; owasp-nodejs-goat@1.3.0 → zaproxy@0.2.0 → request@2.36.0 → hawk@1.0.0 → sntp@0.2.4 → hoek@0.9.1
- **Official severity:** HIGH, CVSS 8.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 4.2.1; no fix for GHSA-c429-5p7v-vgjp
- **Evidence:**
  - [GHSA-jp4x-w63m-7wgm](https://osv.dev/vulnerability/GHSA-jp4x-w63m-7wgm) (CVE-2018-3728): HIGH, CVSS 8.8, fixed in 4.2.1. Prototype Pollution in hoek
  - [GHSA-c429-5p7v-vgjp](https://osv.dev/vulnerability/GHSA-c429-5p7v-vgjp) (CVE-2020-36604): HIGH, CVSS 8.1, no fix published. hoek subject to prototype pollution via the clone function.
- **Initial risk:** High (8.8): highest advisory severity HIGH (CVSS 8.8); 1 advisory(ies) without a published fix
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-024 · 🟧 High (8.8) · Vulnerable transitive dependency

- **What:** hoek@2.16.3: 2 known vulnerabilities (highest HIGH, CVSS 8.8)
- **Component:** `hoek@2.16.3` (npm, scope dev, transitive), purl `pkg:npm/hoek@2.16.3`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt-retire@0.3.12 → request@2.67.0 → hawk@3.1.3 → hoek@2.16.3 ; owasp-nodejs-goat@1.3.0 → grunt-npm-install@0.3.1 → npm@3.10.10 → request@2.75.0 → hawk@3.1.3 → hoek@2.16.3 ; owasp-nodejs-goat@1.3.0 → grunt-retire@0.3.12 → retire@1.1.6 → request@2.79.0 → hawk@3.1.3 → hoek@2.16.3
- **Official severity:** HIGH, CVSS 8.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 4.2.1; no fix for GHSA-c429-5p7v-vgjp
- **Evidence:**
  - [GHSA-jp4x-w63m-7wgm](https://osv.dev/vulnerability/GHSA-jp4x-w63m-7wgm) (CVE-2018-3728): HIGH, CVSS 8.8, fixed in 4.2.1. Prototype Pollution in hoek
  - [GHSA-c429-5p7v-vgjp](https://osv.dev/vulnerability/GHSA-c429-5p7v-vgjp) (CVE-2020-36604): HIGH, CVSS 8.1, no fix published. hoek subject to prototype pollution via the clone function.
- **Initial risk:** High (8.8): highest advisory severity HIGH (CVSS 8.8); 1 advisory(ies) without a published fix
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-025 · 🟧 High (8.8) · Vulnerable transitive dependency

- **What:** tar@2.2.1: 16 known vulnerabilities (highest HIGH, CVSS 8.8)
- **Component:** `tar@2.2.1` (npm, scope dev, transitive), purl `pkg:npm/tar@2.2.1`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt-npm-install@0.3.1 → npm@3.10.10 → tar@2.2.1 ; owasp-nodejs-goat@1.3.0 → grunt-npm-install@0.3.1 → npm@3.10.10 → node-gyp@3.4.0 → tar@2.2.1
- **Official severity:** HIGH, CVSS 8.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 7.5.21
- **Evidence:**
  - [GHSA-r6q2-hw4h-h46w](https://osv.dev/vulnerability/GHSA-r6q2-hw4h-h46w) (CVE-2026-23950): HIGH, CVSS 8.8, fixed in 7.5.4. Race Condition in node-tar Path Reservations via Unicode Ligature Collisions on macOS APFS
  - [GHSA-34x7-hfp2-rc4v](https://osv.dev/vulnerability/GHSA-34x7-hfp2-rc4v) (CVE-2026-24842): HIGH, CVSS 8.2, fixed in 7.5.7. node-tar Vulnerable to Arbitrary File Creation/Overwrite via Hardlink Path Traversal
  - [GHSA-3jfq-g458-7qm9](https://osv.dev/vulnerability/GHSA-3jfq-g458-7qm9) (CVE-2021-32804): HIGH, CVSS 8.2, fixed in 3.2.2. Arbitrary File Creation/Overwrite due to insufficient absolute path sanitization
  - [GHSA-5955-9wpr-37jh](https://osv.dev/vulnerability/GHSA-5955-9wpr-37jh) (CVE-2021-37713): HIGH, CVSS 8.2, fixed in 4.4.18. Arbitrary File Creation/Overwrite on Windows via insufficient relative path sanitization
  - [GHSA-8qq5-rm4j-mr97](https://osv.dev/vulnerability/GHSA-8qq5-rm4j-mr97) (CVE-2026-23745): HIGH, fixed in 7.5.3. node-tar is Vulnerable to Arbitrary File Overwrite and Symlink Poisoning via Insufficient Path Sanitization
  - [GHSA-9ppj-qmqm-q256](https://osv.dev/vulnerability/GHSA-9ppj-qmqm-q256) (CVE-2026-31802): HIGH, fixed in 7.5.11. node-tar Symlink Path Traversal via Drive-Relative Linkpath
  - [GHSA-qffp-2rhf-9h96](https://osv.dev/vulnerability/GHSA-qffp-2rhf-9h96) (CVE-2026-29786): HIGH, fixed in 7.5.10. tar has Hardlink Path Traversal via Drive-Relative Linkpath
  - [GHSA-23hp-3jrh-7fpw](https://osv.dev/vulnerability/GHSA-23hp-3jrh-7fpw) (CVE-2026-59873): HIGH, CVSS 7.5, fixed in 7.5.19. node-tar: Decompression/parse DoS via unlimited input
  - [GHSA-8x88-c5mf-7j5w](https://osv.dev/vulnerability/GHSA-8x88-c5mf-7j5w) (CVE-2026-59874): HIGH, CVSS 7.5, fixed in 7.5.18. node-tar: Negative tar entry size causes infinite loop in archive replace
  - [GHSA-j44m-qm6p-hp7m](https://osv.dev/vulnerability/GHSA-j44m-qm6p-hp7m) (CVE-2018-20834): HIGH, CVSS 7.5, fixed in 2.2.2. Arbitrary File Overwrite in tar
  - [GHSA-r292-9mhp-454m](https://osv.dev/vulnerability/GHSA-r292-9mhp-454m) (CVE-2026-73566): HIGH, CVSS 7.5, fixed in 7.5.21. node-tar: Uncontrolled recursion in mapHas/filesFilter allows uncatchable stack-overflow DoS via crafted long-path tar with member selection
  - [GHSA-83g3-92jg-28cx](https://osv.dev/vulnerability/GHSA-83g3-92jg-28cx) (CVE-2026-26960): HIGH, CVSS 7.1, fixed in 7.5.8. Arbitrary File Read/Write via Hardlink Target Escape Through Symlink Chain in node-tar Extraction
  - … 4 more in findings.json
- **Initial risk:** High (8.8): highest advisory severity HIGH (CVSS 8.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-026 · 🟧 High (8.8) · Vulnerable transitive dependency

- **What:** tar@4.4.8: 18 known vulnerabilities (highest HIGH, CVSS 8.8)
- **Component:** `tar@4.4.8` (npm, scope optional, transitive), purl `pkg:npm/tar@4.4.8`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → nodemon@1.19.1 → chokidar@2.1.6 → fsevents@1.2.9 → node-pre-gyp@0.12.0 → tar@4.4.8 ; owasp-nodejs-goat@1.3.0 → forever@2.0.0 → forever-monitor@2.0.0 → chokidar@2.1.8 → fsevents@1.2.9 → node-pre-gyp@0.12.0 → tar@4.4.8
- **Official severity:** HIGH, CVSS 8.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 7.5.21
- **Evidence:**
  - [GHSA-r6q2-hw4h-h46w](https://osv.dev/vulnerability/GHSA-r6q2-hw4h-h46w) (CVE-2026-23950): HIGH, CVSS 8.8, fixed in 7.5.4. Race Condition in node-tar Path Reservations via Unicode Ligature Collisions on macOS APFS
  - [GHSA-34x7-hfp2-rc4v](https://osv.dev/vulnerability/GHSA-34x7-hfp2-rc4v) (CVE-2026-24842): HIGH, CVSS 8.2, fixed in 7.5.7. node-tar Vulnerable to Arbitrary File Creation/Overwrite via Hardlink Path Traversal
  - [GHSA-3jfq-g458-7qm9](https://osv.dev/vulnerability/GHSA-3jfq-g458-7qm9) (CVE-2021-32804): HIGH, CVSS 8.2, fixed in 4.4.14. Arbitrary File Creation/Overwrite due to insufficient absolute path sanitization
  - [GHSA-5955-9wpr-37jh](https://osv.dev/vulnerability/GHSA-5955-9wpr-37jh) (CVE-2021-37713): HIGH, CVSS 8.2, fixed in 4.4.18. Arbitrary File Creation/Overwrite on Windows via insufficient relative path sanitization
  - [GHSA-9r2w-394v-53qc](https://osv.dev/vulnerability/GHSA-9r2w-394v-53qc) (CVE-2021-37701): HIGH, CVSS 8.2, fixed in 4.4.16. Arbitrary File Creation/Overwrite via insufficient symlink protection due to directory cache poisoning using symbolic links
  - [GHSA-qq89-hq3f-393p](https://osv.dev/vulnerability/GHSA-qq89-hq3f-393p) (CVE-2021-37712): HIGH, CVSS 8.2, fixed in 4.4.18. Arbitrary File Creation/Overwrite via insufficient symlink protection due to directory cache poisoning using symbolic links
  - [GHSA-r628-mhmh-qjhw](https://osv.dev/vulnerability/GHSA-r628-mhmh-qjhw) (CVE-2021-32803): HIGH, CVSS 8.2, fixed in 4.4.15. Arbitrary File Creation/Overwrite via insufficient symlink protection due to directory cache poisoning
  - [GHSA-8qq5-rm4j-mr97](https://osv.dev/vulnerability/GHSA-8qq5-rm4j-mr97) (CVE-2026-23745): HIGH, fixed in 7.5.3. node-tar is Vulnerable to Arbitrary File Overwrite and Symlink Poisoning via Insufficient Path Sanitization
  - [GHSA-9ppj-qmqm-q256](https://osv.dev/vulnerability/GHSA-9ppj-qmqm-q256) (CVE-2026-31802): HIGH, fixed in 7.5.11. node-tar Symlink Path Traversal via Drive-Relative Linkpath
  - [GHSA-qffp-2rhf-9h96](https://osv.dev/vulnerability/GHSA-qffp-2rhf-9h96) (CVE-2026-29786): HIGH, fixed in 7.5.10. tar has Hardlink Path Traversal via Drive-Relative Linkpath
  - [GHSA-23hp-3jrh-7fpw](https://osv.dev/vulnerability/GHSA-23hp-3jrh-7fpw) (CVE-2026-59873): HIGH, CVSS 7.5, fixed in 7.5.19. node-tar: Decompression/parse DoS via unlimited input
  - [GHSA-8x88-c5mf-7j5w](https://osv.dev/vulnerability/GHSA-8x88-c5mf-7j5w) (CVE-2026-59874): HIGH, CVSS 7.5, fixed in 7.5.18. node-tar: Negative tar entry size causes infinite loop in archive replace
  - … 6 more in findings.json
- **Initial risk:** High (8.8): highest advisory severity HIGH (CVSS 8.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-027 · 🟧 High (8.2) · Vulnerable transitive dependency

- **What:** websocket-extensions@0.1.3: 1 known vulnerability (highest HIGH, CVSS 8.2)
- **Component:** `websocket-extensions@0.1.3` (npm, scope dev, transitive), purl `pkg:npm/websocket-extensions@0.1.3`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt-contrib-watch@1.1.0 → tiny-lr@1.1.1 → faye-websocket@0.10.0 → websocket-driver@0.7.0 → websocket-extensions@0.1.3
- **Official severity:** HIGH, CVSS 8.2 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 0.1.4
- **Evidence:**
  - [GHSA-g78m-2chm-r7qv](https://osv.dev/vulnerability/GHSA-g78m-2chm-r7qv) (CVE-2020-7662): HIGH, CVSS 8.2, fixed in 0.1.4. Regular Expression Denial of Service in websocket-extensions (NPM package)
- **Initial risk:** High (8.2): highest advisory severity HIGH (CVSS 8.2)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-028 · 🟧 High (8.1) · Vulnerable transitive dependency

- **What:** extract-zip@1.6.7: 2 known vulnerabilities (highest HIGH, CVSS 8.1)
- **Component:** `extract-zip@1.6.7` (npm, scope dev, transitive), purl `pkg:npm/extract-zip@1.6.7`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → cypress@3.3.1 → extract-zip@1.6.7
- **Official severity:** HIGH, CVSS 8.1 (OSV CVSS v3 vector (score computed))
- **Fix available:** no fixed version published
- **Evidence:**
  - [GHSA-7pqw-9j4j-h8q3](https://osv.dev/vulnerability/GHSA-7pqw-9j4j-h8q3) (CVE-2026-19693): HIGH, CVSS 8.1, no fix published. extract-zip allows arbitrary file writes through symlink archive entries
  - [GHSA-jmr9-qjv8-65gv](https://osv.dev/vulnerability/GHSA-jmr9-qjv8-65gv) (CVE-2026-56876): HIGH, CVSS 8.1, no fix published. extract-zip unvalidated symlink path traversal
- **Initial risk:** High (8.1): highest advisory severity HIGH (CVSS 8.1); 2 advisory(ies) without a published fix
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-029 · 🟧 High (8.1) · Vulnerable transitive dependency

- **What:** lodash@4.17.20: 4 known vulnerabilities (highest HIGH, CVSS 8.1)
- **Component:** `lodash@4.17.20` (npm, scope dev, transitive), purl `pkg:npm/lodash@4.17.20`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt-env@1.0.1 → lodash@4.17.20
- **Official severity:** HIGH, CVSS 8.1 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 4.18.0
- **Evidence:**
  - [GHSA-r5fr-rjxr-66jc](https://osv.dev/vulnerability/GHSA-r5fr-rjxr-66jc) (CVE-2026-4800): HIGH, CVSS 8.1, fixed in 4.18.0. lodash vulnerable to Code Injection via `_.template` imports key names
  - [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) (CVE-2021-23337): HIGH, CVSS 7.2, fixed in 4.17.21. Command Injection in lodash
  - [GHSA-xxjr-mmjv-4gpg](https://osv.dev/vulnerability/GHSA-xxjr-mmjv-4gpg) (CVE-2025-13465): MEDIUM, CVSS 6.5, fixed in 4.17.23. Lodash has Prototype Pollution Vulnerability in `_.unset`, `_.omit`, and `_.pullAt` functions
  - [GHSA-29mw-wpgm-hmr9](https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9) (CVE-2020-28500): MEDIUM, CVSS 5.3, fixed in 4.17.21. Regular Expression Denial of Service (ReDoS) in lodash
- **Initial risk:** High (8.1): highest advisory severity HIGH (CVSS 8.1)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-030 · 🟧 High (8.1) · Vulnerable transitive dependency

- **What:** lodash@4.17.21: 2 known vulnerabilities (highest HIGH, CVSS 8.1)
- **Component:** `lodash@4.17.21` (npm, scope dev, transitive), purl `pkg:npm/lodash@4.17.21`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → jshint@2.12.0 → lodash@4.17.21 ; owasp-nodejs-goat@1.3.0 → grunt-contrib-jshint@3.2.0 → jshint@2.13.6 → lodash@4.17.21
- **Official severity:** HIGH, CVSS 8.1 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 4.18.0
- **Evidence:**
  - [GHSA-r5fr-rjxr-66jc](https://osv.dev/vulnerability/GHSA-r5fr-rjxr-66jc) (CVE-2026-4800): HIGH, CVSS 8.1, fixed in 4.18.0. lodash vulnerable to Code Injection via `_.template` imports key names
  - [GHSA-xxjr-mmjv-4gpg](https://osv.dev/vulnerability/GHSA-xxjr-mmjv-4gpg) (CVE-2025-13465): MEDIUM, CVSS 6.5, fixed in 4.17.23. Lodash has Prototype Pollution Vulnerability in `_.unset`, `_.omit`, and `_.pullAt` functions
- **Initial risk:** High (8.1): highest advisory severity HIGH (CVSS 8.1)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-031 · 🟧 High (8.0) · Modified lockfile

- **What:** grunt-if@0.2.0 is downloaded from github.com, not the npm registry
- **Component:** `grunt-if@0.2.0` (npm, scope dev, direct), purl `pkg:npm/grunt-if@0.2.0`
- **Where:** `package-lock.json:39`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt-if@0.2.0
- **Evidence:**
  - `package-lock.json:39`: `"grunt-if": "https://github.com/binarymist/grunt-if/tarball/master",`
- **Initial risk:** High (8.0): R05_LOCKFILE_UNTRUSTED_SOURCE default level High
- **Why it matters:** The package is downloaded from a host other than the official registry.
- **Basis:** verified fact, confidence high

### F-032 · 🟧 High (8.0) · Vulnerable transitive dependency

- **What:** diff@1.4.0: 2 known vulnerabilities (highest HIGH)
- **Component:** `diff@1.4.0` (npm, scope dev, transitive), purl `pkg:npm/diff@1.4.0`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → mocha@2.5.3 → diff@1.4.0 ; owasp-nodejs-goat@1.3.0 → grunt-if@0.2.0 → grunt-contrib-nodeunit@1.0.0 → nodeunit@0.9.5 → tap@7.1.2 → tap-mocha-reporter@2.0.1 → diff@1.4.0
- **Official severity:** HIGH (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 3.5.1
- **Evidence:**
  - [GHSA-h6ch-v84p-w6p9](https://osv.dev/vulnerability/GHSA-h6ch-v84p-w6p9): HIGH, fixed in 3.5.0. Regular Expression Denial of Service (ReDoS)
  - [GHSA-73rr-hh4g-fpgx](https://osv.dev/vulnerability/GHSA-73rr-hh4g-fpgx) (CVE-2026-24001): LOW, fixed in 3.5.1. jsdiff has a Denial of Service vulnerability in parsePatch and applyPatch
- **Initial risk:** High (8.0): highest advisory severity HIGH
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-033 · 🟧 High (8.0) · Vulnerable direct dependency

- **What:** mongodb@2.2.36: 1 known vulnerability (highest HIGH)
- **Component:** `mongodb@2.2.36` (npm, scope prod, direct), purl `pkg:npm/mongodb@2.2.36`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → mongodb@2.2.36
- **Official severity:** HIGH (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 3.1.13
- **Evidence:**
  - [GHSA-mh5c-679w-hh4r](https://osv.dev/vulnerability/GHSA-mh5c-679w-hh4r): HIGH, fixed in 3.1.13. Denial of Service in mongodb
- **Initial risk:** High (8.0): highest advisory severity HIGH
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-034 · 🟧 High (7.8) · Vulnerable direct dependency

- **What:** async@2.6.1: 1 known vulnerability (highest HIGH, CVSS 7.8)
- **Component:** `async@2.6.1` (npm, scope dev, direct), purl `pkg:npm/async@2.6.1`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → async@2.6.1 ; owasp-nodejs-goat@1.3.0 → grunt-contrib-watch@1.1.0 → async@2.6.1 ; owasp-nodejs-goat@1.3.0 → grunt-jsbeautifier@0.2.13 → async@2.6.1
- **Official severity:** HIGH, CVSS 7.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 2.6.4
- **Evidence:**
  - [GHSA-fwr7-v2mv-hh25](https://osv.dev/vulnerability/GHSA-fwr7-v2mv-hh25) (CVE-2021-43138): HIGH, CVSS 7.8, fixed in 2.6.4. Prototype Pollution in async
- **Initial risk:** High (7.8): highest advisory severity HIGH (CVSS 7.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-035 · 🟧 High (7.8) · Vulnerable transitive dependency

- **What:** npm@3.10.10: 5 known vulnerabilities (highest HIGH, CVSS 7.8)
- **Component:** `npm@3.10.10` (npm, scope dev, transitive), purl `pkg:npm/npm@3.10.10`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt-npm-install@0.3.1 → npm@3.10.10
- **Official severity:** HIGH, CVSS 7.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 6.14.6
- **Evidence:**
  - [GHSA-ph34-pc88-72gc](https://osv.dev/vulnerability/GHSA-ph34-pc88-72gc) (CVE-2018-7408): HIGH, CVSS 7.8, fixed in 5.7.1. Incorrect Permission Assignment for Critical Resource in NPM
  - [GHSA-4328-8hgf-7wjr](https://osv.dev/vulnerability/GHSA-4328-8hgf-7wjr) (CVE-2019-16777): HIGH, CVSS 7.7, fixed in 6.13.4. npm Vulnerable to Global node_modules Binary Overwrite
  - [GHSA-m6cx-g6qm-p2cx](https://osv.dev/vulnerability/GHSA-m6cx-g6qm-p2cx) (CVE-2019-16775): HIGH, CVSS 7.7, fixed in 6.13.3. Arbitrary File Write in npm
  - [GHSA-x8qc-rrcw-4r46](https://osv.dev/vulnerability/GHSA-x8qc-rrcw-4r46) (CVE-2019-16776): HIGH, CVSS 7.7, fixed in 6.13.3. npm symlink reference outside of node_modules
  - [GHSA-93f3-23rq-pjfp](https://osv.dev/vulnerability/GHSA-93f3-23rq-pjfp) (CVE-2020-15095): MEDIUM, CVSS 4.4, fixed in 6.14.6. npm CLI exposing sensitive information through logs
- **Initial risk:** High (7.8): highest advisory severity HIGH (CVSS 7.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-036 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** adm-zip@0.4.4: 8 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `adm-zip@0.4.4` (npm, scope dev, transitive), purl `pkg:npm/adm-zip@0.4.4`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → selenium-webdriver@2.53.3 → adm-zip@0.4.4
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 0.6.1
- **Evidence:**
  - [GHSA-7q85-xj36-vmfc](https://osv.dev/vulnerability/GHSA-7q85-xj36-vmfc) (CVE-2026-77301): HIGH, CVSS 7.5, fixed in 0.6.1. adm-zip: Uncontrolled memory allocation via the declared uncompressed size (DoS)
  - [GHSA-8238-w5pm-2374](https://osv.dev/vulnerability/GHSA-8238-w5pm-2374) (CVE-2026-114102): HIGH, CVSS 7.5, fixed in 0.6.1. adm-zip: Unhandled error event in async DEFLATE decompression crashes Node.js process (DoS)
  - [GHSA-rcw4-f5rp-g42v](https://osv.dev/vulnerability/GHSA-rcw4-f5rp-g42v) (CVE-2026-92000): HIGH, CVSS 7.5, fixed in 0.6.1. adm-zip: Decompression-bomb protection (fix for CVE-2026-39244) can be bypassed by declaring uncompressed size as 0
  - [GHSA-xcpc-8h2w-3j85](https://osv.dev/vulnerability/GHSA-xcpc-8h2w-3j85) (CVE-2026-39244): HIGH, CVSS 7.5, fixed in 0.6.0. adm-zip: Crafted ZIP file triggers 4GB memory allocation
  - [GHSA-j5f4-cc29-5x44](https://osv.dev/vulnerability/GHSA-j5f4-cc29-5x44) (CVE-2026-102282): HIGH, CVSS 7.1, fixed in 0.6.1. adm-zip extraction preserves SUID/SGID bits from untrusted ZIPs -> local privilege escalation
  - [GHSA-p634-w6r4-rjp2](https://osv.dev/vulnerability/GHSA-p634-w6r4-rjp2) (CVE-2026-114104): MEDIUM, CVSS 5.9, fixed in 0.6.1. adm-zip: Duplicate ZIP entry names: getEntry() and extractAllTo() resolve to different content
  - [GHSA-3v6h-hqm4-2rg6](https://osv.dev/vulnerability/GHSA-3v6h-hqm4-2rg6) (CVE-2018-1002204): MEDIUM, CVSS 5.5, fixed in 0.4.11. Arbitrary File Write in adm-zip
  - [GHSA-c6fg-446q-cg94](https://osv.dev/vulnerability/GHSA-c6fg-446q-cg94) (CVE-2026-114103): MEDIUM, CVSS 5.3, fixed in 0.6.1. adm-zip: getDataAsync() bypasses the maxOutputLength size guard enforced by the synchronous getData() path
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-037 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** ansi-regex@3.0.0: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `ansi-regex@3.0.0` (npm, scope dev, transitive), purl `pkg:npm/ansi-regex@3.0.0`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → nodemon@1.19.1 → update-notifier@2.5.0 → boxen@1.3.0 → string-width@2.1.1 → strip-ansi@4.0.0 → ansi-regex@3.0.0 ; owasp-nodejs-goat@1.3.0 → nodemon@1.19.1 → update-notifier@2.5.0 → boxen@1.3.0 → ansi-align@2.0.0 → string-width@2.1.1 → strip-ansi@4.0.0 → ansi-regex@3.0.0 ; owasp-nodejs-goat@1.3.0 → nodemon@1.19.1 → update-notifier@2.5.0 → boxen@1.3.0 → widest-line@2.0.1 → string-width@2.1.1 → strip-ansi@4.0.0 → ansi-regex@3.0.0
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 3.0.1
- **Evidence:**
  - [GHSA-93q8-gq69-wqmw](https://osv.dev/vulnerability/GHSA-93q8-gq69-wqmw) (CVE-2021-3807): HIGH, CVSS 7.5, fixed in 3.0.1. Inefficient Regular Expression Complexity in chalk/ansi-regex
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-038 · 🟧 High (7.5) · Vulnerable direct dependency

- **What:** body-parser@1.18.3: 3 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `body-parser@1.18.3` (npm, scope prod, direct), purl `pkg:npm/body-parser@1.18.3`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → body-parser@1.18.3 ; owasp-nodejs-goat@1.3.0 → express@4.16.4 → body-parser@1.18.3
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.20.9
- **Evidence:**
  - [GHSA-27r3-jxmh-p828](https://osv.dev/vulnerability/GHSA-27r3-jxmh-p828) (CVE-2026-111181): HIGH, CVSS 7.5, fixed in 1.20.9. body-parser vulnerable to Denial of Service via trailing bytes after a compressed request body
  - [GHSA-qwcr-r2fm-qrc7](https://osv.dev/vulnerability/GHSA-qwcr-r2fm-qrc7) (CVE-2024-45590): HIGH, CVSS 7.5, fixed in 1.20.3. body-parser vulnerable to denial of service when url encoding is enabled
  - [GHSA-v422-hmwv-36x6](https://osv.dev/vulnerability/GHSA-v422-hmwv-36x6) (CVE-2026-12590): LOW, CVSS 3.7, fixed in 1.20.6. body-parser vulnerable to denial of service when invalid limit value silently disables size enforcement
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-039 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** brace-expansion@1.1.11: 8 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `brace-expansion@1.1.11` (npm, scope prod, transitive), purl `pkg:npm/brace-expansion@1.1.11`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt@1.0.3 → minimatch@3.0.4 → brace-expansion@1.1.11 ; owasp-nodejs-goat@1.3.0 → jshint@2.12.0 → minimatch@3.0.4 → brace-expansion@1.1.11 ; owasp-nodejs-goat@1.3.0 → nodemon@1.19.1 → minimatch@3.0.4 → brace-expansion@1.1.11
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.1.21
- **Evidence:**
  - [GHSA-6j4f-fj2g-mc7p](https://osv.dev/vulnerability/GHSA-6j4f-fj2g-mc7p) (CVE-2026-102276): HIGH, CVSS 7.5, fixed in 1.1.19. brace-expansion: DoS via uncontrolled recursion in parseCommaParts causing stack exhaustion
  - [GHSA-mh99-v99m-4gvg](https://osv.dev/vulnerability/GHSA-mh99-v99m-4gvg) (CVE-2026-14257): HIGH, CVSS 7.5, fixed in 1.1.17. brace-expansion: DoS via unbounded expansion length causing an out-of-memory process crash
  - [GHSA-qhr7-859c-m2p7](https://osv.dev/vulnerability/GHSA-qhr7-859c-m2p7) (CVE-2026-102278): HIGH, CVSS 7.5, fixed in 1.1.20. brace-expansion: DoS via uncontrolled recursion on nested brace groups causing stack exhaustion
  - [GHSA-rgw5-rvv9-x895](https://osv.dev/vulnerability/GHSA-rgw5-rvv9-x895) (CVE-2026-69152): HIGH, CVSS 7.5, fixed in 1.1.18. brace-expansion: DoS via unbounded intermediate arrays, bypassing the CVE-2026-14257 mitigation
  - [GHSA-f886-m6hf-6m8v](https://osv.dev/vulnerability/GHSA-f886-m6hf-6m8v) (CVE-2026-33750): MEDIUM, CVSS 6.5, fixed in 1.1.13. brace-expansion: Zero-step sequence causes process hang and memory exhaustion
  - [GHSA-3jxr-9vmj-r5cp](https://osv.dev/vulnerability/GHSA-3jxr-9vmj-r5cp) (CVE-2026-13149): MEDIUM, CVSS 5.3, fixed in 1.1.16. brace-expansion: DoS via exponential-time expansion of consecutive non-expanding {} groups
  - [GHSA-q2hr-2g5m-vwhr](https://osv.dev/vulnerability/GHSA-q2hr-2g5m-vwhr) (CVE-2026-102277): MEDIUM, CVSS 5.3, fixed in 1.1.21. brace-expansion: Quadratic-time expansion of the `{a},b}` rewrite causes CPU denial of service
  - [GHSA-v6h2-p8h4-qcjw](https://osv.dev/vulnerability/GHSA-v6h2-p8h4-qcjw) (CVE-2025-5889): LOW, CVSS 3.1, fixed in 1.1.12. brace-expansion Regular Expression Denial of Service vulnerability
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-040 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** brace-expansion@1.1.6: 9 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `brace-expansion@1.1.6` (npm, scope dev, transitive), purl `pkg:npm/brace-expansion@1.1.6`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt-npm-install@0.3.1 → npm@3.10.10 → glob@7.1.0 → minimatch@3.0.3 → brace-expansion@1.1.6 ; owasp-nodejs-goat@1.3.0 → grunt-npm-install@0.3.1 → npm@3.10.10 → node-gyp@3.4.0 → minimatch@3.0.3 → brace-expansion@1.1.6 ; owasp-nodejs-goat@1.3.0 → grunt-npm-install@0.3.1 → npm@3.10.10 → fstream-npm@1.2.0 → fstream-ignore@1.0.5 → minimatch@3.0.3 → brace-expansion@1.1.6
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.1.21
- **Evidence:**
  - [GHSA-6j4f-fj2g-mc7p](https://osv.dev/vulnerability/GHSA-6j4f-fj2g-mc7p) (CVE-2026-102276): HIGH, CVSS 7.5, fixed in 1.1.19. brace-expansion: DoS via uncontrolled recursion in parseCommaParts causing stack exhaustion
  - [GHSA-832h-xg76-4gv6](https://osv.dev/vulnerability/GHSA-832h-xg76-4gv6) (CVE-2017-18077): HIGH, CVSS 7.5, fixed in 1.1.7. ReDoS in brace-expansion
  - [GHSA-mh99-v99m-4gvg](https://osv.dev/vulnerability/GHSA-mh99-v99m-4gvg) (CVE-2026-14257): HIGH, CVSS 7.5, fixed in 1.1.17. brace-expansion: DoS via unbounded expansion length causing an out-of-memory process crash
  - [GHSA-qhr7-859c-m2p7](https://osv.dev/vulnerability/GHSA-qhr7-859c-m2p7) (CVE-2026-102278): HIGH, CVSS 7.5, fixed in 1.1.20. brace-expansion: DoS via uncontrolled recursion on nested brace groups causing stack exhaustion
  - [GHSA-rgw5-rvv9-x895](https://osv.dev/vulnerability/GHSA-rgw5-rvv9-x895) (CVE-2026-69152): HIGH, CVSS 7.5, fixed in 1.1.18. brace-expansion: DoS via unbounded intermediate arrays, bypassing the CVE-2026-14257 mitigation
  - [GHSA-f886-m6hf-6m8v](https://osv.dev/vulnerability/GHSA-f886-m6hf-6m8v) (CVE-2026-33750): MEDIUM, CVSS 6.5, fixed in 1.1.13. brace-expansion: Zero-step sequence causes process hang and memory exhaustion
  - [GHSA-3jxr-9vmj-r5cp](https://osv.dev/vulnerability/GHSA-3jxr-9vmj-r5cp) (CVE-2026-13149): MEDIUM, CVSS 5.3, fixed in 1.1.16. brace-expansion: DoS via exponential-time expansion of consecutive non-expanding {} groups
  - [GHSA-q2hr-2g5m-vwhr](https://osv.dev/vulnerability/GHSA-q2hr-2g5m-vwhr) (CVE-2026-102277): MEDIUM, CVSS 5.3, fixed in 1.1.21. brace-expansion: Quadratic-time expansion of the `{a},b}` rewrite causes CPU denial of service
  - [GHSA-v6h2-p8h4-qcjw](https://osv.dev/vulnerability/GHSA-v6h2-p8h4-qcjw) (CVE-2025-5889): LOW, CVSS 3.1, fixed in 1.1.12. brace-expansion Regular Expression Denial of Service vulnerability
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-041 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** braces@1.8.5: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `braces@1.8.5` (npm, scope dev, transitive), purl `pkg:npm/braces@1.8.5`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt-if@0.2.0 → grunt-contrib-nodeunit@1.0.0 → nodeunit@0.9.5 → tap@7.1.2 → nyc@7.1.0 → micromatch@2.3.11 → braces@1.8.5 ; owasp-nodejs-goat@1.3.0 → grunt-if@0.2.0 → grunt-contrib-nodeunit@1.0.0 → nodeunit@0.9.5 → tap@7.1.2 → nyc@7.1.0 → test-exclude@1.1.0 → micromatch@2.3.11 → braces@1.8.5
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 3.0.3
- **Evidence:**
  - [GHSA-grv7-fg5c-xmjg](https://osv.dev/vulnerability/GHSA-grv7-fg5c-xmjg) (CVE-2024-4068): HIGH, CVSS 7.5, fixed in 3.0.3. Uncontrolled resource consumption in braces
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-042 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** braces@2.3.2: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `braces@2.3.2` (npm, scope prod, transitive), purl `pkg:npm/braces@2.3.2`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → nodemon@1.19.1 → chokidar@2.1.6 → braces@2.3.2 ; owasp-nodejs-goat@1.3.0 → forever@2.0.0 → forever-monitor@2.0.0 → chokidar@2.1.8 → braces@2.3.2 ; owasp-nodejs-goat@1.3.0 → nodemon@1.19.1 → chokidar@2.1.6 → anymatch@2.0.0 → micromatch@3.1.10 → braces@2.3.2
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 3.0.3
- **Evidence:**
  - [GHSA-grv7-fg5c-xmjg](https://osv.dev/vulnerability/GHSA-grv7-fg5c-xmjg) (CVE-2024-4068): HIGH, CVSS 7.5, fixed in 3.0.3. Uncontrolled resource consumption in braces
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-043 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** cross-spawn@4.0.0: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `cross-spawn@4.0.0` (npm, scope dev, transitive), purl `pkg:npm/cross-spawn@4.0.0`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt-if@0.2.0 → grunt-contrib-nodeunit@1.0.0 → nodeunit@0.9.5 → tap@7.1.2 → nyc@7.1.0 → foreground-child@1.5.3 → cross-spawn@4.0.0 ; owasp-nodejs-goat@1.3.0 → grunt-if@0.2.0 → grunt-contrib-nodeunit@1.0.0 → nodeunit@0.9.5 → tap@7.1.2 → nyc@7.1.0 → spawn-wrap@1.2.4 → foreground-child@1.5.3 → cross-spawn@4.0.0
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 6.0.6
- **Evidence:**
  - [GHSA-3xgq-45jj-v275](https://osv.dev/vulnerability/GHSA-3xgq-45jj-v275) (CVE-2024-21538): HIGH, CVSS 7.5, fixed in 6.0.6. Regular Expression Denial of Service (ReDoS) in cross-spawn
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-044 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** cross-spawn@4.0.2: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `cross-spawn@4.0.2` (npm, scope dev, transitive), purl `pkg:npm/cross-spawn@4.0.2`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt-if@0.2.0 → grunt-contrib-nodeunit@1.0.0 → nodeunit@0.9.5 → tap@7.1.2 → foreground-child@1.5.6 → cross-spawn@4.0.2
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 6.0.6
- **Evidence:**
  - [GHSA-3xgq-45jj-v275](https://osv.dev/vulnerability/GHSA-3xgq-45jj-v275) (CVE-2024-21538): HIGH, CVSS 7.5, fixed in 6.0.6. Regular Expression Denial of Service (ReDoS) in cross-spawn
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-045 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** cross-spawn@5.1.0: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `cross-spawn@5.1.0` (npm, scope dev, transitive), purl `pkg:npm/cross-spawn@5.1.0`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → nodemon@1.19.1 → update-notifier@2.5.0 → boxen@1.3.0 → term-size@1.2.0 → execa@0.7.0 → cross-spawn@5.1.0
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 6.0.6
- **Evidence:**
  - [GHSA-3xgq-45jj-v275](https://osv.dev/vulnerability/GHSA-3xgq-45jj-v275) (CVE-2024-21538): HIGH, CVSS 7.5, fixed in 6.0.6. Regular Expression Denial of Service (ReDoS) in cross-spawn
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-046 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** cross-spawn@6.0.5: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `cross-spawn@6.0.5` (npm, scope dev, transitive), purl `pkg:npm/cross-spawn@6.0.5`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → cypress@3.3.1 → execa@0.10.0 → cross-spawn@6.0.5
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 6.0.6
- **Evidence:**
  - [GHSA-3xgq-45jj-v275](https://osv.dev/vulnerability/GHSA-3xgq-45jj-v275) (CVE-2024-21538): HIGH, CVSS 7.5, fixed in 6.0.6. Regular Expression Denial of Service (ReDoS) in cross-spawn
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-047 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** cross-spawn@7.0.3: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `cross-spawn@7.0.3` (npm, scope dev, transitive), purl `pkg:npm/cross-spawn@7.0.3`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → cross-env@7.0.2 → cross-spawn@7.0.3
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 7.0.5
- **Evidence:**
  - [GHSA-3xgq-45jj-v275](https://osv.dev/vulnerability/GHSA-3xgq-45jj-v275) (CVE-2024-21538): HIGH, CVSS 7.5, fixed in 7.0.5. Regular Expression Denial of Service (ReDoS) in cross-spawn
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-048 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** debug@2.2.0: 2 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `debug@2.2.0` (npm, scope prod, transitive), purl `pkg:npm/debug@2.2.0`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → mocha@2.5.3 → debug@2.2.0 ; owasp-nodejs-goat@1.3.0 → helmet@2.3.0 → connect@3.4.1 → debug@2.2.0 ; owasp-nodejs-goat@1.3.0 → helmet@2.3.0 → connect@3.4.1 → finalhandler@0.4.1 → debug@2.2.0
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 2.6.9
- **Evidence:**
  - [GHSA-9vvw-cc9w-f27h](https://osv.dev/vulnerability/GHSA-9vvw-cc9w-f27h) (CVE-2017-20165): HIGH, CVSS 7.5, fixed in 2.6.9. debug Inefficient Regular Expression Complexity vulnerability
  - [GHSA-gxpj-cx7g-858c](https://osv.dev/vulnerability/GHSA-gxpj-cx7g-858c) (CVE-2017-16137): LOW, CVSS 3.7, fixed in 2.6.9. Regular Expression Denial of Service in debug
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-049 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** decode-uri-component@0.2.0: 3 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `decode-uri-component@0.2.0` (npm, scope prod, transitive), purl `pkg:npm/decode-uri-component@0.2.0`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → nodemon@1.19.1 → chokidar@2.1.6 → braces@2.3.2 → snapdragon@0.8.2 → source-map-resolve@0.5.2 → decode-uri-component@0.2.0 ; owasp-nodejs-goat@1.3.0 → forever@2.0.0 → forever-monitor@2.0.0 → chokidar@2.1.8 → braces@2.3.2 → snapdragon@0.8.2 → source-map-resolve@0.5.2 → decode-uri-component@0.2.0 ; owasp-nodejs-goat@1.3.0 → nodemon@1.19.1 → chokidar@2.1.6 → anymatch@2.0.0 → micromatch@3.1.10 → snapdragon@0.8.2 → source-map-resolve@0.5.2 → decode-uri-component@0.2.0
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 0.5.1
- **Evidence:**
  - [GHSA-qr28-fpjm-wq7f](https://osv.dev/vulnerability/GHSA-qr28-fpjm-wq7f) (CVE-2026-118664): HIGH, fixed in 0.5.1. decode-uri-component vulnerable to denial of service via quadratic replacement of percent-encoded runs
  - [GHSA-w573-4hg7-7wgq](https://osv.dev/vulnerability/GHSA-w573-4hg7-7wgq) (CVE-2022-38900): HIGH, CVSS 7.5, fixed in 0.2.1. decode-uri-component vulnerable to Denial of Service (DoS)
  - [GHSA-vcc3-ghjq-m6fr](https://osv.dev/vulnerability/GHSA-vcc3-ghjq-m6fr) (CVE-2026-45822): MEDIUM, fixed in 0.5.0. decode-uri-component: Denial of service via exponential decoding of malformed percent-encoded input
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-050 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** form-data@0.1.4: 2 known vulnerabilities (highest CRITICAL, CVSS 7.5)
- **Component:** `form-data@0.1.4` (npm, scope dev, transitive), purl `pkg:npm/form-data@0.1.4`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → zaproxy@0.2.0 → request@2.36.0 → form-data@0.1.4
- **Official severity:** CRITICAL, CVSS 7.5 (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 2.5.6
- **Evidence:**
  - [GHSA-fjxv-7rqg-78g4](https://osv.dev/vulnerability/GHSA-fjxv-7rqg-78g4) (CVE-2025-7783): CRITICAL, fixed in 2.5.4. form-data uses unsafe random function in form-data for choosing boundary
  - [GHSA-hmw2-7cc7-3qxx](https://osv.dev/vulnerability/GHSA-hmw2-7cc7-3qxx) (CVE-2026-12143): HIGH, CVSS 7.5, fixed in 2.5.6. form-data: CRLF injection in form-data via unescaped multipart field names and filenames
- **Initial risk:** High (7.5): highest advisory severity CRITICAL (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-051 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** form-data@1.0.1: 2 known vulnerabilities (highest CRITICAL, CVSS 7.5)
- **Component:** `form-data@1.0.1` (npm, scope dev, transitive), purl `pkg:npm/form-data@1.0.1`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt-retire@0.3.12 → request@2.67.0 → form-data@1.0.1
- **Official severity:** CRITICAL, CVSS 7.5 (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 2.5.6
- **Evidence:**
  - [GHSA-fjxv-7rqg-78g4](https://osv.dev/vulnerability/GHSA-fjxv-7rqg-78g4) (CVE-2025-7783): CRITICAL, fixed in 2.5.4. form-data uses unsafe random function in form-data for choosing boundary
  - [GHSA-hmw2-7cc7-3qxx](https://osv.dev/vulnerability/GHSA-hmw2-7cc7-3qxx) (CVE-2026-12143): HIGH, CVSS 7.5, fixed in 2.5.6. form-data: CRLF injection in form-data via unescaped multipart field names and filenames
- **Initial risk:** High (7.5): highest advisory severity CRITICAL (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-052 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** form-data@2.0.0: 2 known vulnerabilities (highest CRITICAL, CVSS 7.5)
- **Component:** `form-data@2.0.0` (npm, scope dev, transitive), purl `pkg:npm/form-data@2.0.0`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt-npm-install@0.3.1 → npm@3.10.10 → request@2.75.0 → form-data@2.0.0 ; owasp-nodejs-goat@1.3.0 → grunt-npm-install@0.3.1 → npm@3.10.10 → node-gyp@3.4.0 → request@2.75.0 → form-data@2.0.0 ; owasp-nodejs-goat@1.3.0 → grunt-npm-install@0.3.1 → npm@3.10.10 → npm-registry-client@7.2.1 → request@2.75.0 → form-data@2.0.0
- **Official severity:** CRITICAL, CVSS 7.5 (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 2.5.6
- **Evidence:**
  - [GHSA-fjxv-7rqg-78g4](https://osv.dev/vulnerability/GHSA-fjxv-7rqg-78g4) (CVE-2025-7783): CRITICAL, fixed in 2.5.4. form-data uses unsafe random function in form-data for choosing boundary
  - [GHSA-hmw2-7cc7-3qxx](https://osv.dev/vulnerability/GHSA-hmw2-7cc7-3qxx) (CVE-2026-12143): HIGH, CVSS 7.5, fixed in 2.5.6. form-data: CRLF injection in form-data via unescaped multipart field names and filenames
- **Initial risk:** High (7.5): highest advisory severity CRITICAL (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-053 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** form-data@2.1.4: 2 known vulnerabilities (highest CRITICAL, CVSS 7.5)
- **Component:** `form-data@2.1.4` (npm, scope dev, transitive), purl `pkg:npm/form-data@2.1.4`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt-retire@0.3.12 → retire@1.1.6 → request@2.79.0 → form-data@2.1.4 ; owasp-nodejs-goat@1.3.0 → grunt-if@0.2.0 → grunt-contrib-nodeunit@1.0.0 → nodeunit@0.9.5 → tap@7.1.2 → coveralls@2.13.3 → request@2.79.0 → form-data@2.1.4
- **Official severity:** CRITICAL, CVSS 7.5 (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 2.5.6
- **Evidence:**
  - [GHSA-fjxv-7rqg-78g4](https://osv.dev/vulnerability/GHSA-fjxv-7rqg-78g4) (CVE-2025-7783): CRITICAL, fixed in 2.5.4. form-data uses unsafe random function in form-data for choosing boundary
  - [GHSA-hmw2-7cc7-3qxx](https://osv.dev/vulnerability/GHSA-hmw2-7cc7-3qxx) (CVE-2026-12143): HIGH, CVSS 7.5, fixed in 2.5.6. form-data: CRLF injection in form-data via unescaped multipart field names and filenames
- **Initial risk:** High (7.5): highest advisory severity CRITICAL (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-054 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** form-data@2.3.3: 2 known vulnerabilities (highest CRITICAL, CVSS 7.5)
- **Component:** `form-data@2.3.3` (npm, scope dev, transitive), purl `pkg:npm/form-data@2.3.3`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → cypress@3.3.1 → request@2.88.0 → form-data@2.3.3
- **Official severity:** CRITICAL, CVSS 7.5 (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 2.5.6
- **Evidence:**
  - [GHSA-fjxv-7rqg-78g4](https://osv.dev/vulnerability/GHSA-fjxv-7rqg-78g4) (CVE-2025-7783): CRITICAL, fixed in 2.5.4. form-data uses unsafe random function in form-data for choosing boundary
  - [GHSA-hmw2-7cc7-3qxx](https://osv.dev/vulnerability/GHSA-hmw2-7cc7-3qxx) (CVE-2026-12143): HIGH, CVSS 7.5, fixed in 2.5.6. form-data: CRLF injection in form-data via unescaped multipart field names and filenames
- **Initial risk:** High (7.5): highest advisory severity CRITICAL (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-055 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** fstream@1.0.10: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `fstream@1.0.10` (npm, scope dev, transitive), purl `pkg:npm/fstream@1.0.10`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt-npm-install@0.3.1 → npm@3.10.10 → fstream@1.0.10 ; owasp-nodejs-goat@1.3.0 → grunt-npm-install@0.3.1 → npm@3.10.10 → node-gyp@3.4.0 → fstream@1.0.10 ; owasp-nodejs-goat@1.3.0 → grunt-npm-install@0.3.1 → npm@3.10.10 → tar@2.2.1 → fstream@1.0.10
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.0.12
- **Evidence:**
  - [GHSA-xf7w-r453-m56c](https://osv.dev/vulnerability/GHSA-xf7w-r453-m56c) (CVE-2019-13173): HIGH, CVSS 7.5, fixed in 1.0.12. Arbitrary File Overwrite in fstream
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-056 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** hawk@1.0.0: 2 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `hawk@1.0.0` (npm, scope dev, transitive), purl `pkg:npm/hawk@1.0.0`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → zaproxy@0.2.0 → request@2.36.0 → hawk@1.0.0
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 9.0.1
- **Evidence:**
  - [GHSA-jcpv-g9rr-qxrc](https://osv.dev/vulnerability/GHSA-jcpv-g9rr-qxrc) (CVE-2016-2515): HIGH, CVSS 7.5, fixed in 3.1.3. Regular Expression Denial of Service in hawk
  - [GHSA-44pw-h2cw-w3vq](https://osv.dev/vulnerability/GHSA-44pw-h2cw-w3vq) (CVE-2022-29167): HIGH, CVSS 7.4, fixed in 9.0.1. Uncontrolled Resource Consumption in Hawk
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-057 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** i@0.3.6: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `i@0.3.6` (npm, scope prod, transitive), purl `pkg:npm/i@0.3.6`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → forever@2.0.0 → utile@0.3.0 → i@0.3.6 ; owasp-nodejs-goat@1.3.0 → forever@2.0.0 → forever-monitor@2.0.0 → utile@0.3.0 → i@0.3.6 ; owasp-nodejs-goat@1.3.0 → forever@2.0.0 → flatiron@0.4.3 → broadway@0.3.6 → utile@0.2.1 → i@0.3.6
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 0.3.7
- **Evidence:**
  - [GHSA-x55w-vjjp-222r](https://osv.dev/vulnerability/GHSA-x55w-vjjp-222r) (CVE-2021-3820): HIGH, CVSS 7.5, fixed in 0.3.7. inflect vulnerable to Inefficient Regular Expression Complexity
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-058 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** js-yaml@3.5.5: 7 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `js-yaml@3.5.5` (npm, scope dev, transitive), purl `pkg:npm/js-yaml@3.5.5`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt@1.0.3 → js-yaml@3.5.5 ; owasp-nodejs-goat@1.3.0 → grunt-if@0.2.0 → grunt@1.0.3 → js-yaml@3.5.5 ; owasp-nodejs-goat@1.3.0 → grunt-jsbeautifier@0.2.13 → grunt@1.0.3 → js-yaml@3.5.5
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 3.15.2
- **Evidence:**
  - [GHSA-8j8c-7jfh-h6hx](https://osv.dev/vulnerability/GHSA-8j8c-7jfh-h6hx): HIGH, fixed in 3.13.1. Code Injection in js-yaml
  - [GHSA-2883-xcg3-v3hh](https://osv.dev/vulnerability/GHSA-2883-xcg3-v3hh) (CVE-2026-84375): HIGH, CVSS 7.5, fixed in 3.15.2. js-yaml: maxTotalMergeKeys does not limit CPU use for empty merge sources
  - [GHSA-52cp-r559-cp3m](https://osv.dev/vulnerability/GHSA-52cp-r559-cp3m) (CVE-2026-59869): HIGH, CVSS 7.5, fixed in 3.15.0. js-yaml: YAML merge-key chains can force quadratic CPU consumption
  - [GHSA-5p4m-2wfm-xmqj](https://osv.dev/vulnerability/GHSA-5p4m-2wfm-xmqj): HIGH, CVSS 7.5, fixed in 3.15.1. JS-YAML: Quadratic CPU consumption in !!omap resolution (3.x and 4.x) — CVE-2026-59870 fix not backported
  - [GHSA-2pr6-76vf-7546](https://osv.dev/vulnerability/GHSA-2pr6-76vf-7546): MEDIUM, CVSS 5.9, fixed in 3.13.0. Denial of Service in js-yaml
  - [GHSA-h67p-54hq-rp68](https://osv.dev/vulnerability/GHSA-h67p-54hq-rp68) (CVE-2026-53550): MEDIUM, CVSS 5.3, fixed in 3.15.0. JS-YAML: Quadratic-complexity DoS in merge key handling via repeated aliases
  - [GHSA-mh29-5h37-fv8m](https://osv.dev/vulnerability/GHSA-mh29-5h37-fv8m) (CVE-2025-64718): MEDIUM, CVSS 5.3, fixed in 3.14.2. js-yaml has prototype pollution in merge (<<)
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-059 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** js-yaml@3.6.1: 7 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `js-yaml@3.6.1` (npm, scope dev, transitive), purl `pkg:npm/js-yaml@3.6.1`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → grunt-if@0.2.0 → grunt-contrib-nodeunit@1.0.0 → nodeunit@0.9.5 → tap@7.1.2 → coveralls@2.13.3 → js-yaml@3.6.1
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 3.15.2
- **Evidence:**
  - [GHSA-8j8c-7jfh-h6hx](https://osv.dev/vulnerability/GHSA-8j8c-7jfh-h6hx): HIGH, fixed in 3.13.1. Code Injection in js-yaml
  - [GHSA-2883-xcg3-v3hh](https://osv.dev/vulnerability/GHSA-2883-xcg3-v3hh) (CVE-2026-84375): HIGH, CVSS 7.5, fixed in 3.15.2. js-yaml: maxTotalMergeKeys does not limit CPU use for empty merge sources
  - [GHSA-52cp-r559-cp3m](https://osv.dev/vulnerability/GHSA-52cp-r559-cp3m) (CVE-2026-59869): HIGH, CVSS 7.5, fixed in 3.15.0. js-yaml: YAML merge-key chains can force quadratic CPU consumption
  - [GHSA-5p4m-2wfm-xmqj](https://osv.dev/vulnerability/GHSA-5p4m-2wfm-xmqj): HIGH, CVSS 7.5, fixed in 3.15.1. JS-YAML: Quadratic CPU consumption in !!omap resolution (3.x and 4.x) — CVE-2026-59870 fix not backported
  - [GHSA-2pr6-76vf-7546](https://osv.dev/vulnerability/GHSA-2pr6-76vf-7546): MEDIUM, CVSS 5.9, fixed in 3.13.0. Denial of Service in js-yaml
  - [GHSA-h67p-54hq-rp68](https://osv.dev/vulnerability/GHSA-h67p-54hq-rp68) (CVE-2026-53550): MEDIUM, CVSS 5.3, fixed in 3.15.0. JS-YAML: Quadratic-complexity DoS in merge key handling via repeated aliases
  - [GHSA-mh29-5h37-fv8m](https://osv.dev/vulnerability/GHSA-mh29-5h37-fv8m) (CVE-2025-64718): MEDIUM, CVSS 5.3, fixed in 3.14.2. js-yaml has prototype pollution in merge (<<)
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-060 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** kind-of@6.0.2: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `kind-of@6.0.2` (npm, scope prod, transitive), purl `pkg:npm/kind-of@6.0.2`
- **Where:** `package-lock.json`
- **Dependency path:** owasp-nodejs-goat@1.3.0 → nodemon@1.19.1 → chokidar@2.1.6 → anymatch@2.0.0 → micromatch@3.1.10 → kind-of@6.0.2 ; owasp-nodejs-goat@1.3.0 → grunt-cli@1.3.2 → liftoff@2.5.0 → findup-sync@2.0.0 → micromatch@3.1.10 → kind-of@6.0.2 ; owasp-nodejs-goat@1.3.0 → nodemon@1.19.1 → chokidar@2.1.6 → readdirp@2.2.1 → micromatch@3.1.10 → kind-of@6.0.2
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 6.0.3
- **Evidence:**
  - [GHSA-6c8f-qphg-qjgp](https://osv.dev/vulnerability/GHSA-6c8f-qphg-qjgp) (CVE-2019-20149): HIGH, CVSS 7.5, fixed in 6.0.3. Validation Bypass in kind-of
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

*81 more findings: full evidence in `findings.json`.*

## 5. AI triage and summary (inference, not evidence)

> Generated by **deepseek:deepseek-flash** through the LangGraph agent workflow. This section is *inference* over sections 1-4: it cites finding IDs (`F-001`) and evidence IDs (`F-001/E1` finding evidence, `F-001/T1` tool evidence) and never changes the evidence or the initial risk above. Grounding check passed for 6/6 triaged findings. Knowledge base `7f4bce14289a`.

**NodeGoat carries 1,097 components and 141 findings — including a flagged fsevents@1.2.9 — while the latest merge changes only one HTML view.**

- **What is in the application:** The application is owasp-nodejs-goat@1.3.0, an npm application with 1,091 npm packages (36 direct, 1,055 transitive, nesting up to depth 13), plus 4 GitHub Actions components and 2 container images (mongo:4.4, node:12-alpine). Scopes split into 346 prod, 714 dev, 33 optional and 4 CI components, with two CI workflows (e2e-test, lint), a Dockerfile and docker-compose.yml. The vulnerability lookup (OSV.dev) reports 131 vulnerable components and 311 advisories, against 141 total findings: 22 Critical, 72 High, 32 Medium, 15 Low, of which 131 are vulnerabilities and 10 anomalies.
- **What changed:** The change under review is merge commit c5cb68a (PR #290, "add-blank-space") by a returning author; it touches a single file, app/views/contributions.html, with no dependency manifest additions or changes recorded. One finding is marked new in this change, F-001 (fsevents@1.2.9 flagged as a typosquatted/malicious package), which is inconsistent with a change that adds no packages and should be treated as an attribution question rather than proof the merge introduced it.
- **What appears risky:** The dominant risk is dependency depth and staleness: the tree contains many old, heavily-vendored packages, with repeated Critical findings on minimist (F-008 through F-011), lodash (F-019 through F-021), set-value (F-013, F-014) and underscore (F-015, F-016), and handlebars@4.0.5 alone carrying 20 advisories (F-006). One direct prod dependency, underscore@1.9.1 (F-016), is rated Critical at CVSS 9.8. Supply-chain anomalies sit alongside this: the inventory records an untrusted GitHub-tarball origin for grunt-if@0.2.0, and install scripts in cypress@3.3.1, fsevents@1.2.9 and nodemon@1.19.1. The triage agent assessed fsevents@1.2.9 as likely malicious (F-135), grunt-if@0.2.0 as suspicious (F-031) and the grunt-env/grunt-if entries plus cypress@3.3.1 as needing human review (F-130, F-131, F-134), while it judged the nodemon install-script flag likely benign (F-136).

**Look at first:**

1. `F-001`: It is the only finding marked new in this change and asserts that fsevents@1.2.9 is a documented malicious package, which alone would justify blocking the merge.
2. `F-135`: A second rule flags the same fsevents@1.2.9 component for its install script, and the triage agent assessed it as likely malicious — two independent signals on one package.
3. `F-006`: handlebars@4.0.5 accumulates 20 known advisories including a Critical CVSS 9.8 issue, the largest single-component concentration in the packet.
4. `F-031`: The triage agent assessed this grunt-if@0.2.0 dependency as suspicious because it resolves to a moving GitHub tarball outside the npm registry, matching the untrusted origin recorded in the inventory.
5. `F-016`: underscore@1.9.1 is a direct production dependency rated Critical (CVSS 9.8), so unlike the deep transitive findings it is close to the application's own code.

*Caveats: The findings list in the packet is truncated at F-025 and the vulnerability totals are much larger (141 findings, 131 vulnerable components), so the risk picture here covers only the highest-severity subset shown. F-001 is marked new in this change although the diff adds no dependencies, so its new-in-change status may reflect baseline comparison rather than this merge. ai_triage verdicts are inferences from the triage agent, not confirmed evidence; the fsevents malicious assessment (F-135) carries only medium confidence. Several triage entries (F-130, F-131, F-134) return needs_human_review and explicitly note that confirming signals, such as lockfile presence, were not established.*

**Triage of findings that need judgement** (rules flag them, the triage agent weighs the context):

| Finding | Rule | AI verdict | Confidence | Grounded | Rationale | Patterns |
|---|---|---|---|---|---|---|
| F-031 | R05_LOCKFILE_UNTRUSTED_SOURCE | ⚠️ suspicious | medium | yes | The lockfile resolves grunt-if to a GitHub tarball from binarymist rather than an approved npm registry, and that exact version is not present in the npm registry metadata (F-031/E1, F-031/T3). The package is a direct dev dependency in the OWASP NodeGoat sample and is not newly introduced by the latest commit (F-031/T2, F-031/T1), which weakens an active lockfile-injection theory. However, an unpi | - |
| F-130 | R09_UNPINNED_DEPENDENCY | 👀 needs_human_review | medium | yes | F-130/E1 (confirmed by the surrounding excerpt in F-130/T2) shows a single devDependency, "grunt-env": "latest", an unpinned floating specifier in a Grunt build-tooling block. The playbook's confirming signals are not established here: there is no evidence about lockfile presence, and the entry appears in the build-tooling dependencies rather than a production runtime scope, while F-130/T1 and F-1 | - |
| F-131 | R09_UNPINNED_DEPENDENCY | 👀 needs_human_review | medium | yes | F-131/E1 confirms package.json:51 requests "grunt-if" as a tarball of the moving master branch of a GitHub repo rather than a published, versioned release, so the installed code is not reproducible and can change without any version bump. F-131/T2 shows the dependency sits among grunt build-tooling entries (lines 47-55), which suggests a build-time rather than runtime scope, and the recorded chang | - |
| F-134 | R03_INSTALL_SCRIPT | 👀 needs_human_review | medium | yes | The lockfile confirms cypress@3.3.1 declares a postinstall script (F-134/E1, F-134/T2: "node index.js --exec install"), which runs arbitrary code on every install and is not covered by the organisation's install-script allow-list. However, provenance is strong: the package is the well-known Cypress testing tool published by an established maintainer from the official cypress-io repository since 20 | - |
| F-135 | R03_INSTALL_SCRIPT | ⛔ likely_malicious | medium | yes | fsevents@1.2.9 declares an install script (F-135/E1 hasInstallScript: true; F-135/T2 shows the command is 'node install'), so code executes on every install including CI. On its own that fits the playbook false-positive pattern for native build steps in well-established packages, but F-135/T2 also records the version as deprecated with 'Upgrade to fsevents v2 to mitigate potential security issues' | - |
| F-136 | R03_INSTALL_SCRIPT | ✅ likely_benign | medium | yes | The lockfile flag (F-136/E1) is explained by registry metadata showing the only install script is a local `postinstall: node bin/postinstall // exit 0` hook in F-136/T2 — no download-and-execute, no environment or credential access, and the `// exit 0` guard is the classic informational/donation-message pattern listed among the playbook false positives. Provenance supports this: the package has ex | - |

## 6. Notes and limits

- graph.html limited to depth 2 + vulnerable paths (1103 nodes); use --focus/--max-depth
- Initial risk is a heuristic. Reachability, exploitability (KEV/EPSS), prioritisation and remediation are added by `python -m sscg agent --remediate`.
- Typosquat results are heuristic (name similarity) and need human review.
