# Guardian evidence report: nodejs-goof

*Scanned 2026-11-23T11:12:00+00:00 with sscg 0.1.0*

**Repository → SBOM → Dependency graph → Risk detection → Evidence** ✔

## 1. What is in the application

| | |
|---|---|
| Components | 989 (github-actions 6, docker 3, npm 980) |
| Libraries | 980: 35 direct, 945 transitive, max depth 10 |
| Container images | 3: mongo:3, mysql:5, node:18.13.0 |
| CI/CD | 4 workflow(s), 6 distinct actions |
| SBOM | `sbom.cdx.json` (CycloneDX 1.5, 996 components) |

## 2. What changed

Not analysed (no base commit available, e.g. a shallow clone). See notes.

## 3. What appears risky

**154 findings**: 139 vulnerable components (315 advisories) and 15 supply-chain anomalies.

| Level | Critical | High | Medium | Low | Info |
|---|---|---|---|---|---|
| Findings | 24 | 73 | 37 | 20 | 0 |

*Initial risk = Guardian initial risk (heuristic, 0-10); not a CVSS score. Official severity is shown separately for vulnerabilities.*

| ID | Risk | Type | Finding | Location | New |
|---|---|---|---|---|---|
| F-001 | 🟥 Critical (10.0) | Vulnerable direct dependency | mongoose@4.2.4: 13 known vulnerabilities (highest CRITICAL, CVSS 10.0) | `package-lock.json` |  |
| F-002 | 🟥 Critical (9.8) | Vulnerable transitive dependency | bson@0.4.23: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-003 | 🟥 Critical (9.8) | Vulnerable transitive dependency | ejs@0.8.8: 5 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-004 | 🟥 Critical (9.8) | Vulnerable direct dependency | ejs@1.0.0: 5 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-005 | 🟥 Critical (9.8) | Vulnerable direct dependency | express-fileupload@0.0.5: 3 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-006 | 🟥 Critical (9.8) | Vulnerable transitive dependency | handlebars@4.0.11: 20 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-007 | 🟥 Critical (9.8) | Vulnerable transitive dependency | handlebars@4.0.14: 19 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-008 | 🟥 Critical (9.8) | Vulnerable transitive dependency | json-schema@0.2.3: 1 known vulnerability (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-009 | 🟥 Critical (9.8) | Vulnerable transitive dependency | minimist@0.0.10: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-010 | 🟥 Critical (9.8) | Vulnerable transitive dependency | minimist@0.0.8: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-011 | 🟥 Critical (9.8) | Vulnerable transitive dependency | minimist@1.2.0: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-012 | 🟥 Critical (9.8) | Vulnerable transitive dependency | minimist@1.2.5: 1 known vulnerability (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-013 | 🟥 Critical (9.8) | Vulnerable transitive dependency | mixin-deep@1.3.1: 1 known vulnerability (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-014 | 🟥 Critical (9.8) | Vulnerable transitive dependency | parse-url@5.0.1: 6 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-015 | 🟥 Critical (9.8) | Vulnerable transitive dependency | set-value@0.4.3: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-016 | 🟥 Critical (9.8) | Vulnerable transitive dependency | set-value@2.0.0: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-017 | 🟥 Critical (9.8) | Vulnerable direct dependency | typeorm@0.2.24: 5 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-018 | 🟥 Critical (9.8) | Vulnerable transitive dependency | underscore@1.9.1: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8) | `package-lock.json` |  |
| F-019 | 🟥 Critical (9.3) | Vulnerable transitive dependency | babel-traverse@6.26.0: 1 known vulnerability (highest CRITICAL, CVSS 9.3) | `package-lock.json` |  |
| F-020 | 🟥 Critical (9.1) | Vulnerable transitive dependency | cipher-base@1.0.4: 1 known vulnerability (highest CRITICAL, CVSS 9.1) | `package-lock.json` |  |
| F-021 | 🟥 Critical (9.1) | Vulnerable transitive dependency | lodash@4.17.10: 8 known vulnerabilities (highest CRITICAL, CVSS 9.1) | `package-lock.json` |  |
| F-022 | 🟥 Critical (9.1) | Vulnerable direct dependency | lodash@4.17.4: 9 known vulnerabilities (highest CRITICAL, CVSS 9.1) | `package-lock.json` |  |
| F-023 | 🟥 Critical (9.1) | Vulnerable transitive dependency | netmask@1.0.6: 1 known vulnerability (highest CRITICAL, CVSS 9.1) | `package-lock.json` |  |
| F-024 | 🟥 Critical (9.1) | Vulnerable transitive dependency | sha.js@2.4.11: 1 known vulnerability (highest CRITICAL, CVSS 9.1) | `package-lock.json` |  |
| F-025 | 🟧 High (8.8) | Vulnerable direct dependency | dustjs-linkedin@2.5.0: 1 known vulnerability (highest HIGH, CVSS 8.8) | `package-lock.json` |  |
| F-026 | 🟧 High (8.8) | Vulnerable direct dependency | snyk@1.278.1: 4 known vulnerabilities (highest HIGH, CVSS 8.8) | `package-lock.json` |  |
| F-027 | 🟧 High (8.2) | Vulnerable transitive dependency | toml@3.0.0: 6 known vulnerabilities (highest HIGH, CVSS 8.2) | `package-lock.json` |  |
| F-028 | 🟧 High (8.1) | Vulnerable transitive dependency | degenerator@1.0.4: 1 known vulnerability (highest HIGH, CVSS 8.1) | `package-lock.json` |  |
| F-029 | 🟧 High (8.1) | Vulnerable transitive dependency | ip@1.1.5: 2 known vulnerabilities (highest HIGH, CVSS 8.1) | `package-lock.json` |  |
| F-030 | 🟧 High (8.1) | Vulnerable transitive dependency | lodash@4.17.15: 5 known vulnerabilities (highest HIGH, CVSS 8.1) | `package-lock.json` |  |
| F-031 | 🟧 High (8.1) | Vulnerable transitive dependency | lodash@4.17.21: 2 known vulnerabilities (highest HIGH, CVSS 8.1) | `package-lock.json` |  |
| F-032 | 🟧 High (8.1) | Vulnerable transitive dependency | pac-resolver@3.0.0: 1 known vulnerability (highest HIGH, CVSS 8.1) | `package-lock.json` |  |
| F-033 | 🟧 High (8.1) | Vulnerable transitive dependency | shell-quote@1.6.1: 2 known vulnerabilities (highest HIGH, CVSS 8.1) | `package-lock.json` |  |
| F-034 | 🟧 High (8.0) | Unsafe CI/CD component | .github/workflows/snyk-code.yml: third-party action 'snyk/actions/setup@master' is not pinned to a commit SHA | `.github/workflows/snyk-code.yml:8` |  |
| F-035 | 🟧 High (8.0) | Unsafe CI/CD component | .github/workflows/snyk-test-sarif.yml: third-party action 'snyk/actions/setup@master' is not pinned to a commit SHA | `.github/workflows/snyk-test-sarif.yml:8` |  |
| F-036 | 🟧 High (8.0) | Vulnerable transitive dependency | diff@1.4.0: 2 known vulnerabilities (highest HIGH) | `package-lock.json` |  |
| F-037 | 🟧 High (8.0) | Vulnerable transitive dependency | figlet@1.5.0: 1 known vulnerability (highest HIGH) | `package-lock.json` |  |
| F-038 | 🟧 High (8.0) | Vulnerable transitive dependency | mongodb@2.0.46: 1 known vulnerability (highest HIGH) | `package-lock.json` |  |
| F-039 | 🟧 High (8.0) | Vulnerable transitive dependency | negotiator@0.2.8: 1 known vulnerability (highest HIGH) | `package-lock.json` |  |
| F-040 | 🟧 High (8.0) | Vulnerable transitive dependency | negotiator@0.4.9: 1 known vulnerability (highest HIGH) | `package-lock.json` |  |
| F-041 | 🟧 High (8.0) | Vulnerable transitive dependency | negotiator@0.5.3: 1 known vulnerability (highest HIGH) | `package-lock.json` |  |
| F-042 | 🟧 High (7.8) | Vulnerable transitive dependency | async@2.6.3: 1 known vulnerability (highest HIGH, CVSS 7.8) | `package-lock.json` |  |
| F-043 | 🟧 High (7.8) | Vulnerable transitive dependency | kerberos@0.0.24: 1 known vulnerability (highest HIGH, CVSS 7.8) | `package-lock.json` |  |
| F-044 | 🟧 High (7.8) | Vulnerable transitive dependency | snyk-go-plugin@1.11.1: 1 known vulnerability (highest HIGH, CVSS 7.8) | `package-lock.json` |  |
| F-045 | 🟧 High (7.7) | Vulnerable transitive dependency | elliptic@6.4.1: 9 known vulnerabilities (highest CRITICAL, CVSS 7.7) | `package-lock.json` |  |
| F-046 | 🟧 High (7.5) | Vulnerable direct dependency | adm-zip@0.4.7: 8 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-047 | 🟧 High (7.5) | Vulnerable transitive dependency | ansi-regex@3.0.0: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-048 | 🟧 High (7.5) | Vulnerable transitive dependency | ansi-regex@4.1.0: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-049 | 🟧 High (7.5) | Vulnerable transitive dependency | ansi-regex@5.0.0: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-050 | 🟧 High (7.5) | Vulnerable direct dependency | body-parser@1.9.0: 3 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-051 | 🟧 High (7.5) | Vulnerable transitive dependency | brace-expansion@1.1.11: 8 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-052 | 🟧 High (7.5) | Vulnerable transitive dependency | braces@2.3.2: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-053 | 🟧 High (7.5) | Vulnerable transitive dependency | braces@3.0.2: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-054 | 🟧 High (7.5) | Vulnerable transitive dependency | browserify-sign@4.0.4: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-055 | 🟧 High (7.5) | Vulnerable transitive dependency | cross-spawn@4.0.2: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-056 | 🟧 High (7.5) | Vulnerable transitive dependency | cross-spawn@5.1.0: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-057 | 🟧 High (7.5) | Vulnerable transitive dependency | cross-spawn@6.0.5: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-058 | 🟧 High (7.5) | Vulnerable transitive dependency | debug@2.2.0: 2 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-059 | 🟧 High (7.5) | Vulnerable transitive dependency | decode-uri-component@0.2.0: 3 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-060 | 🟧 High (7.5) | Vulnerable transitive dependency | dicer@0.3.0: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-061 | 🟧 High (7.5) | Vulnerable transitive dependency | form-data@2.3.3: 2 known vulnerabilities (highest CRITICAL, CVSS 7.5) | `package-lock.json` |  |
| F-062 | 🟧 High (7.5) | Vulnerable transitive dependency | fresh@0.2.4: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-063 | 🟧 High (7.5) | Vulnerable transitive dependency | http-cache-semantics@4.1.0: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-064 | 🟧 High (7.5) | Vulnerable transitive dependency | js-yaml@3.13.1: 5 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-065 | 🟧 High (7.5) | Vulnerable transitive dependency | kind-of@6.0.2: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-066 | 🟧 High (7.5) | Vulnerable direct dependency | marked@0.3.5: 6 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-067 | 🟧 High (7.5) | Vulnerable transitive dependency | mime@1.2.11: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-068 | 🟧 High (7.5) | Vulnerable transitive dependency | mime@1.3.4: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-069 | 🟧 High (7.5) | Vulnerable transitive dependency | minimatch@3.0.4: 4 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-070 | 🟧 High (7.5) | Vulnerable direct dependency | moment@2.15.1: 2 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-071 | 🟧 High (7.5) | Vulnerable transitive dependency | mpath@0.1.1: 2 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-072 | 🟧 High (7.5) | Vulnerable transitive dependency | ms@0.6.2: 2 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-073 | 🟧 High (7.5) | Vulnerable transitive dependency | path-to-regexp@0.1.3: 2 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-074 | 🟧 High (7.5) | Vulnerable transitive dependency | picomatch@2.3.0: 2 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-075 | 🟧 High (7.5) | Vulnerable transitive dependency | qs@2.2.4: 3 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-076 | 🟧 High (7.5) | Vulnerable transitive dependency | qs@2.4.2: 4 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-077 | 🟧 High (7.5) | Vulnerable transitive dependency | qs@6.5.2: 3 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-078 | 🟧 High (7.5) | Vulnerable transitive dependency | semver@1.1.4: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-079 | 🟧 High (7.5) | Vulnerable transitive dependency | semver@5.5.0: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-080 | 🟧 High (7.5) | Vulnerable transitive dependency | semver@5.7.0: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-081 | 🟧 High (7.5) | Vulnerable transitive dependency | semver@5.7.1: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-082 | 🟧 High (7.5) | Vulnerable transitive dependency | semver@6.3.0: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-083 | 🟧 High (7.5) | Vulnerable transitive dependency | snyk-gradle-plugin@3.2.2: 2 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-084 | 🟧 High (7.5) | Vulnerable transitive dependency | snyk-php-plugin@1.7.0: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-085 | 🟧 High (7.5) | Vulnerable direct dependency | st@0.2.4: 2 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-086 | 🟧 High (7.5) | Vulnerable transitive dependency | uuid@3.3.2: 1 known vulnerability (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-087 | 🟧 High (7.5) | Vulnerable direct dependency | validator@13.5.2: 4 known vulnerabilities (highest HIGH, CVSS 7.5) | `package-lock.json` |  |
| F-088 | 🟧 High (7.4) | Vulnerable transitive dependency | lodash.set@4.3.2: 1 known vulnerability (highest HIGH, CVSS 7.4) | `package-lock.json` |  |
| F-089 | 🟧 High (7.3) | Vulnerable transitive dependency | cached-path-relative@1.0.2: 1 known vulnerability (highest HIGH, CVSS 7.3) | `package-lock.json` |  |
| F-090 | 🟧 High (7.3) | Vulnerable transitive dependency | dot-prop@4.2.0: 1 known vulnerability (highest HIGH, CVSS 7.3) | `package-lock.json` |  |
| F-091 | 🟧 High (7.3) | Vulnerable transitive dependency | ini@1.1.0: 1 known vulnerability (highest HIGH, CVSS 7.3) | `package-lock.json` |  |
| F-092 | 🟧 High (7.3) | Vulnerable transitive dependency | ini@1.3.5: 1 known vulnerability (highest HIGH, CVSS 7.3) | `package-lock.json` |  |
| F-093 | 🟧 High (7.3) | Vulnerable transitive dependency | jszip@3.2.2: 2 known vulnerabilities (highest HIGH, CVSS 7.3) | `package-lock.json` |  |
| F-094 | 🟧 High (7.3) | Vulnerable transitive dependency | nconf@0.10.0: 1 known vulnerability (highest HIGH, CVSS 7.3) | `package-lock.json` |  |
| F-095 | 🟧 High (7.3) | Vulnerable transitive dependency | parse-path@4.0.1: 1 known vulnerability (highest HIGH, CVSS 7.3) | `package-lock.json` |  |
| F-096 | 🟧 High (7.3) | Vulnerable transitive dependency | y18n@3.2.1: 1 known vulnerability (highest HIGH, CVSS 7.3) | `package-lock.json` |  |
| F-097 | 🟧 High (7.3) | Vulnerable transitive dependency | y18n@4.0.0: 1 known vulnerability (highest HIGH, CVSS 7.3) | `package-lock.json` |  |
| F-098 | 🟨 Medium (6.9) | Vulnerable direct dependency | jquery@2.2.4: 4 known vulnerabilities (highest MEDIUM, CVSS 6.9) | `package-lock.json` |  |
| F-099 | 🟨 Medium (6.5) | Vulnerable transitive dependency | bl@2.2.0: 1 known vulnerability (highest MEDIUM, CVSS 6.5) | `package-lock.json` |  |
| F-100 | 🟨 Medium (6.5) | Vulnerable transitive dependency | bl@3.0.0: 1 known vulnerability (highest MEDIUM, CVSS 6.5) | `package-lock.json` |  |
| F-101 | 🟨 Medium (6.5) | Vulnerable transitive dependency | tough-cookie@2.4.3: 1 known vulnerability (highest MEDIUM, CVSS 6.5) | `package-lock.json` |  |
| F-102 | 🟨 Medium (6.3) | Vulnerable transitive dependency | @snyk/snyk-cocoapods-plugin@2.0.1: 1 known vulnerability (highest MEDIUM, CVSS 6.3) | `package-lock.json` |  |
| F-103 | 🟨 Medium (6.3) | Vulnerable transitive dependency | snyk-docker-plugin@1.33.1: 1 known vulnerability (highest MEDIUM, CVSS 6.3) | `package-lock.json` |  |
| F-104 | 🟨 Medium (6.3) | Vulnerable transitive dependency | snyk-mvn-plugin@2.7.0: 1 known vulnerability (highest MEDIUM, CVSS 6.3) | `package-lock.json` |  |
| F-105 | 🟨 Medium (6.3) | Vulnerable transitive dependency | snyk-python-plugin@1.16.0: 1 known vulnerability (highest MEDIUM, CVSS 6.3) | `package-lock.json` |  |
| F-106 | 🟨 Medium (6.3) | Vulnerable transitive dependency | snyk-sbt-plugin@2.11.0: 1 known vulnerability (highest MEDIUM, CVSS 6.3) | `package-lock.json` |  |
| F-107 | 🟨 Medium (6.1) | Vulnerable direct dependency | express@4.12.4: 2 known vulnerabilities (highest MEDIUM, CVSS 6.1) | `package-lock.json` |  |
| F-108 | 🟨 Medium (6.1) | Vulnerable transitive dependency | request@2.88.0: 1 known vulnerability (highest MEDIUM, CVSS 6.1) | `package-lock.json` |  |
| F-109 | 🟨 Medium (5.8) | Vulnerable transitive dependency | highlight.js@9.18.1: 2 known vulnerabilities (highest MEDIUM, CVSS 5.8) | `package-lock.json` |  |
| F-110 | 🟨 Medium (5.6) | Vulnerable transitive dependency | ajv@6.10.2: 2 known vulnerabilities (highest MEDIUM, CVSS 5.6) | `package-lock.json` |  |
| F-111 | 🟨 Medium (5.5) | Untrusted image | Dockerfile runs 'npm install' with install scripts enabled | `Dockerfile:10` |  |
| F-112 | 🟨 Medium (5.5) | Untrusted image | Dockerfile runs 'npm update' with install scripts enabled | `Dockerfile:9` |  |
| F-113 | 🟨 Medium (5.5) | Vulnerable direct dependency | npmconf@0.0.24: 1 known vulnerability (highest MEDIUM) | `package-lock.json` |  |
| F-114 | 🟨 Medium (5.3) | Vulnerable transitive dependency | bn.js@4.11.8: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-115 | 🟨 Medium (5.3) | Vulnerable transitive dependency | got@6.7.1: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-116 | 🟨 Medium (5.3) | Vulnerable transitive dependency | got@9.6.0: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-117 | 🟨 Medium (5.3) | Vulnerable transitive dependency | hosted-git-info@2.6.0: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-118 | 🟨 Medium (5.3) | Vulnerable transitive dependency | hosted-git-info@2.8.5: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-119 | 🟨 Medium (5.3) | Vulnerable transitive dependency | micromatch@3.1.10: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-120 | 🟨 Medium (5.3) | Vulnerable direct dependency | morgan@1.10.0: 3 known vulnerabilities (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-121 | 🟨 Medium (5.3) | Vulnerable transitive dependency | mquery@1.6.3: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-122 | 🟨 Medium (5.3) | Vulnerable transitive dependency | ms@0.7.1: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-123 | 🟨 Medium (5.3) | Vulnerable direct dependency | ms@0.7.3: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-124 | 🟨 Medium (5.3) | Vulnerable transitive dependency | path-parse@1.0.5: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-125 | 🟨 Medium (5.3) | Vulnerable transitive dependency | path-parse@1.0.6: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-126 | 🟨 Medium (5.3) | Vulnerable transitive dependency | word-wrap@1.2.3: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-127 | 🟨 Medium (5.3) | Vulnerable transitive dependency | xml2js@0.4.19: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-128 | 🟨 Medium (5.3) | Vulnerable transitive dependency | xml2js@0.4.23: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-129 | 🟨 Medium (5.3) | Vulnerable transitive dependency | yargs-parser@8.1.0: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-130 | 🟨 Medium (5.3) | Vulnerable transitive dependency | yargs-parser@9.0.2: 1 known vulnerability (highest MEDIUM, CVSS 5.3) | `package-lock.json` |  |
| F-131 | 🟨 Medium (5.1) | Vulnerable transitive dependency | mem@1.1.0: 1 known vulnerability (highest MEDIUM, CVSS 5.1) | `package-lock.json` |  |
| F-132 | 🟨 Medium (5.0) | Vulnerable transitive dependency | send@0.12.3: 1 known vulnerability (highest MEDIUM, CVSS 5.0) | `package-lock.json` |  |
| F-133 | 🟨 Medium (5.0) | Vulnerable transitive dependency | serve-static@1.9.3: 1 known vulnerability (highest MEDIUM, CVSS 5.0) | `package-lock.json` |  |
| F-134 | 🟨 Medium (4.0) | Vulnerable direct dependency | hbs@4.0.4: 1 known vulnerability (highest MEDIUM, CVSS 4.0) | `package-lock.json` |  |
| F-135 | 🟦 Low (3.7) | Vulnerable transitive dependency | debug@3.2.6: 1 known vulnerability (highest LOW, CVSS 3.7) | `package-lock.json` |  |
| F-136 | 🟦 Low (3.7) | Vulnerable transitive dependency | debug@4.1.1: 1 known vulnerability (highest LOW, CVSS 3.7) | `package-lock.json` |  |
| F-137 | 🟦 Low (3.7) | Vulnerable transitive dependency | pbkdf2@3.0.17: 3 known vulnerabilities (highest CRITICAL, CVSS 3.7) | `package-lock.json` |  |
| F-138 | 🟦 Low (3.4) | Vulnerable transitive dependency | on-headers@1.0.2: 1 known vulnerability (highest LOW, CVSS 3.4) | `package-lock.json` |  |
| F-139 | 🟦 Low (3.0) | Suspicious package update | 'method-override' is requested as 'latest' in package.json | `package.json:36` |  |
| F-140 | 🟦 Low (3.0) | Suspicious package update | 'morgan' is requested as 'latest' in package.json | `package.json:40` |  |
| F-141 | 🟦 Low (3.0) | Unsafe CI/CD component | .github/workflows/codeql-analysis.yml: no top-level 'permissions:' (token gets the repository default, often read/write) | `.github/workflows/codeql-analysis.yml` |  |
| F-142 | 🟦 Low (3.0) | Unsafe CI/CD component | .github/workflows/snyk-code-manual.yml: no top-level 'permissions:' (token gets the repository default, often read/write) | `.github/workflows/snyk-code-manual.yml` |  |
| F-143 | 🟦 Low (3.0) | Unsafe CI/CD component | .github/workflows/snyk-code.yml: no top-level 'permissions:' (token gets the repository default, often read/write) | `.github/workflows/snyk-code.yml` |  |
| F-144 | 🟦 Low (3.0) | Unsafe CI/CD component | .github/workflows/snyk-test-sarif.yml: no top-level 'permissions:' (token gets the repository default, often read/write) | `.github/workflows/snyk-test-sarif.yml` |  |
| F-145 | 🟦 Low (3.0) | Untrusted image | Dockerfile sets no USER: the container runs as the base image's default user (usually root) | `Dockerfile` |  |
| F-146 | 🟦 Low (3.0) | Unsafe install script | core-js@3.6.4 runs an install script (code not inspected) | `package-lock.json` |  |
| F-147 | 🟦 Low (3.0) | Unsafe install script | fsevents@2.3.2 runs an install script (code not inspected) | `package-lock.json` |  |
| F-148 | 🟦 Low (3.0) | Unsafe install script | kerberos@0.0.24 runs an install script (code not inspected) | `package-lock.json` |  |
| F-149 | 🟦 Low (3.0) | Unsafe install script | nodemon@2.0.7 runs an install script (code not inspected) | `package-lock.json` |  |
| F-150 | 🟦 Low (3.0) | Vulnerable transitive dependency | cookie@0.1.2: 1 known vulnerability (highest LOW) | `package-lock.json` |  |
| F-151 | 🟦 Low (3.0) | Vulnerable transitive dependency | cookie@0.4.1: 1 known vulnerability (highest LOW) | `package-lock.json` |  |
| F-152 | 🟦 Low (3.0) | Vulnerable transitive dependency | diff@4.0.2: 1 known vulnerability (highest LOW) | `package-lock.json` |  |
| F-153 | 🟦 Low (2.5) | Vulnerable transitive dependency | tmp@0.0.33: 2 known vulnerabilities (highest HIGH, CVSS 2.5) | `package-lock.json` |  |
| F-154 | 🟦 Low (2.5) | Vulnerable transitive dependency | tmp@0.1.0: 2 known vulnerabilities (highest HIGH, CVSS 2.5) | `package-lock.json` |  |

## 4. Evidence per finding

### F-001 · 🟥 Critical (10.0) · Vulnerable direct dependency

- **What:** mongoose@4.2.4: 13 known vulnerabilities (highest CRITICAL, CVSS 10.0)
- **Component:** `mongoose@4.2.4` (npm, scope prod, direct), purl `pkg:npm/mongoose@4.2.4`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → mongoose@4.2.4
- **Official severity:** CRITICAL, CVSS 10.0 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 6.13.12
- **Evidence:**
  - [GHSA-9m93-w8w6-76hh](https://osv.dev/vulnerability/GHSA-9m93-w8w6-76hh) (CVE-2023-3696): CRITICAL, CVSS 10.0, fixed in 5.13.20. Mongoose Prototype Pollution vulnerability
  - [GHSA-h8hf-x3f4-xwgp](https://osv.dev/vulnerability/GHSA-h8hf-x3f4-xwgp) (CVE-2022-24304): CRITICAL, CVSS 9.8, fixed in 5.13.15. Mongoose Vulnerable to Prototype Pollution in Schema Object
  - [GHSA-m7xq-9374-9rvx](https://osv.dev/vulnerability/GHSA-m7xq-9374-9rvx) (CVE-2024-53900): CRITICAL, CVSS 9.8, fixed in 5.13.23. Mongoose search injection vulnerability
  - [GHSA-pcrw-h46h-c93h](https://osv.dev/vulnerability/GHSA-pcrw-h46h-c93h) (CVE-2026-125120): CRITICAL, CVSS 9.8, fixed in 6.13.11. Mongoose: sanitizeFilter not applied on countDocuments
  - [GHSA-8687-vv9j-hgph](https://osv.dev/vulnerability/GHSA-8687-vv9j-hgph) (CVE-2019-17426): CRITICAL, CVSS 9.1, fixed in 4.13.21. Improper Input Validation in Automattic Mongoose
  - [GHSA-vg7j-7cwx-8wgw](https://osv.dev/vulnerability/GHSA-vg7j-7cwx-8wgw) (CVE-2025-23061): CRITICAL, CVSS 9.0, fixed in 6.13.6. Mongoose search injection vulnerability
  - [GHSA-8332-j7wj-wjw4](https://osv.dev/vulnerability/GHSA-8332-j7wj-wjw4) (CVE-2026-125117): HIGH, CVSS 8.2, fixed in 6.13.12. Mongoose walks into inherited properties when hydrating, setting, and merging, allowing overwrites of built-in functions (denial of service) and shared schema state
  - [GHSA-wpg9-53fq-2r8h](https://osv.dev/vulnerability/GHSA-wpg9-53fq-2r8h) (CVE-2026-42334): HIGH, CVSS 7.5, fixed in 6.13.9. Mongoose's Improper Sanitization of $nor in sanitizeFilter May Allow NoSQL Injection
  - [GHSA-f825-f98c-gj3g](https://osv.dev/vulnerability/GHSA-f825-f98c-gj3g) (CVE-2022-2564): HIGH, CVSS 7.0, fixed in 5.13.15. automattic/mongoose vulnerable to Prototype pollution via Schema.path
  - [GHSA-664h-wqgq-64gw](https://osv.dev/vulnerability/GHSA-664h-wqgq-64gw) (CVE-2026-73562): MEDIUM, CVSS 6.5, fixed in 6.13.10. Mongoose: Prototype pollution in mongoose update casting via __proto__-prefixed dotted path (Schema._getSchema/path getter)
  - [GHSA-6972-9mcm-vhwj](https://osv.dev/vulnerability/GHSA-6972-9mcm-vhwj) (CVE-2026-125118): MEDIUM, CVSS 6.5, fixed in 6.13.12. Mongoose: Prototype pollution via Schema.prototype.virtual()
  - [GHSA-r5xw-q988-826m](https://osv.dev/vulnerability/GHSA-r5xw-q988-826m): MEDIUM, CVSS 5.1, fixed in 4.3.6. Remote Memory Exposure in mongoose
  - … 1 more in findings.json
- **Initial risk:** Critical (10.0): highest advisory severity CRITICAL (CVSS 10.0)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-002 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** bson@0.4.23: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `bson@0.4.23` (npm, scope prod, transitive), purl `pkg:npm/bson@0.4.23`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → mongoose@4.2.4 → bson@0.4.23 ; goof@1.0.1 → mongoose@4.2.4 → mongodb@2.0.46 → mongodb-core@1.2.19 → bson@0.4.23
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.1.4
- **Evidence:**
  - [GHSA-v8w9-2789-6hhr](https://osv.dev/vulnerability/GHSA-v8w9-2789-6hhr) (CVE-2020-7610): CRITICAL, CVSS 9.8, fixed in 1.1.4. Deserialization of Untrusted Data in bson
  - [GHSA-4jwp-vfvf-657p](https://osv.dev/vulnerability/GHSA-4jwp-vfvf-657p) (CVE-2019-2391): MEDIUM, CVSS 5.4, fixed in 1.1.4. Deserialization of Untrusted Data in bson
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-003 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** ejs@0.8.8: 5 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `ejs@0.8.8` (npm, scope prod, transitive), purl `pkg:npm/ejs@0.8.8`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → ejs-locals@1.0.2 → ejs@0.8.8
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 3.1.10
- **Evidence:**
  - [GHSA-3w5v-p54c-f74x](https://osv.dev/vulnerability/GHSA-3w5v-p54c-f74x) (CVE-2017-1000228): CRITICAL, CVSS 9.8, fixed in 2.5.5. ejs is vulnerable to remote code execution due to weak input validation
  - [GHSA-phwq-j96m-2c2q](https://osv.dev/vulnerability/GHSA-phwq-j96m-2c2q) (CVE-2022-29078): CRITICAL, CVSS 9.8, fixed in 3.1.7. ejs template injection vulnerability
  - [GHSA-6x77-rpqf-j6mw](https://osv.dev/vulnerability/GHSA-6x77-rpqf-j6mw) (CVE-2017-1000189): HIGH, CVSS 7.5, fixed in 2.5.5. ejs vulnerable to DoS due to weak input validation
  - [GHSA-hwcf-pp87-7x6p](https://osv.dev/vulnerability/GHSA-hwcf-pp87-7x6p) (CVE-2017-1000188): MEDIUM, CVSS 6.1, fixed in 2.5.5. mde ejs vulnerable to XSS
  - [GHSA-ghr5-ch3p-vcr6](https://osv.dev/vulnerability/GHSA-ghr5-ch3p-vcr6) (CVE-2024-33883): MEDIUM, CVSS 4.0, fixed in 3.1.10. ejs lacks certain pollution protection
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-004 · 🟥 Critical (9.8) · Vulnerable direct dependency

- **What:** ejs@1.0.0: 5 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `ejs@1.0.0` (npm, scope prod, direct), purl `pkg:npm/ejs@1.0.0`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → ejs@1.0.0
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 3.1.10
- **Evidence:**
  - [GHSA-3w5v-p54c-f74x](https://osv.dev/vulnerability/GHSA-3w5v-p54c-f74x) (CVE-2017-1000228): CRITICAL, CVSS 9.8, fixed in 2.5.5. ejs is vulnerable to remote code execution due to weak input validation
  - [GHSA-phwq-j96m-2c2q](https://osv.dev/vulnerability/GHSA-phwq-j96m-2c2q) (CVE-2022-29078): CRITICAL, CVSS 9.8, fixed in 3.1.7. ejs template injection vulnerability
  - [GHSA-6x77-rpqf-j6mw](https://osv.dev/vulnerability/GHSA-6x77-rpqf-j6mw) (CVE-2017-1000189): HIGH, CVSS 7.5, fixed in 2.5.5. ejs vulnerable to DoS due to weak input validation
  - [GHSA-hwcf-pp87-7x6p](https://osv.dev/vulnerability/GHSA-hwcf-pp87-7x6p) (CVE-2017-1000188): MEDIUM, CVSS 6.1, fixed in 2.5.5. mde ejs vulnerable to XSS
  - [GHSA-ghr5-ch3p-vcr6](https://osv.dev/vulnerability/GHSA-ghr5-ch3p-vcr6) (CVE-2024-33883): MEDIUM, CVSS 4.0, fixed in 3.1.10. ejs lacks certain pollution protection
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-005 · 🟥 Critical (9.8) · Vulnerable direct dependency

- **What:** express-fileupload@0.0.5: 3 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `express-fileupload@0.0.5` (npm, scope prod, direct), purl `pkg:npm/express-fileupload@0.0.5`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → express-fileupload@0.0.5
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.1.9; no fix for GHSA-w4m6-x6c2-j5c9
- **Evidence:**
  - [GHSA-9wcg-jrwf-8gg7](https://osv.dev/vulnerability/GHSA-9wcg-jrwf-8gg7) (CVE-2020-7699): CRITICAL, CVSS 9.8, fixed in 1.1.9. Prototype Pollution in express-fileupload
  - [GHSA-w4m6-x6c2-j5c9](https://osv.dev/vulnerability/GHSA-w4m6-x6c2-j5c9) (CVE-2022-27261): HIGH, CVSS 7.5, no fix published. Express-FileUpload Arbitrary File Overwrite
  - [GHSA-q3w9-g74q-vp5f](https://osv.dev/vulnerability/GHSA-q3w9-g74q-vp5f): LOW, fixed in 1.1.6-alpha.6. Denial of Service in express-fileupload
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8); 1 advisory(ies) without a published fix
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-006 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** handlebars@4.0.11: 20 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `handlebars@4.0.11` (npm, scope prod, transitive), purl `pkg:npm/handlebars@4.0.11`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → istanbul-reports@1.4.0 → handlebars@4.0.11
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

- **What:** handlebars@4.0.14: 19 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `handlebars@4.0.14` (npm, scope prod, transitive), purl `pkg:npm/handlebars@4.0.14`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → hbs@4.0.4 → handlebars@4.0.14
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
  - … 7 more in findings.json
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-008 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** json-schema@0.2.3: 1 known vulnerability (highest CRITICAL, CVSS 9.8)
- **Component:** `json-schema@0.2.3` (npm, scope prod, transitive), purl `pkg:npm/json-schema@0.2.3`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → tap@11.1.5 → coveralls@3.0.9 → request@2.88.0 → http-signature@1.2.0 → jsprim@1.4.1 → json-schema@0.2.3
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 0.4.0
- **Evidence:**
  - [GHSA-896r-f27r-55mw](https://osv.dev/vulnerability/GHSA-896r-f27r-55mw) (CVE-2021-3918): CRITICAL, CVSS 9.8, fixed in 0.4.0. json-schema is vulnerable to Prototype Pollution
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-009 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** minimist@0.0.10: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `minimist@0.0.10` (npm, scope prod, transitive), purl `pkg:npm/minimist@0.0.10`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → hbs@4.0.4 → handlebars@4.0.14 → optimist@0.6.1 → minimist@0.0.10 ; goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → istanbul-reports@1.4.0 → handlebars@4.0.11 → optimist@0.6.1 → minimist@0.0.10
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 0.2.4
- **Evidence:**
  - [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) (CVE-2021-44906): CRITICAL, CVSS 9.8, fixed in 0.2.4. Prototype Pollution in minimist
  - [GHSA-vh95-rmgr-6w4m](https://osv.dev/vulnerability/GHSA-vh95-rmgr-6w4m) (CVE-2020-7598): MEDIUM, CVSS 5.6, fixed in 0.2.1. Prototype Pollution in minimist
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-010 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** minimist@0.0.8: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `minimist@0.0.8` (npm, scope prod, transitive), purl `pkg:npm/minimist@0.0.8`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → tap@11.1.5 → mkdirp@0.5.1 → minimist@0.0.8 ; goof@1.0.1 → hbs@4.0.4 → handlebars@4.0.14 → optimist@0.6.1 → minimist@0.0.8 ; goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → mkdirp@0.5.1 → minimist@0.0.8
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 0.2.4
- **Evidence:**
  - [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) (CVE-2021-44906): CRITICAL, CVSS 9.8, fixed in 0.2.4. Prototype Pollution in minimist
  - [GHSA-vh95-rmgr-6w4m](https://osv.dev/vulnerability/GHSA-vh95-rmgr-6w4m) (CVE-2020-7598): MEDIUM, CVSS 5.6, fixed in 0.2.1. Prototype Pollution in minimist
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-011 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** minimist@1.2.0: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `minimist@1.2.0` (npm, scope prod, transitive), purl `pkg:npm/minimist@1.2.0`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → tap@11.1.5 → coveralls@3.0.9 → minimist@1.2.0 ; goof@1.0.1 → browserify@13.3.0 → subarg@1.0.0 → minimist@1.2.0 ; goof@1.0.1 → browserify@13.3.0 → deps-sort@2.0.0 → subarg@1.0.0 → minimist@1.2.0
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.2.6
- **Evidence:**
  - [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) (CVE-2021-44906): CRITICAL, CVSS 9.8, fixed in 1.2.6. Prototype Pollution in minimist
  - [GHSA-vh95-rmgr-6w4m](https://osv.dev/vulnerability/GHSA-vh95-rmgr-6w4m) (CVE-2020-7598): MEDIUM, CVSS 5.6, fixed in 1.2.3. Prototype Pollution in minimist
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-012 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** minimist@1.2.5: 1 known vulnerability (highest CRITICAL, CVSS 9.8)
- **Component:** `minimist@1.2.5` (npm, scope prod, transitive), purl `pkg:npm/minimist@1.2.5`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → typeorm@0.2.24 → mkdirp@0.5.5 → minimist@1.2.5
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.2.6
- **Evidence:**
  - [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) (CVE-2021-44906): CRITICAL, CVSS 9.8, fixed in 1.2.6. Prototype Pollution in minimist
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-013 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** mixin-deep@1.3.1: 1 known vulnerability (highest CRITICAL, CVSS 9.8)
- **Component:** `mixin-deep@1.3.1` (npm, scope prod, transitive), purl `pkg:npm/mixin-deep@1.3.1`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → micromatch@3.1.10 → snapdragon@0.8.2 → base@0.11.2 → mixin-deep@1.3.1 ; goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → test-exclude@4.2.1 → micromatch@3.1.10 → snapdragon@0.8.2 → base@0.11.2 → mixin-deep@1.3.1 ; goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → micromatch@3.1.10 → braces@2.3.2 → snapdragon@0.8.2 → base@0.11.2 → mixin-deep@1.3.1
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.3.2
- **Evidence:**
  - [GHSA-fhjf-83wg-r2j9](https://osv.dev/vulnerability/GHSA-fhjf-83wg-r2j9) (CVE-2019-10746): CRITICAL, CVSS 9.8, fixed in 1.3.2. Prototype Pollution in mixin-deep
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-014 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** parse-url@5.0.1: 6 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `parse-url@5.0.1` (npm, scope dev, transitive), purl `pkg:npm/parse-url@5.0.1`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → snyk@1.278.1 → git-url-parse@11.1.2 → git-up@4.0.1 → parse-url@5.0.1
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 8.1.0
- **Evidence:**
  - [GHSA-7f3x-x4pr-wqhj](https://osv.dev/vulnerability/GHSA-7f3x-x4pr-wqhj) (CVE-2022-2216): CRITICAL, CVSS 9.8, fixed in 6.0.1. Server-Side Request Forgery in parse-url
  - [GHSA-j9fq-vwqv-2fm2](https://osv.dev/vulnerability/GHSA-j9fq-vwqv-2fm2) (CVE-2022-2900): CRITICAL, CVSS 9.1, fixed in 8.1.0. Server-Side Request Forgery (SSRF) in GitHub repository ionicabizau/parse-url
  - [GHSA-4p35-cfcx-8653](https://osv.dev/vulnerability/GHSA-4p35-cfcx-8653) (CVE-2022-0722): HIGH, CVSS 7.5, fixed in 6.0.1. Hostname confusion in parse-url
  - [GHSA-jpp7-7chh-cf67](https://osv.dev/vulnerability/GHSA-jpp7-7chh-cf67) (CVE-2022-2218): MEDIUM, CVSS 6.1, fixed in 6.0.1. Cross site scripting in parse-url
  - [GHSA-pqw5-jmp5-px4v](https://osv.dev/vulnerability/GHSA-pqw5-jmp5-px4v) (CVE-2022-3224): MEDIUM, CVSS 6.1, fixed in 8.1.0. parse-url parses http URLs incorrectly, making it vulnerable to host name spoofing
  - [GHSA-q6wq-5p59-983w](https://osv.dev/vulnerability/GHSA-q6wq-5p59-983w) (CVE-2022-2217): MEDIUM, CVSS 6.1, fixed in 6.0.1. Cross site scripting in parse-url
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-015 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** set-value@0.4.3: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `set-value@0.4.3` (npm, scope prod, transitive), purl `pkg:npm/set-value@0.4.3`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → micromatch@3.1.10 → snapdragon@0.8.2 → base@0.11.2 → cache-base@1.0.1 → union-value@1.0.0 → set-value@0.4.3 ; goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → test-exclude@4.2.1 → micromatch@3.1.10 → snapdragon@0.8.2 → base@0.11.2 → cache-base@1.0.1 → union-value@1.0.0 → set-value@0.4.3 ; goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → micromatch@3.1.10 → braces@2.3.2 → snapdragon@0.8.2 → base@0.11.2 → cache-base@1.0.1 → union-value@1.0.0 → set-value@0.4.3
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 2.0.1
- **Evidence:**
  - [GHSA-4g88-fppr-53pp](https://osv.dev/vulnerability/GHSA-4g88-fppr-53pp) (CVE-2019-10747): CRITICAL, CVSS 9.8, fixed in 2.0.1. Prototype Pollution in set-value
  - [GHSA-4jqc-8m5r-9rpr](https://osv.dev/vulnerability/GHSA-4jqc-8m5r-9rpr) (CVE-2021-23440): HIGH, CVSS 7.3, fixed in 2.0.1. Prototype Pollution in set-value
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-016 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** set-value@2.0.0: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `set-value@2.0.0` (npm, scope prod, transitive), purl `pkg:npm/set-value@2.0.0`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → micromatch@3.1.10 → snapdragon@0.8.2 → base@0.11.2 → cache-base@1.0.1 → set-value@2.0.0 ; goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → test-exclude@4.2.1 → micromatch@3.1.10 → snapdragon@0.8.2 → base@0.11.2 → cache-base@1.0.1 → set-value@2.0.0 ; goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → micromatch@3.1.10 → braces@2.3.2 → snapdragon@0.8.2 → base@0.11.2 → cache-base@1.0.1 → set-value@2.0.0
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 2.0.1
- **Evidence:**
  - [GHSA-4g88-fppr-53pp](https://osv.dev/vulnerability/GHSA-4g88-fppr-53pp) (CVE-2019-10747): CRITICAL, CVSS 9.8, fixed in 2.0.1. Prototype Pollution in set-value
  - [GHSA-4jqc-8m5r-9rpr](https://osv.dev/vulnerability/GHSA-4jqc-8m5r-9rpr) (CVE-2021-23440): HIGH, CVSS 7.3, fixed in 2.0.1. Prototype Pollution in set-value
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-017 · 🟥 Critical (9.8) · Vulnerable direct dependency

- **What:** typeorm@0.2.24: 5 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `typeorm@0.2.24` (npm, scope prod, direct), purl `pkg:npm/typeorm@0.2.24`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → typeorm@0.2.24
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 0.3.31
- **Evidence:**
  - [GHSA-fx4w-v43j-vc45](https://osv.dev/vulnerability/GHSA-fx4w-v43j-vc45) (CVE-2022-33171): CRITICAL, CVSS 9.8, fixed in 0.3.0. SQL injection in typeORM
  - [GHSA-pf2j-9qmp-jqr2](https://osv.dev/vulnerability/GHSA-pf2j-9qmp-jqr2) (CVE-2020-8158): CRITICAL, CVSS 9.8, fixed in 0.2.25. TypeORM vulnerable to MAID and Prototype Pollution
  - [GHSA-q2pj-6v73-8rgj](https://osv.dev/vulnerability/GHSA-q2pj-6v73-8rgj) (CVE-2025-60542): MEDIUM, CVSS 6.5, fixed in 0.3.26. TypeORM vulnerable to SQL injection via crafted request to repository.save or repository.update
  - [GHSA-9ggv-8w38-r7pm](https://osv.dev/vulnerability/GHSA-9ggv-8w38-r7pm): MEDIUM, CVSS 5.9, fixed in 0.3.29. TypeORM: SQL Injection in UpdateQueryBuilder/SoftDeleteQueryBuilder orderBy (MySQL/MariaDB)
  - [GHSA-2rp8-mm9q-fp49](https://osv.dev/vulnerability/GHSA-2rp8-mm9q-fp49) (CVE-2026-73651): MEDIUM, CVSS 5.7, fixed in 0.3.31.  TypeORM: migration:generate template-literal code injection
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-018 · 🟥 Critical (9.8) · Vulnerable transitive dependency

- **What:** underscore@1.9.1: 2 known vulnerabilities (highest CRITICAL, CVSS 9.8)
- **Component:** `underscore@1.9.1` (npm, scope prod, transitive), purl `pkg:npm/underscore@1.9.1`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → cfenv@1.2.2 → underscore@1.9.1
- **Official severity:** CRITICAL, CVSS 9.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.13.8
- **Evidence:**
  - [GHSA-cf4h-3jhx-xvhq](https://osv.dev/vulnerability/GHSA-cf4h-3jhx-xvhq) (CVE-2021-23358): CRITICAL, CVSS 9.8, fixed in 1.12.1. Arbitrary Code Execution in underscore
  - [GHSA-qpx9-hpmf-5gmw](https://osv.dev/vulnerability/GHSA-qpx9-hpmf-5gmw) (CVE-2026-27601): MEDIUM, CVSS 5.9, fixed in 1.13.8. Underscore has unlimited recursion in _.flatten and _.isEqual, potential for DoS attack
- **Initial risk:** Critical (9.8): highest advisory severity CRITICAL (CVSS 9.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-019 · 🟥 Critical (9.3) · Vulnerable transitive dependency

- **What:** babel-traverse@6.26.0: 1 known vulnerability (highest CRITICAL, CVSS 9.3)
- **Component:** `babel-traverse@6.26.0` (npm, scope prod, transitive), purl `pkg:npm/babel-traverse@6.26.0`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → istanbul-lib-instrument@1.10.1 → babel-traverse@6.26.0 ; goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → istanbul-lib-instrument@1.10.1 → babel-template@6.26.0 → babel-traverse@6.26.0
- **Official severity:** CRITICAL, CVSS 9.3 (OSV CVSS v3 vector (score computed))
- **Fix available:** no fixed version published
- **Evidence:**
  - [GHSA-67hx-6x53-jw92](https://osv.dev/vulnerability/GHSA-67hx-6x53-jw92) (CVE-2023-45133): CRITICAL, CVSS 9.3, no fix published. Babel vulnerable to arbitrary code execution when compiling specifically crafted malicious code
- **Initial risk:** Critical (9.3): highest advisory severity CRITICAL (CVSS 9.3); 1 advisory(ies) without a published fix
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-020 · 🟥 Critical (9.1) · Vulnerable transitive dependency

- **What:** cipher-base@1.0.4: 1 known vulnerability (highest CRITICAL, CVSS 9.1)
- **Component:** `cipher-base@1.0.4` (npm, scope dev, transitive), purl `pkg:npm/cipher-base@1.0.4`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → browserify@13.3.0 → crypto-browserify@3.12.0 → create-hash@1.2.0 → cipher-base@1.0.4 ; goof@1.0.1 → browserify@13.3.0 → crypto-browserify@3.12.0 → create-hmac@1.1.7 → cipher-base@1.0.4 ; goof@1.0.1 → browserify@13.3.0 → crypto-browserify@3.12.0 → browserify-cipher@1.0.1 → browserify-aes@1.2.0 → cipher-base@1.0.4
- **Official severity:** CRITICAL, CVSS 9.1 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.0.5
- **Evidence:**
  - [GHSA-cpq7-6gpm-g9rc](https://osv.dev/vulnerability/GHSA-cpq7-6gpm-g9rc) (CVE-2025-9287): CRITICAL, CVSS 9.1, fixed in 1.0.5. cipher-base is missing type checks, leading to hash rewind and passing on crafted data
- **Initial risk:** Critical (9.1): highest advisory severity CRITICAL (CVSS 9.1)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-021 · 🟥 Critical (9.1) · Vulnerable transitive dependency

- **What:** lodash@4.17.10: 8 known vulnerabilities (highest CRITICAL, CVSS 9.1)
- **Component:** `lodash@4.17.10` (npm, scope prod, transitive), purl `pkg:npm/lodash@4.17.10`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → istanbul-lib-instrument@1.10.1 → babel-generator@6.26.1 → lodash@4.17.10 ; goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → istanbul-lib-instrument@1.10.1 → babel-template@6.26.0 → lodash@4.17.10 ; goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → istanbul-lib-instrument@1.10.1 → babel-traverse@6.26.0 → lodash@4.17.10
- **Official severity:** CRITICAL, CVSS 9.1 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 4.18.0
- **Evidence:**
  - [GHSA-jf85-cpcp-j695](https://osv.dev/vulnerability/GHSA-jf85-cpcp-j695) (CVE-2019-10744): CRITICAL, CVSS 9.1, fixed in 4.17.12. Prototype Pollution in lodash
  - [GHSA-r5fr-rjxr-66jc](https://osv.dev/vulnerability/GHSA-r5fr-rjxr-66jc) (CVE-2026-4800): HIGH, CVSS 8.1, fixed in 4.18.0. lodash vulnerable to Code Injection via `_.template` imports key names
  - [GHSA-4xc9-xhrj-v574](https://osv.dev/vulnerability/GHSA-4xc9-xhrj-v574) (CVE-2018-16487): HIGH, fixed in 4.17.11. Prototype Pollution in lodash
  - [GHSA-p6mc-m468-83gw](https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw) (CVE-2020-8203): HIGH, CVSS 7.4, fixed in 4.17.19. Prototype Pollution in lodash
  - [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) (CVE-2021-23337): HIGH, CVSS 7.2, fixed in 4.17.21. Command Injection in lodash
  - [GHSA-x5rq-j2xg-h7qm](https://osv.dev/vulnerability/GHSA-x5rq-j2xg-h7qm) (CVE-2019-1010266): MEDIUM, CVSS 6.5, fixed in 4.17.11. Regular Expression Denial of Service (ReDoS) in lodash
  - [GHSA-xxjr-mmjv-4gpg](https://osv.dev/vulnerability/GHSA-xxjr-mmjv-4gpg) (CVE-2025-13465): MEDIUM, CVSS 6.5, fixed in 4.17.23. Lodash has Prototype Pollution Vulnerability in `_.unset`, `_.omit`, and `_.pullAt` functions
  - [GHSA-29mw-wpgm-hmr9](https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9) (CVE-2020-28500): MEDIUM, CVSS 5.3, fixed in 4.17.21. Regular Expression Denial of Service (ReDoS) in lodash
- **Initial risk:** Critical (9.1): highest advisory severity CRITICAL (CVSS 9.1)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-022 · 🟥 Critical (9.1) · Vulnerable direct dependency

- **What:** lodash@4.17.4: 9 known vulnerabilities (highest CRITICAL, CVSS 9.1)
- **Component:** `lodash@4.17.4` (npm, scope prod, direct), purl `pkg:npm/lodash@4.17.4`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → lodash@4.17.4 ; goof@1.0.1 → snyk@1.278.1 → @snyk/dep-graph@1.13.1 → lodash@4.17.4 ; goof@1.0.1 → snyk@1.278.1 → @snyk/snyk-cocoapods-plugin@2.0.1 → @snyk/dep-graph@1.13.1 → lodash@4.17.4
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

### F-023 · 🟥 Critical (9.1) · Vulnerable transitive dependency

- **What:** netmask@1.0.6: 1 known vulnerability (highest CRITICAL, CVSS 9.1)
- **Component:** `netmask@1.0.6` (npm, scope dev, transitive), purl `pkg:npm/netmask@1.0.6`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → snyk@1.278.1 → proxy-agent@3.1.1 → pac-proxy-agent@3.0.1 → pac-resolver@3.0.0 → netmask@1.0.6
- **Official severity:** CRITICAL, CVSS 9.1 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.1.0
- **Evidence:**
  - [GHSA-4c7m-wxvm-r7gc](https://osv.dev/vulnerability/GHSA-4c7m-wxvm-r7gc) (CVE-2021-28918, CVE-2021-29418): CRITICAL, CVSS 9.1, fixed in 1.1.0. Improper parsing of octal bytes in netmask
- **Initial risk:** Critical (9.1): highest advisory severity CRITICAL (CVSS 9.1)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-024 · 🟥 Critical (9.1) · Vulnerable transitive dependency

- **What:** sha.js@2.4.11: 1 known vulnerability (highest CRITICAL, CVSS 9.1)
- **Component:** `sha.js@2.4.11` (npm, scope prod, transitive), purl `pkg:npm/sha.js@2.4.11`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → typeorm@0.2.24 → sha.js@2.4.11 ; goof@1.0.1 → browserify@13.3.0 → shasum@1.0.2 → sha.js@2.4.11 ; goof@1.0.1 → browserify@13.3.0 → crypto-browserify@3.12.0 → create-hash@1.2.0 → sha.js@2.4.11
- **Official severity:** CRITICAL, CVSS 9.1 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 2.4.12
- **Evidence:**
  - [GHSA-95m3-7q98-8xr5](https://osv.dev/vulnerability/GHSA-95m3-7q98-8xr5) (CVE-2025-9288): CRITICAL, CVSS 9.1, fixed in 2.4.12. sha.js is missing type checks leading to hash rewind and passing on crafted data
- **Initial risk:** Critical (9.1): highest advisory severity CRITICAL (CVSS 9.1)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-025 · 🟧 High (8.8) · Vulnerable direct dependency

- **What:** dustjs-linkedin@2.5.0: 1 known vulnerability (highest HIGH, CVSS 8.8)
- **Component:** `dustjs-linkedin@2.5.0` (npm, scope prod, direct), purl `pkg:npm/dustjs-linkedin@2.5.0`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → dustjs-linkedin@2.5.0
- **Official severity:** HIGH, CVSS 8.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 3.0.0
- **Evidence:**
  - [GHSA-c6rp-wrp9-qr4q](https://osv.dev/vulnerability/GHSA-c6rp-wrp9-qr4q) (CVE-2021-4264): HIGH, CVSS 8.8, fixed in 3.0.0. dustjs-linkedin vulnerable to Prototype Pollution
- **Initial risk:** High (8.8): highest advisory severity HIGH (CVSS 8.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-026 · 🟧 High (8.8) · Vulnerable direct dependency

- **What:** snyk@1.278.1: 4 known vulnerabilities (highest HIGH, CVSS 8.8)
- **Component:** `snyk@1.278.1` (npm, scope dev, direct), purl `pkg:npm/snyk@1.278.1`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → snyk@1.278.1
- **Official severity:** HIGH, CVSS 8.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.1297.3
- **Evidence:**
  - [GHSA-4vrv-93c7-m92j](https://osv.dev/vulnerability/GHSA-4vrv-93c7-m92j) (CVE-2022-24441): HIGH, CVSS 8.8, fixed in 1.1064.0. snyk Code Injection vulnerability
  - [GHSA-hpqj-7cj6-hfj8](https://osv.dev/vulnerability/GHSA-hpqj-7cj6-hfj8) (CVE-2022-40764): HIGH, CVSS 7.8, fixed in 1.996.0. Snyk CLI affected by Command Injection vulnerability
  - [GHSA-6hwc-9h8r-3vmf](https://osv.dev/vulnerability/GHSA-6hwc-9h8r-3vmf) (CVE-2025-6624): HIGH, CVSS 7.2, fixed in 1.1297.3. Snyk CLI Insertion of Sensitive Information into Log File allowed in DEBUG or DEBUG/TRACE mode
  - [GHSA-4x6g-3cmx-w76r](https://osv.dev/vulnerability/GHSA-4x6g-3cmx-w76r) (CVE-2022-22984): MEDIUM, CVSS 6.3, fixed in 1.1064.0. Snyk plugins vulnerable to Command Injection
- **Initial risk:** High (8.8): highest advisory severity HIGH (CVSS 8.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-027 · 🟧 High (8.2) · Vulnerable transitive dependency

- **What:** toml@3.0.0: 6 known vulnerabilities (highest HIGH, CVSS 8.2)
- **Component:** `toml@3.0.0` (npm, scope dev, transitive), purl `pkg:npm/toml@3.0.0`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → snyk@1.278.1 → snyk-go-plugin@1.11.1 → snyk-go-parser@1.3.1 → toml@3.0.0
- **Official severity:** HIGH, CVSS 8.2 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 5.0.1
- **Evidence:**
  - [GHSA-v5mp-jgw5-2x6j](https://osv.dev/vulnerability/GHSA-v5mp-jgw5-2x6j) (CVE-2026-63376): HIGH, CVSS 8.2, fixed in 4.1.2. toml-node: Prototype Pollution Leads to `Object.prototype` Corruption via `__proto__` Key-Path Desynchronization
  - [GHSA-4qx8-w7c3-pj3p](https://osv.dev/vulnerability/GHSA-4qx8-w7c3-pj3p) (CVE-2026-114141): HIGH, fixed in 5.0.1. toml-node: Quadratic-complexity DoS via many array-of-tables headers in toml.parse()
  - [GHSA-9j65-hcg3-gc64](https://osv.dev/vulnerability/GHSA-9j65-hcg3-gc64) (CVE-2026-114143): HIGH, fixed in 5.0.1. toml-node: Quadratic-complexity DoS via long dotted keys or table paths in toml.parse()
  - [GHSA-h895-cgqg-jf52](https://osv.dev/vulnerability/GHSA-h895-cgqg-jf52) (CVE-2026-114142): HIGH, fixed in 5.0.1. toml-node: Prototype pollution: parsing a TOML document can write to Object.prototype
  - [GHSA-82x6-q7mm-w9cf](https://osv.dev/vulnerability/GHSA-82x6-q7mm-w9cf) (CVE-2026-77465): HIGH, CVSS 7.5, fixed in 4.2.0. toml-node: Uncontrolled Recursion
  - [GHSA-9qmh-m7c6-f92p](https://osv.dev/vulnerability/GHSA-9qmh-m7c6-f92p) (CVE-2026-114144): HIGH, CVSS 7.5, fixed in 5.0.1. toml-node: Uncontrolled resource consumption (CPU DoS) via unbounded-length integer literals in toml.parse()
- **Initial risk:** High (8.2): highest advisory severity HIGH (CVSS 8.2)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-028 · 🟧 High (8.1) · Vulnerable transitive dependency

- **What:** degenerator@1.0.4: 1 known vulnerability (highest HIGH, CVSS 8.1)
- **Component:** `degenerator@1.0.4` (npm, scope dev, transitive), purl `pkg:npm/degenerator@1.0.4`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → snyk@1.278.1 → proxy-agent@3.1.1 → pac-proxy-agent@3.0.1 → pac-resolver@3.0.0 → degenerator@1.0.4
- **Official severity:** HIGH, CVSS 8.1 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 3.0.1
- **Evidence:**
  - [GHSA-9j49-mfvp-vmhm](https://osv.dev/vulnerability/GHSA-9j49-mfvp-vmhm) (CVE-2021-23406): HIGH, CVSS 8.1, fixed in 3.0.1. Code Injection in pac-resolver
- **Initial risk:** High (8.1): highest advisory severity HIGH (CVSS 8.1)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-029 · 🟧 High (8.1) · Vulnerable transitive dependency

- **What:** ip@1.1.5: 2 known vulnerabilities (highest HIGH, CVSS 8.1)
- **Component:** `ip@1.1.5` (npm, scope dev, transitive), purl `pkg:npm/ip@1.1.5`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → snyk@1.278.1 → proxy-agent@3.1.1 → pac-proxy-agent@3.0.1 → pac-resolver@3.0.0 → ip@1.1.5 ; goof@1.0.1 → snyk@1.278.1 → proxy-agent@3.1.1 → socks-proxy-agent@4.0.2 → socks@2.3.3 → ip@1.1.5 ; goof@1.0.1 → snyk@1.278.1 → proxy-agent@3.1.1 → pac-proxy-agent@3.0.1 → socks-proxy-agent@4.0.2 → socks@2.3.3 → ip@1.1.5
- **Official severity:** HIGH, CVSS 8.1 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.1.9; no fix for GHSA-2p57-rm9w-gvfp
- **Evidence:**
  - [GHSA-2p57-rm9w-gvfp](https://osv.dev/vulnerability/GHSA-2p57-rm9w-gvfp) (CVE-2024-29415): HIGH, CVSS 8.1, no fix published. ip SSRF improper categorization in isPublic
  - [GHSA-78xj-cgh5-2h22](https://osv.dev/vulnerability/GHSA-78xj-cgh5-2h22) (CVE-2023-42282): LOW, fixed in 1.1.9. NPM IP package incorrectly identifies some private IP addresses as public
- **Initial risk:** High (8.1): highest advisory severity HIGH (CVSS 8.1); 1 advisory(ies) without a published fix
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-030 · 🟧 High (8.1) · Vulnerable transitive dependency

- **What:** lodash@4.17.15: 5 known vulnerabilities (highest HIGH, CVSS 8.1)
- **Component:** `lodash@4.17.15` (npm, scope dev, transitive), purl `pkg:npm/lodash@4.17.15`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → snyk@1.278.1 → lodash@4.17.15 ; goof@1.0.1 → snyk@1.278.1 → inquirer@6.5.2 → lodash@4.17.15 ; goof@1.0.1 → snyk@1.278.1 → snyk-config@2.2.3 → lodash@4.17.15
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

### F-031 · 🟧 High (8.1) · Vulnerable transitive dependency

- **What:** lodash@4.17.21: 2 known vulnerabilities (highest HIGH, CVSS 8.1)
- **Component:** `lodash@4.17.21` (npm, scope prod, transitive), purl `pkg:npm/lodash@4.17.21`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → hbs@4.0.4 → handlebars@4.0.14 → async@2.6.3 → lodash@4.17.21
- **Official severity:** HIGH, CVSS 8.1 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 4.18.0
- **Evidence:**
  - [GHSA-r5fr-rjxr-66jc](https://osv.dev/vulnerability/GHSA-r5fr-rjxr-66jc) (CVE-2026-4800): HIGH, CVSS 8.1, fixed in 4.18.0. lodash vulnerable to Code Injection via `_.template` imports key names
  - [GHSA-xxjr-mmjv-4gpg](https://osv.dev/vulnerability/GHSA-xxjr-mmjv-4gpg) (CVE-2025-13465): MEDIUM, CVSS 6.5, fixed in 4.17.23. Lodash has Prototype Pollution Vulnerability in `_.unset`, `_.omit`, and `_.pullAt` functions
- **Initial risk:** High (8.1): highest advisory severity HIGH (CVSS 8.1)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-032 · 🟧 High (8.1) · Vulnerable transitive dependency

- **What:** pac-resolver@3.0.0: 1 known vulnerability (highest HIGH, CVSS 8.1)
- **Component:** `pac-resolver@3.0.0` (npm, scope dev, transitive), purl `pkg:npm/pac-resolver@3.0.0`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → snyk@1.278.1 → proxy-agent@3.1.1 → pac-proxy-agent@3.0.1 → pac-resolver@3.0.0
- **Official severity:** HIGH, CVSS 8.1 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 5.0.0
- **Evidence:**
  - [GHSA-9j49-mfvp-vmhm](https://osv.dev/vulnerability/GHSA-9j49-mfvp-vmhm) (CVE-2021-23406): HIGH, CVSS 8.1, fixed in 5.0.0. Code Injection in pac-resolver
- **Initial risk:** High (8.1): highest advisory severity HIGH (CVSS 8.1)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-033 · 🟧 High (8.1) · Vulnerable transitive dependency

- **What:** shell-quote@1.6.1: 2 known vulnerabilities (highest HIGH, CVSS 8.1)
- **Component:** `shell-quote@1.6.1` (npm, scope dev, transitive), purl `pkg:npm/shell-quote@1.6.1`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → browserify@13.3.0 → shell-quote@1.6.1
- **Official severity:** HIGH, CVSS 8.1 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.9.0
- **Evidence:**
  - [GHSA-w7jw-789q-3m8p](https://osv.dev/vulnerability/GHSA-w7jw-789q-3m8p) (CVE-2026-9277): HIGH, CVSS 8.1, fixed in 1.8.4. shell-quote quote() does not escape newlines in object .op values
  - [GHSA-395f-4hp3-45gv](https://osv.dev/vulnerability/GHSA-395f-4hp3-45gv) (CVE-2026-13311): HIGH, CVSS 7.5, fixed in 1.9.0. shell-quote: Quadratic-complexity Denial of Service in `parse()` (CWE-407)
- **Initial risk:** High (8.1): highest advisory severity HIGH (CVSS 8.1)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-034 · 🟧 High (8.0) · Unsafe CI/CD component

- **What:** .github/workflows/snyk-code.yml: third-party action 'snyk/actions/setup@master' is not pinned to a commit SHA
- **Component:** `snyk/actions/setup@master` (github-actions, scope ci, direct), purl `pkg:github/snyk/actions@master#setup`
- **Where:** `.github/workflows/snyk-code.yml:8`
- **Dependency path:** snyk code test → snyk/actions/setup@master ; snyk test → snyk/actions/setup@master
- **Evidence:**
  - `.github/workflows/snyk-code.yml:8`: `- uses: snyk/actions/setup@master`
- **Initial risk:** High (8.0): R15_CI_UNPINNED_ACTION default level High
- **Why it matters:** A third-party action referenced by tag/branch can be changed by its owner at any time.
- **Basis:** verified fact, confidence high

### F-035 · 🟧 High (8.0) · Unsafe CI/CD component

- **What:** .github/workflows/snyk-test-sarif.yml: third-party action 'snyk/actions/setup@master' is not pinned to a commit SHA
- **Component:** `snyk/actions/setup@master` (github-actions, scope ci, direct), purl `pkg:github/snyk/actions@master#setup`
- **Where:** `.github/workflows/snyk-test-sarif.yml:8`
- **Dependency path:** snyk code test → snyk/actions/setup@master ; snyk test → snyk/actions/setup@master
- **Evidence:**
  - `.github/workflows/snyk-test-sarif.yml:8`: `- uses: snyk/actions/setup@master`
- **Initial risk:** High (8.0): R15_CI_UNPINNED_ACTION default level High
- **Why it matters:** A third-party action referenced by tag/branch can be changed by its owner at any time.
- **Basis:** verified fact, confidence high

### F-036 · 🟧 High (8.0) · Vulnerable transitive dependency

- **What:** diff@1.4.0: 2 known vulnerabilities (highest HIGH)
- **Component:** `diff@1.4.0` (npm, scope prod, transitive), purl `pkg:npm/diff@1.4.0`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → tap@11.1.5 → tap-mocha-reporter@3.0.9 → diff@1.4.0
- **Official severity:** HIGH (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 3.5.1
- **Evidence:**
  - [GHSA-h6ch-v84p-w6p9](https://osv.dev/vulnerability/GHSA-h6ch-v84p-w6p9): HIGH, fixed in 3.5.0. Regular Expression Denial of Service (ReDoS)
  - [GHSA-73rr-hh4g-fpgx](https://osv.dev/vulnerability/GHSA-73rr-hh4g-fpgx) (CVE-2026-24001): LOW, fixed in 3.5.1. jsdiff has a Denial of Service vulnerability in parsePatch and applyPatch
- **Initial risk:** High (8.0): highest advisory severity HIGH
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-037 · 🟧 High (8.0) · Vulnerable transitive dependency

- **What:** figlet@1.5.0: 1 known vulnerability (highest HIGH)
- **Component:** `figlet@1.5.0` (npm, scope prod, transitive), purl `pkg:npm/figlet@1.5.0`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → typeorm@0.2.24 → yargonaut@1.1.4 → figlet@1.5.0
- **Official severity:** HIGH (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 1.11.3
- **Evidence:**
  - [GHSA-62ch-8vmq-8xm7](https://osv.dev/vulnerability/GHSA-62ch-8vmq-8xm7) (CVE-2026-96780): HIGH, fixed in 1.11.3. figlet is vulnerable to denial of service via unbounded loop when whitespaceBreak is used with a small width
- **Initial risk:** High (8.0): highest advisory severity HIGH
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-038 · 🟧 High (8.0) · Vulnerable transitive dependency

- **What:** mongodb@2.0.46: 1 known vulnerability (highest HIGH)
- **Component:** `mongodb@2.0.46` (npm, scope prod, transitive), purl `pkg:npm/mongodb@2.0.46`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → mongoose@4.2.4 → mongodb@2.0.46
- **Official severity:** HIGH (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 3.1.13
- **Evidence:**
  - [GHSA-mh5c-679w-hh4r](https://osv.dev/vulnerability/GHSA-mh5c-679w-hh4r): HIGH, fixed in 3.1.13. Denial of Service in mongodb
- **Initial risk:** High (8.0): highest advisory severity HIGH
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-039 · 🟧 High (8.0) · Vulnerable transitive dependency

- **What:** negotiator@0.2.8: 1 known vulnerability (highest HIGH)
- **Component:** `negotiator@0.2.8` (npm, scope prod, transitive), purl `pkg:npm/negotiator@0.2.8`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → st@0.2.4 → negotiator@0.2.8
- **Official severity:** HIGH (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 0.6.1
- **Evidence:**
  - [GHSA-7mc5-chhp-fmc3](https://osv.dev/vulnerability/GHSA-7mc5-chhp-fmc3) (CVE-2016-10539): HIGH, fixed in 0.6.1. Regular Expression Denial of Service in negotiator
- **Initial risk:** High (8.0): highest advisory severity HIGH
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-040 · 🟧 High (8.0) · Vulnerable transitive dependency

- **What:** negotiator@0.4.9: 1 known vulnerability (highest HIGH)
- **Component:** `negotiator@0.4.9` (npm, scope prod, transitive), purl `pkg:npm/negotiator@0.4.9`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → errorhandler@1.2.0 → accepts@1.1.4 → negotiator@0.4.9
- **Official severity:** HIGH (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 0.6.1
- **Evidence:**
  - [GHSA-7mc5-chhp-fmc3](https://osv.dev/vulnerability/GHSA-7mc5-chhp-fmc3) (CVE-2016-10539): HIGH, fixed in 0.6.1. Regular Expression Denial of Service in negotiator
- **Initial risk:** High (8.0): highest advisory severity HIGH
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-041 · 🟧 High (8.0) · Vulnerable transitive dependency

- **What:** negotiator@0.5.3: 1 known vulnerability (highest HIGH)
- **Component:** `negotiator@0.5.3` (npm, scope prod, transitive), purl `pkg:npm/negotiator@0.5.3`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → express@4.12.4 → accepts@1.2.13 → negotiator@0.5.3
- **Official severity:** HIGH (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 0.6.1
- **Evidence:**
  - [GHSA-7mc5-chhp-fmc3](https://osv.dev/vulnerability/GHSA-7mc5-chhp-fmc3) (CVE-2016-10539): HIGH, fixed in 0.6.1. Regular Expression Denial of Service in negotiator
- **Initial risk:** High (8.0): highest advisory severity HIGH
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-042 · 🟧 High (7.8) · Vulnerable transitive dependency

- **What:** async@2.6.3: 1 known vulnerability (highest HIGH, CVSS 7.8)
- **Component:** `async@2.6.3` (npm, scope prod, transitive), purl `pkg:npm/async@2.6.3`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → hbs@4.0.4 → handlebars@4.0.14 → async@2.6.3
- **Official severity:** HIGH, CVSS 7.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 2.6.4
- **Evidence:**
  - [GHSA-fwr7-v2mv-hh25](https://osv.dev/vulnerability/GHSA-fwr7-v2mv-hh25) (CVE-2021-43138): HIGH, CVSS 7.8, fixed in 2.6.4. Prototype Pollution in async
- **Initial risk:** High (7.8): highest advisory severity HIGH (CVSS 7.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-043 · 🟧 High (7.8) · Vulnerable transitive dependency

- **What:** kerberos@0.0.24: 1 known vulnerability (highest HIGH, CVSS 7.8)
- **Component:** `kerberos@0.0.24` (npm, scope optional, transitive), purl `pkg:npm/kerberos@0.0.24`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → mongoose@4.2.4 → mongodb@2.0.46 → mongodb-core@1.2.19 → kerberos@0.0.24
- **Official severity:** HIGH, CVSS 7.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.0.0
- **Evidence:**
  - [GHSA-m2mx-rfpw-jghv](https://osv.dev/vulnerability/GHSA-m2mx-rfpw-jghv) (CVE-2020-13110): HIGH, CVSS 7.8, fixed in 1.0.0. DLL Injection in kerberos
- **Initial risk:** High (7.8): highest advisory severity HIGH (CVSS 7.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-044 · 🟧 High (7.8) · Vulnerable transitive dependency

- **What:** snyk-go-plugin@1.11.1: 1 known vulnerability (highest HIGH, CVSS 7.8)
- **Component:** `snyk-go-plugin@1.11.1` (npm, scope dev, transitive), purl `pkg:npm/snyk-go-plugin@1.11.1`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → snyk@1.278.1 → snyk-go-plugin@1.11.1
- **Official severity:** HIGH, CVSS 7.8 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.19.1
- **Evidence:**
  - [GHSA-hpqj-7cj6-hfj8](https://osv.dev/vulnerability/GHSA-hpqj-7cj6-hfj8) (CVE-2022-40764): HIGH, CVSS 7.8, fixed in 1.19.1. Snyk CLI affected by Command Injection vulnerability
- **Initial risk:** High (7.8): highest advisory severity HIGH (CVSS 7.8)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-045 · 🟧 High (7.7) · Vulnerable transitive dependency

- **What:** elliptic@6.4.1: 9 known vulnerabilities (highest CRITICAL, CVSS 7.7)
- **Component:** `elliptic@6.4.1` (npm, scope dev, transitive), purl `pkg:npm/elliptic@6.4.1`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → browserify@13.3.0 → crypto-browserify@3.12.0 → browserify-sign@4.0.4 → elliptic@6.4.1 ; goof@1.0.1 → browserify@13.3.0 → crypto-browserify@3.12.0 → create-ecdh@4.0.3 → elliptic@6.4.1
- **Official severity:** CRITICAL, CVSS 7.7 (advisory severity label (OSV))
- **Fix available:** upgrade to ≥ 6.6.1; no fix for GHSA-848j-6mx2-7j84
- **Evidence:**
  - [GHSA-vjh7-7g9h-fjfh](https://osv.dev/vulnerability/GHSA-vjh7-7g9h-fjfh): CRITICAL, fixed in 6.6.1. Elliptic's private key extraction in ECDSA upon signing a malformed input (e.g. a string)
  - [GHSA-vh7m-p724-62c2](https://osv.dev/vulnerability/GHSA-vh7m-p724-62c2) (CVE-2020-13822): HIGH, CVSS 7.7, fixed in 6.5.3. Signature Malleabillity in elliptic
  - [GHSA-r9p9-mrjm-926w](https://osv.dev/vulnerability/GHSA-r9p9-mrjm-926w) (CVE-2020-28498): MEDIUM, CVSS 6.8, fixed in 6.5.4. Elliptic Uses a Broken or Risky Cryptographic Algorithm
  - [GHSA-848j-6mx2-7j84](https://osv.dev/vulnerability/GHSA-848j-6mx2-7j84) (CVE-2025-14505): MEDIUM, CVSS 5.6, no fix published. Elliptic Uses a Cryptographic Primitive with a Risky Implementation
  - [GHSA-434g-2637-qmqr](https://osv.dev/vulnerability/GHSA-434g-2637-qmqr) (CVE-2024-48949): MEDIUM, CVSS 5.3, fixed in 6.5.6. Elliptic's verify function omits uniqueness validation
  - [GHSA-49q7-c7j4-3p7m](https://osv.dev/vulnerability/GHSA-49q7-c7j4-3p7m) (CVE-2024-42461): MEDIUM, CVSS 5.3, fixed in 6.5.7. Elliptic allows BER-encoded signatures
  - [GHSA-977x-g7h5-7qgw](https://osv.dev/vulnerability/GHSA-977x-g7h5-7qgw) (CVE-2024-42460): MEDIUM, CVSS 5.3, fixed in 6.5.7. Elliptic's ECDSA missing check for whether leading bit of r and s is zero
  - [GHSA-f7q4-pwc6-w24p](https://osv.dev/vulnerability/GHSA-f7q4-pwc6-w24p) (CVE-2024-42459): MEDIUM, CVSS 5.3, fixed in 6.5.7. Elliptic's EDDSA missing signature length check
  - [GHSA-fc9h-whq2-v747](https://osv.dev/vulnerability/GHSA-fc9h-whq2-v747) (CVE-2024-48948): MEDIUM, CVSS 4.8, fixed in 6.6.0. Valid ECDSA signatures erroneously rejected in Elliptic
- **Initial risk:** High (7.7): highest advisory severity CRITICAL (CVSS 7.7); 1 advisory(ies) without a published fix
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-046 · 🟧 High (7.5) · Vulnerable direct dependency

- **What:** adm-zip@0.4.7: 8 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `adm-zip@0.4.7` (npm, scope prod, direct), purl `pkg:npm/adm-zip@0.4.7`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → adm-zip@0.4.7
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

### F-047 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** ansi-regex@3.0.0: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `ansi-regex@3.0.0` (npm, scope prod, transitive), purl `pkg:npm/ansi-regex@3.0.0`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → snyk@1.278.1 → inquirer@6.5.2 → string-width@2.1.1 → strip-ansi@4.0.0 → ansi-regex@3.0.0 ; goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → yargs@11.1.0 → string-width@2.1.1 → strip-ansi@4.0.0 → ansi-regex@3.0.0 ; goof@1.0.1 → snyk@1.278.1 → update-notifier@2.5.0 → boxen@1.3.0 → string-width@2.1.1 → strip-ansi@4.0.0 → ansi-regex@3.0.0
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 3.0.1
- **Evidence:**
  - [GHSA-93q8-gq69-wqmw](https://osv.dev/vulnerability/GHSA-93q8-gq69-wqmw) (CVE-2021-3807): HIGH, CVSS 7.5, fixed in 3.0.1. Inefficient Regular Expression Complexity in chalk/ansi-regex
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-048 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** ansi-regex@4.1.0: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `ansi-regex@4.1.0` (npm, scope prod, transitive), purl `pkg:npm/ansi-regex@4.1.0`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → snyk@1.278.1 → strip-ansi@5.2.0 → ansi-regex@4.1.0 ; goof@1.0.1 → snyk@1.278.1 → inquirer@6.5.2 → strip-ansi@5.2.0 → ansi-regex@4.1.0 ; goof@1.0.1 → snyk@1.278.1 → wrap-ansi@5.1.0 → strip-ansi@5.2.0 → ansi-regex@4.1.0
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 4.1.1
- **Evidence:**
  - [GHSA-93q8-gq69-wqmw](https://osv.dev/vulnerability/GHSA-93q8-gq69-wqmw) (CVE-2021-3807): HIGH, CVSS 7.5, fixed in 4.1.1. Inefficient Regular Expression Complexity in chalk/ansi-regex
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-049 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** ansi-regex@5.0.0: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `ansi-regex@5.0.0` (npm, scope prod, transitive), purl `pkg:npm/ansi-regex@5.0.0`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → typeorm@0.2.24 → cli-highlight@2.1.4 → yargs@15.4.1 → cliui@6.0.0 → strip-ansi@6.0.0 → ansi-regex@5.0.0 ; goof@1.0.1 → nodemon@2.0.7 → update-notifier@4.1.3 → boxen@4.2.0 → string-width@4.2.2 → strip-ansi@6.0.0 → ansi-regex@5.0.0 ; goof@1.0.1 → typeorm@0.2.24 → cli-highlight@2.1.4 → yargs@15.4.1 → string-width@4.2.0 → strip-ansi@6.0.0 → ansi-regex@5.0.0
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 5.0.1
- **Evidence:**
  - [GHSA-93q8-gq69-wqmw](https://osv.dev/vulnerability/GHSA-93q8-gq69-wqmw) (CVE-2021-3807): HIGH, CVSS 7.5, fixed in 5.0.1. Inefficient Regular Expression Complexity in chalk/ansi-regex
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-050 · 🟧 High (7.5) · Vulnerable direct dependency

- **What:** body-parser@1.9.0: 3 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `body-parser@1.9.0` (npm, scope prod, direct), purl `pkg:npm/body-parser@1.9.0`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → body-parser@1.9.0
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 1.20.9
- **Evidence:**
  - [GHSA-27r3-jxmh-p828](https://osv.dev/vulnerability/GHSA-27r3-jxmh-p828) (CVE-2026-111181): HIGH, CVSS 7.5, fixed in 1.20.9. body-parser vulnerable to Denial of Service via trailing bytes after a compressed request body
  - [GHSA-qwcr-r2fm-qrc7](https://osv.dev/vulnerability/GHSA-qwcr-r2fm-qrc7) (CVE-2024-45590): HIGH, CVSS 7.5, fixed in 1.20.3. body-parser vulnerable to denial of service when url encoding is enabled
  - [GHSA-v422-hmwv-36x6](https://osv.dev/vulnerability/GHSA-v422-hmwv-36x6) (CVE-2026-12590): LOW, CVSS 3.7, fixed in 1.20.6. body-parser vulnerable to denial of service when invalid limit value silently disables size enforcement
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-051 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** brace-expansion@1.1.11: 8 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `brace-expansion@1.1.11` (npm, scope prod, transitive), purl `pkg:npm/brace-expansion@1.1.11`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → nodemon@2.0.7 → minimatch@3.0.4 → brace-expansion@1.1.11 ; goof@1.0.1 → browserify@13.3.0 → glob@7.1.3 → minimatch@3.0.4 → brace-expansion@1.1.11 ; goof@1.0.1 → snyk@1.278.1 → glob@7.1.3 → minimatch@3.0.4 → brace-expansion@1.1.11
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

### F-052 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** braces@2.3.2: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `braces@2.3.2` (npm, scope prod, transitive), purl `pkg:npm/braces@2.3.2`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → micromatch@3.1.10 → braces@2.3.2 ; goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → test-exclude@4.2.1 → micromatch@3.1.10 → braces@2.3.2
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 3.0.3
- **Evidence:**
  - [GHSA-grv7-fg5c-xmjg](https://osv.dev/vulnerability/GHSA-grv7-fg5c-xmjg) (CVE-2024-4068): HIGH, CVSS 7.5, fixed in 3.0.3. Uncontrolled resource consumption in braces
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-053 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** braces@3.0.2: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `braces@3.0.2` (npm, scope dev, transitive), purl `pkg:npm/braces@3.0.2`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → nodemon@2.0.7 → chokidar@3.5.1 → braces@3.0.2
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 3.0.3
- **Evidence:**
  - [GHSA-grv7-fg5c-xmjg](https://osv.dev/vulnerability/GHSA-grv7-fg5c-xmjg) (CVE-2024-4068): HIGH, CVSS 7.5, fixed in 3.0.3. Uncontrolled resource consumption in braces
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-054 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** browserify-sign@4.0.4: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `browserify-sign@4.0.4` (npm, scope dev, transitive), purl `pkg:npm/browserify-sign@4.0.4`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → browserify@13.3.0 → crypto-browserify@3.12.0 → browserify-sign@4.0.4
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 4.2.2
- **Evidence:**
  - [GHSA-x9w5-v3q2-3rhw](https://osv.dev/vulnerability/GHSA-x9w5-v3q2-3rhw) (CVE-2023-46234): HIGH, CVSS 7.5, fixed in 4.2.2. browserify-sign upper bound check issue in `dsaVerify` leads to a signature forgery attack
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-055 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** cross-spawn@4.0.2: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `cross-spawn@4.0.2` (npm, scope prod, transitive), purl `pkg:npm/cross-spawn@4.0.2`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → tap@11.1.5 → foreground-child@1.5.6 → cross-spawn@4.0.2 ; goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → foreground-child@1.5.6 → cross-spawn@4.0.2 ; goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → spawn-wrap@1.4.2 → foreground-child@1.5.6 → cross-spawn@4.0.2
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 6.0.6
- **Evidence:**
  - [GHSA-3xgq-45jj-v275](https://osv.dev/vulnerability/GHSA-3xgq-45jj-v275) (CVE-2024-21538): HIGH, CVSS 7.5, fixed in 6.0.6. Regular Expression Denial of Service (ReDoS) in cross-spawn
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-056 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** cross-spawn@5.1.0: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `cross-spawn@5.1.0` (npm, scope prod, transitive), purl `pkg:npm/cross-spawn@5.1.0`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → yargs@11.1.0 → os-locale@2.1.0 → execa@0.7.0 → cross-spawn@5.1.0 ; goof@1.0.1 → snyk@1.278.1 → update-notifier@2.5.0 → boxen@1.3.0 → term-size@1.2.0 → execa@0.7.0 → cross-spawn@5.1.0
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 6.0.6
- **Evidence:**
  - [GHSA-3xgq-45jj-v275](https://osv.dev/vulnerability/GHSA-3xgq-45jj-v275) (CVE-2024-21538): HIGH, CVSS 7.5, fixed in 6.0.6. Regular Expression Denial of Service (ReDoS) in cross-spawn
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-057 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** cross-spawn@6.0.5: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `cross-spawn@6.0.5` (npm, scope dev, transitive), purl `pkg:npm/cross-spawn@6.0.5`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → snyk@1.278.1 → os-name@3.1.0 → windows-release@3.2.0 → execa@1.0.0 → cross-spawn@6.0.5
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 6.0.6
- **Evidence:**
  - [GHSA-3xgq-45jj-v275](https://osv.dev/vulnerability/GHSA-3xgq-45jj-v275) (CVE-2024-21538): HIGH, CVSS 7.5, fixed in 6.0.6. Regular Expression Denial of Service (ReDoS) in cross-spawn
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-058 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** debug@2.2.0: 2 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `debug@2.2.0` (npm, scope prod, transitive), purl `pkg:npm/debug@2.2.0`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → express@4.12.4 → debug@2.2.0 ; goof@1.0.1 → mongoose@4.2.4 → mquery@1.6.3 → debug@2.2.0 ; goof@1.0.1 → express@4.12.4 → finalhandler@0.3.6 → debug@2.2.0
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 2.6.9
- **Evidence:**
  - [GHSA-9vvw-cc9w-f27h](https://osv.dev/vulnerability/GHSA-9vvw-cc9w-f27h) (CVE-2017-20165): HIGH, CVSS 7.5, fixed in 2.6.9. debug Inefficient Regular Expression Complexity vulnerability
  - [GHSA-gxpj-cx7g-858c](https://osv.dev/vulnerability/GHSA-gxpj-cx7g-858c) (CVE-2017-16137): LOW, CVSS 3.7, fixed in 2.6.9. Regular Expression Denial of Service in debug
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-059 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** decode-uri-component@0.2.0: 3 known vulnerabilities (highest HIGH, CVSS 7.5)
- **Component:** `decode-uri-component@0.2.0` (npm, scope prod, transitive), purl `pkg:npm/decode-uri-component@0.2.0`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → micromatch@3.1.10 → snapdragon@0.8.2 → source-map-resolve@0.5.1 → decode-uri-component@0.2.0 ; goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → test-exclude@4.2.1 → micromatch@3.1.10 → snapdragon@0.8.2 → source-map-resolve@0.5.1 → decode-uri-component@0.2.0 ; goof@1.0.1 → tap@11.1.5 → nyc@11.9.0 → micromatch@3.1.10 → braces@2.3.2 → snapdragon@0.8.2 → source-map-resolve@0.5.1 → decode-uri-component@0.2.0
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** upgrade to ≥ 0.5.1
- **Evidence:**
  - [GHSA-qr28-fpjm-wq7f](https://osv.dev/vulnerability/GHSA-qr28-fpjm-wq7f) (CVE-2026-118664): HIGH, fixed in 0.5.1. decode-uri-component vulnerable to denial of service via quadratic replacement of percent-encoded runs
  - [GHSA-w573-4hg7-7wgq](https://osv.dev/vulnerability/GHSA-w573-4hg7-7wgq) (CVE-2022-38900): HIGH, CVSS 7.5, fixed in 0.2.1. decode-uri-component vulnerable to Denial of Service (DoS)
  - [GHSA-vcc3-ghjq-m6fr](https://osv.dev/vulnerability/GHSA-vcc3-ghjq-m6fr) (CVE-2026-45822): MEDIUM, fixed in 0.5.0. decode-uri-component: Denial of service via exponential decoding of malformed percent-encoded input
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5)
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

### F-060 · 🟧 High (7.5) · Vulnerable transitive dependency

- **What:** dicer@0.3.0: 1 known vulnerability (highest HIGH, CVSS 7.5)
- **Component:** `dicer@0.3.0` (npm, scope prod, transitive), purl `pkg:npm/dicer@0.3.0`
- **Where:** `package-lock.json`
- **Dependency path:** goof@1.0.1 → express-fileupload@0.0.5 → connect-busboy@0.0.2 → busboy@0.3.1 → dicer@0.3.0
- **Official severity:** HIGH, CVSS 7.5 (OSV CVSS v3 vector (score computed))
- **Fix available:** no fixed version published
- **Evidence:**
  - [GHSA-wm7h-9275-46v2](https://osv.dev/vulnerability/GHSA-wm7h-9275-46v2) (CVE-2022-24434): HIGH, CVSS 7.5, no fix published. Crash in HeaderParser in dicer
- **Initial risk:** High (7.5): highest advisory severity HIGH (CVSS 7.5); 1 advisory(ies) without a published fix
- **Why it matters:** Published advisories affect this exact version.
- **Basis:** verified fact, confidence high

*94 more findings: full evidence in `findings.json`.*

## 5. Notes and limits

- what changed: base revision 'HEAD~1' not found (shallow clone or first commit), change analysis skipped
- Day 1 scope: visibility and detection. Reachability, exploitability (KEV/EPSS) and remediation are Day 2.
- Typosquat results are heuristic (name similarity) and need human review.
