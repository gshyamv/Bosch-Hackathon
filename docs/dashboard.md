# The SSCG Dashboard: What Happens in the UI

This guide walks through the Streamlit dashboard (`sscg/ui/app.py`) from top to bottom. For each part it explains what you see, where the data comes from, and what happens when you click something.

The dashboard covers **all five Day 1 columns** of the problem statement and answers the Day 1 checkpoint question: *"Show us what is in the application, what changed, and what appears risky."*

| Page section | Day 1 column |
|---|---|
| ① Components | 1 · Discover Components |
| ② Supply chain view | 2 · Build the Supply Chain View |
| ③ Vulnerabilities | 3 · Detect Vulnerabilities |
| ④ Suspicious changes | 4 · Detect Suspicious Changes (+ "what changed") |
| ⑤ Evidence | 5 · Present Evidence |

---

## Contents

1. [Starting the dashboard](#1-starting-the-dashboard)
2. [How the page works](#2-how-the-page-works)
3. [Choosing a repository and scanning](#3-choosing-a-repository-and-scanning)
4. [Pipeline banner and headline numbers](#4-pipeline-banner-and-headline-numbers)
5. [① Components](#5--components)
6. [② Supply chain view (4 tabs)](#6--supply-chain-view)
7. [③ Vulnerabilities](#7--vulnerabilities)
8. [④ Suspicious changes](#8--suspicious-changes)
9. [⑤ Evidence](#9--evidence)
10. [Notes at the bottom](#10-notes-at-the-bottom)
11. [A three-minute demo walkthrough](#11-a-three-minute-demo-walkthrough)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Starting the dashboard

```powershell
cd "C:\Users\VICTUS\Desktop\Bosch Hack\sscg"
streamlit run ui/app.py
```

Streamlit opens **http://localhost:8501**. To stop it, press `Ctrl+C` in the terminal.

---

## 2. How the page works

The dashboard does **not** scan anything itself. It is a viewer on top of the command-line scanner:

```
 [Scan repository] button
         │
         ▼
 python -m sscg scan <repo> --out out/<repo name> [--base X | --no-diff] [--no-vulns] [--offline] [--focus X]
         │      (runs in the background, in the sscg/ folder)
         ▼
 out/<repo name>/  summary.json · graph.json · graph.html · sbom.cdx.json · findings.json · report.md
         │
         ▼
 the page reads these files and draws everything below the button
```

Three consequences:
* **Results appear immediately for repos that were scanned before.** Choosing a repository shows its last saved scan.
* **Changing an option does nothing until you click *Scan repository*.**
* **The dashboard and the command line share results.** A terminal scan shows up here and vice versa.

**Safety:** scanning only reads files. Nothing in the scanned repository is installed, built or executed. For "what changed", the older commit is read with `git archive` into a temporary folder, without checking anything out.

---

## 3. Choosing a repository and scanning

| Control | What it does |
|---|---|
| **Repository** (dropdown) | **sscg-demo-target (ours)**, **nodejs-goof (snyk-labs)** or **juice-shop (OWASP)**, or **Other path...** for any folder. |
| **Repository path** | Filled in for the sample apps; for *Other path...* type or paste a folder. |
| **Vulnerability detection (OSV)** ☑ *(on by default)* | Checks every library version against OSV.dev (name and version only) and fetches CVE, severity and fix details. Off: section ③ stays empty and nothing is red in the graph. |
| **Offline (cache only)** ☐ | Uses only saved API answers in `sscg/.cache/`. All three sample apps are fully cached. |
| **Compare with commit (what changed)** | The older commit to compare with, default `HEAD~1` (the previous commit). Any commit id works, e.g. `bf0e651`. **Empty** = no comparison. The comparison is skipped automatically for repos without history (the two public samples are shallow clones). |
| **Focus graph on package (optional)** | The graph shows only that package, what depends on it and what it depends on. Numbers and findings still cover everything. |
| **Scan repository** | Runs the scan. Spinner: *"Discovering components, building the SBOM and graph, detecting risks..."*. A few seconds for the samples (the first online run takes longer while advisory details are downloaded). |

Messages here:
* **Blue box, "No scan yet for this repository"**: nothing saved yet; click **Scan repository**.
* **Red box with error text**: the scan failed (e.g. a wrong path); the box shows the scanner's error.
* **Yellow box, "This result was produced before risk detection existed"**: an old result; scan again to get sections ③–⑤.

> Results are saved by **folder name**: two different folders with the same name overwrite each other.

---

## 4. Pipeline banner and headline numbers

Right under the controls:

**Repository ✔ → SBOM ✔ → Dependency graph ✔ → Risk detection ✔ → Evidence ✔**

This is the "Expected Outcome (Day 1)" chain from the slide. Below it are six headline numbers:

| Tile | Meaning | demo-target | goof | juice-shop |
|---|---|---|---|---|
| **Components** | everything in the supply chain | 31 | 989 | 1,790 |
| **Vulnerable components** | components with at least one published advisory (section ③) | 16 | 139 | 55 |
| **Suspicious changes** | anomaly findings (section ④) | 25 | 15 | 28 |
| **Critical findings** / **High findings** | findings at that **initial risk** level | 21 / 8 | 24 / 73 | 7 / 29 |
| **New in latest change** | findings that did not exist in the compared commit (hover ⓘ) | 25 | 0* | 0* |

\* No history to compare (shallow clones).

---

## 5. ① Components

*Column 1: "What is in the application?"*

| Tile | Meaning |
|---|---|
| **Components** | libraries + container images + CI actions + files downloaded during builds |
| **Libraries** | npm, PyPI, Maven packages |
| **Direct** / **Transitive** | listed by the developers / pulled in by other libraries |
| **Max depth** | longest chain from the app to a library (1 = direct) |
| **Container images** | distinct images in Dockerfiles, compose files and workflows |
| **CI actions** | distinct GitHub Actions across all workflows |

Below: **Manifests** (every file understood) and **By ecosystem / Resolution**. Resolution says how exact each version is:

| Resolution | Meaning | Exact? |
|---|---|---|
| `lockfile` | read from `package-lock.json`, `yarn.lock` or `poetry.lock` | yes |
| `deps.dev` | resolved by deps.dev from a pinned version | yes |
| `deps.dev-approx` | resolved from a version *range* (lowest match) | approximate |
| `dockerfile` / `compose` / `workflow` | read from that file | yes |
| `sbom` | read from an imported SBOM | as exact as the SBOM |
| `unresolved` | version unknown (e.g. inherited from a Maven parent POM) | no |

---

## 6. ② Supply chain view

*Column 2: "How does it fit together, and where does each piece come from?"* Four tabs.

### 6.1 Tab: Dependency graph

**The interactive graph** (left) is `graph.html`: zoom with the wheel or ➕ ➖, drag to move or rearrange, ⤢ to re-centre, **hover** for details.

| Symbol | Meaning |
|---|---|
| ★ black star | the repository |
| 🟩 green box | a manifest, Dockerfile, compose file or workflow |
| 🟠 / 🔵 / 🟣 dot | npm / PyPI / Maven package |
| ■ blue square | container image |
| ▲ dark triangle | GitHub Action |
| ⚪ grey dot | file downloaded during a build or CI run |
| ◆ diamond | **suspicious**: the component has an anomaly finding (section ④), an install script, or an untrusted origin |
| 🔴 red fill | the version has published advisories (section ③) |
| big node, thick border | direct dependency |
| arrow A → B | "A depends on B" (hover: the requested version range or how it is used) |

**Hovering a component** shows name, version, ecosystem, scope, direct/transitive, depth, number of dependents, resolution, origin, source file, install-script / untrusted-origin flags, image or action facts (registry, tag, digest, pinned, ref), advisory IDs, and its **finding IDs** (e.g. `findings: F-004, F-012`), which you can open in section ⑤.

> Above 600 nodes the graph is trimmed to 2 levels **plus every vulnerable or suspicious component and its path**. Use **Focus graph on package** for a specific corner. Numbers, SBOM and findings always use the full graph.

**Right panel:** legend, **Top blast radius** (packages with the most dependents), **Heaviest direct deps** (direct dependencies that pull in the most packages).

**🔎 Why is this package here?** Type a package name (e.g. `qs`). For each version found: ecosystem, scope, origin, its **finding IDs**, and up to 5 shortest paths from the app. Example for nodejs-goof:
```
goof@1.0.1  →  express@4.12.4  →  qs@2.4.2
goof@1.0.1  →  body-parser@1.9.0  →  qs@2.2.4
goof@1.0.1  →  tap@11.1.5  →  coveralls@3.0.9  →  request@2.88.0  →  qs@6.5.2
```

**Duplicates** (fold-out): packages installed in more than one version.

### 6.2 Tab: SBOM (CycloneDX)

`sbom.cdx.json` in **CycloneDX 1.5**. Tiles: **Format**, **SBOM components** (components + one entry per manifest/Dockerfile/workflow, hence higher than ①), **Dependency entries**, **With hashes**. Then the component types, a **Download** button and a table (type, name, version, scope `required`/`optional`/`excluded`, purl, origin). The caption reminds you that an existing SBOM can also be *consumed*: `python -m sscg scan <repo> --sbom bom.cdx.json`.

### 6.3 Tab: Container images & CI/CD

* **🐳 Container images:** one row per image (registry, repository, tag, digest, `pinned_by_digest`, `official_image`, scope `prod`/`build`/`ci`, `used_in` file:line), plus one line per Dockerfile/compose file with its images, runtime user and build-time downloads.
* **⚙️ CI/CD workflows:** per workflow: triggers, token permissions, and an actions table (action, ref, `pinned_to_sha`, file:line).
* **🌐 Files downloaded during build / CI:** URL, host, scope, file:line.

### 6.4 Tab: Origins

Components per host (`registry.npmjs.org`, `docker.io`, `github.com`, …), npm packages **not** served by the npm registry, and packages with install scripts. These are the *facts*; whether they are a problem is judged in section ④.

---

## 7. ③ Vulnerabilities

*Column 3: known vulnerabilities, their CVE, severity and fix, traced back to their source.*

**Tiles:** Vulnerable components · Advisories (after de-duplicating GHSA/PYSEC/CVE copies of the same issue) · how many components have their **highest** official severity at Critical / High / Medium · **With a fix** (a fixed version is published).

**Filters:** official severity (CRITICAL … UNKNOWN) and direct / transitive.

**Table:** one row per vulnerable component.

| Column | Meaning |
|---|---|
| ID | finding ID (open it in ⑤ for the full evidence) |
| Component / Ecosystem | the vulnerable package version |
| Dependency | `direct` (developers chose it) or `transitive` (pulled in) |
| Severity / CVSS | highest **official** severity among its advisories; CVSS v3 score where a vector is published |
| Advisories | number of distinct advisories |
| CVEs | up to 4 CVE IDs |
| Fix (upgrade to ≥) | lowest version that fixes all its advisories, or `no fix` |
| Introduced via | the **direct dependency** that brings it in (`(direct)` if it is one) |
| Risk | Guardian initial risk (see ⑤) |

**Trace a vulnerable component to its source:** pick one to see its dependency paths and an advisory table (advisory ID, CVEs, severity, CVSS, fixed in, summary, **link to OSV**).

Example (demo target): `F-007 log4j-core@2.14.1` → path `com.acme:notifier → log4j-core@2.14.1` → `GHSA-jfh8-c2jp-5v3q · CVE-2021-44228 · CRITICAL · 10.0 · fixed in 2.15.0`, …

---

## 8. ④ Suspicious changes

*Column 4: supply-chain anomalies, and what changed.*

### What changed

Shown when an older commit was compared:
* **Base → HEAD** with both commit messages (and "+ uncommitted changes" if the working tree differs from HEAD)
* **Author** of HEAD and **first-time contributor: ⚠️ yes / no**
* Tiles: **Files changed**, **Components added / removed / changed**
* **Files** table (A added, M modified, D deleted) and **Components** table (e.g. `lodash@4.17.15 → lodash@4.17.15 · resolved, integrity`: same version, different source and hash)

Without history: *"No base commit compared … anomalies describe the current state only."*

### Anomalies

A line with counts per slide category (Typosquatted package, Unsafe install script, Modified lockfile, Unexpected dependency, Suspicious package update, Untrusted image, Unsafe CI/CD component), then the anomaly table: **ID · Risk · Score · Type · Finding · Location (file:line) · New (🆕)**.

The 19 rules behind it (R01–R19) are listed in the main README §8.2. Examples from the demo target: `crossenv` typosquat + documented malicious package, an install script that collects tokens and hides a URL in base64, lodash with the **same version but a new hash** from an unknown mirror, an untrusted base image with `curl | sh`, a `pull_request_target` workflow that checks out PR code with `write-all` and passes `NPM_TOKEN` to a downloaded script, all by a first-time contributor.

---

## 9. ⑤ Evidence

*Column 5: for every finding, what was detected, which component, dependency path, supporting evidence and initial risk level.*

**Filters:** risk level, category (anomaly / vulnerability), **only new in latest change**.

**Findings table:** every finding (vulnerabilities and anomalies) sorted by initial risk.

**Open a finding:** pick one to see its **evidence card**:

| Line on the card | Answers |
|---|---|
| `F-005 · 🟥 Critical (10.0) · Modified lockfile · 🆕 new in this change` | ID, initial risk, category, newness |
| **What** | what was detected |
| **Component** | which component (ecosystem, scope, direct/transitive, purl) |
| **Where** | file:line (or commit) |
| **Dependency path** | how the component gets into the app |
| **Official severity / Fix available** | vulnerabilities only: CVSS / label and source, upgrade target |
| **Evidence** | file lines with the exact text, advisory records with links, lockfile values before → after, commit (sha, author, message, first-time), decoded hidden strings |
| **Initial risk** | score, level and the reasons that produced it, labelled *"Guardian initial risk (heuristic, 0–10); not a CVSS score"* |
| **Why it matters** | one sentence |
| **Basis** | *verified fact* (e.g. the hash did change) or *heuristic* (e.g. the name looks like a typosquat), plus confidence |

**How the initial risk is computed:** start from the highest CVSS score (vulnerabilities) or the rule's level (anomalies: Critical 9.5, High 8.0, Medium 5.5, Low 3.0), add **+1.0 if new in the latest change**, cap at 10. Level: ≥ 9 Critical, ≥ 7 High, ≥ 4 Medium, ≥ 2 Low, else Info. Exploitability and reachability come on Day 2.

**Downloads:** `findings.json` (machine-readable, all findings) and `report.md` (human-readable). **Show the full evidence report** renders `report.md` inline.

---

## 10. Notes at the bottom

Grey ℹ️ lines report anything unusual, for example:
* `what changed: base revision 'HEAD~1' not found (shallow clone or first commit), change analysis skipped`
* `package.json: no lockfile -> transitive deps resolved via deps.dev (approximate)`
* `graph.html limited to depth 2 + vulnerable paths (1814 nodes); use --focus/--max-depth`
* `OSV unavailable (offline / network): vulnerabilities not checked`
* `detector ... failed: ...`: one detector hit an error; all other results are still valid

---

## 11. A three-minute demo walkthrough

1. **Pick `sscg-demo-target`**, tick **Offline**, keep **Compare with commit = HEAD~1**, click **Scan repository**.
2. **Banner:** *"Repository → SBOM → graph → risk detection → evidence, all done: 41 findings, 25 of them new in the last commit."*
3. **① and ②:** *"31 components across npm, PyPI, Maven, a container image and CI; here is the SBOM and the graph."* Hover a ◆ diamond.
4. **③:** filter Critical, then trace `minimist`: *"a transitive vulnerability, introduced via mkdirp, CVSS 9.8 (CVE-2021-44906); upgrading to ≥ 0.2.4 fixes both advisories."* Show Log4Shell in log4j-core.
5. **④ What changed:** *"A first-time contributor's 'routine dependency refresh' touched 6 files: it added a typosquat, swapped lodash's tarball under the same version, moved to an untrusted base image, and turned CI into a secret-leaking pull_request_target workflow."*
6. **⑤:** tick **Only new**, open **F-005** (lodash hash swap) and **F-001** (install script with the decoded endpoint): *"every claim has a file line, a before/after value or a commit behind it."*
7. Switch to **juice-shop**: *"1,790 components, no lockfile, 16 workflows; GITHUB_TOKEN handed to two unpinned third-party actions."*

---

## 12. Troubleshooting

| What you see | Cause and fix |
|---|---|
| "No scan yet for this repository" | Click **Scan repository**. |
| Red error box | Usually a wrong path; paste the full folder path. |
| Yellow "produced before risk detection existed" | Old result: scan again. |
| Section ③ empty / no red nodes | **Vulnerability detection** was off, or OSV was unreachable (see notes). Tick it, or tick **Offline** for the sample apps. |
| "No base commit compared" | Shallow clone / single commit, or the compare box is empty. Enter a commit id, or fetch history (`git fetch --deepen=1`). |
| New in latest change = 0 | Nothing changed between the two commits, or no comparison ran. |
| Graph looks cut off | Large graphs are trimmed: use **Focus graph on package**. |
| Old results after changing options | Options apply only to the next scan. |
| `streamlit: command not found` | `pip install -r requirements.txt` in `sscg/`. |
