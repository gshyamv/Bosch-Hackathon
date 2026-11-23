# The SSCG Dashboard: What Happens in the UI

This guide walks through the Streamlit dashboard (`sscg/ui/app.py`) from top to bottom. For each part it explains what you see, where the data comes from, and what happens when you click something.

The dashboard covers **Day 1, columns 1–2** of the problem statement: *Discover Components* and *Build the Supply Chain View*. It shows what is in an application and where each piece comes from. It does **not** yet judge risk; that is columns 3–5.

---

## Contents

1. [Starting the dashboard](#1-starting-the-dashboard)
2. [How the page works](#2-how-the-page-works)
3. [Choosing a repository and scanning](#3-choosing-a-repository-and-scanning)
4. [Section ①: Components](#4-section--components)
5. [Section ②: Supply chain view (4 tabs)](#5-section--supply-chain-view)
   - [Tab: Dependency graph](#51-tab-dependency-graph)
   - [Tab: SBOM (CycloneDX)](#52-tab-sbom-cyclonedx)
   - [Tab: Container images & CI/CD](#53-tab-container-images--cicd)
   - [Tab: Origins](#54-tab-origins)
6. [Notes at the bottom](#6-notes-at-the-bottom)
7. [A two-minute demo walkthrough](#7-a-two-minute-demo-walkthrough)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Starting the dashboard

```powershell
cd "C:\Users\VICTUS\Desktop\Bosch Hack\sscg"
streamlit run ui/app.py
```

Streamlit opens **http://localhost:8501** in your browser. To stop it, press `Ctrl+C` in the terminal.

---

## 2. How the page works

The dashboard does **not** scan anything itself. It is a viewer on top of the command-line scanner:

```
 [Scan repository] button
         │
         ▼
 python -m sscg scan <repo> --out out/<repo name> [--osv] [--offline] [--focus X]
         │      (runs in the background, in the sscg/ folder)
         ▼
 out/<repo name>/   summary.json · graph.json · graph.html · sbom.cdx.json
         │
         ▼
 the page reads these files and draws everything below the button
```

Three consequences:

* **Results appear immediately for repos that were scanned before.** Choosing a repository shows its last saved scan from `out/<repo name>/` straight away, without rescanning.
* **Changing an option does nothing until you click *Scan repository*.** The checkboxes and the focus box only take effect on the next scan.
* **The dashboard and the command line share results.** A scan run in the terminal shows up in the dashboard, and the other way round.

**Safety:** scanning only reads files. Nothing in the scanned repository is installed, built or executed.

---

## 3. Choosing a repository and scanning

At the top of the page:

| Control | What it does |
|---|---|
| **Repository** (dropdown) | Pick a sample app: **sscg-demo-target (ours)** or **nodejs-goof (snyk-labs)**. Pick **Other path...** to scan any folder. |
| **Repository path** | Filled in automatically for the two sample apps. For *Other path...*, type or paste a folder path. |
| **Vulnerability overlay (OSV)** ☑ *(on by default)* | Asks OSV.dev which package versions have published security advisories, and colours them red in the graph. Only package names and versions are sent. |
| **Offline (cache only)** ☐ | Uses only the saved answers in `sscg/.cache/`, so nothing goes to the network. Use this when Wi-Fi is unreliable. The two sample apps are fully cached. |
| **Focus on package (optional)** | Type a package name (e.g. `qs`). The graph then shows only that package, everything that depends on it, and everything it depends on. The numbers on the page still describe the whole repository. |
| **Scan repository** button | Runs the scan. A spinner reads *"Discovering manifests, lockfiles, Dockerfiles and workflows..."*. The sample apps take a few seconds (nodejs-goof has ~1,000 packages). |

**Messages you might see here:**

* **Blue box, "No scan yet for this repository. Click Scan repository."** The chosen folder has no saved results yet. Nothing else is shown until you scan.
* **Red box with error text.** The scan failed. The box shows the last part of the scanner's error output, e.g. a path that doesn't exist.

> Results are saved by **folder name**. Two different folders with the same name (e.g. two folders called `app`) overwrite each other's results.

---

## 4. Section ①: Components

*Answers the column 1 question: "What is in the application?"*

### The seven numbers

| Tile | Meaning | sscg-demo-target | nodejs-goof |
|---|---|---|---|
| **Components** | Everything in the supply chain: code libraries, container images, CI actions and files downloaded during builds | 31 | 989 |
| **Libraries** | Code packages only: npm, PyPI, Maven | 25 | 980 |
| **Direct** | Libraries the developers listed themselves (in `package.json`, `requirements.txt`, `pom.xml`) | 13 | 35 |
| **Transitive** | Libraries pulled in by other libraries | 12 | 945 |
| **Max depth** | Longest chain from the app to a library (1 = direct) | 2 | 10 |
| **Container images** | Distinct base and service images found in Dockerfiles, compose files and workflows | 1 | 3 |
| **CI actions** | Distinct GitHub Actions used across all workflows (one action used in 4 workflows counts once) | 3 | 6 |

### The two grey lines under the numbers

* **Manifests:** every file the scanner understood, e.g. `acme-orders@1.0.0 (package.json) | worker (worker/requirements.txt) | Dockerfile (Dockerfile) | ci (.github/workflows/ci.yml)`.
* **By ecosystem / Resolution:** counts per type (`npm 7, pypi 10, maven 8, docker 1, github-actions 3, url 2`) and how each component was found:

| Resolution | Meaning | Exact? |
|---|---|---|
| `lockfile` | read from `package-lock.json`, `yarn.lock` or `poetry.lock` | yes |
| `deps.dev` | resolved through Google's deps.dev service from a pinned version | yes |
| `deps.dev-approx` | resolved from a version *range* (lowest matching version) | approximate |
| `dockerfile` / `compose` / `workflow` | read from that file | yes |
| `sbom` | read from an imported SBOM | as exact as the SBOM |
| `unresolved` | version could not be determined (e.g. inherited from a Maven parent POM) | no |

---

## 5. Section ②: Supply chain view

*Answers the column 2 question: "How does it fit together, and where does each piece come from?"* Four tabs.

### 5.1 Tab: Dependency graph

#### The interactive graph (left)

This is `out/<repo>/graph.html` embedded in the page.

| You can… | How |
|---|---|
| Zoom | mouse wheel, or the ➕ ➖ buttons |
| Move around | drag the background, or the arrow buttons |
| Re-centre | the ⤢ button |
| Rearrange | drag a node; the layout settles itself (physics simulation) |
| See details | **hover** over a node or an arrow |

**What the shapes and colours mean:**

| Symbol | Meaning |
|---|---|
| ★ black star | the repository |
| 🟩 green box | a manifest, Dockerfile, compose file or workflow |
| 🟠 orange dot | npm package |
| 🔵 blue dot | PyPI package |
| 🟣 purple dot | Maven package |
| ■ blue square | container image |
| ▲ dark triangle | GitHub Action |
| ⚪ grey dot | file downloaded during a build or CI run |
| ◆ diamond | npm package that runs an install script, or that is **not** downloaded from the official npm registry |
| 🔴 red fill | package version has published security advisories (only when the OSV overlay is on) |
| big node with thick border | direct dependency |
| arrow A → B | "A depends on B" |

**Hovering a component** shows:
* name and version, ecosystem, scope (`prod`, `dev`, `optional`, `build`, `ci`)
* DIRECT or transitive, its depth, and how many nodes point to it
* how it was resolved, its **origin** (download URL or registry), and the file it was found in
* `INSTALL SCRIPT` / `UNTRUSTED ORIGIN`, if they apply
* for images: registry, tag, digest, `pinned_by_digest`, `official_image`
* for actions: `ref`, `pinned_to_sha`
* for downloaded files: `host`
* with the OSV overlay: number of advisories and the first six advisory IDs

**Hovering a green box** shows the file path. Workflows also show their triggers and permissions; Dockerfiles show the number of stages and the runtime user.

**Hovering an arrow** shows the version range that was requested, e.g. `^1.2.0`, or for containers and CI how it is used, e.g. `FROM, stage 1 (final)`.

> **Large graphs are trimmed.** Above 600 nodes, the graph shows only the first 2 levels, plus every package with advisories and its full path. nodejs-goof is trimmed this way; a note at the bottom of the page says so. To see a particular corner, use **Focus on package** and scan again. The numbers, the SBOM and the "Why" search always use the full graph.

#### The panel on the right

* **Legend:** the symbol key above, in short form.
* **Top blast radius:** the packages with the most other packages depending on them, directly or indirectly. In nodejs-goof, 76 packages sit on top of `inherits@2.0.3`, so a problem in it reaches all of them.
* **Heaviest direct deps:** the direct dependencies that pull in the most other packages. In nodejs-goof, `tap` alone brings in 345.

#### 🔎 "Why is this package here?" (below the graph)

Type a package name (default `minimist`, the name only, no version) and press Enter.

* The dashboard searches the **full** graph (`graph.json`) for that name, ignoring upper/lower case.
* For **each version** found, it shows the version, ecosystem, scope and origin, followed by up to **5 shortest paths** from the application to that package.
* If nothing matches, it shows *"Not in the graph"*.

Example for `qs` in nodejs-goof: three versions, three different parents.
```
goof@1.0.1  →  express@4.12.4  →  qs@2.4.2
goof@1.0.1  →  body-parser@1.9.0  →  qs@2.2.4
goof@1.0.1  →  tap@11.1.5  →  coveralls@3.0.9  →  request@2.88.0  →  qs@6.5.2
```

#### Two fold-out panels

* **Dependency paths to packages with published advisories (N):** appears only if the OSV overlay found something. One row per affected package: name, depth, number of advisories and the path from the app, deepest first. This is a preview of column 3.
* **Duplicates: same package in several versions (N):** packages installed in more than one version, e.g. nodejs-goof has `ms` in 7 versions.

---

### 5.2 Tab: SBOM (CycloneDX)

The Software Bill of Materials written by the scan: `out/<repo>/sbom.cdx.json`, in the **CycloneDX 1.5** standard format.

| Tile | Meaning |
|---|---|
| **Format** | `CycloneDX 1.5` |
| **SBOM components** | All components **plus** one entry per manifest, Dockerfile and workflow (hover the ⓘ for this explanation). That's why it is higher than *Components* in section ① (36 vs 31 for the demo target). |
| **Dependency entries** | One "depends on" list per item, including the repository itself |
| **With hashes** | Components that carry a cryptographic hash (from lockfile integrity values or image digests) |

Below the tiles:

* **Component types:** e.g. `library 25, application 8, file 2, container 1`. Libraries are packages, containers are images, applications are CI actions and the manifest entries, and files are downloads.
* **Download sbom.cdx.json:** saves the SBOM as `<repo name>.cdx.json`, ready for other tools (Dependency-Track, Grype, …).
* **Component table:**

| Column | Meaning |
|---|---|
| type | `library`, `container`, `application`, `file` |
| name / version | as recorded |
| scope | `required` (runtime), `optional`, `excluded` (dev, test, build or CI only) |
| purl | the standard package identifier, e.g. `pkg:npm/qs@2.4.2` |
| origin | where it is downloaded from |

* **Consume an existing SBOM:** a reminder that the scanner can also *read* an SBOM made elsewhere, instead of scanning files. This is the "consume" half of the column 2 requirement:
  `python -m sscg scan <repo> --sbom bom.cdx.json`

---

### 5.3 Tab: Container images & CI/CD

Column 2 asks to *"inspect at least one container image or CI/CD workflow"*. This tab shows both. Everything is read from the files; no image is pulled and no workflow is run.

#### 🐳 Container images

A table with one row per distinct image:

| Column | Meaning | Example |
|---|---|---|
| image | short name and tag | `fastbuilds42/node:latest` |
| registry | where it is pulled from | `docker.io` |
| repository | full repository path | `fastbuilds42/node` |
| tag | version label (`latest` if none was given) | `latest` |
| digest | content hash, if the image is pinned to one | — |
| pinned_by_digest | **true** = always the same image; **false** = the tag can point to a different image tomorrow | false |
| official_image | **true** = a Docker Official Image (`docker.io/library/...`) | false |
| scope | `prod` = the image that ships, `build` = an earlier build stage, `ci` = used in a workflow | prod |
| used_in | every file and line that uses it | `Dockerfile:1` |

Under the table there is one line per Dockerfile or compose file: the images it uses, which **user** the container runs as (or "not set (inherits the base image default)"), and any **files downloaded during the build** (e.g. `RUN curl http://…/bootstrap.sh`).

If the repository has no Dockerfile or compose file: *"No Dockerfile or compose file found."*

#### ⚙️ CI/CD workflows

For each workflow file in `.github/workflows/`:

* **Header line:** file, workflow name, **triggers** (what starts it: `push`, `pull_request`, `pull_request_target`, `schedule`, …) and **permissions** (what the workflow's token may do: e.g. `write-all`, or "not set (repository default)").
* **Actions table:**

| Column | Meaning |
|---|---|
| action | exactly as written, e.g. `actions/checkout@v4` |
| ref | the version reference after `@` |
| pinned_to_sha | **true** = pinned to a full commit hash, which can never change; **false** = a tag or branch, which its owner can move |
| source | file and line of this use |

* A grey line lists any job container images or files downloaded in `run:` steps.

If there are no workflows: *"No GitHub Actions workflow found."*

#### 🌐 Files downloaded during build / CI

Shown only if something is downloaded: one row per URL with its host, scope (`prod`, `build` or `ci`) and the file and line it comes from.

---

### 5.4 Tab: Origins

*"Identify where each component originates"* (column 2).

* **Where components come from:** a table of hosts and how many components come from each, e.g. `registry.npmjs.org 6`, `github.com 3`, `docker.io 1`, `npm-mirror.example.invalid 1`.
* **npm packages not served by the npm registry:** listed only if any exist, e.g. `lodash@4.17.15 <- https://npm-mirror.example.invalid/...`.
* **Packages with install scripts:** listed only if any exist. These packages run their own code when installed (`hasInstallScript` in the lockfile), e.g. `crossenv@7.0.3`.

> These are **facts**, not verdicts. Deciding whether a mirror, an install script or an unpinned action is actually a problem is column 4 (*Detect Suspicious Changes*), which comes next.

---

## 6. Notes at the bottom

Small grey ℹ️ lines at the very bottom report anything unusual from the scan, for example:

* `graph.html limited to depth 2 + vulnerable paths (997 nodes); use --focus/--max-depth`
* `worker/requirements.txt: ...` or `no lockfile -> transitive deps resolved via deps.dev (approximate)`
* `OSV unavailable (offline / network)`: the overlay could not run, so no node is red
* `error in <file>: ...`: one file could not be read; the rest of the scan still completed

---

## 7. A two-minute demo walkthrough

1. **Pick `nodejs-goof`**, tick **Offline**, click **Scan repository**.
2. **Section ①:** *"The developers chose 35 packages; the app ships 980, 96% of them transitive and up to 10 levels deep."*
3. **Dependency graph tab:** hover a red node, then point at **Top blast radius** (`inherits` sits under 76 packages).
4. **Why is this package here?** Type `qs`: *"Nobody installed qs, yet three versions ship, each through a different parent."*
5. **SBOM tab:** *"Every scan produces a standard CycloneDX SBOM"*, then click **Download**.
6. **Container images & CI/CD tab:** three images, none pinned by digest; six actions, none pinned to a commit.
7. **Switch to `sscg-demo-target`**, then the **Container images & CI/CD** and **Origins** tabs: the untrusted base image `fastbuilds42/node:latest`, the `curl` downloads, a workflow with `write-all` permissions and `pull_request_target`, lodash from an unofficial mirror, and `crossenv` with an install script. *"Day 1 shows all of this; columns 3–5 will flag it."*

---

## 8. Troubleshooting

| What you see | Cause and fix |
|---|---|
| "No scan yet for this repository" | No saved results for that folder. Click **Scan repository**. |
| Red error box after scanning | Read the message. Usually a wrong path. For *Other path...*, paste the full folder path. |
| No red nodes | The OSV box was unticked, or the network was unavailable (see the notes at the bottom). Tick it and scan again; tick **Offline** for the sample apps. |
| Graph looks cut off | Large graphs are trimmed above 600 nodes. Use **Focus on package**. |
| Old results after changing options | Options apply only to the next scan. Click **Scan repository**. |
| Graph is blank for a moment | The layout is still settling; wait a few seconds, or use the ⤢ button. |
| `streamlit: command not found` | Install the requirements: `pip install -r requirements.txt` (run in `sscg/`). |
