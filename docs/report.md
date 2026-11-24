# Dependency Graph: Progress Report

**Project:** Software Supply Chain Guardian (Bosch Hackathon)
**Milestone:** dependency graph
**Date:** 23 Nov 2026
**Status:** Graph delivered and checked. Only the GitHub push is left.

> **Update:** the code has moved. Pillars 1–2 (including SBOM generate/consume and container + CI/CD inspection) now live in **`sscg/`**. See **`sscg/README.md`** for setup, usage, outputs and verification. The paths below (`Bosch/graph/...`, `dependency/...`) describe the earlier layout: the old builder is in `archive/depgraph-v0/`, the target repos are in `targets/`, and the screenshots are in `docs/screenshots/`.

---

## 1. Summary

The goal was a dependency graph that shows what is inside an application, how each package got there, and where the risk sits.

We built it in two ways and checked one against the other:

1. **A simple pipeline** (`npm ls` → Python → interactive HTML). It was written from scratch to follow the original plan.
2. **The team's full builder** (`Bosch/graph/depgraph.py`). We ran it on the new target repo with a vulnerability overlay and added it to the Streamlit dashboard.

Both builders report the same package counts for the target repo `snyk-labs/nodejs-goof`. The headline numbers:

| Metric | Value |
|---|---|
| Total packages | **980** (752 unique names) |
| Direct dependencies | **35** (32 prod + 3 dev, which matches `package.json`) |
| Transitive dependencies | **945**: 96% of the app is code nobody chose directly |
| Dependency edges | 1,648 |
| Max depth | **10** levels |
| Vulnerable packages (OSV.dev) | **139**, with 317 advisories in total |
| Vulnerable direct dependencies | 19 of 35 |
| Deepest vulnerable path | 8 levels (`goof → tap → nyc → micromatch → snapdragon → base → cache-base → union-value → set-value`) |
| Packages with install scripts | `core-js`, `fsevents`, `kerberos`, `nodemon` |
| Packages in several versions | 148 (e.g. `ms` ×7, `debug` ×6, `readable-stream` ×6, `lodash` ×4) |
| Build time | ~4 s online, under 1 s when served from the cache |

---

## 2. Tech stack

| Layer | Tool / version | What it is used for |
|---|---|---|
| OS / shell | Windows 11, PowerShell 7, Git Bash | Development environment |
| Source control | git 2.44.0 | Cloning target repos (`--depth 1`) |
| JS runtime | Node.js 20.17.0, npm 10.8.2 | Resolving the npm tree without installing it (`--package-lock-only`, `--ignore-scripts`) |
| Language | Python 3.12.4 | All graph code |
| Graph model | networkx 3.4.2 | Directed graph, shortest paths, depth, blast radius, cycle detection |
| Visualisation | pyvis 0.3.2 (vis-network) | Interactive HTML graph; vis.js is embedded, so it works offline |
| Dashboard | Streamlit 1.42.0 | "Dependency Graph" tab: metrics, graph, "Why is X here?", vulnerable paths |
| HTTP | requests | Calls to OSV and deps.dev, cached on disk in `graph/.cache/` |
| Vulnerability data | OSV.dev API | Advisories per package version (the red nodes) |
| Non-npm resolution | deps.dev API | Transitive dependencies for PyPI and Maven when there is no lockfile |
| Testing | `streamlit.testing.v1.AppTest` | Headless test of the dashboard on both demo repos |
| Screenshots | Microsoft Edge (headless) | Backup images in case the live demo fails |

---

## 3. What was done, step by step

### Step 1: Set up and clone the target repo
- Checked the toolchain. Node, npm, Python, git, networkx and pyvis were already installed.
- Cloned `snyk-labs/nodejs-goof` into `dependency/nodejs-goof`. It is a deliberately vulnerable Express app, a good stand-in for a real-world app.

### Step 2: Get the full dependency tree, safely
```powershell
cd dependency\nodejs-goof
npm install --package-lock-only --ignore-scripts
npm ls --all --json --package-lock-only > tree.json
```
- `--ignore-scripts` means no third-party code ran on our machine.
- **Change from the original plan:** we added `--package-lock-only` to `npm ls`. Without it, npm checks `node_modules`, which we never install, so every package shows as "missing".

### Step 3: Simple graph (`dependency/build_graph.py`)
- Reads `tree.json` and builds a networkx `DiGraph` keyed by `name@version`, so a package npm de-duplicates appears once and has many parents.
- Colors: **red** = app, **blue** = direct, **orange** = transitive. Node size = number of packages that depend on it. Hover shows depth, parents and children.
- `--trace <pkg>` prints every path from the app to that package.
- Output: `dependency/graph.html`.

```powershell
python build_graph.py nodejs-goof/tree.json -o graph.html --trace qs
```

### Step 4: Full graph with vulnerabilities (`Bosch/graph/depgraph.py`)
```powershell
cd Bosch\graph
python depgraph.py ..\..\dependency\nodejs-goof --out out\nodejs-goof --osv --why qs lodash express
```
On top of the simple graph, this adds:
- the origin of every package (`resolved` URL), its integrity hash and its scope (prod/dev/optional);
- OSV vulnerabilities, with vulnerable nodes in **red**;
- the deepest vulnerable paths, blast radius, the direct dependencies that pull in the most packages, duplicates, and install scripts;
- `graph.json` (machine-readable, for the agent and SBOM work) and `summary.json`.

### Step 5: Cross-check the two builders

| | build_graph.py | depgraph.py |
|---|---|---|
| Packages | 980 | 980 |
| Direct / transitive | 35 / 945 | 35 / 945 |
| Max depth | 10 | 10 |
| Edges | 1,649 | 1,648 |

The edge difference is fully explained. `npm ls` lists **peer dependencies** as children, so `build_graph.py` has 2 extra edges: `dustjs-helpers → dustjs-linkedin` and `acorn-dynamic-import → acorn`. `depgraph.py` leaves peer dependencies out but adds one `repo → app` edge (1,649 − 2 + 1 = 1,648). Every other edge is the same in both.

**About the 212 packages with no origin URL:** this is expected. They are **bundled** dependencies that ship inside `nyc`'s own tarball (`"inBundle": true` in the lockfile), so they have no download URL of their own.

### Step 6: Offline check
- We rebuilt both repos with `--offline`, which uses only the cache. The results were identical: 980 packages and 139 vulnerable for goof; 25 packages and 16 vulnerable for the demo target. **The demo does not need Wi-Fi.**
- `graph.html` embeds vis.js, so the graph itself renders with no internet. Only cosmetic Bootstrap CSS comes from a CDN.

### Step 7: Dashboard fixes (`Bosch/graph/app.py`)
- **Bug fixed:** the default repo path pointed to `Desktop\Bosch\...`, a folder that no longer exists.
- Added a **demo repo picker** (`sscg-demo-target` / `nodejs-goof` / other path).
- `depgraph.py` and `out/` are now found relative to `app.py`, so `streamlit run` works from any folder.
- **Tested headless** with Streamlit `AppTest` on both repos: no exceptions, and the metrics match the command-line output.

```powershell
cd Bosch\graph
streamlit run app.py
```

### Step 8: Backup screenshots
Saved in `Bosch/graph/out/screenshots/`:

| File | Shows |
|---|---|
| `goof_full_graph.png` | Full goof graph, vulnerable nodes in red |
| `goof_focus_qs.png` | **Demo slide:** the 3 paths from the app to `qs`, all vulnerable |
| `goof_simple_graph.png` | Simple graph: direct vs transitive |
| `demo_target_graph.png` | Our own demo repo |

![qs focus](Bosch/graph/out/screenshots/goof_focus_qs.png)

---

## 4. Key finding for the presentation: trace one path

The first plan used the example `my-app → express → body-parser → qs`. **That path does not exist in this repo.** `express@4.12.4` is older than the versions that use body-parser, and it depends on `qs` directly. The graph shows **three versions of `qs`, each brought in by a different parent:**

```
goof → express@4.12.4 → qs@2.4.2                              (4 advisories)
goof → body-parser@1.9.0 → qs@2.2.4                           (3 advisories)
goof → tap@11.1.5 → coveralls@3.0.9 → request@2.88.0 → qs@6.5.2  (3 advisories)
```

**Talking point:** "Nobody on this team ever installed `qs`, yet three vulnerable copies of it ship in the app. The graph tells us the fix: upgrade `express`, `body-parser` and `tap`, not `qs`."

Other numbers worth quoting:
- **Blast radius:** `inherits@2.0.3` sits under 76 packages, and `safe-buffer@5.1.2` under 63.
- **Heaviest direct dependencies:** `tap` brings in +345 packages, `snyk` +325, `browserify` +141.
- **Dev dependencies matter too:** 45 of the 139 vulnerable packages are dev-only, i.e. a risk to the build pipeline rather than to production.

---

## 5. 4 PM acceptance checklist

| Item | Status |
|---|---|
| One command builds the graph for every repo | ✅ `depgraph.py` (tested on 6 repos, including goof) |
| `graph.html` opens offline; legend; direct vs transitive visible | ✅ |
| Every node has version, depth, scope, origin, source, resolution | ✅ (bundled dependencies have no origin URL, as expected) |
| "Why is X here?" works live | ✅ CLI `--why` and the Streamlit search box |
| Vulnerable nodes red; at least one multi-level vulnerable path | ✅ 8-level path |
| Stats ready to quote | ✅ Section 4 |
| Untrusted origin and install script flagged on the demo repo | ✅ `lodash` from `npm-mirror.example.invalid`; install scripts listed |
| Outputs pre-generated, `--offline` tested, screenshots | ✅ |
| Code and `out/` pushed to GitHub | ⏳ **Not done.** Needs the team's repo URL and a go-ahead |

---

## 6. File map

```
Bosch Hack/
├── report.md                          ← this file
├── dependency/
│   ├── build_graph.py                 ← simple builder (new)
│   ├── graph.html                     ← simple graph of nodejs-goof
│   └── nodejs-goof/                   ← cloned target (never installed or run)
│       └── tree.json                  ← npm ls output
└── Bosch/
    ├── blueprint.md, graph_blueprint.md
    ├── sscg-demo-target/              ← our planted-risk demo repo
    └── graph/
        ├── depgraph.py                ← full builder
        ├── app.py                     ← Streamlit dashboard (fixed)
        ├── .cache/                    ← cached OSV and deps.dev responses
        └── out/
            ├── nodejs-goof/           ← graph.html, graph.json, summary.json
            ├── nodejs-goof-focus-qs/  ← focused view for the demo
            ├── sscg-demo-target/
            └── screenshots/
```

---

## 7. Next steps

1. **Push to GitHub:** code, `out/` and this report. Needs the repo URL.
2. **Rehearse** the two-minute demo script (`graph_blueprint.md` §9), using `goof_focus_qs.png` as the "trace one path" moment.
3. **Stretch goals,** in order of value (from `graph_blueprint.md` §12):
   1. **Graph diff (base vs head):** color added and changed nodes, to answer "what changed" right on the graph.
   2. **CycloneDX export** from `graph.json`, which covers the SBOM pillar.
   3. **Severity colors** (critical / high / medium) instead of plain red.
   4. **Agent tools:** expose `why(pkg)` and `blast_radius(pkg)` to the Claude agent.
