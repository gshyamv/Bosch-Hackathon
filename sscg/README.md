# Software Supply Chain Guardian (SSCG): Day 1, pillars 1–2

This code covers the first two Day 1 pillars from the problem statement:

| Pillar | Requirement | Where |
|---|---|---|
| **1 Discover components** | Analyze package manifests and lockfiles | `sscg/discover/npm.py`, `pypi.py`, `maven.py` |
| | Identify direct and transitive dependencies | lockfiles; deps.dev when there is no lockfile (`discover/depsdev.py`) |
| | Capture component names and versions | every node in `graph.json` / component in `sbom.cdx.json` |
| **2 Build the supply chain view** | Generate **or** consume an SBOM (CycloneDX or SPDX) | `sscg/sbom.py`: **both**, CycloneDX 1.5 JSON |
| | Build the dependency graph | `sscg/graph.py`, `sscg/export.py` → `graph.html`, `graph.json` |
| | Identify where each component originates | `resolved` URL / registry per component, "Origins" tab |
| | Inspect at least one container image **or** CI/CD workflow | **both**: `discover/docker.py` (Dockerfile, compose), `discover/gha.py` (GitHub Actions) |

Pillars 3–5 (vulnerability details, suspicious-change detection, evidence and risk level) are not part of this step. The optional `--osv` flag only marks packages that have published advisories, as an overlay on the graph.

## Safety

Scanning is **static**. The tool only reads files. It never runs `npm install`, `pip install`, `mvn`, `docker build` or a workflow. Network access goes only to two public APIs: deps.dev (resolution) and OSV.dev (`--osv`). Every response is cached in `.cache/`, so `--offline` works.

## Setup (Windows PowerShell)

```powershell
cd sscg
python -m venv .venv; .\.venv\Scripts\Activate.ps1     # optional
pip install -r requirements.txt
```
Requirements: Python 3.11+ (developed on 3.12.4). Node, npm and Docker are **not** needed to scan.

## Usage

```powershell
# scan a repository -> out/<repo>/
python -m sscg scan ..\targets\sscg-demo-target
python -m sscg scan ..\targets\nodejs-goof --osv --why qs

# consume an existing CycloneDX SBOM (from sscg, Syft, cdxgen ...) instead of scanning
python -m sscg scan ..\targets\nodejs-goof --sbom path\to\bom.cdx.json --out out\goof-from-sbom

# dashboard
streamlit run ui/app.py
```

| Flag | Meaning |
|---|---|
| `--sbom FILE` | consume a CycloneDX JSON SBOM instead of scanning manifests |
| `--osv` | mark packages that have published advisories (OSV.dev) |
| `--offline` | answer API calls from `.cache/` only |
| `--why NAME ...` | print the dependency paths that pull in a package |
| `--focus NAME` | `graph.html` shows only that package's ancestors and descendants |
| `--max-depth N` | `graph.html` shows only N levels (large graphs are cut to 2 automatically) |
| `--out DIR` | output folder (default `out/<repo name>`) |

## Outputs (`out/<repo>/`)

| File | Content |
|---|---|
| `sbom.cdx.json` | CycloneDX 1.5 SBOM. Every component, with purl, version, scope, hashes (from lockfile integrity / image digest), download URL, and the full `dependencies` graph. |
| `graph.json` | Nodes and edges with all attributes (input for later pillars) |
| `graph.html` | Interactive graph; works offline (vis.js is embedded) |
| `graph.mmd` | Mermaid diagram (small graphs only) |
| `summary.json` | Counts, depth, origins, duplicates, blast radius, container and CI inventory, paths |

### What goes into the SBOM

| Component | CycloneDX type | Identity | Origin |
|---|---|---|---|
| npm / PyPI / Maven package | `library` | `pkg:npm/…`, `pkg:pypi/…`, `pkg:maven/…` | lockfile `resolved` URL |
| Container base image | `container` | `pkg:docker/<repo>@<tag or digest>?repository_url=<registry>` | `docker://<registry>/<repo>` |
| GitHub Action | `application` | `pkg:github/<owner>/<repo>@<ref>` | `https://github.com/<owner>/<repo>` (vcs) |
| File downloaded in a build or CI step | `file` | its URL | the URL |
| Manifest / Dockerfile / workflow | `application` | `app:<path>` | — |

Scope: `required` = runtime, `optional` = optional dependencies, `excluded` = dev/test/build/CI only. Facts that CycloneDX has no field for are kept as `sscg:*` properties (e.g. `sscg:direct`, `sscg:depth`, `sscg:source`, `sscg:pinned_to_sha`, `sscg:pinned_by_digest`, `sscg:runs_as`). A lockfile integrity value that is not a well-formed hash is not emitted as a hash. It is kept as `sscg:integrity_malformed`.

### What the container and CI inspection records

* **Dockerfile:** every `FROM` image (registry, repository, tag, digest, official Docker Hub image or not, build stage vs final runtime stage), `ARG` substitution, files fetched with `RUN curl/wget` or `ADD <url>`, and the final `USER`.
* **docker-compose:** the image of every service.
* **GitHub Actions:** triggers, `permissions`, every `uses:` action with its ref and whether it is pinned to a commit SHA, job container and service images, and files fetched in `run:` steps. Each use keeps its own `file:line`.

## Verification (done on both targets)

| Check | sscg-demo-target | nodejs-goof |
|---|---|---|
| Matches blueprint ground truth §7.1 (components, image, CI actions) | ✅ | n/a |
| SBOM validates against the official CycloneDX 1.5 JSON schema | ✅ 0 errors | ✅ 0 errors |
| Round-trip: generate → consume → identical graph (nodes, edges, attributes) | ✅ | ✅ |
| Same dependency graph as the previous builder (`archive/depgraph-v0`) | ✅ 0 diffs | ✅ 0 diffs |

## Layout

```
sscg/
├── README.md, requirements.txt
├── sscg/
│   ├── __main__.py        CLI: python -m sscg scan <repo>
│   ├── model.py           DepGraph (repo -> manifest -> component -> component)
│   ├── cache.py           cached HTTP (deps.dev, OSV) for offline use
│   ├── discover/          ① npm.py, pypi.py, maven.py, depsdev.py  ② docker.py, gha.py
│   ├── sbom.py            ② CycloneDX 1.5 writer + reader
│   ├── graph.py           ② depth, paths ("why"), origins, inventory, summary
│   ├── export.py          ② graph.html / graph.json / graph.mmd
│   └── vulns.py           OSV overlay (--osv)
├── ui/app.py              Streamlit dashboard
├── .cache/                cached API responses
└── out/<repo>/            scan results
```

## Known limitations

* Workflows: GitHub Actions only (no GitLab CI, Jenkins, Azure Pipelines).
* Container images are inspected from the Dockerfile and compose files, not pulled. OS packages *inside* an image are not listed (that needs Syft or Trivy on a pulled image).
* PyPI `requirements.txt` and Maven transitive dependencies come from deps.dev. They are marked `deps.dev` (pinned) or `deps.dev-approx` (version range). Maven versions inherited from a parent POM show as `managed-by-parent` (`resolution: unresolved`).
* npm peer dependencies are not drawn as edges.
* Foreign SBOMs carry no `sscg:` hints. Their GitHub Actions arrive as plain `pkg:github` components and are counted as libraries.
