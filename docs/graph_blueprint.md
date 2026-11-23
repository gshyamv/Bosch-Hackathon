# Dependency Graph: Blueprint for the 4 PM Checkpoint

> **Deliverable:** a dependency graph for *any* repository the team picks. It shows what is in the application, how each component got there, and where risk sits in the graph.
> **Status at 13:51:** a working, tested builder already exists at **`graph/depgraph.py`**. The rest of today is about **running it on the team's repos, putting it in the UI, and rehearsing.** Don't rewrite it.

---

## 0. TL;DR: what to do right now

```powershell
cd C:\Users\VICTUS\Desktop\Bosch\graph
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install networkx pyvis requests streamlit
python depgraph.py ..\sscg-demo-target --out out\demo --osv --why minimist follow-redirects
start out\demo\graph.html          # opens the interactive graph in the browser
```
Then each teammate runs it on the repos they found (section 5) and reports back with the intake card (section 6).

### Already tested on 5 repos
| Repo | Ecosystem / input | Manifests | Packages | Direct | Max depth | Vulnerable pkgs | Time | Resolution |
|------|-------------------|-----------|----------|--------|-----------|-----------------|------|------------|
| `sscg-demo-target` (ours) | npm lock v3 + requirements.txt + pom.xml | 3 | 25 | 13 | 2 | 16 | 3 s | lockfile + deps.dev |
| `OWASP/NodeGoat` | npm lock **v1** | 1 | **1,091** | 36 | **13** | 131 | 5 s | 100% lockfile |
| `juice-shop/juice-shop` | package.json **without lockfile** | 2 | 1,754 | 155 | 9 | 55 | 84 s | deps.dev (approx) |
| `adeyosemanputra/pygoat` | 24 × requirements.txt | 25 | 99 | 59 | 3 | 36 | 37 s | deps.dev |
| `snyk-labs/java-goof` | 8 × pom.xml (multi-module) | 8 | 59 | 37 | 3 | 16 | 13 s | deps.dev; 9 versions come from a Spring parent POM ("unresolved") |

Second runs are instant because every API call is cached in `graph/.cache/`, and `--offline` works.

---

## 1. What the judges need to see (slide pillar 2, with a preview of pillar 3)

| Slide requirement | Where the graph shows it |
|-------------------|--------------------------|
| "Build the dependency graph" | `graph.html` (interactive) and `graph.json` (machine-readable) |
| "Identify direct and transitive dependencies" | Big nodes with a thick border are **direct**; small nodes are transitive; every node has a `depth` |
| "Identify where each component originates" | Each node's tooltip shows `origin` (the `resolved` URL) and its `source` manifest:line. Non-registry origins are drawn as ◆ diamonds |
| "Trace vulnerable transitive dependencies back to their source" | Vulnerable nodes are **red**, and `summary.json → vulnerable_paths` gives e.g. `acme-orders → mkdirp → minimist` |
| "Show what is in the application" | `summary.json`: apps, counts per ecosystem, direct vs transitive, depth histogram |

**Insights that make the graph more than a picture (all computed already):**
- **Why is X here?** The k shortest dependency paths from the app to any package (`--why minimist`).
- **Blast radius:** how many packages depend on X, directly or transitively. NodeGoat: `inherits@2.0.3` sits under 105 packages.
- **Heaviest direct dependencies:** how many packages each direct dependency brings in. NodeGoat: `grunt-if` brings in +386.
- **Duplicates:** the same package at several versions (198 in NodeGoat).
- **Cycles,** plus **depth histogram:** "36 direct deps turn into 1,091 packages, 13 levels deep."
- **Untrusted origins and install scripts.** NodeGoat: `grunt-if` is fetched from a **GitHub tarball**, not the registry. Demo repo: `lodash` comes from `npm-mirror.example.invalid`, and `crossenv` has an install script.

---

## 2. Graph data model (the contract for UI, agent and Day-2 code)

```
repo:<name>  ──▶  app:<manifest path>  ──▶  pkg:<purl>  ──▶  pkg:<purl> ...
 (★ star)          (green box, one per manifest)      (dot, coloured by ecosystem)
```

**Node `id`** = Package URL (purl), the same id CycloneDX uses as `bom-ref`:
`pkg:npm/lodash@4.17.15`, `pkg:pypi/pyyaml@5.3`, `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1`

| Node attribute | Example | Meaning |
|----------------|---------|---------|
| `kind` | `repo` / `app` / `package` | Layer |
| `ecosystem`, `name`, `version`, `label` | `npm`, `minimist`, `0.0.8`, `minimist@0.0.8` | Identity |
| `direct` | `true` | Declared in a manifest |
| `depth` | `2` | 1 = direct; shortest distance from the app |
| `dependents` | `1` | In-degree (direct parents) |
| `scope` | `prod` / `dev` / `optional` / `test` / `build` | Where it's used |
| `source` | `package-lock.json`, `worker/requirements.txt:4` | Evidence: which file declared it |
| `resolved`, `integrity` | `https://registry.npmjs.org/...tgz`, `sha512-...` | **Origin**, plus a hash for Day-1 tamper checks |
| `install_script` | `true` | npm `hasInstallScript` |
| `resolution` | `lockfile` / `deps.dev` / `deps.dev-approx` / `sbom` / `unresolved` / `internal-module` | **How confident we are.** Say this out loud: honesty scores points |
| `vulns` | `["GHSA-…", …]` | OSV advisory IDs (with `--osv`) |

**Edge** `parent → child` with `spec` = the requested version range (`^1.10.0`).

**Files written to `--out`:**
| File | Use |
|------|-----|
| `graph.json` | `{"nodes":[{id, ...attrs}], "edges":[{source, target, spec}]}` for Streamlit and the AI agent tools |
| `graph.html` | Interactive pyvis graph with JS inlined, so it works offline and inside Streamlit |
| `graph.mmd` | Mermaid text, only for graphs ≤ 80 nodes; paste into README or slides |
| `summary.json` | All stats, vulnerable paths, `why` answers, notes |

---

## 3. How each ecosystem is resolved (and how accurate it is)

| Input found | Strategy | Accuracy | Network |
|-------------|----------|----------|---------|
| `package-lock.json` v2/v3 / `npm-shrinkwrap.json` | Parse `packages` and apply **Node's real resolution rule**: look in `parent/node_modules/dep` first, then walk up the tree | **Exact** | None |
| `package-lock.json` v1 (old repos, e.g. NodeGoat) | Recurse into nested `dependencies`; resolve `requires` innermost-scope-first | **Exact** | None |
| `yarn.lock` v1 | Parse `name@range` blocks; edges via `dep@range` lookups | **Exact** | None |
| `yarn.lock` berry / pnpm / **no lockfile** | deps.dev resolves each direct dep at the range's lower bound (`^4.17` → `4.17.0`) | **Approximate** (labelled `deps.dev-approx`) | deps.dev |
| `requirements*.txt` (follows `-r`) | Pinned `==` → deps.dev exact graph; `>=`/`~=` → lower bound; unpinned → latest | Good / approx | deps.dev |
| `poetry.lock` (+ `pyproject.toml` for direct deps) | Full graph from the lockfile | **Exact** | None |
| `pom.xml` (multi-module) | Resolves `${properties}`, `${project.version}` and `<dependencyManagement>`; same-groupId deps become `internal-module`; transitive deps via deps.dev | Good; parent-BOM versions stay `unresolved` | deps.dev |
| Any CycloneDX JSON SBOM (`--sbom`) | Components + `dependencies` section (from Syft, cdxgen or GitHub's SBOM export) | As good as the SBOM | None |

`node_modules`, `.git`, `venv`, `target`, `dist`, `build` and `vendor` folders are skipped, and a broken manifest becomes a `note` instead of a crash.

**Security hardening (a good point to tell judges):** the repos we scan may be hostile. A tampered lockfile can put `</script><script>…` into a "version" field. `graph.html` therefore uses numeric node ids and replaces `<`, `>` and `&` in every label, tooltip and edge text, so a malicious repo can't run script in our dashboard. The scanner also never executes repo code.

**Key algorithms (for when a judge asks "how?")**
- **npm resolution:** `resolve(parent_key, dep)` checks `parent/node_modules/dep`, then strips one `/node_modules/x` level and retries up to the root. This is exactly how Node finds modules, so hoisted and nested duplicate versions come out right.
- **Why is X here:** `nx.shortest_simple_paths(G, repo, X)` (Yen's k-shortest paths), first 5.
- **Blast radius:** `|ancestors(X) ∩ packages|`. **Heaviest direct dep:** `|descendants(d)|`.
- **Big-graph view:** over 600 nodes, `graph.html` shows depth ≤ 2 **plus every vulnerable node and its path**, so red nodes are never hidden. `graph.json` always holds the full graph. `--focus X` shows X's ancestors and descendants only.

---

## 4. Commands (cheat sheet)

Run these **from `C:\Users\VICTUS\Desktop\Bosch\graph`** so the `.cache` is reused.

```powershell
# Full graph + vulnerability overlay
python depgraph.py <repo> --out out\<name> --osv

# Explain why packages are present
python depgraph.py <repo> --out out\<name> --osv --why minimist lodash

# Zoom into one package (great live in the demo)
python depgraph.py <repo> --out out\<name>-focus --osv --focus marked

# Limit depth for huge repos
python depgraph.py <repo> --out out\<name> --osv --max-depth 3

# No Wi-Fi? Use cached responses only
python depgraph.py <repo> --out out\<name> --osv --offline

# Consume an SBOM instead (fixes Maven parent-POM gaps). Docker Desktop must be RUNNING first.
docker run --rm -v "C:\path\to\repo:/src:ro" anchore/syft:latest dir:/src -o cyclonedx-json > repo.cdx.json
python depgraph.py <repo> --sbom repo.cdx.json --out out\<name>-sbom --osv
```

---

## 5. Plan from now to 4 PM

| Time | Who | Task | Done when |
|------|-----|------|-----------|
| **13:55–14:10** | You | Set up the venv (section 0), run on the demo repo, open `graph.html`, skim `summary.json` | Graph opens, red nodes visible |
| **14:10–14:15** | You → team | Send teammates sections 4, 6 and 7 (commands, intake card, safety rules) | Everyone can run it |
| **14:15–14:50** | Teammates | Run `depgraph.py` on each repo they found; fill one **intake card** each; report failures with the `note:` lines | ≥ 4 repos carded |
| **14:15–14:50** | You | Add the **Dependency Graph tab** in Streamlit (section 8) | Tab renders the graph + stats + "Why is X here?" |
| **14:50–15:10** | All | **Pick demo repos**: 1 = our demo target (story), 2 = one real large repo (scale, e.g. NodeGoat), 3 = optional other ecosystem (pygoat / java-goof) | 2–3 repos chosen |
| **15:10–15:30** | All | Pre-generate every demo output with `--osv`; test `--offline`; take screenshots as a backup | Demo works with Wi-Fi off |
| **15:30–15:50** | Presenter | Rehearse the 2-minute graph demo (section 9) twice | Under 2:30 |
| **15:50–16:00** | You | `git add graph/ out/ && git commit && git push`; buffer | Pushed |

**If a teammate's repo fails:** don't debug during the push. Check section 10 first; otherwise drop that repo and use one that works.

---

## 6. Repo intake card (each teammate fills one per repo)

```
Repo URL:                      Commit/branch:
Ecosystems + manifests found:  (e.g. package.json + package-lock.json v3, 2× pom.xml)
Lockfile present?   yes / no   (no → results are "approximate")
Command run:        python depgraph.py ...
Packages / direct / max depth:
Vulnerable packages:           Top vulnerable path:
Untrusted origins / install scripts:
Duplicates / cycles:
Notes / errors printed:
Build time:
Demo value (1-5) + why:        (story? scale? multi-ecosystem? Dockerfile/CI present for later pillars?)
```

**What makes a good demo repo**
- ✅ Has a **lockfile** (exact graph, fast, no network)
- ✅ Transitive vulnerability **2+ levels deep** (shows "trace back to source")
- ✅ 200–1,500 packages (impressive, still renders)
- ✅ Also has a Dockerfile and a `.github/workflows/` (reused for other Day-1 pillars)
- ✅ Bonus: git history with dependency bumps (for "what changed")
- ❌ Avoid: repos without manifests, monorepos with 50+ packages (slow), yarn berry or pnpm only (approximate)

**Safety rules for teammates**
1. `git clone --depth 1` into a separate folder. **Never** `npm install`, `pip install`, `mvn`, `docker build` or run anything from a test repo: install scripts execute code.
2. `depgraph.py` only *reads* files and calls OSV and deps.dev. It never executes repo code.
3. Don't push test repos to your own GitHub with Actions enabled.

**Candidates already checked** (clone and go): `OWASP/NodeGoat` (npm v1 lock, best scale demo), `snyk-labs/nodejs-goof`, `juice-shop/juice-shop` (no lockfile, so approximate), `adeyosemanputra/pygoat`, `snyk-labs/java-goof`, `WebGoat/WebGoat`.

---

## 7. Reading the graph (legend: put this next to the graph in the UI)

| Visual | Meaning |
|--------|---------|
| ★ dark star | Repository |
| Green box | Application / manifest (one per package.json, requirements.txt, pom.xml) |
| Amber dot / blue dot / purple dot | npm / PyPI / Maven package |
| **Red dot** | Has known vulnerabilities (OSV); hover for advisory IDs |
| Large node, thick border | **Direct** dependency |
| Small node | Transitive dependency |
| ◆ diamond | **Install script** or **non-registry origin** (suspicious-change signal) |
| Edge hover | Requested version range |
| Node hover | Version, scope, depth, dependents, origin URL, source file, resolution, advisories |

---

## 8. Streamlit "Dependency Graph" tab (copy and paste)

Save as `graph/app.py` and run `streamlit run app.py` from the `graph` folder.

```python
import json, subprocess, sys
from pathlib import Path
import itertools
import networkx as nx
import streamlit as st
import streamlit.components.v1 as components

st.set_page_config(page_title="Supply Chain Guardian: Dependency Graph", layout="wide")
st.title("🛡️ Supply Chain Guardian: Dependency Graph")

repo = st.text_input("Repository path", r"C:\Users\VICTUS\Desktop\Bosch\sscg-demo-target")
name = Path(repo).name
out = Path("out") / name
c1, c2, c3 = st.columns([1, 1, 2])
osv = c1.checkbox("Vulnerability overlay (OSV)", value=True)
offline = c2.checkbox("Offline (cache only)", value=False)
focus = c3.text_input("Focus on package (optional)")

if st.button("Build graph", type="primary"):
    cmd = [sys.executable, "depgraph.py", repo, "--out", str(out)]
    cmd += ["--osv"] * osv + ["--offline"] * offline + (["--focus", focus] if focus else [])
    with st.spinner("Discovering manifests and resolving dependencies..."):
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        st.error(r.stderr[-2000:])

if (out / "summary.json").exists():
    s = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    m = st.columns(6)
    m[0].metric("Packages", s["packages"]); m[1].metric("Direct", s["direct"])
    m[2].metric("Transitive", s["transitive"]); m[3].metric("Max depth", s["max_depth"])
    m[4].metric("Vulnerable", s["vulnerable_packages"]); m[5].metric("Ecosystems", len(s["by_ecosystem"]))
    st.caption("Apps: " + " | ".join(s["apps"]) + f"   Resolution: {s['resolution']}")

    left, right = st.columns([3, 1])
    with left:
        html_file = (out / "graph.html").resolve()
        if hasattr(st, "iframe"):   # newer Streamlit (components.html is deprecated there)
            st.iframe(html_file, height=820)
        else:                       # older Streamlit
            components.html(html_file.read_text(encoding="utf-8"), height=820, scrolling=True)
    with right:
        st.markdown("**Legend**  \n★ repo · 🟩 app · 🟠 npm · 🔵 PyPI · 🟣 Maven  \n🔴 vulnerable · ◆ install script / untrusted origin  \nbig = direct · small = transitive")
        st.markdown("**Top blast radius**")
        st.dataframe(s["top_blast_radius"], hide_index=True)
        st.markdown("**Heaviest direct deps**")
        st.dataframe(s["heaviest_direct_deps"], hide_index=True)
        if s["untrusted_origins"]: st.warning("Untrusted origins:\n\n" + "\n\n".join(s["untrusted_origins"]))
        if s["install_scripts"]: st.warning("Install scripts: " + ", ".join(s["install_scripts"]))

    st.subheader("🔎 Why is this package here?")
    q = st.text_input("Package name", "minimist")
    if q:
        d = json.loads((out / "graph.json").read_text(encoding="utf-8"))
        G = nx.DiGraph()
        for n in d["nodes"]: G.add_node(n["id"], **n)
        for e in d["edges"]: G.add_edge(e["source"], e["target"])
        top = next(n for n in G if n.startswith("repo:"))
        hits = [n for n, a in G.nodes(data=True) if a.get("name", "").lower() == q.lower()]
        if not hits: st.info("Not in the graph")
        for h in hits:
            st.markdown(f"**{G.nodes[h]['label']}**: {len(G.nodes[h].get('vulns', []))} advisories, "
                        f"origin `{G.nodes[h].get('resolved') or G.nodes[h].get('source')}`")
            for p in itertools.islice(nx.shortest_simple_paths(G, top, h), 5):
                st.code("  →  ".join(G.nodes[x]["label"] for x in p[1:]))

    st.subheader("🧬 Vulnerable dependency paths (deepest first)")
    st.dataframe(s["vulnerable_paths"], hide_index=True)
    with st.expander("Duplicates (same package, several versions)"):
        st.json(s["duplicates"])
    for n in s["notes"]: st.caption("ℹ️ " + n)
```

---

## 9. Two-minute graph demo script

1. **(20 s) Our story repo:** "Three ecosystems in one repo: npm, Python and Java. The guardian found 3 manifests and 25 packages, 13 direct and 12 transitive." Open the graph and point at the three green app boxes.
2. **(30 s) Trace back to source:** hover over red `minimist@0.0.8`. "Nobody chose minimist. `--why minimist` shows `acme-orders → mkdirp → minimist`, and it has 2 advisories, including a critical one. Same for `follow-redirects` via `axios`."
3. **(20 s) Origin:** hover over the ◆ `lodash`. "Its origin is `npm-mirror.example.invalid`, not the npm registry, and `crossenv` ◆ has an install script. That's the bridge to suspicious-change detection."
4. **(40 s) Scale (NodeGoat):** "36 direct dependencies become **1,091 packages, 13 levels deep**. `inherits` sits under 105 packages, so that's its blast radius. `grunt-if` alone drags in 386 packages *and* is downloaded from a GitHub tarball instead of the registry. 131 packages have known advisories; here's the deepest path, 7 levels down." Use `--focus` on one package to zoom in.
5. **(10 s) Honesty:** "Every node says how it was resolved: exact from a lockfile, or approximate from deps.dev. The full graph is in `graph.json`, which our AI agent will query next."

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `0 packages` / "no supported manifests" | Repo uses an unsupported format (Gradle, Go, Cargo, pnpm-only) | Use `--sbom` with Syft output, or pick another repo |
| Many `deps.dev-approx` nodes | No lockfile | Fine, and it's labelled. Prefer repos with lockfiles for the demo |
| Maven nodes `managed-by-parent` / `unresolved` | Version comes from a parent POM / BOM (e.g. Spring Boot) | `--sbom` with Syft output; say "parent BOM resolution is on our roadmap" |
| `graph.html` slow or hairball | > 600 nodes | It auto-limits to depth 2 + vulnerable paths; also `--max-depth 2` or `--focus <pkg>` |
| `docker: error during connect … dockerDesktopLinuxEngine` | Docker Desktop not running | Start Docker Desktop, wait until it says "running", retry |
| Slow first run (juice-shop ≈ 84 s) | Hundreds of deps.dev calls | Run once before the demo, then use `--offline` |
| `OSV unavailable` note | No network | `--offline` uses cache; pre-run with `--osv` |
| Empty SBOM error | Syft/Docker failed, so the file is empty | Check Docker; re-run Syft |
| Can't find package in "why" | Name mismatch (PyPI names are normalised: `PyYAML` → `pyyaml`) | Use the lowercase, dash-separated name |

---

## 11. 4 PM acceptance checklist

- [ ] One command builds the graph for **every** repo the team picked
- [ ] `graph.html` opens offline; legend shown; direct/transitive distinguishable
- [ ] Every node has version, depth, scope, **origin**, source file and resolution method
- [ ] "Why is X here?" works live (CLI and/or Streamlit)
- [ ] Vulnerable nodes are red; at least one **multi-level vulnerable path** is shown
- [ ] Stats ready to quote: packages, direct vs transitive, max depth, blast radius, heaviest dependency
- [ ] Untrusted origin and install script flagged on the demo repo
- [ ] Outputs pre-generated and `--offline` tested (Wi-Fi-proof); screenshots taken as backup
- [ ] Code + `out/` pushed to GitHub

---

## 12. If you finish early (stretch, in order of value)

1. **Graph diff (base vs head):** build the graph at `HEAD~1` and `HEAD` (use `git worktree add ../base HEAD~1`) and colour **added** nodes blue and **changed** nodes orange. This answers "what changed" directly on the graph; on the demo repo it shows `crossenv` added and `lodash`'s origin changed.
2. **CycloneDX export from the graph:** components + `dependencies` from `graph.json`, which gives the SBOM pillar for free.
3. **Severity colours:** fetch OSV details for red nodes (critical = dark red, high = red, medium = orange).
4. **Agent tool:** expose `why(package)` and `blast_radius(package)` from `graph.json` as tools for the Claude agent in `blueprint.md` §6.11.
