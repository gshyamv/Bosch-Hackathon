"""Streamlit dashboard: Day 1 "Build the Guardian's Eyes", all five columns.

① Discover components · ② Build the supply chain view · ③ Detect vulnerabilities
④ Detect suspicious changes (+ what changed) · ⑤ Present evidence
Run from the sscg/ folder:  streamlit run ui/app.py
"""
import itertools
import json
import subprocess
import sys
from pathlib import Path

import altair as alt
import networkx as nx
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

ROOT = Path(__file__).resolve().parent.parent          # sscg/
sys.path.insert(0, str(ROOT))
from sscg.export import DEP_COLOR, render_html  # noqa: E402
from sscg.model import NON_LIBRARY  # noqa: E402
from sscg.report import _ev as evidence_text  # noqa: E402
from sscg.report_export import to_html as report_html, to_pdf as report_pdf  # noqa: E402

GRAPH_VIEWS = ["Direct vs transitive (by level)", "Direct dependencies only",
               "One direct dependency's transitive tree", "Full graph (ecosystems & risk)"]
LAYERED_MAX = 300


@st.cache_data(show_spinner=False)
def report_bytes(md_path: str, mtime: float, fmt: str) -> bytes:
    """report.html / report.pdf from the scan folder; rendered from report.md when missing or older
    (folders scanned before these formats existed)."""
    md, f = Path(md_path), Path(md_path).with_suffix("." + fmt)
    if f.exists() and f.stat().st_mtime >= mtime:
        return f.read_bytes()
    text = md.read_text(encoding="utf-8")
    return report_html(text).encode("utf-8") if fmt == "html" else report_pdf(text)


@st.cache_resource(show_spinner=False)
def load_graph(path: str, mtime: float) -> nx.DiGraph:
    """graph.json -> networkx graph (cached until the file changes)."""
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    G = nx.DiGraph()
    for n in d["nodes"]:
        G.add_node(n["id"], **{k: v for k, v in n.items() if k != "id"})
    for e in d["edges"]:
        G.add_edge(e["source"], e["target"], **{k: v for k, v in e.items() if k not in ("source", "target")})
    return G


def library(G, n, libs_only: bool) -> bool:
    a = G.nodes[n]
    return a["kind"] == "package" and (not libs_only or a["ecosystem"] not in NON_LIBRARY)


def with_parents(G, top, pk: set) -> nx.DiGraph:
    """Subgraph of the chosen components plus the manifests that declare them and the repo node."""
    apps = {p for n in pk for p in G.predecessors(n) if G.nodes[p]["kind"] == "app"}
    return G.subgraph({top} | apps | pk).copy()


@st.cache_data(show_spinner=False, max_entries=32)
def view_html(path: str, mtime: float, mode: str, levels: int, libs_only: bool, root: str | None) -> tuple[str, dict]:
    """Build one direct/transitive view and its HTML. Returns (html, counts of what is shown)."""
    G = load_graph(path, mtime)
    top = next(n for n in G if n.startswith("repo:"))
    if mode == GRAPH_VIEWS[2] and root:
        dist = nx.single_source_shortest_path_length(G, root)
        pk = {n for n in dist if library(G, n, libs_only) and dist[n] <= levels}
        H = with_parents(G, top, pk)
        for n in pk:                          # columns count from the chosen dependency
            H.nodes[n]["_level"] = dist[n] + 2
    else:
        lim = 1 if mode == GRAPH_VIEWS[1] else levels
        pk = {n for n in G if library(G, n, libs_only) and (G.nodes[n].get("depth") or 99) <= lim}
        H = with_parents(G, top, pk)
        if mode == GRAPH_VIEWS[1]:            # show how much each direct dependency drags in
            for n in pk:
                below = sum(1 for d in nx.descendants(G, n) if library(G, d, True))
                H.nodes[n]["label"] = f"{H.nodes[n]['label']}  (+{below})"
    shown = [n for n in H if H.nodes[n]["kind"] == "package"]
    layered = len(shown) <= LAYERED_MAX   # columns per level stay readable up to a few hundred nodes
    counts = {"nodes": len(shown), "edges": H.number_of_edges(), "layered": layered,
              "direct": sum(1 for n in shown if H.nodes[n].get("direct")),
              "transitive": sum(1 for n in shown if not H.nodes[n].get("direct"))}
    return render_html(H, mode="dependency", layered=layered, small_labels=len(shown) <= 250), counts

TARGETS = ROOT.parent / "targets"
PRESETS = {
    "sscg-demo-target (ours)": TARGETS / "sscg-demo-target",
    "nodejs-goof (snyk-labs)": TARGETS / "nodejs-goof",
    "juice-shop (OWASP)": TARGETS / "juice-shop",
}
LEVELS = ["Critical", "High", "Medium", "Low", "Info"]
ICON = {"Critical": "🟥", "High": "🟧", "Medium": "🟨", "Low": "🟦", "Info": "⬜"}

st.set_page_config(page_title="Supply Chain Guardian", layout="wide")
st.title("🛡️ Supply Chain Guardian")
st.caption("Day 1 · Build the Guardian's Eyes: show what is in the application, what changed, and what appears risky.")

# ------------------------------------------------------------------ controls
choice = st.selectbox("Repository", list(PRESETS) + ["Other path..."])
repo = st.text_input("Repository path", str(PRESETS.get(choice, "")), key=f"repo:{choice}")
name = Path(repo).name
out = ROOT / "out" / name
c1, c2, c3, c4 = st.columns([1, 1, 1, 1])
osv = c1.checkbox("Vulnerability detection (OSV)", value=True)
offline = c2.checkbox("Offline (cache only)", value=False)
base = c3.text_input("Compare with commit (what changed)", "HEAD~1",
                     help="Base commit for 'what changed'. Leave empty to skip the comparison.")
focus = c4.text_input("Focus graph on package (optional)")
a1, a2, a3, _ = st.columns([1, 1, 1, 1])
agentic = a1.toggle("Agentic AI (LangGraph agents)", value=False,
                    help="Runs `python -m sscg agent`: the same pipeline plus AI triage of suspicious changes and an "
                         "AI summary. Uses the API key in sscg/.env; without one it runs the rules-only fallback.")
llm_choice = a2.selectbox("LLM provider", ["auto", "claude", "gemini", "groq", "deepseek", "grok", "none"],
                          disabled=not agentic,
                          help="groq = Groq / GroqCloud; grok = xAI Grok")
day2 = a3.toggle("Day 2: prioritise & remediate", value=False, disabled=not agentic,
                 help="Adds exploitability (KEV/EPSS), reachability, prioritisation and remediation proposals. The run "
                      "then pauses for your approval below; approved fixes are validated in a sandbox copy.")

if st.button("Scan repository", type="primary"):
    cmd = [sys.executable, "-m", "sscg", "agent" if agentic else "scan", repo, "--out", str(out), "--top", "0"]
    cmd += (["--base", base] if base.strip() else ["--no-diff"]) + ([] if osv else ["--no-vulns"])
    cmd += ["--offline"] * offline + (["--focus", focus] if focus else [])
    cmd += ["--llm", llm_choice] if agentic else []
    cmd += ["--day2", "--decisions", "later"] if agentic and day2 else []
    with st.spinner("Agents at work: discovery, detection, AI triage, summary..." if agentic else
                    "Discovering components, building the SBOM and graph, detecting risks..."):
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", cwd=ROOT)
    if r.returncode != 0:
        st.error(r.stderr[-2000:])

if not (out / "summary.json").exists():
    st.info("No scan yet for this repository. Click **Scan repository**.")
    st.stop()

s = json.loads((out / "summary.json").read_text(encoding="utf-8"))
doc = json.loads((out / "findings.json").read_text(encoding="utf-8")) if (out / "findings.json").exists() else None
F = doc["findings"] if doc else []
vul = [f for f in F if f["category"] == "vulnerability"]
ano = [f for f in F if f["category"] == "anomaly"]
ch = doc["change"] if doc else None

# ------------------------------------------------------------------ pipeline + headline
st.markdown("**Repository** ✔ → **SBOM** ✔ → **Dependency graph** ✔ → "
            f"**Risk detection** {'✔' if doc else '—'} → **Evidence** {'✔' if doc else '—'}")
k = st.columns(6)
k[0].metric("Components", s["components_total"])
k[1].metric("Vulnerable components", len(vul))
k[2].metric("Suspicious changes", len(ano))
k[3].metric("Critical findings", doc["counts"]["by_level"]["Critical"] if doc else 0)
k[4].metric("High findings", doc["counts"]["by_level"]["High"] if doc else 0)
k[5].metric("New in latest change", doc["counts"]["new_in_change"] if doc else 0,
            help="Findings that did not exist in the base commit" if ch else "No base commit was compared")
if not doc:
    st.warning("This result was produced before risk detection existed. Click **Scan repository** to refresh it.")


def finding_table(rows):
    return pd.DataFrame([{
        "ID": f["finding_id"], "Risk": f"{ICON[f['risk']['level']]} {f['risk']['level']}",
        "Score": f["risk"]["score"], "Type": f["type"], "Finding": f["title"],
        "Location": f["location"] or "", "New": "🆕" if f["new_in_change"] else ""} for f in rows])


def finding_card(f):
    r, comp = f["risk"], f["component"]
    st.markdown(f"#### {f['finding_id']} · {ICON[r['level']]} {r['level']} ({r['score']}) · {f['type']}"
                + (" · 🆕 new in this change" if f["new_in_change"] else ""))
    st.markdown(f"**What:** {f['title']}")
    if comp:
        st.markdown(f"**Component:** `{comp['label']}` · {comp['ecosystem']} · scope `{comp['scope']}` · "
                    f"{'direct' if comp['direct'] else 'transitive'}" + (f" · purl `{comp['purl']}`" if comp["purl"] else ""))
    if f["location"]:
        st.markdown(f"**Where:** `{f['location']}`")
    if f["dependency_paths"]:
        st.markdown("**Dependency path:**")
        for p in f["dependency_paths"]:
            st.code("  →  ".join(p))
    if f.get("severity"):
        sv, fx = f["severity"], f["fixes"]
        st.markdown(f"**Official severity:** {sv['label']}" + (f", CVSS {sv['cvss']}" if sv["cvss"] else "")
                    + f" *({sv['source']})*  \n**Fix available:** "
                    + (f"upgrade to ≥ `{fx['upgrade_to_at_least']}`" if fx["upgrade_to_at_least"] else "no fixed version published")
                    + (f" · no fix for {', '.join(fx['advisories_without_fix'])}" if fx["advisories_without_fix"] else ""))
    st.markdown("**Evidence:**")
    for e in f["evidence"]:
        st.markdown(f"- {evidence_text(e)}")
    st.markdown(f"**Initial risk:** {r['level']} ({r['score']}): {'; '.join(r['reasons'])}  \n"
                f"*{r['label']}*  \n**Why it matters:** {f['why_it_matters']}  \n"
                f"**Basis:** {f['classification'].replace('_', ' ')} · confidence {f['confidence']}")


# ------------------------------------------------------------------ ① Discover components
st.header("① Components")
m = st.columns(7)
m[0].metric("Components", s["components_total"])
m[1].metric("Libraries", s["packages"])
m[2].metric("Direct", s["direct"])
m[3].metric("Transitive", s["transitive"])
m[4].metric("Max depth", s["max_depth"])
m[5].metric("Container images", len(s["container_images"]))
m[6].metric("CI actions", s["by_ecosystem"].get("github-actions", 0))
st.caption("Manifests: " + " | ".join(s["apps"]))
st.caption("By ecosystem: " + ", ".join(f"{k} {v}" for k, v in s["by_ecosystem"].items())
           + "   ·   Resolution: " + ", ".join(f"{k} {v}" for k, v in s["resolution"].items()))

# ------------------------------------------------------------------ ② Supply chain view
st.header("② Supply chain view")
tab_graph, tab_sbom, tab_container, tab_origin = st.tabs(
    ["Dependency graph", "SBOM (CycloneDX)", "Container images & CI/CD", "Origins"])

with tab_graph:
    gpath = out / "graph.json"
    gkey = (str(gpath), gpath.stat().st_mtime)
    G = load_graph(*gkey)
    top = next(n for n in G if n.startswith("repo:"))

    # --- direct vs transitive at a glance: libraries per dependency level
    st.markdown("**Direct vs transitive libraries by dependency level**")
    hist = {int(k): v for k, v in s["depth_histogram"].items()}
    lvl_df = pd.DataFrame([{"Level": k, "Kind": "Direct" if k == 1 else "Transitive", "Libraries": v}
                           for k, v in sorted(hist.items())])
    g1, g2, g3 = st.columns([1, 1, 4])
    g1.metric("Direct", s["direct"], help="Libraries listed in the manifests (level 1)")
    g2.metric("Transitive", s["transitive"], help="Libraries pulled in by other libraries (level 2 and deeper)")
    if not lvl_df.empty:
        bars = alt.Chart(lvl_df).mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4, size=26).encode(
            x=alt.X("Level:O", title="Dependency level (1 = direct)", axis=alt.Axis(labelAngle=0)),
            y=alt.Y("Libraries:Q", title="Libraries"),
            color=alt.Color("Kind:N", title=None, legend=alt.Legend(orient="top"),
                            scale=alt.Scale(domain=["Direct", "Transitive"],
                                            range=[DEP_COLOR["direct"], DEP_COLOR["transitive"]])),
            tooltip=[alt.Tooltip("Level:O", title="Level"), alt.Tooltip("Kind:N"),
                     alt.Tooltip("Libraries:Q")])
        chart = (bars.properties(height=200)
                 .configure(background="#fcfcfb", padding=12)
                 .configure_view(stroke=None)
                 .configure_axis(labelColor="#52514e", titleColor="#52514e", gridColor="#e1e0d9",
                                 domainColor="#c3c2b7", tickColor="#c3c2b7")
                 .configure_legend(labelColor="#0b0b0b", symbolType="square"))
        g3.altair_chart(chart, use_container_width=True, theme=None)
        with st.expander("Table: libraries per level"):
            st.dataframe(lvl_df, hide_index=True)

    # --- graph views
    view_mode = st.radio("Graph view", GRAPH_VIEWS, horizontal=True)
    maxd = max(hist) if hist else 1
    left, right = st.columns([3, 1])
    if view_mode == GRAPH_VIEWS[3]:
        with left:
            components.html((out / "graph.html").read_text(encoding="utf-8"), height=820, scrolling=True)
        with right:
            st.markdown("**Legend**  \n★ repo · 🟩 manifest / Dockerfile / workflow  \n"
                        "🟠 npm · 🔵 PyPI · 🟣 Maven · ■ container image · ▲ CI action · ⚪ downloaded file  \n"
                        "◆ suspicious (has an anomaly finding, install script or untrusted origin)  \n"
                        "🔴 has published advisories · big = direct · small = transitive")
    else:
        o1, o2 = st.columns([2, 1])
        libs_only = o2.checkbox("Libraries only", value=True,
                                help="Hide container images, CI actions and downloaded files (they have no transitive "
                                     "dependencies)")
        root, levels = None, 1
        if view_mode == GRAPH_VIEWS[2]:
            directs = sorted((n for n in G if G.nodes[n].get("direct") and library(G, n, libs_only)),
                             key=lambda n: -sum(1 for d in nx.descendants(G, n) if library(G, d, True)))
            if directs:
                pick = o1.selectbox("Direct dependency", directs, format_func=lambda n: (
                    f"{G.nodes[n]['label']}  (+{sum(1 for d in nx.descendants(G, n) if library(G, d, True))} "
                    "transitive)"))
                root = pick
                below = nx.single_source_shortest_path_length(G, root)
                deep = max(below.values()) if below else 0
                levels = o1.slider("Levels below it", 1, max(deep, 1), max(deep, 1)) if deep > 1 else max(deep, 1)
        elif view_mode == GRAPH_VIEWS[0]:
            levels = o1.slider("Show levels (1 = direct only)", 1, maxd,
                               min(maxd, 3 if s["packages"] > 300 else maxd)) if maxd > 1 else 1
        html, cnt = view_html(*gkey, view_mode, levels, libs_only, root)
        with left:
            layout = ("Columns, left to right: repository · manifests · "
                      + ("the chosen dependency · each level below it" if root else "level 1 (direct) · level 2 · …")
                      if cnt["layered"] else
                      f"More than {LAYERED_MAX} components, so a clustered layout is used (reduce the levels to "
                      "get columns per level).")
            st.caption(f"Showing {cnt['nodes']} components ({cnt['direct']} direct, {cnt['transitive']} transitive) "
                       f"and {cnt['edges']} edges. {layout}")
            if cnt["nodes"] > 1200:
                st.warning("Large view: it may take a moment to draw. Reduce the levels for a faster, clearer picture.")
            components.html(html, height=820, scrolling=True)
        with right:
            position = ("Columns = dependency levels, so direct vs transitive is also shown by position.  \n"
                        if cnt["layered"] else "Big blue nodes = direct, small orange = transitive.  \n")
            hidden = ("  \nLabels of transitive nodes are hidden in large views; hover to see them."
                      if cnt["nodes"] > 250 else "")
            st.markdown(
                f"**Legend**  \n<span style='color:{DEP_COLOR['direct']}'>●</span> **direct** dependency (big)  \n"
                f"<span style='color:{DEP_COLOR['transitive']}'>●</span> **transitive** dependency (small)  \n"
                "★ repository · dark grey box = manifest / Dockerfile / workflow  \n"
                "red outline = has published advisories · ◆ = suspicious (has an anomaly finding)  \n"
                + position + "Hover a node for its version, path data, advisories and finding IDs." + hidden,
                unsafe_allow_html=True)
    with right:
        st.markdown("**Top blast radius**")
        st.dataframe(s["top_blast_radius"], hide_index=True)
        st.markdown("**Heaviest direct deps**")
        st.dataframe(s["heaviest_direct_deps"], hide_index=True)

    st.subheader("🔎 Why is this package here?")
    q = st.text_input("Package name", "minimist")
    if q:
        hits = [n for n, a in G.nodes(data=True) if str(a.get("name", "")).lower() == q.lower()]
        if not hits:
            st.info("Not in the graph")
        for h in hits:
            a = G.nodes[h]
            st.markdown(f"**{a['label']}** · {a.get('ecosystem')} · scope `{a.get('scope')}` · "
                        f"origin `{a.get('resolved') or a.get('source')}`"
                        + (f" · findings {', '.join(a['findings'])}" if a.get("findings") else ""))
            for p in itertools.islice(nx.shortest_simple_paths(G, top, h), 5):
                st.code("  →  ".join(G.nodes[x]["label"] for x in p[1:]))
    with st.expander(f"Duplicates: same package in several versions ({len(s['duplicates'])})"):
        st.json(s["duplicates"])

with tab_sbom:
    sb = out / "sbom.cdx.json"
    bom = json.loads(sb.read_text(encoding="utf-8"))
    types = pd.Series([c["type"] for c in bom["components"]]).value_counts()
    kk = st.columns(4)
    kk[0].metric("Format", f"{bom['bomFormat']} {bom['specVersion']}")
    kk[1].metric("SBOM components", len(bom["components"]),
                 help="All supply-chain components plus one entry per manifest, Dockerfile and workflow")
    kk[2].metric("Dependency entries", len(bom["dependencies"]))
    kk[3].metric("With hashes", sum(1 for c in bom["components"] if c.get("hashes")))
    st.caption("Component types: " + ", ".join(f"{t} {n}" for t, n in types.items()))
    st.download_button("Download sbom.cdx.json", sb.read_bytes(), file_name=f"{name}.cdx.json",
                       mime="application/json")
    rows = [{"type": c["type"], "name": c["name"], "version": c.get("version", ""), "scope": c.get("scope", ""),
             "purl": c.get("purl", ""),
             "origin": (c.get("externalReferences") or [{}])[0].get("url", "")} for c in bom["components"]]
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
    st.caption("Consume an existing SBOM instead of scanning:  `python -m sscg scan <repo> --sbom bom.cdx.json`")

with tab_container:
    st.subheader("🐳 Container images")
    if s["container_images"]:
        st.dataframe(pd.DataFrame(s["container_images"]), hide_index=True, use_container_width=True)
        for df in s["dockerfiles"]:
            st.markdown(f"**{df['file']}**: images {', '.join(df['images']) or 'none'}"
                        + (f" · runs as: {df['runs_as']}" if df.get("runs_as") else "")
                        + (f" · downloads: {', '.join(df['downloads'])}" if df["downloads"] else ""))
    else:
        st.info("No Dockerfile or compose file found.")
    st.subheader("⚙️ CI/CD workflows")
    if s["ci_workflows"]:
        for w in s["ci_workflows"]:
            st.markdown(f"**{w['file']}** ({w['workflow']}) · triggers: {', '.join(w['triggers'])} · "
                        f"permissions: {w['permissions']}")
            if w["actions"]:
                st.dataframe(pd.DataFrame(w["actions"]), hide_index=True, use_container_width=True)
            if w["images"] or w["downloads"]:
                st.caption("images: " + ", ".join(w["images"]) + "  downloads: " + ", ".join(w["downloads"]))
    else:
        st.info("No GitHub Actions workflow found.")
    if s["remote_artifacts"]:
        st.subheader("🌐 Files downloaded during build / CI")
        st.dataframe(pd.DataFrame(s["remote_artifacts"]), hide_index=True, use_container_width=True)

with tab_origin:
    st.markdown("**Where components come from** (host of the download / registry URL)")
    st.dataframe(pd.DataFrame(sorted(s["origins"].items(), key=lambda x: -x[1]), columns=["host", "components"]),
                 hide_index=True)
    if s["untrusted_origins"]:
        st.markdown("**npm packages not served by the npm registry**")
        st.code("\n".join(s["untrusted_origins"]))
    if s["install_scripts"]:
        st.markdown("**Packages with install scripts** (lockfile `hasInstallScript`)")
        st.code("\n".join(s["install_scripts"]))

if not doc:
    st.stop()

# ------------------------------------------------------------------ ③ Detect vulnerabilities
st.header("③ Vulnerabilities")
if not vul:
    st.info("No component version has a published advisory" + ("" if osv else " (vulnerability detection was off)."))
else:
    sev_count = pd.Series([f["severity"]["label"] for f in vul]).value_counts()
    v = st.columns(6)
    v[0].metric("Vulnerable components", len(vul))
    v[1].metric("Advisories", doc["counts"]["advisories"])
    for i, lab in enumerate(["CRITICAL", "HIGH", "MEDIUM"], 2):
        v[i].metric(f"Highest = {lab.title()}", int(sev_count.get(lab, 0)))
    v[5].metric("With a fix", sum(1 for f in vul if f["fixes"]["upgrade_to_at_least"]))
    fc1, fc2 = st.columns(2)
    sev_pick = fc1.multiselect("Official severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
                               default=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"])
    kind_pick = fc2.multiselect("Dependency", ["direct", "transitive"], default=["direct", "transitive"])
    rows = [f for f in vul if f["severity"]["label"] in sev_pick
            and ("direct" if f["is_direct"] else "transitive") in kind_pick]
    st.dataframe(pd.DataFrame([{
        "ID": f["finding_id"], "Component": f["component"]["label"], "Ecosystem": f["component"]["ecosystem"],
        "Dependency": "direct" if f["is_direct"] else "transitive",
        "Severity": f["severity"]["label"], "CVSS": f["severity"]["cvss"], "Advisories": len(f["evidence"]),
        "CVEs": ", ".join(sorted({c for e in f["evidence"] for c in e.get("cves", [])})[:4]),
        "Fix (upgrade to ≥)": f["fixes"]["upgrade_to_at_least"] or "no fix",
        "Introduced via": ", ".join(f["introduced_by"]) or "(direct)",
        "Risk": f"{ICON[f['risk']['level']]} {f['risk']['score']}"} for f in rows]),
        hide_index=True, use_container_width=True)
    pick = st.selectbox("Trace a vulnerable component to its source",
                        [f"{f['finding_id']} · {f['component']['label']}" for f in rows] or ["-"])
    sel = next((f for f in rows if pick.startswith(f["finding_id"] + " ")), None)
    if sel:
        for p in sel["dependency_paths"]:
            st.code("  →  ".join(p))
        st.dataframe(pd.DataFrame([{"Advisory": e["id"], "CVEs": ", ".join(e["cves"]), "Severity": e["severity"],
                                    "CVSS": e["cvss_score"], "Fixed in": e["fixed_in"] or "no fix",
                                    "Summary": e["summary"], "Link": e["url"]} for e in sel["evidence"]]),
                     hide_index=True, use_container_width=True,
                     column_config={"Link": st.column_config.LinkColumn("Link")})

# ------------------------------------------------------------------ ④ Detect suspicious changes
st.header("④ Suspicious changes")
st.subheader("What changed")
if ch:
    b, h = ch["base"], ch["head"]
    st.markdown(f"Base `{b['short']}` *{b['message']}* → HEAD `{h['short']}` *{h['message']}*"
                + (" + uncommitted changes" if ch["head_dirty"] else ""))
    st.markdown(f"Author: **{h['author']}** <{h['email']}> · first-time contributor: "
                + {True: "**⚠️ yes**", False: "no", None: "unknown"}[ch["first_time_author"]])
    w = st.columns(4)
    w[0].metric("Files changed", len(ch["files"]))
    w[1].metric("Components added", len(ch["added"]))
    w[2].metric("Components removed", len(ch["removed"]))
    w[3].metric("Components changed", len(ch["changed"]))
    cc1, cc2 = st.columns(2)
    with cc1:
        st.markdown("**Files**")
        st.dataframe(pd.DataFrame(ch["files"]), hide_index=True, use_container_width=True)
    with cc2:
        rows = ([{"change": "added", "component": a["label"], "detail": a["source"]} for a in ch["added"]]
                + [{"change": "removed", "component": a["label"], "detail": a["source"]} for a in ch["removed"]]
                + [{"change": "changed", "component": f"{x['base']} → {x['head']}", "detail": ", ".join(x["fields"])}
                   for x in ch["changed"]])
        st.markdown("**Components**")
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
else:
    st.info("No base commit compared (shallow clone, first commit, or comparison turned off). "
            "Anomalies below describe the current state only.")

st.subheader(f"Anomalies ({len(ano)})")
if ano:
    by_type = pd.Series([f["type"] for f in ano]).value_counts()
    st.caption(" · ".join(f"{t}: {n}" for t, n in by_type.items()))
    st.dataframe(finding_table(ano), hide_index=True, use_container_width=True)
else:
    st.success("No supply-chain anomaly detected.")

# ------------------------------------------------------------------ ⑤ Present evidence
st.header("⑤ Evidence")
e1, e2, e3 = st.columns(3)
lv = e1.multiselect("Risk level", LEVELS, default=LEVELS)
cat = e2.multiselect("Category", ["anomaly", "vulnerability"], default=["anomaly", "vulnerability"])
only_new = e3.checkbox("Only new in latest change", value=False)
sel_rows = [f for f in F if f["risk"]["level"] in lv and f["category"] in cat and (f["new_in_change"] or not only_new)]
st.dataframe(finding_table(sel_rows), hide_index=True, use_container_width=True)
pick = st.selectbox("Open a finding", [f"{f['finding_id']} · {f['title'][:100]}" for f in sel_rows] or ["-"])
sel = next((f for f in sel_rows if pick.startswith(f["finding_id"] + " ")), None)
if sel:
    with st.container(border=True):
        finding_card(sel)
d1, d2, d3, d4 = st.columns(4)
d1.download_button("Download findings.json", (out / "findings.json").read_bytes(), file_name=f"{name}.findings.json",
                   mime="application/json")
if (out / "report.md").exists():
    rmd = out / "report.md"
    d2.download_button("Download report.md", rmd.read_bytes(), file_name=f"{name}.report.md",
                       mime="text/markdown")
    d3.download_button("Download report.html", report_bytes(str(rmd), rmd.stat().st_mtime, "html"),
                       file_name=f"{name}.report.html", mime="text/html")
    try:
        d4.download_button("Download report.pdf", report_bytes(str(rmd), rmd.stat().st_mtime, "pdf"),
                           file_name=f"{name}.report.pdf", mime="application/pdf")
    except Exception as e:  # noqa: BLE001  (e.g. reportlab not installed)
        d4.caption(f"PDF unavailable: {type(e).__name__}: {e}")
    with st.expander("Show the full evidence report"):
        st.markdown((out / "report.md").read_text(encoding="utf-8"))

for n in s["notes"]:
    st.caption("ℹ️ " + n)

# ------------------------------------------------------------------ ⑥ AI triage (agent graph, inference only)
ag_path = out / "agentic.json"
if ag_path.exists():
    ag = json.loads(ag_path.read_text(encoding="utf-8"))
    st.header("⑥ AI triage and summary")
    st.caption(f"Inference by **{ag['engine']}** via the LangGraph agent workflow, kept apart from the evidence above. "
               "It cites finding / evidence IDs (F-012/E1 finding evidence, F-012/T1 tool evidence) and never changes "
               f"the initial risk. Knowledge base {ag['kb_version']}. See docs/agentic.md.")
    if (out / "findings.json").exists() and ag_path.stat().st_mtime < (out / "findings.json").stat().st_mtime - 5:
        st.warning("This AI triage is from an earlier agent run; the findings above were rescanned since. "
                   "Turn on **Agentic AI** and scan again to refresh it.")
    nar = ag.get("narrative") or {}
    if nar:
        with st.container(border=True):
            st.markdown(f"**{nar['headline']}**")
            st.markdown(f"- **What is in the application:** {nar['what_is_in_the_app']}\n"
                        f"- **What changed:** {nar['what_changed']}\n- **What appears risky:** {nar['what_appears_risky']}")
            for c in nar.get("top_concerns", []):
                st.markdown(f"👉 `{c['finding_id']}`: {c['why']}")
            for c in nar.get("caveats", []):
                st.caption(c)
    tri = ag.get("triage", {})
    if tri:
        VI = {"likely_malicious": "⛔", "suspicious": "⚠️", "needs_human_review": "👀", "likely_benign": "✅"}
        st.dataframe(pd.DataFrame([{
            "ID": fid, "Rule": t["rule"], "AI verdict": f"{VI.get(t['verdict'], '')} {t['verdict']}",
            "Confidence": t["confidence"], "Grounded": "yes" if t["grounding"].get("ok", True) else "⚠ no",
            "Rounds": t["rounds"], "Rationale": t["rationale"]} for fid, t in sorted(tri.items())]),
            hide_index=True, use_container_width=True)
        pick_t = st.selectbox("Open a triage decision", sorted(tri))
        t = tri[pick_t]
        with st.container(border=True):
            st.markdown(f"**{pick_t}** · {t['verdict']} ({t['confidence']}) · by `{t['generated_by']}`  \n{t['rationale']}")
            if t.get("benign_explanations"):
                st.markdown("**Innocent explanations considered:** " + "; ".join(t["benign_explanations"]))
            if t.get("recommended_next_step"):
                st.markdown(f"**Reviewer should check:** {t['recommended_next_step']}")
            if t.get("matched_patterns"):
                st.markdown("**Matches attack patterns:** " + ", ".join(t["matched_patterns"]))
            if not t["grounding"].get("ok", True):
                st.warning(f"Grounding check: {t['grounding']}")
            for e in ag.get("tool_evidence", {}).get(pick_t, []):
                with st.expander(f"{e['id']} · tool `{e['tool']}` (round {e['round'] + 1})"):
                    st.json(e["result"])
    u = ag.get("llm_usage", {})
    st.caption(f"LLM calls {u.get('calls', 0)} · tokens in/out {u.get('input_tokens', 0)}/{u.get('output_tokens', 0)} · "
               f"secrets redacted before sending {u.get('secrets_redacted', 0)} · "
               + " · ".join(f"{r['agent']} {r['seconds']}s" for r in ag.get("agent_runs", []) if r["kind"] != "llm"))
    st.download_button("Download agentic.json", ag_path.read_bytes(), file_name=f"{name}.agentic.json",
                       mime="application/json")

# ================================================================== Day 2: Brain & Shield
D2 = out / "day2"
pending_f, day2_f = D2 / "pending.json", D2 / "day2.json"
if pending_f.exists() or day2_f.exists():
    st.divider()
    st.header("Day 2 · Brain & Shield")
    st.caption("Prioritize risks → recommend safe remediation → human approval → build & test in a sandbox → rescan → "
               "verified remediation. The original repository is never modified.")
    PRIO_ICON = {"P0": "🟥", "P1": "🟧", "P2": "🟨", "P3": "🟦"}

    if pending_f.exists():   # ---------------------------------------------- the run is paused: human approval
        pend = json.loads(pending_f.read_text(encoding="utf-8"))
        props = pend["proposals"]
        st.subheader("⏸️ Waiting for your approval")
        st.caption(f"Run `{pend['run_id']}` paused at the human-approval step ({pend['created']}). Only approved "
                   "proposals with a patch are applied, in a sandbox copy; manual proposals can be acknowledged or "
                   "risk-accepted.")
        OPTIONS = ["defer", "approve", "reject", "accept_risk", "request_changes"]
        LABEL = {"defer": "⏳ defer", "approve": "✅ approve", "reject": "🚫 reject", "accept_risk": "⚖️ accept risk",
                 "request_changes": "✏️ request changes"}
        with st.form("approval"):
            decisions = {}
            for p in props:
                head = (f"{p['proposal_id']} · {PRIO_ICON.get(p['priority'], '')} {p['priority']}"
                        f"{' 🔥' if p['urgent'] else ''} · {p['action'].replace('_', ' ')} · {p['component'] or ''} "
                        f"{p['from_version'] or ''} → {p['to_version'] or ''}" + ("" if p["patchable"] else " · manual"))
                with st.expander(head, expanded=bool(p["urgent"])):
                    st.markdown(f"**Why (verified):** {p['rationale']}")
                    if p.get("ai_rationale"):
                        st.markdown(f"**Advisor (AI inference):** {p['ai_rationale']}")
                    st.markdown(f"**Compatibility:** {p['compatibility_level']}: {p.get('compatibility_impact') or '-'}  \n"
                                f"**Findings:** {', '.join(p['finding_ids'])}"
                                + (f"  \n**Residual advisories:** {', '.join(p['residual_advisories'])}"
                                   if p.get("residual_advisories") else ""))
                    if p.get("diff"):
                        st.code(p["diff"][:4000], language="diff")
                    decisions[p["proposal_id"]] = st.radio(
                        "Decision", OPTIONS, horizontal=True, key=f"dec-{pend['run_id']}-{p['proposal_id']}",
                        index=0, format_func=lambda x: LABEL[x])
            f1, f2 = st.columns([1, 2])
            approver = f1.text_input("Approver (recorded in the audit trail)")
            reason = f2.text_input("Reason / comment (optional)")
            submitted = st.form_submit_button("Submit decisions and validate", type="primary")
        if submitted:
            if not approver.strip():
                st.error("Enter the approver's name: every decision is recorded with who made it.")
            else:
                cmd = [sys.executable, "-m", "sscg", "approve", repo, "--out", str(out), "--by", approver.strip(),
                       "--reason", reason or "decided in the dashboard"]
                for d in ("approve", "reject", "accept_risk", "request_changes"):
                    ids = [k for k, v in decisions.items() if v == d]
                    if ids:
                        cmd += [f"--{d.replace('_', '-')}", ",".join(ids)]
                with st.spinner("Applying the approved fixes in a sandbox, building, testing and rescanning... "
                                "(can take a few minutes)"):
                    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", cwd=ROOT)
                if r.returncode != 0:
                    st.error((r.stdout + r.stderr)[-2500:])
                else:
                    st.rerun()

    if day2_f.exists() and not pending_f.exists():   # ------------------------ results of the last Day 2 run
        d2 = json.loads(day2_f.read_text(encoding="utf-8"))
        val = (d2.get("validations") or [{}])[-1]
        verdict = val.get("verdict", "not_run")
        k = st.columns(5)
        k[0].metric("Verdict", {"verified": "✅ verified", "partially_verified": "🟨 partial", "failed": "❌ failed",
                                "not_run": "⏸️ not run"}.get(verdict, verdict), help="; ".join(val.get("reasons", [])))
        k[1].metric("Confidence", val.get("confidence", "-"))
        k[2].metric("Findings before → after", f"{val.get('findings_before', '-')} → {val.get('findings_after', '-')}")
        k[3].metric("Resolved", len(val.get("resolved", [])))
        k[4].metric("New after the fix", len([n for n in val.get("new", []) if n.get("kind") == "introduced"]),
                    help="excluding expected changes (e.g. the replacement package) and packages that are still "
                         "vulnerable at a new version")
        for r_ in val.get("reasons", []):
            st.caption("• " + r_)
        t1, t2, t3, t4 = st.tabs(["① Priorities", "③ Proposals & decisions", "④ Validation", "⑤ Report & patch"])
        with t1:
            st.dataframe(pd.DataFrame([{
                "Priority": f"{PRIO_ICON.get(p['priority'], '')} {p['priority']}", "Urgent": "🔥" if p["urgent"] else "",
                "Score": p["score"], "ID": p["finding_id"], "Component": p["component"] or "", "Finding": p["title"],
                "Why": "; ".join(p["reasons"][1:4]), "Confidence": p["confidence"]} for p in d2.get("priorities", [])]),
                hide_index=True, use_container_width=True)
            src = d2.get("exploitability_sources") or {}
            st.caption(f"CISA KEV {((src.get('kev') or {}).get('date') or 'n/a')} · EPSS "
                       f"{((src.get('epss') or {}).get('date') or 'n/a')} · reachability {d2.get('reachability_summary')}"
                       f" · network service: {(d2.get('exposure') or {}).get('network_service')}")
        with t2:
            appr = {a["proposal_id"]: a for a in d2.get("approvals", [])}
            st.dataframe(pd.DataFrame([{
                "ID": p["proposal_id"], "Status": p["status"], "Priority": p["priority"], "Action": p["action"],
                "Component": p["component"], "From": p["from_version"], "To": p["to_version"],
                "Compatibility": p["compatibility_level"],
                "Decision": f"{appr[p['proposal_id']]['decision']} by {appr[p['proposal_id']]['approver']}"
                if p["proposal_id"] in appr else "",
                "Validation": (val.get("per_proposal") or {}).get(p["proposal_id"], {}).get("status", "")}
                for p in d2.get("proposals", [])]), hide_index=True, use_container_width=True)
            pick_p = st.selectbox("Open a proposal", [p["proposal_id"] for p in d2.get("proposals", [])] or ["-"])
            pp = next((p for p in d2.get("proposals", []) if p["proposal_id"] == pick_p), None)
            if pp:
                st.markdown(f"**Why (verified):** {pp['rationale']}  \n**Expected risk reduction:** "
                            f"{pp.get('expected_risk_reduction') or '-'}  \n**Rollback:** {pp.get('rollback') or '-'}")
                if pp.get("ai_rationale"):
                    st.markdown(f"**Advisor (AI inference):** {pp['ai_rationale']}")
                if pp.get("diff"):
                    st.code(pp["diff"][:6000], language="diff")
        with t3:
            if verdict == "not_run":
                st.info("No approved proposal with a patch was validated.")
            else:
                before = {s["step"].split(": ", 1)[1]: s for s in val.get("steps_before", [])}
                st.dataframe(pd.DataFrame([{
                    "Step": s["step"].split(": ", 1)[1],
                    "Before (unchanged)": before.get(s["step"].split(": ", 1)[1], {}).get("status", "-"),
                    "After (remediated)": s["status"], "Seconds": s["seconds"]} for s in val.get("steps_after", [])]),
                    hide_index=True, use_container_width=True)
                for s in val.get("steps_after", []) + val.get("steps_before", []):
                    if s["status"] in ("failed", "timeout"):
                        with st.expander(f"{s['step']}: {s['status']} (log)"):
                            st.code(s.get("log", ""))
                sd = val.get("sbom_diff") or {}
                c1, c2 = st.columns(2)
                c1.markdown("**SBOM changes**  \n" + "  \n".join(f"↕ {x}" for x in sd.get("changed", [])[:20]))
                KIND = {"introduced": "🆕 introduced", "still_vulnerable": "➡️ still vulnerable", "expected": "✔️ expected"}
                c2.markdown("**Findings that only exist after the fix**  \n" + "  \n".join(
                    f"{KIND.get(n.get('kind'), n.get('kind'))}: {n['title'][:90]}" for n in val.get("new", [])))
                st.caption(f"Resolved: {', '.join(val.get('resolved', []))}  \nRemaining: "
                           f"{', '.join(val.get('remaining', []))}")
        with t4:
            b1, b2, b3, b4 = st.columns(4)
            if (D2 / "remediation_report.html").exists():
                b1.download_button("remediation_report.html", (D2 / "remediation_report.html").read_bytes(),
                                   file_name=f"{name}.remediation_report.html", mime="text/html")
            if (D2 / "remediation_report.pdf").exists():
                b2.download_button("remediation_report.pdf", (D2 / "remediation_report.pdf").read_bytes(),
                                   file_name=f"{name}.remediation_report.pdf", mime="application/pdf")
            if (D2 / "remediation.patch").exists():
                b3.download_button("remediation.patch", (D2 / "remediation.patch").read_bytes(),
                                   file_name=f"{name}.remediation.patch", mime="text/x-diff")
            b4.download_button("day2.json", day2_f.read_bytes(), file_name=f"{name}.day2.json", mime="application/json")
            if (D2 / "remediation_report.md").exists():
                with st.expander("Show the full remediation report", expanded=False):
                    st.markdown((D2 / "remediation_report.md").read_text(encoding="utf-8"))
