"""Streamlit dashboard: Day 1 pillars 1-2 (Discover components, Build the supply chain view).

Run from the sscg/ folder:  streamlit run ui/app.py
"""
import itertools
import json
import subprocess
import sys
from pathlib import Path

import networkx as nx
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

ROOT = Path(__file__).resolve().parent.parent          # sscg/
TARGETS = ROOT.parent / "targets"
PRESETS = {
    "sscg-demo-target (ours)": TARGETS / "sscg-demo-target",
    "nodejs-goof (snyk-labs)": TARGETS / "nodejs-goof",
}

st.set_page_config(page_title="Supply Chain Guardian: Supply Chain View", layout="wide")
st.title("🛡️ Supply Chain Guardian: Supply Chain View")
st.caption("Day 1 · ① Discover components · ② Build the supply chain view (SBOM, dependency graph, origins, "
           "container images and CI/CD workflows)")

choice = st.selectbox("Repository", list(PRESETS) + ["Other path..."])
repo = st.text_input("Repository path", str(PRESETS.get(choice, "")), key=f"repo:{choice}")
name = Path(repo).name
out = ROOT / "out" / name
c1, c2, c3 = st.columns([1, 1, 2])
osv = c1.checkbox("Vulnerability overlay (OSV)", value=True)
offline = c2.checkbox("Offline (cache only)", value=False)
focus = c3.text_input("Focus on package (optional)")

if st.button("Scan repository", type="primary"):
    cmd = [sys.executable, "-m", "sscg", "scan", repo, "--out", str(out)]
    cmd += ["--osv"] * osv + ["--offline"] * offline + (["--focus", focus] if focus else [])
    with st.spinner("Discovering manifests, lockfiles, Dockerfiles and workflows..."):
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", cwd=ROOT)
    if r.returncode != 0:
        st.error(r.stderr[-2000:])

if not (out / "summary.json").exists():
    st.info("No scan yet for this repository. Click **Scan repository**.")
    st.stop()

s = json.loads((out / "summary.json").read_text(encoding="utf-8"))

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
    left, right = st.columns([3, 1])
    with left:
        html_file = (out / "graph.html").resolve()
        components.html(html_file.read_text(encoding="utf-8"), height=820, scrolling=True)
    with right:
        st.markdown("**Legend**  \n★ repo · 🟩 manifest / Dockerfile / workflow  \n"
                    "🟠 npm · 🔵 PyPI · 🟣 Maven · ■ container image · ▲ CI action · ⚪ downloaded file  \n"
                    "◆ install script / untrusted origin · 🔴 has published advisories  \n"
                    "big = direct · small = transitive")
        st.markdown("**Top blast radius**")
        st.dataframe(s["top_blast_radius"], hide_index=True)
        st.markdown("**Heaviest direct deps**")
        st.dataframe(s["heaviest_direct_deps"], hide_index=True)

    st.subheader("🔎 Why is this package here?")
    q = st.text_input("Package name", "minimist")
    if q:
        d = json.loads((out / "graph.json").read_text(encoding="utf-8"))
        G = nx.DiGraph()
        for n in d["nodes"]:
            G.add_node(n["id"], **n)
        for e in d["edges"]:
            G.add_edge(e["source"], e["target"])
        top = next(n for n in G if n.startswith("repo:"))
        hits = [n for n, a in G.nodes(data=True) if str(a.get("name", "")).lower() == q.lower()]
        if not hits:
            st.info("Not in the graph")
        for h in hits:
            a = G.nodes[h]
            st.markdown(f"**{a['label']}** · {a.get('ecosystem')} · scope `{a.get('scope')}` · "
                        f"origin `{a.get('resolved') or a.get('source')}`")
            for p in itertools.islice(nx.shortest_simple_paths(G, top, h), 5):
                st.code("  →  ".join(G.nodes[x]["label"] for x in p[1:]))
    if s["vulnerable_paths"]:
        with st.expander(f"Dependency paths to packages with published advisories ({s['vulnerable_packages']})"):
            st.dataframe(s["vulnerable_paths"], hide_index=True)
    with st.expander(f"Duplicates: same package in several versions ({len(s['duplicates'])})"):
        st.json(s["duplicates"])

with tab_sbom:
    sb = out / "sbom.cdx.json"
    bom = json.loads(sb.read_text(encoding="utf-8"))
    types = pd.Series([c["type"] for c in bom["components"]]).value_counts()
    k = st.columns(4)
    k[0].metric("Format", f"{bom['bomFormat']} {bom['specVersion']}")
    k[1].metric("SBOM components", len(bom["components"]),
                help="All supply-chain components plus one entry per manifest, Dockerfile and workflow")
    k[2].metric("Dependency entries", len(bom["dependencies"]))
    k[3].metric("With hashes", sum(1 for c in bom["components"] if c.get("hashes")))
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

for n in s["notes"]:
    st.caption("ℹ️ " + n)
