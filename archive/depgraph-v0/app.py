import json, subprocess, sys
from pathlib import Path
import itertools
import networkx as nx
import streamlit as st
import streamlit.components.v1 as components

st.set_page_config(page_title="Supply Chain Guardian: Dependency Graph", layout="wide")
st.title("🛡️ Supply Chain Guardian: Dependency Graph")

HERE = Path(__file__).resolve().parent
PRESETS = {
    "sscg-demo-target (ours)": HERE.parent / "sscg-demo-target",
    "nodejs-goof (snyk-labs)": HERE.parent.parent / "dependency" / "nodejs-goof",
}
choice = st.selectbox("Demo repository", list(PRESETS) + ["Other path..."])
default = str(PRESETS.get(choice, ""))
repo = st.text_input("Repository path", default, key=f"repo:{choice}")
name = Path(repo).name
out = HERE / "out" / name
c1, c2, c3 = st.columns([1, 1, 2])
osv = c1.checkbox("Vulnerability overlay (OSV)", value=True)
offline = c2.checkbox("Offline (cache only)", value=False)
focus = c3.text_input("Focus on package (optional)")

if st.button("Build graph", type="primary"):
    cmd = [sys.executable, str(HERE / "depgraph.py"), repo, "--out", str(out)]
    cmd += ["--osv"] * osv + ["--offline"] * offline + (["--focus", focus] if focus else [])
    with st.spinner("Discovering manifests and resolving dependencies..."):
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", cwd=HERE)
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
