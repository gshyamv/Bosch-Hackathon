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

import networkx as nx
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

ROOT = Path(__file__).resolve().parent.parent          # sscg/
sys.path.insert(0, str(ROOT))
from sscg.report import _ev as evidence_text  # noqa: E402

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

if st.button("Scan repository", type="primary"):
    cmd = [sys.executable, "-m", "sscg", "scan", repo, "--out", str(out), "--top", "0"]
    cmd += (["--base", base] if base.strip() else ["--no-diff"]) + ([] if osv else ["--no-vulns"])
    cmd += ["--offline"] * offline + (["--focus", focus] if focus else [])
    with st.spinner("Discovering components, building the SBOM and graph, detecting risks..."):
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
    left, right = st.columns([3, 1])
    with left:
        components.html((out / "graph.html").read_text(encoding="utf-8"), height=820, scrolling=True)
    with right:
        st.markdown("**Legend**  \n★ repo · 🟩 manifest / Dockerfile / workflow  \n"
                    "🟠 npm · 🔵 PyPI · 🟣 Maven · ■ container image · ▲ CI action · ⚪ downloaded file  \n"
                    "◆ suspicious (has an anomaly finding, install script or untrusted origin)  \n"
                    "🔴 has published advisories · big = direct · small = transitive")
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
d1, d2 = st.columns(2)
d1.download_button("Download findings.json", (out / "findings.json").read_bytes(), file_name=f"{name}.findings.json",
                   mime="application/json")
if (out / "report.md").exists():
    d2.download_button("Download report.md", (out / "report.md").read_bytes(), file_name=f"{name}.report.md",
                       mime="text/markdown")
    with st.expander("Show the full evidence report"):
        st.markdown((out / "report.md").read_text(encoding="utf-8"))

for n in s["notes"]:
    st.caption("ℹ️ " + n)
