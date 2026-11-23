"""Graph exports: graph.json (machine-readable), graph.html (interactive, offline), graph.mmd (Mermaid).

render_html() draws a (sub)graph in one of two colourings:
  "ecosystem"  : colour by ecosystem, red fill = published advisories        (graph.html)
  "dependency" : blue = direct, orange = transitive, red border = advisories (direct/transitive views)
With layered=True nodes are placed in columns by dependency level: repo | manifests | direct | depth 2 | depth 3 ...
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

import networkx as nx

from .graph import TRUSTED_NPM_HOSTS

ECO_COLOR = {"npm": "#e8a33d", "pypi": "#4b8bbe", "maven": "#8e6bbf",
             "docker": "#1d63ed", "github-actions": "#24292f", "url": "#7f8c8d"}
ECO_SHAPE = {"docker": "square", "github-actions": "triangle"}
# direct / transitive: categorical slots 1-2 of the reference palette (validated on the light chart surface)
DEP_COLOR = {"direct": "#2a78d6", "transitive": "#eb6834"}
VULN_BORDER = "#d03b3b"   # status "critical"; always paired with the advisory text in the tooltip
INK, INK_2 = "#0b0b0b", "#52514e"
FACT_KEYS = ("registry", "tag", "digest", "pinned_by_digest", "official_image", "ref", "pinned_to_sha", "host")
APP_KEYS = ("triggers", "permissions", "stages", "runs_as")


def _safe(s) -> str:
    """Scanned repos are hostile: a lockfile 'version' could contain </script>. Neutralise HTML."""
    return str(s).replace("<", "‹").replace(">", "›").replace("&", "＆")


def _tooltip(a: dict, untrusted: bool) -> str:
    return "\n".join(filter(None, [  # all values already passed through _safe()
        a["label"], f"ecosystem: {a['ecosystem']}  scope: {a.get('scope')}",
        f"{'DIRECT' if a.get('direct') else 'transitive'}  depth: {a.get('depth')}  dependents: {a.get('dependents')}",
        f"resolution: {a.get('resolution')}", f"origin: {a.get('resolved')}" if a.get("resolved") else "",
        f"source: {a.get('source')}", "INSTALL SCRIPT" if a.get("install_script") else "",
        "UNTRUSTED ORIGIN" if untrusted else "",
        *[f"{k}: {a[k]}" for k in FACT_KEYS if a.get(k) not in (None, "")],
        f"{len(a['vulns'])} advisories: {', '.join(a['vulns'][:6])}" if a.get("vulns") else "",
        f"findings: {', '.join(a['findings'])}" if a.get("findings") else ""]))


def render_html(H: nx.DiGraph, mode: str = "ecosystem", layered: bool = False, small_labels: bool = True) -> str:
    """HTML for the graph. small_labels=False hides transitive labels (big views stay readable; hover still works)."""
    from pyvis.network import Network
    # no global font_color: pyvis would override every per-node font with it
    net = Network(height="800px", width="100%", directed=True, cdn_resources="in_line", bgcolor="#fcfcfb")
    boxes = mode == "dependency" and layered and small_labels  # readable tree: name inside a coloured box
    num = {n: i for i, n in enumerate(H.nodes)}  # numeric ids: no repo text in ids
    for n, a in H.nodes(data=True):
        a = {k: (_safe(v) if isinstance(v, str) else v) for k, v in a.items()}
        lvl = a.get("_level", {"repo": 0, "app": 1}.get(a["kind"], (a.get("depth") or 1) + 1))
        extra = {"level": lvl} if layered else {}
        if a["kind"] == "repo":
            net.add_node(num[n], label=a["label"], shape="star", color=INK if mode == "dependency" else "#333333",
                         size=30, **extra)
            continue
        if a["kind"] == "app":
            info = [f"{k}: {_safe(', '.join(map(str, a[k])) if isinstance(a[k], list) else a[k])}"
                    for k in APP_KEYS if a.get(k) not in (None, "", [])]
            dep = mode == "dependency"
            net.add_node(num[n], label=a["label"], shape="box", color=INK_2 if dep else "#2ca02c",
                         font={"color": "#ffffff" if dep else INK}, margin=8,
                         title="\n".join([f"{a['ecosystem']} manifest: {a['source']}"] + info), **extra)
            continue
        untrusted = bool(a.get("resolved")) and (urlparse(a["resolved"]).hostname or "") not in TRUSTED_NPM_HOSTS \
            and a["ecosystem"] == "npm"
        shape = "diamond" if (untrusted or a.get("install_script") or a.get("suspicious")) \
            else ECO_SHAPE.get(a["ecosystem"], "dot")
        direct = bool(a.get("direct"))
        if mode == "dependency":
            fill = DEP_COLOR["direct" if direct else "transitive"]
            color = {"background": fill, "border": VULN_BORDER if a.get("vulns") else fill,
                     "highlight": {"background": fill, "border": INK}}
            border = 4 if a.get("vulns") else 1
        else:
            color = "#d62728" if a.get("vulns") else ECO_COLOR.get(a["ecosystem"], "#7f8c8d")
            border = 3 if direct else 1
        tip = _tooltip(a, untrusted)
        if boxes:
            # name inside the box; dark ink clears 4.5:1 on both fills (white is only 3.2:1 on orange)
            mark = "◆ " if shape == "diamond" else ""
            net.add_node(num[n], label=mark + a["label"], title=tip, shape="box", color=color, margin=6,
                         borderWidth=3 if a.get("vulns") else 1, widthConstraint={"maximum": 260},
                         font={"color": INK, "size": 15 if direct else 13}, **extra)
            continue
        label = a["label"] if (direct or small_labels) else " "
        size = (14 if direct else 7) if layered else (20 if direct else 10)
        net.add_node(num[n], label=label, title=tip, color=color, size=size, shape=shape, borderWidth=border, **extra)
    for u, v, e in H.edges(data=True):
        net.add_edge(num[u], num[v], title=_safe(e.get("spec", "")), color="#c3c2b7", arrows="to")
    if layered:
        net.set_options(json.dumps({
            "layout": {"hierarchical": {"enabled": True, "direction": "LR", "sortMethod": "directed",
                                        "levelSeparation": 320 if boxes else 220,
                                        "nodeSpacing": 42 if boxes else 18, "treeSpacing": 60}},
            "physics": {"enabled": False},
            "edges": {"smooth": {"type": "cubicBezier", "forceDirection": "horizontal", "roundness": 0.4},
                      "width": 0.6},
            "interaction": {"hover": True, "navigationButtons": True}}))
    else:
        net.set_options('{"physics":{"solver":"forceAtlas2Based","stabilization":{"iterations":250}},'
                        '"interaction":{"hover":true,"navigationButtons":true}}')
    return net.generate_html(notebook=False)


def export_html(H: nx.DiGraph, path: Path):
    path.write_text(render_html(H), encoding="utf-8")


def export_mermaid(H: nx.DiGraph, path: Path, max_nodes: int = 80) -> bool:
    if H.number_of_nodes() > max_nodes:
        return False
    ids = {n: f"n{i}" for i, n in enumerate(H.nodes)}
    lines = ["graph LR"]
    for n, a in H.nodes(data=True):
        label = _safe(a["label"]).replace('"', "'")
        lines.append(f'  {ids[n]}["{label}"]' + (":::vuln" if a.get("vulns") else ""))
    lines += [f"  {ids[u]} --> {ids[v]}" for u, v in H.edges]
    lines.append("  classDef vuln fill:#f8d7da,stroke:#d62728")
    path.write_text("\n".join(lines), encoding="utf-8")
    return True


def export_json(G: nx.DiGraph, path: Path):
    path.write_text(json.dumps({
        "nodes": [{"id": n, **a} for n, a in G.nodes(data=True)],
        "edges": [{"source": u, "target": v, **e} for u, v, e in G.edges(data=True)],
    }, indent=1, default=str), encoding="utf-8")
