"""Graph exports: graph.json (machine-readable), graph.html (interactive, offline), graph.mmd (Mermaid)."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

import networkx as nx

from .graph import TRUSTED_NPM_HOSTS

ECO_COLOR = {"npm": "#e8a33d", "pypi": "#4b8bbe", "maven": "#8e6bbf",
             "docker": "#1d63ed", "github-actions": "#24292f", "url": "#7f8c8d"}
ECO_SHAPE = {"docker": "square", "github-actions": "triangle"}
FACT_KEYS = ("registry", "tag", "digest", "pinned_by_digest", "official_image", "ref", "pinned_to_sha", "host")
APP_KEYS = ("triggers", "permissions", "stages", "runs_as")


def _safe(s) -> str:
    """Scanned repos are hostile: a lockfile 'version' could contain </script>. Neutralise HTML."""
    return str(s).replace("<", "‹").replace(">", "›").replace("&", "＆")


def export_html(H: nx.DiGraph, path: Path):
    from pyvis.network import Network
    net = Network(height="800px", width="100%", directed=True, cdn_resources="in_line")
    num = {n: i for i, n in enumerate(H.nodes)}  # numeric ids: no repo text in ids
    for n, a in H.nodes(data=True):
        a = {k: (_safe(v) if isinstance(v, str) else v) for k, v in a.items()}
        if a["kind"] == "repo":
            net.add_node(num[n], label=a["label"], shape="star", color="#333333", size=30)
            continue
        if a["kind"] == "app":
            extra = [f"{k}: {_safe(', '.join(map(str, a[k])) if isinstance(a[k], list) else a[k])}"
                     for k in APP_KEYS if a.get(k) not in (None, "", [])]
            net.add_node(num[n], label=a["label"], shape="box", color="#2ca02c",
                         title="\n".join([f"{a['ecosystem']} manifest: {a['source']}"] + extra))
            continue
        untrusted = a.get("resolved") and (urlparse(a["resolved"]).hostname or "") not in TRUSTED_NPM_HOSTS \
            and a["ecosystem"] == "npm"
        color = "#d62728" if a.get("vulns") else ECO_COLOR.get(a["ecosystem"], "#7f8c8d")
        tip = "\n".join(filter(None, [  # all values already passed through _safe()
            a["label"], f"ecosystem: {a['ecosystem']}  scope: {a.get('scope')}",
            f"{'DIRECT' if a.get('direct') else 'transitive'}  depth: {a.get('depth')}  dependents: {a.get('dependents')}",
            f"resolution: {a.get('resolution')}", f"origin: {a.get('resolved')}" if a.get("resolved") else "",
            f"source: {a.get('source')}", "INSTALL SCRIPT" if a.get("install_script") else "",
            "UNTRUSTED ORIGIN" if untrusted else "",
            *[f"{k}: {a[k]}" for k in FACT_KEYS if a.get(k) not in (None, "")],
            f"{len(a['vulns'])} advisories: {', '.join(a['vulns'][:6])}" if a.get("vulns") else ""]))
        shape = "diamond" if (untrusted or a.get("install_script")) else ECO_SHAPE.get(a["ecosystem"], "dot")
        net.add_node(num[n], label=a["label"], title=tip, color=color, size=20 if a.get("direct") else 10,
                     shape=shape, borderWidth=3 if a.get("direct") else 1)
    for u, v, e in H.edges(data=True):
        net.add_edge(num[u], num[v], title=_safe(e.get("spec", "")), color="#bbbbbb", arrows="to")
    net.set_options('{"physics":{"solver":"forceAtlas2Based","stabilization":{"iterations":250}},'
                    '"interaction":{"hover":true,"navigationButtons":true}}')
    path.write_text(net.generate_html(notebook=False), encoding="utf-8")


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
