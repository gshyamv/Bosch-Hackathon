"""Relevance + root-cause clusters (ported from VulnerabilityVision, on SSCG's purl nodes).

show = has a finding, is a direct dependency, or lies on a path to a package with a finding.
cluster = findings sharing one root cause: the direct dependency that pulls the packages in, an image, or a file.
"""
from __future__ import annotations

import hashlib
import re

import networkx as nx

EXPOSURE = {"prod": "runtime", "dev": "build-time", "build": "build-time", "ci": "build-time", "test": "test-only",
            "optional": "optional-platform"}
WEIGHT = {"runtime": 1.0, "build-time": 0.6, "optional-platform": 0.3, "test-only": 0.2}


def compute(dg) -> dict[str, dict]:
    G = dg.G
    hit = {n for n, a in G.nodes(data=True) if a.get("findings") or a.get("vulns") or a.get("suspicious")}
    path = set().union(*(nx.ancestors(G, n) for n in hit)) if hit else set()
    out = {}
    for n, a in G.nodes(data=True):
        why = ("has findings" if n in hit else "structural" if a["kind"] != "package" else "direct dependency"
               if a.get("direct") else "on a path to a finding" if n in path else None)
        out[n] = {"show": why is not None, "reason": why or "transitive, no finding below it",
                  "exposure": EXPOSURE.get(a.get("scope"), "runtime")}
    return out


def _root(dg, n: str) -> str:
    """The first package on the shortest path from the repository (= the direct dependency)."""
    if not nx.has_path(dg.G, dg.top, n):
        return n
    return next((x for x in nx.shortest_path(dg.G, dg.top, n) if dg.G.nodes[x]["kind"] == "package"), n)


def clusters(dg, findings: list) -> list[dict]:
    groups: dict[tuple, list] = {}
    for f in findings:
        n = (f.get("component") or {}).get("id")
        if n and n in dg.G:
            key = ("image" if dg.G.nodes[n]["ecosystem"] == "docker" else "dependency", _root(dg, n))
        else:
            key = ("file", re.sub(r":\d+$", "", f.get("location") or "repository"))
        groups.setdefault(key, []).append(f)
    out = []
    for (kind, root), fs in groups.items():
        a = dg.G.nodes.get(root, {})
        nodes = sorted({f["component"]["id"] for f in fs if f.get("component")})
        exp = max((EXPOSURE.get((f.get("component") or {}).get("scope"), "runtime") for f in fs), key=WEIGHT.get)
        label = a.get("label", root)
        out.append({"cluster_id": "cl-" + hashlib.sha1(f"{kind}|{root}".encode()).hexdigest()[:10], "kind": kind,
                    "root": label, "root_id": root, "node_ids": nodes, "exposure": exp,
                    "title": f"{len(fs)} finding(s) via {label}", "finding_ids": [f["finding_id"] for f in fs],
                    "evidence_ids": [f["finding_id"] for f in fs],
                    "score": round(max(f["risk"]["score"] for f in fs) * WEIGHT[exp], 2)})
    return sorted(out, key=lambda c: (-c["score"], c["cluster_id"]))


def annotate(proposals: list, cls: list) -> None:
    """Group proposals by root cause; one proposal may touch several clusters."""
    for p in proposals:
        mine = [c for c in cls if set(c["finding_ids"]) & set(p["finding_ids"])]
        p["cluster_ids"] = [c["cluster_id"] for c in mine]
        wide = [c for c in mine if c["kind"] == "dependency" and len(c["finding_ids"]) > len(p["finding_ids"])]
        for c in wide[:2]:
            p["notes"] = p.get("notes", []) + [
                f"root cause {c['cluster_id']}: {c['root']} pulls in packages with {len(c['finding_ids'])} findings "
                f"({', '.join(c['finding_ids'][:6])}); upgrading it may resolve several at once (not verified)"]
