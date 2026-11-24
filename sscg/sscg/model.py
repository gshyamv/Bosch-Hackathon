"""Graph model: repo -> app (one per manifest / Dockerfile / workflow) -> component -> component ..."""
from __future__ import annotations

from urllib.parse import quote

import networkx as nx

# Ecosystems that are supply-chain components but not code libraries.
NON_LIBRARY = {"docker", "github-actions", "url"}


def purl(eco: str, name: str, version: str) -> str:
    if eco == "npm":
        return f"pkg:npm/{quote(name, safe='/')}@{version}"
    if eco == "pypi":
        return f"pkg:pypi/{name}@{version}"
    if eco == "maven":
        g, _, a = name.partition(":")
        return f"pkg:maven/{g}/{a}@{version}"
    eco = {"rubygems": "gem", "go": "golang"}.get(eco, eco)
    return f"pkg:{eco}/{name}@{version}"


class DepGraph:
    def __init__(self, repo_name: str):
        self.G = nx.DiGraph()
        self.top = f"repo:{repo_name}"
        self.G.add_node(self.top, kind="repo", label=repo_name, ecosystem="-")
        self.notes: list[str] = []

    def app(self, manifest_rel: str, eco: str, name: str, version: str = "") -> str:
        rid = f"app:{manifest_rel}"
        self.G.add_node(rid, kind="app", ecosystem=eco, name=name, version=version,
                        label=f"{name}@{version}" if version else name, source=manifest_rel)
        self.G.add_edge(self.top, rid)
        return rid

    def pkg(self, eco: str, name: str, version: str, nid: str | None = None, **attrs) -> str:
        nid = nid or purl(eco, name, version)
        scope = attrs.pop("scope", "prod")
        label = attrs.pop("label", None) or (f"{name}@{version}" if version else name)
        if nid not in self.G:
            self.G.add_node(nid, kind="package", ecosystem=eco, name=name, version=version,
                            label=label, direct=False, scope=scope, **attrs)
        else:
            node = self.G.nodes[nid]
            if scope == "prod":
                node["scope"] = "prod"  # prod anywhere wins over dev/test/build/ci
            for k, v in attrs.items():
                node.setdefault(k, v)
        return nid

    def dep(self, parent: str, child: str, spec: str = "", direct: bool = False, location: str = ""):
        """location = file:line of this particular use (one component can be used in several files)."""
        if parent == child:
            return
        self.G.add_edge(parent, child, spec=spec or "", **({"location": location} if location else {}))
        if direct:
            self.G.nodes[child]["direct"] = True
