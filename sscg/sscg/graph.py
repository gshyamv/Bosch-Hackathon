"""Pillar 2: the dependency graph view: depth, dependency paths ("why is X here?"), origins, inventory."""
from __future__ import annotations

import collections
import itertools
from urllib.parse import urlparse

import networkx as nx

from .model import NON_LIBRARY, DepGraph

TRUSTED_NPM_HOSTS = {"registry.npmjs.org", "registry.yarnpkg.com"}


def compute_depth(dg: DepGraph):
    dist = nx.single_source_shortest_path_length(dg.G, dg.top)
    for n, a in dg.G.nodes(data=True):
        if a["kind"] == "package":
            a["depth"] = dist[n] - 1 if n in dist else None  # 1 = direct dependency
            a["dependents"] = dg.G.in_degree(n)


def find_nodes(G, query: str):
    q = query.lower()
    return [n for n, a in G.nodes(data=True) if a["kind"] == "package"
            and (str(a.get("name", "")).lower() == q or str(a.get("label", "")).lower() == q or n.lower() == q)]


def why(dg: DepGraph, query: str, k: int = 5):
    """All (up to k) shortest dependency paths that pull `query` into the application."""
    out = {}
    for n in find_nodes(dg.G, query):
        paths = itertools.islice(nx.shortest_simple_paths(dg.G, dg.top, n), k) if nx.has_path(dg.G, dg.top, n) else []
        out[n] = [[dg.G.nodes[x]["label"] for x in p[1:]] for p in paths]
    return out


def _inventory(G) -> dict:
    """Container images, Dockerfiles, CI workflows and downloaded files, as plain facts."""
    A = lambda n: G.nodes[n]
    kids = lambda n, eco: [c for c in G.successors(n) if A(c).get("ecosystem") == eco]
    images = [{"image": a["label"], "registry": a.get("registry"), "repository": a.get("repository"),
               "tag": a.get("tag"), "digest": a.get("digest") or None, "pinned_by_digest": a.get("pinned_by_digest"),
               "official_image": a.get("official_image"), "scope": a.get("scope"),
               "used_in": [G.edges[p, n].get("location") or A(p)["source"]
                           for p in G.predecessors(n) if A(p)["kind"] == "app"]}
              for n, a in G.nodes(data=True) if a["kind"] == "package" and a["ecosystem"] == "docker"]
    dockerfiles = [{"file": a["source"], "stages": a.get("stages"), "runs_as": a.get("runs_as"),
                    "images": [A(c)["label"] for c in kids(n, "docker")],
                    "downloads": [A(c)["name"] for c in kids(n, "url")]}
                   for n, a in G.nodes(data=True) if a["kind"] == "app" and a["ecosystem"] == "docker"]
    workflows = [{"workflow": a["name"], "file": a["source"], "triggers": a.get("triggers"),
                  "permissions": a.get("permissions"),
                  "actions": [{"action": A(c)["label"], "ref": A(c).get("ref"), "pinned_to_sha": A(c).get("pinned_to_sha"),
                               "source": G.edges[n, c].get("location") or A(c).get("source")}
                              for c in kids(n, "github-actions")],
                  "images": [A(c)["label"] for c in kids(n, "docker")],
                  "downloads": [A(c)["name"] for c in kids(n, "url")]}
                 for n, a in G.nodes(data=True) if a["kind"] == "app" and a["ecosystem"] == "github-actions"]
    artifacts = [{"url": a["name"], "host": a.get("host"), "scope": a.get("scope"), "source": a.get("source")}
                 for n, a in G.nodes(data=True) if a["kind"] == "package" and a["ecosystem"] == "url"]
    return {"container_images": images, "dockerfiles": dockerfiles,
            "ci_workflows": workflows, "remote_artifacts": artifacts}


def summarize(dg: DepGraph) -> dict:
    G = dg.G
    A = lambda n: G.nodes[n]
    comps = [n for n, a in G.nodes(data=True) if a["kind"] == "package"]
    pk = [n for n in comps if A(n)["ecosystem"] not in NON_LIBRARY]  # code libraries
    pkg_set = set(pk)
    by_name = collections.defaultdict(set)
    for n in pk:
        by_name[(A(n)["ecosystem"], A(n)["name"])].add(A(n)["version"])
    blast = sorted(((len(nx.ancestors(G, n) & pkg_set), A(n)["label"]) for n in pk), reverse=True)[:10]
    heavy = sorted(((len(nx.descendants(G, n)), A(n)["label"]) for n in pk if A(n).get("direct")), reverse=True)[:10]
    hosts = collections.Counter(urlparse(A(n)["resolved"]).hostname or "local"
                                for n in comps if A(n).get("resolved"))
    vulnerable = [n for n in pk if A(n).get("vulns")]
    vuln_paths = []
    for n in sorted(vulnerable, key=lambda n: (A(n).get("depth") or 0), reverse=True):
        if nx.has_path(G, dg.top, n):
            p = nx.shortest_path(G, dg.top, n)
            vuln_paths.append({"package": A(n)["label"], "depth": A(n).get("depth"), "advisories": len(A(n)["vulns"]),
                               "path": " -> ".join(A(x)["label"] for x in p[1:])})
    inv = _inventory(G)
    return {
        "apps": [G.nodes[n]["label"] + f"  ({G.nodes[n]['source']})" for n in G.successors(dg.top)],
        "components_total": len(comps),
        "packages": len(pk),
        "edges": G.number_of_edges(),
        "by_ecosystem": dict(collections.Counter(A(n)["ecosystem"] for n in comps)),
        "direct": sum(1 for n in pk if A(n).get("direct")),
        "transitive": sum(1 for n in pk if not A(n).get("direct")),
        "max_depth": max((A(n).get("depth") or 0 for n in pk), default=0),
        "depth_histogram": dict(sorted(collections.Counter(A(n).get("depth") for n in pk
                                                           if A(n).get("depth") is not None).items())),
        "by_scope": dict(collections.Counter(A(n).get("scope") for n in comps)),
        "resolution": dict(collections.Counter(A(n).get("resolution") for n in comps)),
        "origins": dict(hosts),
        "untrusted_origins": [A(n)["label"] + " <- " + A(n)["resolved"] for n in pk if A(n).get("resolved")
                              and (urlparse(A(n)["resolved"]).hostname or "") not in TRUSTED_NPM_HOSTS
                              and A(n)["ecosystem"] == "npm"],
        "install_scripts": [A(n)["label"] for n in pk if A(n).get("install_script")],
        "duplicates": {f"{e}:{nm}": sorted(v) for (e, nm), v in by_name.items() if len(v) > 1},
        "top_blast_radius": [{"package": l, "dependents_transitive": c} for c, l in blast],
        "heaviest_direct_deps": [{"package": l, "brings_in": c} for c, l in heavy],
        "vulnerable_packages": len(vulnerable),
        "vulnerable_paths": vuln_paths[:50],
        "cycles": len(list(itertools.islice(nx.simple_cycles(G), 100))),
        **inv,
        "notes": dg.notes,
    }


def view(dg: DepGraph, focus: str | None, max_depth: int | None, limit: int = 600) -> nx.DiGraph:
    """The part of the graph to draw: everything, one package's neighbourhood, or the top levels."""
    G = dg.G
    if focus:
        keep = set()
        for n in find_nodes(G, focus):
            keep |= nx.ancestors(G, n) | nx.descendants(G, n) | {n}
        return G.subgraph(keep).copy()
    if max_depth is None and G.number_of_nodes() > limit:
        max_depth = 2
        dg.notes.append(f"graph.html limited to depth {max_depth} + vulnerable paths "
                        f"({G.number_of_nodes()} nodes); use --focus/--max-depth")
    if max_depth is None:
        return G
    keep = {n for n, a in G.nodes(data=True) if a["kind"] != "package" or (a.get("depth") or 99) <= max_depth}
    for n, a in G.nodes(data=True):  # always keep vulnerable / suspicious nodes and their path
        if (a.get("vulns") or a.get("suspicious")) and nx.has_path(G, dg.top, n):
            keep |= set(nx.shortest_path(G, dg.top, n))
    return G.subgraph(keep).copy()
