"""Build an interactive dependency graph from `npm ls --all --json` output.

Usage:
    python build_graph.py nodejs-goof/tree.json                 # build graph.html + print stats
    python build_graph.py nodejs-goof/tree.json --trace qs      # also print every path to qs
    python build_graph.py nodejs-goof/tree.json -o out.html

Nodes are keyed by name@version, so a package that npm de-duplicates
appears once, with an edge from every package that needs it.
"""

import argparse
import json
import sys
from collections import Counter

import networkx as nx
from pyvis.network import Network

COLORS = {
    "root": "#e15759",        # red    - the app itself
    "direct": "#4e79a7",      # blue   - listed in package.json
    "transitive": "#f28e2b",  # orange - pulled in by something else
}


def load_tree(path):
    with open(path, encoding="utf-8-sig") as f:  # -sig tolerates a BOM from PowerShell
        return json.load(f)


def build_graph(tree):
    g = nx.DiGraph()
    root = f"{tree.get('name', 'root')}@{tree.get('version', '0.0.0')}"
    g.add_node(root, name=tree.get("name", "root"), version=tree.get("version", ""), kind="root")

    def walk(parent, deps):
        for name, info in (deps or {}).items():
            version = info.get("version", "?")
            node = f"{name}@{version}"
            seen = node in g
            if not seen:
                g.add_node(node, name=name, version=version, kind="transitive")
            g.add_edge(parent, node)
            # Deduped entries carry no children; the full copy is walked elsewhere.
            if not seen or info.get("dependencies"):
                walk(node, info.get("dependencies"))

    walk(root, tree.get("dependencies"))
    for child in g.successors(root):
        g.nodes[child]["kind"] = "direct"
    return g, root


def stats(g, root):
    kinds = Counter(d["kind"] for _, d in g.nodes(data=True))
    names = {d["name"] for n, d in g.nodes(data=True) if n != root}
    multi = Counter(d["name"] for n, d in g.nodes(data=True) if n != root)
    depth = nx.single_source_shortest_path_length(g, root)
    return {
        "packages": g.number_of_nodes() - 1,
        "unique_names": len(names),
        "direct": kinds["direct"],
        "transitive": kinds["transitive"],
        "edges": g.number_of_edges(),
        "max_depth": max(depth.values()),
        "multi_version": sorted(((n, c) for n, c in multi.items() if c > 1), key=lambda x: -x[1]),
        "most_depended_on": sorted(
            ((n, g.in_degree(n)) for n in g if n != root), key=lambda x: -x[1]
        )[:10],
    }


def trace(g, root, name, limit=20):
    """Return every simple path from root to any version of `name`, shortest first."""
    targets = [n for n, d in g.nodes(data=True) if d["name"] == name]
    paths = []
    for t in targets:
        for p in nx.all_simple_paths(g, root, t, cutoff=12):
            paths.append(p)
            if len(paths) >= limit * 5:
                break
    paths.sort(key=len)
    return targets, paths[:limit]


def export_html(g, root, out_path, s):
    net = Network(
        height="900px", width="100%", directed=True,
        bgcolor="#ffffff", font_color="#222222",
        select_menu=False, filter_menu=False, cdn_resources="remote",
    )
    depth = nx.single_source_shortest_path_length(g, root)
    for n, d in g.nodes(data=True):
        kind = d["kind"]
        parents = sorted(g.predecessors(n))
        title = (
            f"{n}\n{kind} dependency, depth {depth.get(n, '?')}\n"
            f"needed by {len(parents)}: {', '.join(parents[:8])}{' ...' if len(parents) > 8 else ''}\n"
            f"depends on {g.out_degree(n)}"
        )
        size = 40 if kind == "root" else 12 + min(g.in_degree(n), 20) * 1.5
        net.add_node(
            n, label=d["name"] if kind != "transitive" else d["name"],
            title=title, color=COLORS[kind], size=size,
            shape="dot", font={"size": 22 if kind != "transitive" else 12},
        )
    for u, v in g.edges():
        net.add_edge(u, v, color="#bbbbbb", width=0.6, arrows={"to": {"scaleFactor": 0.4}})

    net.set_options(json.dumps({
        "physics": {
            "solver": "forceAtlas2Based",
            "forceAtlas2Based": {"gravitationalConstant": -60, "springLength": 80, "avoidOverlap": 0.4},
            "stabilization": {"iterations": 400},
        },
        "interaction": {"hover": True, "tooltipDelay": 100, "navigationButtons": True},
        "edges": {"smooth": False},
    }))
    html = net.generate_html()

    legend = f"""
<div style="position:fixed;top:12px;left:12px;z-index:10;background:#fff;border:1px solid #ddd;
            border-radius:8px;padding:12px 16px;font:14px sans-serif;box-shadow:0 2px 8px #0002">
  <b>{root}</b><br>
  <span style="color:{COLORS['root']}">&#9679;</span> app &nbsp;
  <span style="color:{COLORS['direct']}">&#9679;</span> direct ({s['direct']}) &nbsp;
  <span style="color:{COLORS['transitive']}">&#9679;</span> transitive ({s['transitive']})<br>
  {s['packages']} packages &middot; {s['edges']} edges &middot; max depth {s['max_depth']}<br>
  <small>Node size = number of packages that depend on it. Hover for details.</small>
</div>"""
    html = html.replace("<body>", "<body>" + legend, 1)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tree", help="output of: npm ls --all --json --package-lock-only")
    ap.add_argument("-o", "--out", default="graph.html")
    ap.add_argument("--trace", action="append", default=[], help="package name to trace (repeatable)")
    args = ap.parse_args()

    g, root = build_graph(load_tree(args.tree))
    s = stats(g, root)

    print(f"Root: {root}")
    print(f"Total packages (name@version): {s['packages']}  ({s['unique_names']} unique names)")
    print(f"  direct:     {s['direct']}")
    print(f"  transitive: {s['transitive']}  ({s['transitive'] / s['packages']:.0%} of all packages)")
    print(f"Edges: {s['edges']}   Max depth: {s['max_depth']}")
    print("Most depended-on:", ", ".join(f"{n} ({c})" for n, c in s["most_depended_on"][:5]))
    if s["multi_version"]:
        print("Installed in several versions:", ", ".join(f"{n} x{c}" for n, c in s["multi_version"][:8]))

    for name in args.trace:
        targets, paths = trace(g, root, name)
        print(f"\nPaths to {name}: versions present = {targets or 'none'}")
        for p in paths:
            print("  " + " -> ".join(p))

    export_html(g, root, args.out, s)
    print(f"\nWrote {args.out}")


if __name__ == "__main__":
    sys.exit(main())
