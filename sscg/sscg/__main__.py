"""CLI: python -m sscg scan <repo> [--out DIR] [--sbom bom.cdx.json] [--osv] [--offline]
                                  [--why NAME ...] [--focus NAME] [--max-depth N]

Outputs (default folder: out/<repo name>/):
  sbom.cdx.json  CycloneDX 1.5 SBOM (components + dependency relationships)
  graph.json     nodes + edges + attributes (input for UI / later pillars)
  graph.html     interactive graph (offline)
  graph.mmd      Mermaid diagram (small graphs only)
  summary.json   counts, depth, origins, container / CI inventory, paths
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import cache
from .discover import discover
from .export import export_html, export_json, export_mermaid
from .graph import compute_depth, summarize, view, why
from .model import DepGraph
from .sbom import read_cyclonedx, write_cyclonedx
from .vulns import osv_overlay


def build(repo: Path, sbom: Path | None = None, osv: bool = False) -> DepGraph:
    dg = DepGraph(repo.name)
    if sbom:
        read_cyclonedx(dg, sbom)  # consume
    else:
        found = discover(repo, dg)
        if not found:
            dg.notes.append("no supported manifests found")
    if osv:
        osv_overlay(dg)
    compute_depth(dg)
    return dg


def scan(args):
    cache.OFFLINE = args.offline
    repo = args.repo.resolve()
    out = args.out or cache.ROOT / "out" / repo.name
    out.mkdir(parents=True, exist_ok=True)

    dg = build(repo, args.sbom, args.osv)
    s = summarize(dg)
    H = view(dg, args.focus, args.max_depth)
    bom = write_cyclonedx(dg, out / "sbom.cdx.json")  # generate
    export_json(dg.G, out / "graph.json")
    export_html(H, out / "graph.html")
    has_mmd = export_mermaid(H, out / "graph.mmd")
    s["notes"] = dg.notes
    s["sbom"] = {"file": "sbom.cdx.json", "format": "CycloneDX 1.5 JSON",
                 "components": len(bom["components"]), "dependency_entries": len(bom["dependencies"])}
    s["why"] = {q: why(dg, q) for q in args.why}
    (out / "summary.json").write_text(json.dumps(s, indent=2), encoding="utf-8")

    print(f"\n=== Supply chain view: {repo.name} ===")
    for k in ("apps", "components_total", "packages", "edges", "by_ecosystem", "direct", "transitive", "max_depth",
              "depth_histogram", "by_scope", "resolution", "origins", "vulnerable_packages", "cycles"):
        print(f"{k:>18}: {s[k]}")
    for k in ("untrusted_origins", "install_scripts"):
        if s[k]:
            print(f"{k:>18}: {s[k]}")
    print(f"{'duplicates':>18}: {len(s['duplicates'])} packages in several versions")
    print("   top blast radius:", ", ".join(f"{x['package']}({x['dependents_transitive']})" for x in s["top_blast_radius"][:5]))
    print("  heaviest direct  :", ", ".join(f"{x['package']}(+{x['brings_in']})" for x in s["heaviest_direct_deps"][:5]))
    for d in s["dockerfiles"]:
        print(f"  CONTAINER {d['file']}: images {d['images']}"
              + (f", runs as: {d['runs_as']}" if d["runs_as"] else "")
              + (f", downloads {d['downloads']}" if d["downloads"] else ""))
    for im in s["container_images"]:
        print(f"    image {im['image']}: registry {im['registry']}, official {im['official_image']}, "
              f"pinned by digest {im['pinned_by_digest']}, used in {im['used_in']}")
    for w in s["ci_workflows"]:
        print(f"  CI {w['file']} ({w['workflow']}): triggers {w['triggers']}, permissions: {w['permissions']}")
        for a in w["actions"]:
            print(f"    action {a['action']}  pinned to SHA: {a['pinned_to_sha']}  ({a['source']})")
        for u in w["downloads"]:
            print(f"    download {u}")
    for vp in s["vulnerable_paths"][:8]:
        print(f"  VULN path (depth {vp['depth']}, {vp['advisories']} adv): {vp['path']}")
    for q, res in s["why"].items():
        for node, paths in res.items():
            print(f"  WHY {node}:")
            for p in paths:
                print("     " + " -> ".join(p))
    for n in dg.notes:
        print("  note:", n)
    print(f"\n  SBOM: {s['sbom']['components']} components, {s['sbom']['dependency_entries']} dependency entries")
    print(f"wrote {out / 'sbom.cdx.json'}, {out / 'graph.json'}, {out / 'graph.html'}, {out / 'summary.json'}"
          + (f", {out / 'graph.mmd'}" if has_mmd else ""))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m sscg", description="Software Supply Chain Guardian")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="discover components, build the dependency graph and the SBOM")
    sc.add_argument("repo", type=Path, help="repository folder to scan (read only; nothing is installed or run)")
    sc.add_argument("--out", type=Path, help="output folder (default: out/<repo name>)")
    sc.add_argument("--sbom", type=Path, help="consume this CycloneDX JSON SBOM instead of scanning manifests")
    sc.add_argument("--osv", action="store_true", help="colour packages with published advisories (OSV.dev)")
    sc.add_argument("--offline", action="store_true", help="answer API calls from .cache only")
    sc.add_argument("--why", nargs="*", default=[], help="show the dependency paths that pull in these packages")
    sc.add_argument("--focus", help="graph.html shows only this package's ancestors + descendants")
    sc.add_argument("--max-depth", type=int, help="graph.html shows only this many levels")
    args = ap.parse_args(argv)
    scan(args)


if __name__ == "__main__":
    sys.exit(main())
