"""CLI: python -m sscg scan <repo> [--out DIR] [--base REV] [--sbom FILE] [--offline] [--no-vulns] [--no-diff]
                                  [--why NAME ...] [--focus NAME] [--max-depth N]

Day 1 pipeline: Repository -> SBOM -> Dependency graph -> Risk detection -> Evidence
Outputs (default folder: out/<repo name>/):
  sbom.cdx.json  CycloneDX 1.5 SBOM                         (column 2)
  graph.html     interactive graph · graph.json · graph.mmd (column 2)
  summary.json   counts, origins, container / CI inventory  (columns 1-2)
  findings.json  vulnerabilities + anomalies with evidence  (columns 3-5)
  report.md      human-readable evidence report             (column 5)
  report.html    the same report as a standalone web page   (column 5)
  report.pdf     the same report as an A4 PDF               (column 5)
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from . import __version__, cache, diff, findings, report, report_export, vulns
from .discover import discover
from .export import export_html, export_json, export_mermaid
from .graph import compute_depth, summarize, view, why
from .model import DepGraph
from .rules import Ctx, run_all
from .sbom import read_cyclonedx, write_cyclonedx


def build(repo: Path, sbom: Path | None = None, check_vulns: bool = True) -> DepGraph:
    dg = DepGraph(repo.name)
    if sbom:
        read_cyclonedx(dg, sbom)  # consume
    else:
        found = discover(repo, dg)
        if not found:
            dg.notes.append("no supported manifests found")
    if check_vulns and vulns.osv_overlay(dg):
        vulns.enrich(dg)
    compute_depth(dg)
    return dg


def detect(repo: Path, dg: DepGraph, base_rev: str | None) -> tuple[list, object]:
    """Columns 3-4: vulnerability findings + rule findings, marked 'new' if absent in the base commit."""
    with tempfile.TemporaryDirectory(prefix="sscg-base-") as tmp:
        change = diff.compute(repo, dg, base_rev, Path(tmp)) if base_rev else None
        raws = findings.vulnerability_raws(dg) + run_all(Ctx(repo, dg, change))
        base_keys = None
        if change:
            base_raws = run_all(Ctx(change.base_dir, change.base_dg, None))
            base_keys = {r["key"] for r in base_raws} | {
                ("VULN", a["ecosystem"], a["name"], a["version"])
                for _, a in change.base_dg.G.nodes(data=True) if a["kind"] == "package"}
        return findings.build(dg, raws, change, base_keys), change


def scan(args):
    cache.OFFLINE = args.offline
    repo = args.repo.resolve()
    out = args.out or cache.ROOT / "out" / repo.name
    out.mkdir(parents=True, exist_ok=True)

    dg = build(repo, args.sbom, not args.no_vulns)
    fs, change = detect(repo, dg, None if (args.no_diff or args.sbom) else args.base)
    s = summarize(dg)
    H = view(dg, args.focus, args.max_depth)
    bom = write_cyclonedx(dg, out / "sbom.cdx.json")
    export_json(dg.G, out / "graph.json")
    export_html(H, out / "graph.html")
    has_mmd = export_mermaid(H, out / "graph.mmd")
    s["notes"] = dg.notes
    s["sbom"] = {"file": "sbom.cdx.json", "format": "CycloneDX 1.5 JSON",
                 "components": len(bom["components"]), "dependency_entries": len(bom["dependencies"])}
    s["why"] = {q: why(dg, q) for q in args.why}
    doc = findings.document(repo.name, dg, fs, change, __version__)
    s["findings"] = doc["counts"]
    (out / "summary.json").write_text(json.dumps(s, indent=2), encoding="utf-8")
    (out / "findings.json").write_text(json.dumps(doc, indent=1, default=str), encoding="utf-8")
    md = report.render(doc, s)
    (out / "report.md").write_text(md, encoding="utf-8")
    report_files = report_export.write_all(md, out)

    c = doc["counts"]
    print(f"\n=== Guardian scan: {repo.name} ===")
    print(f"  ① components      : {s['components_total']} ({s['packages']} libraries: {s['direct']} direct, "
          f"{s['transitive']} transitive, depth {s['max_depth']}) · {len(s['container_images'])} images · "
          f"{s['by_ecosystem'].get('github-actions', 0)} CI actions")
    print(f"  ② SBOM            : {s['sbom']['components']} components (CycloneDX 1.5)")
    if change:
        h, b = change.head, change.base
        print(f"  what changed      : {b['short']} -> {h['short']} by {h['author']}"
              f"{' (FIRST-TIME contributor)' if change.first_time_author else ''}: \"{h['message']}\"; "
              f"{len(change.files)} files, +{len(change.added)} / -{len(change.removed)} / ~{len(change.changed)} components")
    print(f"  ③ vulnerabilities : {c['vulnerabilities']} vulnerable components ({c['advisories']} advisories)")
    print(f"  ④ anomalies       : {c['anomalies']}  ({', '.join(f'{k} {v}' for k, v in c['by_rule'].items() if k != 'VULN')})")
    print(f"  ⑤ findings        : {c['total']} · " + " · ".join(f"{k} {v}" for k, v in c["by_level"].items())
          + f" · new in change {c['new_in_change']}")
    for f in fs[:args.top]:
        r = f["risk"]
        print(f"    {f['finding_id']} {r['level']:<8} {r['score']:>4}  {'NEW ' if f['new_in_change'] else '    '}"
              f"{f['title'][:110]}")
    for q, res in s["why"].items():
        for node, paths in res.items():
            print(f"  WHY {node}:")
            for p in paths:
                print("     " + " -> ".join(p))
    for n in dg.notes:
        print("  note:", n)
    print(f"\nwrote {out}: sbom.cdx.json, graph.json, graph.html, summary.json, findings.json, report.md, "
          + ", ".join(report_files) + (", graph.mmd" if has_mmd else ""))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m sscg", description="Software Supply Chain Guardian")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="discover, build the SBOM and graph, detect risks, write evidence")
    sc.add_argument("repo", type=Path, help="repository folder to scan (read only; nothing is installed or run)")
    sc.add_argument("--out", type=Path, help="output folder (default: out/<repo name>)")
    sc.add_argument("--base", default="HEAD~1", help="commit to compare against for 'what changed' (default HEAD~1)")
    sc.add_argument("--no-diff", action="store_true", help="skip the base-commit comparison")
    sc.add_argument("--sbom", type=Path, help="consume this CycloneDX JSON SBOM instead of scanning manifests")
    sc.add_argument("--no-vulns", action="store_true", help="skip vulnerability detection (OSV.dev)")
    sc.add_argument("--osv", action="store_true", help=argparse.SUPPRESS)  # kept for old commands; now the default
    sc.add_argument("--offline", action="store_true", help="answer API calls from .cache only")
    sc.add_argument("--why", nargs="*", default=[], help="show the dependency paths that pull in these packages")
    sc.add_argument("--focus", help="graph.html shows only this package's ancestors + descendants")
    sc.add_argument("--max-depth", type=int, help="graph.html shows only this many levels")
    sc.add_argument("--top", type=int, default=15, help="how many top findings to print (default 15)")
    args = ap.parse_args(argv)
    scan(args)


if __name__ == "__main__":
    sys.exit(main())
