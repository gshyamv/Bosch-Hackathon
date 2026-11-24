"""The detection pipeline steps, shared by the `scan` CLI and the agent graph (agents/workers.py).

build  : discover     components (or consume an SBOM), OSV vulnerabilities, depth
detect : detect       vulnerability + rule findings, "what changed" against a base commit
emit   : evidence     SBOM, graph, summary, findings.json, report (md / html / pdf)
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from . import __version__, diff, findings, report, report_export, vulns
from .discover import discover
from .export import export_html, export_json, export_mermaid
from .graph import compute_depth, summarize, view, why
from .model import DepGraph
from .rules import Ctx, run_all
from .sbom import read_cyclonedx, write_cyclonedx
from .target import as_target


def build(target, sbom: Path | None = None, check_vulns: bool = True) -> DepGraph:
    """target: a Target, a folder, a GitHub URL or a page URL (target.as_target)."""
    target = as_target(target)
    dg = DepGraph(target.name)
    if sbom:
        read_cyclonedx(dg, sbom)  # consume
    elif target.kind == "live":
        from .discover.livepage import add_page
        target.head_dir()
        add_page(dg, target.page)
    else:
        found = discover(target.head_dir(), dg)
        if not found:
            dg.notes.append("no supported manifests found")
    if check_vulns and vulns.osv_overlay(dg):
        vulns.enrich(dg)
    dg.notes += [n for n in target.notes if n not in dg.notes]
    compute_depth(dg)
    return dg


def detect(target, dg: DepGraph, base_rev: str | None) -> tuple[list, object]:
    """Vulnerability findings + rule findings, marked 'new' if absent in the base commit."""
    target = as_target(target)
    repo = target.head_dir()
    with tempfile.TemporaryDirectory(prefix="sscg-base-") as tmp:
        change = diff.compute(target, dg, base_rev, Path(tmp)) if base_rev else None
        raws = findings.vulnerability_raws(dg) + run_all(Ctx(repo, dg, change))
        base_keys = None
        if change:
            base_raws = run_all(Ctx(change.base_dir, change.base_dg, None))
            base_keys = {r["key"] for r in base_raws} | {
                ("VULN", a["ecosystem"], a["name"], a["version"])
                for _, a in change.base_dg.G.nodes(data=True) if a["kind"] == "package"}
        fs = findings.build(dg, raws, change, base_keys)
        findings.add_permalinks(fs, target)
        return fs, change


def emit(target, out: Path, dg: DepGraph, fs: list, change, *, focus: str | None = None,
         max_depth: int | None = None, why_q=(), agentic: dict | None = None) -> dict:
    """Write every detection artifact. `agentic` (optional) adds the clearly separated AI section to the report.

    Shared by the plain `scan` command and the agent graph's Reporter node, so both produce identical evidence.
    """
    target = as_target(target)
    out.mkdir(parents=True, exist_ok=True)
    s = summarize(dg)
    H = view(dg, focus, max_depth)
    bom = write_cyclonedx(dg, out / "sbom.cdx.json")
    export_json(dg.G, out / "graph.json")
    export_html(H, out / "graph.html")
    has_mmd = export_mermaid(H, out / "graph.mmd")
    s["notes"] = dg.notes
    s["sbom"] = {"file": "sbom.cdx.json", "format": "CycloneDX 1.5 JSON",
                 "components": len(bom["components"]), "dependency_entries": len(bom["dependencies"])}
    s["why"] = {q: why(dg, q) for q in why_q}
    doc = findings.document(target.name, dg, fs, change, __version__)
    doc["scan"]["target"] = {"kind": target.kind, "display": target.display, "sha": target.sha}
    s["findings"] = doc["counts"]
    (out / "summary.json").write_text(json.dumps(s, indent=2), encoding="utf-8")
    (out / "findings.json").write_text(json.dumps(doc, indent=1, default=str), encoding="utf-8")
    md = report.render(doc, s, agentic)
    (out / "report.md").write_text(md, encoding="utf-8")
    report_files = report_export.write_all(md, out)
    files = ["sbom.cdx.json", "graph.json", "graph.html", "summary.json", "findings.json", "report.md",
             *report_files] + (["graph.mmd"] if has_mmd else [])
    return {"summary": s, "doc": doc, "files": files}


def print_console(target, out: Path, dg: DepGraph, fs: list, change, res: dict, top: int):
    s, doc = res["summary"], res["doc"]
    c = doc["counts"]
    print(f"\n=== Guardian scan: {as_target(target).display if not isinstance(target, Path) else target.name} ===")
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
    for f in fs[:top]:
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
    print(f"\nwrote {out}: " + ", ".join(res["files"]))
