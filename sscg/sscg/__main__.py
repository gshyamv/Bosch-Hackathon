"""CLI: python -m sscg scan <repo> [--out DIR] [--base REV] [--sbom FILE] [--offline] [--no-vulns] [--no-diff]
                                  [--why NAME ...] [--focus NAME] [--max-depth N]
     python -m sscg agent <repo> [same options] [--llm auto|claude|gemini|groq|grok|none] [--day2-preview]
     python -m sscg agent . --llm groq --list-models     (which models your API key can use)
       (the same pipeline as a LangGraph multi-agent workflow; see docs/agentic.md; also writes agentic.json)

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
import sys
from pathlib import Path

from . import cache
from .pipeline import build, detect, emit, print_console  # noqa: F401  (kept importable from here)


def scan(args):
    cache.OFFLINE = args.offline
    repo = args.repo.resolve()
    out = args.out or cache.ROOT / "out" / repo.name

    dg = build(repo, args.sbom, not args.no_vulns)
    fs, change = detect(repo, dg, None if (args.no_diff or args.sbom) else args.base)
    res = emit(repo, out, dg, fs, change, focus=args.focus, max_depth=args.max_depth, why_q=args.why)
    print_console(repo, out, dg, fs, change, res, args.top)


def _scan_args(sc):
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


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):  # Windows consoles default to cp1252, which cannot print ① ... ⑤
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(prog="python -m sscg", description="Software Supply Chain Guardian")
    sub = ap.add_subparsers(dest="cmd", required=True)
    _scan_args(sub.add_parser("scan", help="discover, build the SBOM and graph, detect risks, write evidence"))
    ag = sub.add_parser("agent", help="the same Day 1 pipeline run as a LangGraph multi-agent workflow, "
                                      "with AI triage of suspicious changes and an AI evidence summary")
    _scan_args(ag)
    ag.add_argument("--llm", choices=["auto", "claude", "gemini", "groq", "grok", "none"],
                    help="LLM provider (default: SSCG_LLM_PROVIDER from .env, else auto = first provider with a key; "
                         "groq = Groq/GroqCloud, grok = xAI; 'none' = rules-only fallback, no data leaves the machine)")
    ag.add_argument("--list-models", action="store_true",
                    help="print the models the --llm provider's API key can use, then exit (no generation quota used)")
    ag.add_argument("--max-triage", type=int, help="max findings sent to the triage agent (default 15)")
    ag.add_argument("--day2-preview", action="store_true",
                    help="also run the Day 2 scaffold: prioritise -> propose remediation -> human approval "
                         "(interrupt) -> validation stub. Nothing is changed in the repository.")
    ag.add_argument("--decisions", choices=["ask", "defer", "reject"], default="ask",
                    help="--day2-preview approval step: ask on the console (default, falls back to defer when not "
                         "interactive), defer (leave pending), or reject all")
    args = ap.parse_args(argv)
    if args.cmd == "agent":
        from .agents.runner import run  # imported lazily: plain `scan` never needs LangGraph or an LLM SDK
        return run(args)
    scan(args)


if __name__ == "__main__":
    sys.exit(main())
