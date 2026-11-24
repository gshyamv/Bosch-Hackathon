"""CLI: python -m sscg scan <repo> [--out DIR] [--base REV] [--sbom FILE] [--offline] [--no-vulns] [--no-diff]
                                  [--why NAME ...] [--focus NAME] [--max-depth N]
     python -m sscg agent <repo> [same options] [--llm auto|claude|gemini|groq|grok|none] [--remediate]
     python -m sscg agent . --llm groq --list-models     (which models your API key can use)
       (the same pipeline as a LangGraph multi-agent workflow; see docs/agentic.md; also writes agentic.json)
     python -m sscg serve [--port 8000]   (web dashboard: React UI in sscg/web + this API)

Pipeline: Repository -> SBOM -> Dependency graph -> Risk detection -> Evidence
          (agent --remediate) -> Prioritise -> Recommend -> Human approval -> Validate -> Report
Outputs (default folder: out/<repo name>/):
  sbom.cdx.json  CycloneDX 1.5 SBOM                         (discover)
  graph.html     interactive graph · graph.json · graph.mmd (discover)
  summary.json   counts, origins, container / CI inventory  (discover)
  findings.json  vulnerabilities + anomalies with evidence  (detect)
  report.md      human-readable evidence report             (evidence)
  report.html    the same report as a standalone web page   (evidence)
  report.pdf     the same report as an A4 PDF               (evidence)
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import cache, source
from .pipeline import build, detect, emit, print_console  # noqa: F401  (kept importable from here)


def scan(args):
    cache.OFFLINE = args.offline
    try:
        repo = source.resolve(args.repo, offline=args.offline)
    except source.SourceError as e:
        sys.exit(f"error: {e}")
    out = args.out or cache.ROOT / "out" / repo.name

    dg = build(repo, args.sbom, not args.no_vulns)
    fs, change = detect(repo, dg, None if (args.no_diff or args.sbom) else args.base)
    res = emit(repo, out, dg, fs, change, focus=args.focus, max_depth=args.max_depth, why_q=args.why)
    print_console(repo, out, dg, fs, change, res, args.top)


def _scan_args(sc):
    sc.add_argument("repo", help="https URL of a git repository (e.g. https://github.com/owner/repo, optionally /tree/<branch|tag|commit>), fetched into repos/<name>; or a local folder. Read only: nothing is installed or run")
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
    ag = sub.add_parser("agent", help="the same pipeline run as a LangGraph multi-agent workflow, "
                                      "with AI triage of suspicious changes and an AI evidence summary")
    _scan_args(ag)
    ag.add_argument("--llm", choices=["auto", "claude", "gemini", "groq", "deepseek", "grok", "none"],
                    help="LLM provider (default: SSCG_LLM_PROVIDER from .env, else auto = first provider with a key; "
                         "groq = Groq/GroqCloud, grok = xAI; 'none' = rules-only fallback, no data leaves the machine)")
    ag.add_argument("--list-models", action="store_true",
                    help="print the models the --llm provider's API key can use, then exit (no generation quota used)")
    ag.add_argument("--max-triage", type=int, help="max findings sent to the triage agent (default 15)")
    ag.add_argument("--remediate", dest="remediate", action="store_true",
                    help="also prioritise and remediate: exploitability (KEV/EPSS) + reachability -> prioritise -> recommend "
                         "remediation -> human approval -> validate in a sandbox -> report. The repository itself "
                         "is never modified.")
    ag.add_argument("--decisions", choices=["ask", "later", "defer", "reject"], default="ask",
                    help="--remediate approval step: ask on the console (default; becomes 'later' when not interactive), "
                         "later = pause and decide with `python -m sscg approve` or the dashboard, "
                         "defer = leave all pending, reject = reject all")
    ag.add_argument("--no-baseline", action="store_true",
                    help="--remediate validation: skip building the unchanged repository for the before/after comparison")

    apv = sub.add_parser("approve", help="record human decisions for a paused run and resume it "
                                         "(validation in a sandbox + remediation report)")
    apv.add_argument("repo", help="the repository URL or folder the paused run scanned (a URL is not re-fetched)")
    apv.add_argument("--out", type=Path, help="output folder used by the run (default: out/<repo name>)")
    apv.add_argument("--run", help="run id (default: the paused run in out/<repo>/remediation/pending.json)")
    for flag in ("approve", "reject", "accept-risk", "request-changes"):
        apv.add_argument(f"--{flag}", metavar="IDS", help="comma-separated proposal ids, or all-patchable / all")
    apv.add_argument("--by", help="approver name recorded in the audit trail (default: git user.name)")
    apv.add_argument("--reason", help="reason recorded with the decisions")
    apv.add_argument("--offline", action="store_true", help="answer API calls from .cache only")

    srv = sub.add_parser("serve", help="start the web dashboard (React UI + API) at http://127.0.0.1:8000")
    srv.add_argument("--host", default="127.0.0.1", help="interface to listen on (default 127.0.0.1: this machine only)")
    srv.add_argument("--port", type=int, default=8000)
    args = ap.parse_args(argv)
    if args.cmd == "serve":
        from .server import serve  # imported lazily: scan / agent never need FastAPI
        return serve(args.host, args.port)
    if args.cmd == "agent":
        from .agents.runner import run  # imported lazily: plain `scan` never needs LangGraph or an LLM SDK
        return run(args)
    if args.cmd == "approve":
        from .agents.runner import resume
        return resume(args)
    scan(args)


if __name__ == "__main__":
    sys.exit(main())
