"""`python -m sscg agent <repo>`: run the agent graph, handle the human-approval interrupt, print the result."""
from __future__ import annotations

import collections
import dataclasses
import json
import sys
import uuid

from langgraph.types import Command

from .. import cache
from ..pipeline import print_console
from . import config, kb, llm
from .graph import build_graph
from .runtime import Runtime, register, release
from .workers import agentic_payload

DECISIONS = {"a": "approve", "r": "reject", "c": "request_changes", "k": "accept_risk", "d": "defer", "": "defer"}


def _ask(request: dict, mode: str) -> list:
    props = request.get("proposals", [])
    interactive = mode == "ask" and sys.stdin.isatty()
    if not interactive:
        decision = "reject" if mode == "reject" else "defer"
        print(f"\n  [Human Approval] {len(props)} proposal(s) {'rejected' if decision == 'reject' else 'deferred'} "
              f"automatically "
              f"({'--decisions ' + mode if mode != 'ask' else 'console is not interactive'}). Nothing was applied.")
        return [{"proposal_id": p["proposal_id"], "decision": decision, "approver": f"cli:{decision}-default",
                 "reason": "no interactive approver"} for p in props]
    print("\n  [Human Approval] The graph is paused. Decide each proposal "
          "(a=approve, r=reject, c=request changes, k=accept risk, Enter=defer). Approving changes nothing yet: "
          "Day 2 validation is a stub.")
    who = input("  your name (recorded as approver): ").strip() or "anonymous"
    out = []
    for p in props:
        print(f"\n  {p['proposal_id']}  {p['action'].upper()}  {p['component'] or ''}"
              f"{' -> ' + p['to_version'] if p['to_version'] else ''}  (findings {', '.join(p['finding_ids'])})")
        print(f"     {p['rationale'][:200]}")
        d = input("     decision [a/r/c/k/Enter]: ").strip().lower()[:1]
        reason = input("     reason (optional): ").strip() if d in ("r", "c", "k") else ""
        out.append({"proposal_id": p["proposal_id"], "decision": DECISIONS.get(d, "defer"), "approver": who,
                    "reason": reason})
    return out


def run(args) -> int:
    config.load_env()
    cache.OFFLINE = args.offline
    settings = config.resolve(args.llm, args.max_triage)
    if getattr(args, "list_models", False):
        return _list_models(settings)
    client = None
    if settings.provider != "none":
        print(f"\n  LLM check ({settings.provider}): trying {settings.model} ...", flush=True)
        client, chosen, tried = llm.preflight(settings)
        for t in tried:
            print(f"    {t}")
        if client:
            settings = chosen
        else:
            why = f"{settings.provider} not usable ({'; '.join(tried)[:300]}): rules-only fallback. Check the key and " \
                  f"{config.MODEL_ENV[settings.provider]} in sscg/.env"
            print(f"  ! {why}")
            settings = dataclasses.replace(settings, provider="none", model=None, reason=why)
    repo = args.repo.resolve()
    out = args.out or cache.ROOT / "out" / repo.name
    out.mkdir(parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex[:12]
    rt = register(Runtime(run_id=run_id, repo=repo, out=out, settings=settings, kb=kb.load(), llm=client))

    print(f"\n=== Guardian agents: {repo.name} (run {run_id}) ===")
    print(f"  engine: {settings.engine}  ({settings.reason})")
    graph = build_graph(day2_preview=args.day2_preview)
    cfg = {"configurable": {"thread_id": run_id}, "max_concurrency": settings.concurrency, "recursion_limit": 80}
    init = {"run_id": run_id, "repo": str(repo), "out": str(out),
            "options": {"base": args.base, "no_diff": args.no_diff, "sbom": str(args.sbom) if args.sbom else None,
                        "no_vulns": args.no_vulns, "offline": args.offline, "focus": args.focus,
                        "max_depth": args.max_depth, "why": args.why, "day2": args.day2_preview}}
    try:
        graph.invoke(init, cfg)
        while True:  # human-in-the-loop: resume until no node is waiting on an interrupt
            pending = [i for t in graph.get_state(cfg).tasks for i in t.interrupts]
            if not pending:
                break
            graph.invoke(Command(resume=_ask(pending[0].value, args.decisions)), cfg)
        final = graph.get_state(cfg).values
        payload = agentic_payload(final, rt)  # final audit trail (includes Day 2 nodes, if any)
        (out / "agentic.json").write_text(json.dumps(payload, indent=1, default=str), encoding="utf-8")
        print_console(repo, out, rt.dg, rt.fs, rt.change, rt.emitted, args.top)
        _summary(final, payload)
    finally:
        release(run_id)
    return 0


def _list_models(settings) -> int:
    if settings.provider == "none":
        print(f"No usable provider: {settings.reason}")
        return 1
    try:
        names = llm.list_models(settings)
    except Exception as e:  # noqa: BLE001
        print(f"{settings.provider}: could not list models: {llm.describe(e)[0]}")
        return 1
    print(f"{settings.provider}: {len(names)} models available to this key "
          f"(set {config.MODEL_ENV[settings.provider]} in sscg/.env; comma-separated = fallbacks):")
    for n in names:
        print("  " + n)
    print(f"current setting: {settings.model}")
    return 0


def _summary(state: dict, p: dict) -> None:
    tri = state.get("triage", {})
    v = collections.Counter(t["verdict"] for t in tri.values())
    print(f"\n  AI triage ({p['engine']}): {len(tri)} findings judged · "
          + " · ".join(f"{k} {n}" for k, n in v.most_common())
          + f" · grounding failures {sum(1 for t in tri.values() if not t['grounding'].get('ok', True))}")
    n = state.get("narrative") or {}
    if n:
        print(f"  Summary: {n['headline']}")
        for c in n.get("top_concerns", []):
            print(f"    -> {c['finding_id']}: {c['why'][:140]}")
    u = p["llm_usage"]
    print(f"  LLM usage: {u['calls']} calls, {u['input_tokens']} input / {u['output_tokens']} output tokens, "
          f"{u['secrets_redacted']} secret(s) redacted before sending")
    per = collections.defaultdict(lambda: [0, 0.0])
    for r in state.get("agent_runs", []):
        per[r["agent"]][0] += 1
        per[r["agent"]][1] += r["seconds"]
    print("  Agent runs: " + " · ".join(f"{a} {c}x {s:.1f}s" for a, (c, s) in per.items()))
    if state.get("proposals"):
        print("  Day 2 preview: " + ", ".join(f"{x['proposal_id']} {x['action']} {x['status']}" for x in state["proposals"])
              + " (day2_preview.json)")
    print("  wrote agentic.json (triage, tool evidence, narrative, audit trail)")
