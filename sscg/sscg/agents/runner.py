"""CLI runners.

`python -m sscg agent <repo> [--remediate]`  run the agent graph. With --remediate the run stops at the human-approval
                                        interrupt; the state is checkpointed in SQLite (out/<repo>/.sscg-state/),
                                        so the approval can happen later, in another process or in the dashboard.
`python -m sscg approve <repo> ...`     record human decisions and resume the paused run: validation + report.
"""
from __future__ import annotations

import collections
import dataclasses
import json
import os
import sqlite3
import sys
import uuid
from pathlib import Path

from langgraph.types import Command

from .. import cache
from ..pipeline import print_console
from . import config, kb, llm
from .graph import build_graph
from .runtime import Runtime, now, register, release
from .workers import agentic_payload

DECISIONS = {"a": "approve", "r": "reject", "c": "request_changes", "k": "accept_risk", "d": "defer", "": "defer"}
STATE_DIR = ".sscg-state"


def checkpointer(out: Path):
    """SQLite checkpointer in out/<repo>/.sscg-state/: a run paused for approval survives this process."""
    from langgraph.checkpoint.sqlite import SqliteSaver
    d = out / STATE_DIR
    d.mkdir(parents=True, exist_ok=True)
    return SqliteSaver(sqlite3.connect(d / "checkpoints.sqlite", check_same_thread=False))


def _approver() -> str:
    from .. import gitutil
    name = gitutil.git(Path.cwd(), "config", "user.name") or os.getenv("USERNAME") or os.getenv("USER") or "unknown"
    return name.strip()


def _ask(request: dict, mode: str) -> list | None:
    """Decisions for the approval interrupt, or None = pause and decide later (mode 'later')."""
    props = request.get("proposals", [])
    if mode == "ask" and not sys.stdin.isatty():
        mode = "later"
    if mode == "later":
        return None
    if mode in ("defer", "reject"):
        print(f"\n  [Human Approval] {len(props)} proposal(s) {'rejected' if mode == 'reject' else 'deferred'} "
              f"automatically (--decisions {mode}). Nothing was applied.")
        return [{"proposal_id": p["proposal_id"], "decision": mode, "approver": f"cli:{mode}-default",
                 "reason": "no interactive approver"} for p in props]
    print("\n  [Human Approval] The graph is paused. Decide each proposal "
          "(a=approve, r=reject, c=request changes, k=accept risk, Enter=defer). Only approved proposals with a "
          "patch are applied, in a sandbox copy.")
    who = input(f"  your name (recorded as approver) [{_approver()}]: ").strip() or _approver()
    out = []
    for p in props:
        print(f"\n  {p['proposal_id']} {p['priority'] or ''}{' URGENT' if p['urgent'] else ''}  {p['action'].upper()}  "
              f"{p['component'] or ''} {p['from_version'] or ''} -> {p['to_version'] or ''}  "
              f"(findings {', '.join(p['finding_ids'])})")
        print(f"     {p['rationale'][:220]}")
        print(f"     compatibility {p['compatibility_level']}: {(p['compatibility_impact'] or '')[:120]}"
              + ("" if p["patchable"] else "  [manual: no patch, approve = acknowledge]"))
        d = input("     decision [a/r/c/k/Enter]: ").strip().lower()[:1]
        reason = input("     reason (optional): ").strip() if d in ("r", "c", "k") else ""
        out.append({"proposal_id": p["proposal_id"], "decision": DECISIONS.get(d, "defer"), "approver": who,
                    "reason": reason})
    return out


def _select_llm(settings):
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
    return client, settings


def _drive(graph, cfg, mode: str, first_input) -> dict:
    """Invoke, answer interrupts (or pause), return the latest state values."""
    graph.invoke(first_input, cfg)
    while True:
        pending = [i for t in graph.get_state(cfg).tasks for i in t.interrupts]
        if not pending:
            return {"paused": False, "state": graph.get_state(cfg).values}
        answer = _ask(pending[0].value, mode)
        if answer is None:
            return {"paused": True, "state": graph.get_state(cfg).values, "request": pending[0].value}
        graph.invoke(Command(resume=answer), cfg)


def _write_pending(rt, request: dict) -> Path:
    d = rt.out / "remediation"
    d.mkdir(parents=True, exist_ok=True)
    f = d / "pending.json"
    f.write_text(json.dumps({"run_id": rt.run_id, "repo": str(rt.repo), "created": now(), **request}, indent=1,
                            default=str), encoding="utf-8")
    return f


def run(args) -> int:
    config.load_env()
    cache.OFFLINE = args.offline
    settings = config.resolve(args.llm, args.max_triage)
    if getattr(args, "list_models", False):
        return _list_models(settings)
    client, settings = _select_llm(settings)
    repo = _repo(args, update=True)
    out = args.out or cache.ROOT / "out" / repo.name
    out.mkdir(parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex[:12]
    rt = register(Runtime(run_id=run_id, repo=repo, out=out, settings=settings, kb=kb.load(), llm=client))

    print(f"\n=== Guardian agents: {repo.name} (run {run_id}) ===")
    print(f"  engine: {settings.engine}  ({settings.reason})")
    graph = build_graph(remediate=args.remediate, checkpointer=checkpointer(out) if args.remediate else None)
    cfg = {"configurable": {"thread_id": run_id}, "max_concurrency": settings.concurrency, "recursion_limit": 80}
    init = {"run_id": run_id, "repo": str(repo), "out": str(out),
            "options": {"base": args.base, "no_diff": args.no_diff, "sbom": str(args.sbom) if args.sbom else None,
                        "no_vulns": args.no_vulns, "offline": args.offline, "focus": args.focus,
                        "max_depth": args.max_depth, "why": args.why, "remediation": args.remediate,
                        "no_baseline": getattr(args, "no_baseline", False)}}
    try:
        res = _drive(graph, cfg, args.decisions, init)
        final = res["state"]
        payload = agentic_payload(final, rt)
        (out / "agentic.json").write_text(json.dumps(payload, indent=1, default=str), encoding="utf-8")
        print_console(repo, out, rt.dg, rt.fs, rt.change, rt.emitted, args.top)
        _summary(final, payload)
        if res["paused"]:
            f = _write_pending(rt, res["request"])
            props = res["request"]["proposals"]
            patch = [p["proposal_id"] for p in props if p["patchable"]]
            print(f"\n  PAUSED for human approval: {len(props)} proposal(s), {len(patch)} with a patch ({f}).")
            print("  Decide in the dashboard (python -m sscg serve -> Remediation page) or on the command line, e.g.:")
            out_opt = f' --out "{out}"' if args.out else ""
            print(f"    python -m sscg approve {args.repo}{out_opt} --approve {','.join(patch[:3]) or 'P-001'} "
                  f"--by \"<your name>\"")
            print("  (--approve / --reject / --accept-risk / --request-changes take ID,ID,... or all-patchable;"
                  " --reason TEXT)")
    finally:
        release(run_id)
    return 0


def _ids(spec: str | None, props: list) -> list[str]:
    if not spec:
        return []
    if spec in ("all", "all-patchable"):
        return [p["proposal_id"] for p in props if spec == "all" or p["patchable"]]
    return [x.strip().upper() for x in spec.split(",") if x.strip()]


def _repo(args, update: bool):
    """Repository argument -> local folder; a URL is cloned / updated into repos/ (not updated when resuming)."""
    from .. import source
    try:
        return source.resolve(args.repo, update=update, offline=args.offline)
    except source.SourceError as e:
        print(f"error: {e}")
        raise SystemExit(2)


def resume(args) -> int:
    """`python -m sscg approve <repo> ...`: record the human decisions and resume the paused run."""
    config.load_env()
    cache.OFFLINE = args.offline
    repo = _repo(args, update=False)
    out = args.out or cache.ROOT / "out" / repo.name
    pend_file = out / "remediation" / "pending.json"
    pending = json.loads(pend_file.read_text(encoding="utf-8")) if pend_file.exists() else {}
    run_id = args.run or pending.get("run_id")
    if not run_id:
        print(f"No run waiting for approval for {repo.name}: run `python -m sscg agent {args.repo} --remediate` first.")
        return 1
    props = pending.get("proposals", [])
    who = args.by or _approver()
    decisions, seen = [], set()
    for flag in ("approve", "reject", "accept_risk", "request_changes"):
        for pid in _ids(getattr(args, flag), props):
            if pid not in seen:
                seen.add(pid)
                decisions.append({"proposal_id": pid, "decision": flag, "approver": who, "reason": args.reason or ""})
    unknown = sorted(seen - {p["proposal_id"] for p in props})
    if unknown:
        print(f"Unknown proposal id(s): {', '.join(unknown)}. Pending: {', '.join(p['proposal_id'] for p in props)}")
        return 1
    decisions += [{"proposal_id": p["proposal_id"], "decision": "defer", "approver": who, "reason": "not decided"}
                  for p in props if p["proposal_id"] not in seen]
    settings = dataclasses.replace(config.resolve("none"), reason="resume: validation and report need no LLM")
    rt = register(Runtime(run_id=run_id, repo=repo, out=out, settings=settings, kb=kb.load(), llm=None))
    try:
        graph = build_graph(remediate=True, checkpointer=checkpointer(out))
        cfg = {"configurable": {"thread_id": run_id}, "recursion_limit": 80}
        snap = graph.get_state(cfg)
        if "human_approval" not in (snap.next or ()):
            print(f"Run {run_id} is not waiting for approval (next: {snap.next or 'finished'}). A finished run cannot "
                  f"be approved again: start a new one with `python -m sscg agent {args.repo} --remediate`.")
            return 1
        # the approval must cover exactly what was reviewed: refuse if manifests, lockfiles, Dockerfiles, workflows
        # or any file a proposal edits changed since the run paused (sscg/snapshot.py)
        from .. import snapshot
        request = next((i.value for t in snap.tasks for i in t.interrupts), None) or {}
        source = request.get("source")
        if source:
            drift = snapshot.changes(source, snapshot.fingerprint(repo, list(source.get("files", {}))))
            if drift:
                print(f"The repository changed since run {run_id} paused for approval, so the reviewed proposals no "
                      f"longer describe what would be applied:")
                for d in drift[:15]:
                    print(f"    {d}")
                print(f"  Nothing was applied. Start a new run: python -m sscg agent {args.repo} --remediate")
                return 1
        # keep the engine that actually produced the AI output (resuming itself needs no LLM)
        engine = ((snap.values.get("plan") or {}).get("llm") or {}).get("engine") or ""
        if ":" in engine:
            prov, model = engine.split(":", 1)
            rt.settings = dataclasses.replace(rt.settings, provider=prov, model=model,
                                              reason=f"{engine} (resumed for approval: validation and report use no LLM)")
        print(f"\n=== Guardian: resuming run {run_id} for {repo.name} ===")
        print("  decisions: " + (", ".join(f"{d['proposal_id']} {d['decision']}" for d in decisions
                                           if d["decision"] != "defer") or "none (all deferred)") + f" (by {who})")
        from ..pipeline import build     # the live dependency graph is not checkpointed: rebuild it (cached)
        opts = snap.values["options"]
        rt.dg = build(repo, Path(opts["sbom"]) if opts.get("sbom") else None, check_vulns=not opts.get("no_vulns"))
        rt.labels = {str(a.get("label")) for _, a in rt.dg.G.nodes(data=True)}
        graph.invoke(Command(resume=decisions), cfg)
        final = graph.get_state(cfg).values
        payload = agentic_payload(final, rt)
        (out / "agentic.json").write_text(json.dumps(payload, indent=1, default=str), encoding="utf-8")
        pend_file.unlink(missing_ok=True)
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


def _summary(state: dict, payload: dict) -> None:
    tri = state.get("triage", {})
    if tri:
        v = collections.Counter(t["verdict"] for t in tri.values())
        print(f"\n  AI triage ({payload['engine']}): {len(tri)} findings judged · "
              + " · ".join(f"{k} {n}" for k, n in v.most_common())
              + f" · grounding failures {sum(1 for t in tri.values() if not t['grounding'].get('ok', True))}")
    nar = state.get("narrative") or {}
    if nar:
        print(f"  Summary: {nar['headline']}")
        for c in nar.get("top_concerns", []):
            print(f"    -> {c['finding_id']}: {c['why'][:140]}")
    u = payload["llm_usage"]
    print(f"  LLM usage: {u['calls']} calls, {u['input_tokens']} input / {u['output_tokens']} output tokens, "
          f"{u['secrets_redacted']} secret(s) redacted before sending")
    per = collections.defaultdict(lambda: [0, 0.0])
    for r in state.get("agent_runs", []):
        per[r["agent"]][0] += 1
        per[r["agent"]][1] += r["seconds"]
    print("  Agent runs: " + " · ".join(f"{a} {c}x {s:.1f}s" for a, (c, s) in per.items()))
    pri = state.get("priorities") or []
    if pri:
        n = collections.Counter(x["priority"] for x in pri)
        print("\n  Priorities: " + " · ".join(f"{k} {n.get(k, 0)}" for k in ("P0", "P1", "P2", "P3"))
              + f" · urgent {sum(x['urgent'] for x in pri)}")
        for x in pri[:6]:
            print(f"    {x['priority']} {x['score']:>4} {'URGENT ' if x['urgent'] else '       '}{x['finding_id']} "
                  f"{(x['component'] or x['title'])[:48]:<48} conf {x['confidence']}")
    props = state.get("proposals") or []
    if props:
        print(f"\n  Remediation proposals: {len(props)} ({sum(x['patchable'] for x in props)} with a patch)")
        for x in props:
            print(f"    {x['proposal_id']} {x['status']:<13} {x['action']:<17} {(x['component'] or '')[:42]:<42} "
                  f"{(x['from_version'] or '')[:14]} -> {(x['to_version'] or '')[:24]}")
    for val in state.get("validations") or []:
        print(f"\n  Validation: {val['verdict'].upper()} (confidence {val['confidence']})")
        for r in val["reasons"]:
            print(f"    - {r[:150]}")
        if val.get("patch_file"):
            print(f"    patch: {val['patch_file']}")
    files = (state.get("artifacts") or {}).get("remediation")
    if files:
        print("  Remediation report: " + ", ".join(Path(f).name for f in files) + f" in {Path(files[0]).parent}")
    print("  wrote agentic.json (triage, tool evidence, narrative, remediation state, audit trail)")
