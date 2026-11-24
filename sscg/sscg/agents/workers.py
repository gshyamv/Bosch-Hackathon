"""Deterministic agents. They wrap the existing sscg modules as tools; no LLM is involved here.

Orchestrator (plan) -> Discovery (cols 1-2) -> Vulnerability Intel (col 3) -> Detection (col 4)
-> Evidence Gatherer (feeds the Triage agent) ... Reporter (col 5)
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .. import vulns
from ..graph import compute_depth, summarize
from ..pipeline import build, detect, emit
from .. import relevance
from .guard import redact
from .pqueue import PriorityQueue
from .runtime import get, now, traced
from .tools import OKF_TOOLS, REPEATABLE, run_tool

MANIFEST_GLOBS = {"npm": ["package.json"], "pypi": ["requirements*.txt", "pyproject.toml", "setup.py"],
                  "maven": ["pom.xml"], "container": ["Dockerfile*", "Containerfile", "docker-compose*.y*ml"],
                  "ci": [".github/workflows/*.y*ml"]}


def _present(repo: Path) -> dict:
    """Quick look (top level + one folder down) so the plan can say what it expects to find."""
    found = {}
    for kind, globs in MANIFEST_GLOBS.items():
        hits = [p for g in globs for p in [*repo.glob(g), *repo.glob(f"*/{g}")] if "node_modules" not in p.parts]
        if hits:
            found[kind] = sorted({str(p.relative_to(repo)).replace("\\", "/") for p in hits})[:5]
    return found


@traced("Orchestrator", "deterministic")
def plan(state: dict) -> dict:
    """Decide what runs and why. Routing is deterministic on purpose: auditable and repeatable."""
    rt = get(state["run_id"])
    o = state["options"]
    is_git = rt.target.kind == "github" or getattr(rt.target, "is_git", False)
    base = None if (o.get("no_diff") or o.get("sbom")) else o.get("base")
    why_no_base = ("--no-diff" if o.get("no_diff") else "an SBOM was supplied" if o.get("sbom") else
                   None if is_git else "not a git repository root")
    if base and not is_git:
        base = None
    # Shallow clones (e.g. juice-shop, nodejs-goof) have no HEAD~1. `base` is still passed on to Detection so that
    # diff.compute writes the same note into findings.json as `scan` does; the plan just reports it honestly.
    if base and not rt.target.resolve(base):
        why_no_base = f"base revision '{base}' not found (shallow clone or first commit)"
    s = rt.settings
    compare = base if base and not why_no_base else None
    p = {
        "repo": rt.target.display, "detected": _present(rt.repo), "git_repository": is_git,
        "compare_with": base, "compare_available": bool(compare),
        "compare_skipped_because": None if compare else why_no_base,
        "sbom_input": o.get("sbom"), "vulnerability_lookup": not o.get("no_vulns"), "offline": o.get("offline"),
        "llm": {"engine": s.engine, "reason": s.reason, "max_triage": s.max_triage, "max_rounds": s.max_rounds},
        "steps": ["discovery", *([] if o.get("no_vulns") else ["vulnerability_intel"]), "detection",
                  "evidence_gatherer <-> triage (loop)", "narrator", "reporter",
                  *(["prioritize", "propose_remediation", "human_approval", "validate"] if o.get("remediation") else [])],
    }
    rt.log("Orchestrator", f"plan: {', '.join(p['detected']) or 'no manifests seen at top level'}; "
                           f"compare with {compare or 'nothing (' + str(p['compare_skipped_because']) + ')'}; "
                           f"LLM {s.engine}")
    return {"plan": p}


@traced("Discovery", "deterministic")
def discovery(state: dict) -> dict:
    rt = get(state["run_id"])
    sbom = state["options"].get("sbom")
    rt.dg = build(rt.target, Path(sbom) if sbom else None, check_vulns=False)
    s = summarize(rt.dg)
    inv = {k: s[k] for k in ("components_total", "packages", "direct", "transitive", "max_depth", "by_ecosystem",
                             "by_scope", "untrusted_origins", "install_scripts")}
    inv["container_images"] = [i["image"] for i in s["container_images"]]
    inv["ci_workflows"] = len(s["ci_workflows"])
    inv["apps"] = s["apps"]
    rt.log("Discovery", f"{inv['components_total']} components ({inv['direct']} direct, {inv['transitive']} "
                        f"transitive), {len(inv['container_images'])} images, {inv['ci_workflows']} CI workflows")
    return {"inventory": inv, "_run": {"components": inv["components_total"]}}


@traced("Vulnerability Intel", "deterministic")
def vuln_intel(state: dict) -> dict:
    rt = get(state["run_id"])
    if state["options"].get("no_vulns"):
        return {"vuln_summary": {"checked": False}}
    ok = vulns.osv_overlay(rt.dg)
    if ok:
        vulns.enrich(rt.dg)
    compute_depth(rt.dg)
    vulnerable = [a for _, a in rt.dg.G.nodes(data=True) if any(not x["malicious"] for x in a.get("advisories", []))]
    summ = {"checked": ok, "source": "OSV.dev", "vulnerable_components": len(vulnerable),
            "advisories": sum(len(a.get("advisories", [])) for a in vulnerable)}
    rt.log("Vulnerability Intel", f"OSV: {summ['vulnerable_components']} vulnerable components" if ok
           else "OSV unreachable: vulnerabilities not checked")
    return {"vuln_summary": summ}


def _json_safe(x):
    return json.loads(json.dumps(x, default=str))


@traced("Detection", "deterministic")
def detection(state: dict) -> dict:
    rt = get(state["run_id"])
    fs, change = detect(rt.target, rt.dg, state["plan"]["compare_with"])
    rt.fs, rt.change = fs, change
    rt.labels = {str(a.get("label")) for _, a in rt.dg.G.nodes(data=True)}
    findings = _json_safe([{k: v for k, v in f.items() if not k.startswith("_")} for f in fs])
    cls = relevance.clusters(rt.dg, findings)
    rt.note(lambda c: c.on_detection(findings, cls))
    # Only findings whose rule needs judgement go to triage (knowledge base: playbook.triage), highest risk first.
    pq = PriorityQueue([f for f in findings if f["category"] == "anomaly" and rt.kb.needs_triage(f["rule"])],
                       key=lambda f: (-f["risk"]["score"], f["finding_id"]))
    skipped = max(0, len(pq) - rt.settings.max_triage)
    queue = [f["finding_id"] for f in pq.take(rt.settings.max_triage)]
    rt.log("Detection", f"{len(findings)} findings; {len(queue)} need judgement -> triage"
                        + (f" ({skipped} more over the SSCG_LLM_MAX_TRIAGE cap)" if skipped else ""))
    return {"findings": findings, "clusters": cls, "change": _json_safe(change.as_dict()) if change else None,
            "triage_queue": queue, "triage_round": 0,
            "notes": [f"{skipped} findings needing judgement were not triaged (cap SSCG_LLM_MAX_TRIAGE)"] if skipped else []}


@traced("Evidence Gatherer", "deterministic")
def gather_evidence(state: dict) -> dict:
    """Round 0: the playbook's default tools. Later rounds: the tools the Triage agent asked for."""
    rt = get(state["run_id"])
    rnd = state.get("triage_round", 0)
    by_id = {f["finding_id"]: f for f in state["findings"]}
    have = state.get("tool_evidence", {})
    jobs = []                                    # (finding_id, tool, query)
    for fid in state["triage_queue"]:
        f = by_id[fid]
        done = {(e["tool"], e.get("query", "")) for e in have.get(fid, [])}
        if rnd == 0:
            # the playbook's tools, plus an OKF lookup for every triaged finding whenever the context store is open
            wanted = [(t, "") for t in rt.kb.playbook(f["rule"]).get("default_tools", [])]
            if rt.ctx:
                wanted.append(("okf_search", ""))
        else:
            reqs = state.get("triage", {}).get(fid, {}).get("evidence_requests", [])
            wanted = [(r["tool"], (r.get("query") or "").strip() if r["tool"] in OKF_TOOLS else "") for r in reqs]
        ran_tools = {t for t, _ in done}
        for tool, q in dict.fromkeys(wanted):
            if (tool, q) in done or (tool in ran_tools and tool not in REPEATABLE):
                continue
            jobs.append((fid, tool, q))
    with ThreadPoolExecutor(max_workers=6) as ex:
        results = list(ex.map(lambda j: run_tool(j[1], rt, by_id[j[0]], state, j[2]), jobs))
    new: dict = {}
    for (fid, tool, q), res in zip(jobs, results):
        n = len(have.get(fid, [])) + len(new.get(fid, [])) + 1
        new.setdefault(fid, []).append({"id": f"{fid}/T{n}", "tool": tool, "round": rnd, "at": now(),
                                        **({"query": q} if q else {}),
                                        "result": redact(res)[0]})  # stored redacted: it ends up in agentic.json
        if rnd:                                  # later rounds: the Triage agent asked, a specialist answered
            from . import bus
            owner = "OKF Knowledge" if tool.startswith("okf") else "Evidence Gatherer"
            bus.post(state["run_id"], "Triage", owner, "question", f"{fid}: run {tool}" + (f" for '{q}'" if q else ""), [fid])
            r0 = res if isinstance(res, dict) else {}
            got = r0.get("results") or r0.get("error") or str(res)[:200]
            bus.post(state["run_id"], owner, "Triage", "answer",
                     f"{fid}: {tool} -> " + (f"{len(got)} result(s)" if isinstance(got, list) else str(got)[:200]), [fid])
    rt.log("Evidence Gatherer", f"round {rnd}: ran {len(jobs)} read-only tool calls for {len(state['triage_queue'])} findings")
    return {"tool_evidence": new, "_run": {"round": rnd, "tool_calls": len(jobs)}}


def _triage_basis(state: dict, rt) -> dict:
    from .triage import triage_basis
    return triage_basis(state.get("findings", []), rt.kb, state.get("triage", {}))


def agentic_payload(state: dict, rt) -> dict:
    """What goes into agentic.json and the report's AI section."""
    runs = state.get("agent_runs", [])
    return {
        "run_id": state["run_id"], "generated_at": now(), "engine": rt.settings.engine,
        "provider": rt.settings.provider, "model": rt.settings.model, "engine_reason": rt.settings.reason,
        "kb_version": rt.kb.version, "plan": state.get("plan"),
        "narrative": state.get("narrative"), "clusters": state.get("clusters", []), "triage": state.get("triage", {}),
        "tool_evidence": state.get("tool_evidence", {}),
        # how each finding's verdict was reached: vulnerabilities are deterministic (never sent to the AI)
        "triage_basis": _triage_basis(state, rt),
        "llm_usage": {"calls": sum(r.get("llm_calls", 0) for r in runs),
                      "input_tokens": sum(r.get("input_tokens", 0) for r in runs),
                      "output_tokens": sum(r.get("output_tokens", 0) for r in runs),
                      "secrets_redacted": sum(r.get("redactions", 0) for r in runs)},
        "remediation": {k: state.get(k) for k in ("priorities", "proposals", "approvals", "validations") if state.get(k)},
        "agent_runs": runs, "notes": state.get("notes", []),
        "basis": "AI inference over findings.json evidence. It never replaces the evidence or the initial risk score.",
    }


@traced("Reporter", "deterministic")
def reporter(state: dict) -> dict:
    rt = get(state["run_id"])
    o = state["options"]
    payload = agentic_payload(state, rt)
    rt.emitted = emit(rt.target, rt.out, rt.dg, rt.fs, rt.change, focus=o.get("focus"), max_depth=o.get("max_depth"),
                      why_q=o.get("why") or (), agentic=payload)
    (rt.out / "agentic.json").write_text(json.dumps(payload, indent=1, default=str), encoding="utf-8")
    files = rt.emitted["files"] + ["agentic.json"]
    rt.log("Reporter", f"wrote {len(files)} files to {rt.out}")
    return {"artifacts": {"out": str(rt.out), "files": files}}
