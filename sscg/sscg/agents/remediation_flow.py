"""The human approval gate, validation and the remediation report.

human_approval  LangGraph interrupt(): the run pauses until a human decides each proposal. With the SQLite
                checkpointer the pause survives the process: `python -m sscg approve <repo> ...` (or the
                dashboard) resumes it later. Out-of-scope rule: nothing is applied without an ApprovalRecord.
validate        sandbox copy -> approved edits -> build / test (before and after) -> rescan -> compare
                (sscg/validation.py). Writes remediation/remediation.patch. Nothing in the original repository changes.
"""
from __future__ import annotations

import os
from pathlib import Path

from langgraph.types import interrupt

from .. import validation
from .runtime import get, now, traced
from .schemas import ApprovalRecord, ValidationReport

STATUS = {"approve": "approved", "reject": "rejected", "request_changes": "needs_changes",
          "accept_risk": "risk_accepted", "defer": "pending"}


def system_suggestion(p: dict) -> dict | None:
    """The system's own call on low-priority risk. Shown with a 'System suggestion' tag; a human still decides."""
    if p.get("urgent") or p.get("priority") not in ("P2", "P3"):
        return None
    if p.get("priority") == "P3":
        return {"decision": "accept_risk", "confidence": "medium",
                "reason": "Low priority: not urgent, no known exploitation (KEV) and low exploit probability (EPSS), "
                          "or the package is not reachable from application code. Accepting the risk and re-checking "
                          "on the next scan is reasonable."}
    if p.get("patchable") and p.get("compatibility_level") in ("patch", "minor", None):
        return {"decision": "approve", "confidence": "medium",
                "reason": "Moderate priority with a low-impact upgrade available: approving is cheap and removes the risk."}
    return {"decision": "defer", "confidence": "low",
            "reason": "Moderate priority but the fix may break compatibility: defer to a planned upgrade."}


def approval_request(props: list) -> dict:
    """What the human (CLI / dashboard) is asked to decide."""
    return {"type": "approval_request", "proposals": [
        {"system_suggestion": system_suggestion(p)} | {k: p.get(k) for k in ("proposal_id", "action", "component", "from_version", "to_version", "priority",
                               "urgent", "patchable", "compatibility_level", "compatibility_impact", "rationale",
                               "ai_rationale", "residual_advisories", "finding_ids", "files_affected", "diff", "status", "cluster_ids")}
        for p in props]}


@traced("Human Approval", "human")
def human_approval(state: dict) -> dict:
    props = state.get("proposals", [])
    if not props:
        return {}
    _write_report(state, "Human Approval")             # the one report: before-state + "awaiting approval"
    answer = interrupt(approval_request(props))          # <- the graph stops here until a human answers
    ids = {p["proposal_id"] for p in props}
    records = [ApprovalRecord(proposal_id=a["proposal_id"], decision=a["decision"],
                              approver=a.get("approver") or "unknown", reason=a.get("reason", ""),
                              decided_at=now(), expires_at=a.get("expires_at")).model_dump()
               for a in (answer or []) if a.get("proposal_id") in ids and a.get("decision") in STATUS]
    rt = get(state["run_id"])
    for r in records:
        rt.note(lambda c, r=r: c.write("ApprovalNote", {**r, "reviewer": f"human:{r['approver']}", "comment": r["reason"]}))
    dec = {r["proposal_id"]: r["decision"] for r in records}
    updated = [{**p, "status": STATUS[dec[p["proposal_id"]]] if p["proposal_id"] in dec else "pending"} for p in props]
    n = {s: sum(p["status"] == s for p in updated) for s in ("approved", "rejected", "risk_accepted", "pending")}
    get(state["run_id"]).log("Human Approval", " · ".join(f"{k} {v}" for k, v in n.items()))
    return {"approvals": records, "proposals": updated, "_run": n}


@traced("Validation", "deterministic")
def validate(state: dict) -> dict:
    rt = get(state["run_id"])
    props = state.get("proposals", [])
    approved = [p for p in props if p["status"] == "approved" and p.get("patchable")]
    if not approved:
        rep = ValidationReport(verdict="not_run", reasons=["no approved proposal with a patch"])
        rt.log("Validation", "nothing approved to validate")
        return {"validations": [rep.model_dump()]}
    base = ((state.get("change") or {}).get("base") or {}).get("sha")
    work = Path(os.getenv("SSCG_SANDBOX_DIR") or (Path(os.getenv("TEMP", "/tmp")) / f"sscg-validate-{state['run_id']}"))
    res = validation.validate(rt.target, state["findings"], rt.dg, props, base, workdir=work,
                              baseline=not state["options"].get("no_baseline"),
                              log=lambda m: rt.log("Validation", m))
    v, conf, reasons = validation.verdict(res)
    out = rt.out / "remediation"
    out.mkdir(parents=True, exist_ok=True)
    patch = out / "remediation.patch"
    patch.write_text(res["patch"], encoding="utf-8")
    import json
    (out / "sandbox_trace.json").write_text(json.dumps(res.get("sandbox_trace") or {}, indent=2), encoding="utf-8")

    def lv(f):
        return ((f.get("severity") or {}).get("label") if f.get("category") == "vulnerability" else None)             or (f.get("risk") or {}).get("level") or "unknown"

    def by_level(fs):
        c = {}
        for f in fs:
            c[str(lv(f)).capitalize()] = c.get(str(lv(f)).capitalize(), 0) + 1
        return c
    (out / "post_analysis.json").write_text(json.dumps({
        "before": {"total": res["findings_before"], "by_level": by_level(state["findings"])},
        "after": {"total": res["findings_after"], "by_level": by_level(res.get("after_findings") or [])},
        "resolved": res["resolved"], "remaining": res["remaining"], "new": res["new"],
        "sbom_diff": res.get("sbom_diff"), "docker": res["docker"], "verdict": v, "confidence": conf,
        "reasons": reasons, "after_findings": [{k: f.get(k) for k in ("finding_id", "title", "rule", "category")}
                                               | {"level": lv(f)} for f in res.get("after_findings") or []]},
        indent=2, default=str), encoding="utf-8")
    rep = ValidationReport(proposal_ids=[p["proposal_id"] for p in approved], verdict=v, confidence=conf,
                           reasons=reasons, patch_file=str(patch), **{k: res[k] for k in (
                               "steps_before", "steps_after", "findings_before", "findings_after", "resolved",
                               "remaining", "new", "per_proposal", "sbom_diff", "applied_files", "workdir", "docker")})
    rt.note(lambda c: c.write("ValidationResult", {
        "validation_id": "val-1", **{k: getattr(rep, k) for k in ("proposal_ids", "verdict", "confidence", "reasons", "resolved", "new",
                                                              "sbom_diff")}, "steps": rep.steps_before + rep.steps_after}))
    rt.log("Validation", f"{v.upper()} ({conf} confidence): resolved {len(res['resolved'])}, remaining "
                         f"{len(res['remaining'])}, new {len(res['new'])} · patch: {patch}")
    return {"validations": [rep.model_dump()], "_run": {"verdict": v, "resolved": len(res["resolved"]),
                                                        "new": len(res["new"])}}


def _write_report(state: dict, agent: str) -> list[str]:
    """Rewrite out/<repo>/report.md/.html/.pdf (the single report) with the current remediation state.
    A report problem never breaks the run."""
    from .. import report
    rt = get(state["run_id"])
    try:
        return report.write(rt.out, rem=report.remediation_from(state, rt.out))
    except Exception as e:  # noqa: BLE001
        rt.log(agent, f"report not written: {type(e).__name__}: {e}")
        return []


@traced("Remediation Reporter", "deterministic")
def remediation_report(state: dict) -> dict:
    """Rewrites the single report (out/<repo>/report.md/.html/.pdf) with the after-state, and writes the
    machine-readable remediation/remediation.json."""
    import json

    rt = get(state["run_id"])
    out = rt.out / "remediation"
    out.mkdir(parents=True, exist_ok=True)
    generated = now()
    report_files = _write_report(state, "Remediation Reporter")
    files = []
    doc = {"run_id": state["run_id"], "application": rt.target.name, "generated_at": generated,
           "exploitability_sources": (state.get("exploitability") or {}).get("sources"),
           "exposure": (state.get("reachability") or {}).get("exposure"),
           "reachability_summary": (state.get("reachability") or {}).get("summary"),
           **{k: state.get(k, []) for k in ("priorities", "proposals", "approvals", "validations")}}
    (out / "remediation.json").write_text(json.dumps(doc, indent=1, default=str), encoding="utf-8")
    files.append("remediation.json")
    if (out / "remediation.patch").exists():
        files.append("remediation.patch")
    rt.log("Remediation Reporter", f"wrote {', '.join(report_files)} to {rt.out} and {', '.join(files)} to {out}")
    return {"artifacts": {**(state.get("artifacts") or {}),
                          "remediation": [str(rt.out / f) for f in report_files] + [str(out / f) for f in files]}}
