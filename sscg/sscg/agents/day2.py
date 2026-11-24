"""Day 2 scaffold ("Build the Guardian's Brain & Shield"), enabled with --day2-preview.

prioritize -> propose_remediation -> human_approval (LangGraph interrupt) -> validate

Everything here is a deliberately simple, deterministic PLACEHOLDER so the graph, state and contracts already work
end to end. Each node says what the real Day 2 agent should do (TODO). Nothing modifies the repository: proposals
are text, approval is recorded, validation is "not_run". No action ever runs without an ApprovalRecord.
"""
from __future__ import annotations

import json

from langgraph.types import interrupt

from .runtime import get, now, traced
from .schemas import ApprovalRecord, PriorityItem, RemediationProposal, ValidationReport

VERDICT_ADJ = {"likely_malicious": 1.0, "suspicious": 0.5, "needs_human_review": 0.0, "likely_benign": -1.5}
MAX_PROPOSALS = 5


def _tier(score: float) -> str:
    return "P0" if score >= 10 else "P1" if score >= 8 else "P2" if score >= 5 else "P3"


@traced("Prioritizer", "deterministic")
def prioritize(state: dict) -> dict:
    """TODO Day 2: add exploitability (CISA KEV, EPSS), reachability (imports / call sites), exposure (prod vs dev,
    internet-facing) and let an LLM write the explanation; keep the score itself formula-based and explainable."""
    tri = state.get("triage", {})
    items = []
    for f in state["findings"]:
        factors = {"initial_risk": f["risk"]["score"]}
        score = f["risk"]["score"]
        if f["finding_id"] in tri:
            adj = VERDICT_ADJ[tri[f["finding_id"]]["verdict"]]
            factors["ai_triage_verdict"] = f"{tri[f['finding_id']]['verdict']} ({adj:+})"
            score += adj
        if (f.get("component") or {}).get("scope") == "prod":
            factors["production_scope"] = "+0.5"
            score += 0.5
        items.append(PriorityItem(finding_id=f["finding_id"], priority=_tier(score), score=round(score, 1),
                                  factors=factors, confidence="medium",
                                  explanation="preview formula: initial risk + triage verdict + production scope"))
    items.sort(key=lambda i: -i.score)
    get(state["run_id"]).log("Prioritizer", f"P0 {sum(i.priority == 'P0' for i in items)}, "
                                            f"P1 {sum(i.priority == 'P1' for i in items)}")
    return {"priorities": [i.model_dump() for i in items]}


@traced("Remediation", "deterministic")
def propose_remediation(state: dict) -> dict:
    """TODO Day 2: resolve safe versions (npm view / PyPI, semver), generate the actual diff on a sandbox branch,
    and let an LLM draft rationale, compatibility impact and rollback from the evidence (grounded like triage)."""
    rt = get(state["run_id"])
    by_id = {f["finding_id"]: f for f in state["findings"]}
    props = []
    for item in [i for i in state["priorities"] if i["priority"] in ("P0", "P1")]:
        f = by_id[item["finding_id"]]
        comp = f.get("component") or {}
        same = next((p for p in props if comp.get("label") and p.component == comp["label"]), None)
        if same:  # one proposal per component: several findings on it are fixed together
            same.finding_ids.append(f["finding_id"])
            continue
        if len(props) >= MAX_PROPOSALS:
            continue
        loc = (f.get("location") or "").rsplit(":", 1)[0]
        if f["category"] == "vulnerability" and f.get("fixes", {}).get("upgrade_to_at_least"):
            action, to, why = "upgrade", f["fixes"]["upgrade_to_at_least"], "lowest version that fixes all advisories with a fix"
        else:
            opt = (rt.kb.playbook(f["rule"]).get("remediation_options") or [{"action": "escalate_review", "when": "no playbook option"}])[0]
            action, to, why = opt["action"], None, opt["when"]
        props.append(RemediationProposal(
            proposal_id=f"P-{len(props) + 1:03d}", finding_ids=[f["finding_id"]], action=action,
            component=comp.get("label"), from_version=comp.get("version"), to_version=to,
            files_affected=[loc] if loc and not loc.startswith("commit") else [],
            rationale=f"{f['title']}. {why}.", expected_risk_reduction=f"resolves {f['finding_id']} if validated",
            compatibility_impact="unknown: to be assessed by the Day 2 remediation agent",
            rollback="revert the remediation commit on the sandbox branch",
            validation_plan=["apply on a sandbox branch", "build the container", "run unit and integration tests",
                             "rescan with python -m sscg agent", "compare SBOM and findings before / after"],
            generated_by="rules (Day 2 preview)", status="pending"))
    rt.log("Remediation", f"{len(props)} proposal(s) for P0/P1 findings (text only, nothing applied)")
    return {"proposals": [p.model_dump() for p in props]}


@traced("Human Approval", "human")
def human_approval(state: dict) -> dict:
    """Pauses the graph (LangGraph interrupt + checkpointer) until a human answers. The answer is a list of
    {proposal_id, decision, approver, reason}; the runner collects it on the console (Day 2: dashboard button)."""
    props = state.get("proposals", [])
    if not props:
        return {}
    answer = interrupt({"type": "approval_request", "proposals": props})
    records = [ApprovalRecord(proposal_id=a["proposal_id"], decision=a["decision"], approver=a.get("approver", "unknown"),
                              reason=a.get("reason", ""), decided_at=now()).model_dump() for a in (answer or [])]
    status = {"approve": "approved", "reject": "rejected", "request_changes": "needs_changes",
              "accept_risk": "risk_accepted", "defer": "pending"}
    dec = {r["proposal_id"]: r["decision"] for r in records}
    updated = [{**p, "status": status.get(dec.get(p["proposal_id"], "defer"), "pending")} for p in props]
    return {"approvals": records, "proposals": updated}


@traced("Validation", "deterministic")
def validate(state: dict) -> dict:
    """TODO Day 2: for each APPROVED proposal: copy the repo to a sandbox, apply the diff, docker build, run tests,
    re-run this graph's Day 1 part on the result, diff SBOM + findings, and fill ValidationReport."""
    rt = get(state["run_id"])
    reports = [ValidationReport(proposal_id=p["proposal_id"], verdict="not_run",
                                notes="Day 2 TODO: sandbox apply, build, test, rescan, before/after diff").model_dump()
               for p in state.get("proposals", []) if p["status"] == "approved"]
    out = {k: state.get(k) for k in ("priorities", "proposals", "approvals")}
    out["validations"] = reports
    (rt.out / "day2_preview.json").write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")
    rt.log("Validation", f"{len(reports)} approved proposal(s) recorded; validation not implemented yet "
                         f"(day2_preview.json written)")
    return {"validations": reports}
