"""The orchestrator: a LangGraph StateGraph wiring the agents together.

    START -> orchestrator -> discovery -> vuln_intel -> detection --(nothing to judge)--> narrate
                                                   |
                                                   v
                       +------------------> gather_evidence --Send x N--> triage_one (parallel)
                       |                                                      |
                       +----(more evidence requested, round < max)---- triage_join
                                                                              |
                                                              narrate -> report -> END
                    (--remediate: report -> [exploit_intel || reachability_scan] -> prioritize -> plan_remediation
                              -> advise_remediation -> human_approval [interrupt: pause, resume with `sscg approve`]
                              -> validate (sandbox build/test/rescan) -> remediation_report -> END)

Routing is deterministic (plain Python functions); LLMs only work inside the triage, narrator and remediation
advisor nodes. A checkpointer is always attached (SQLite for --remediate), so the human-approval interrupt can pause the
run and another process (CLI `approve` or the dashboard) can resume it.
"""
from __future__ import annotations

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from . import narrator, prioritizer, remediation_flow, remediator, triage, workers
from .state import GuardianState


def _after_discovery(state: dict) -> str:
    return "vuln_intel" if not state["options"].get("no_vulns") else "detection"


def _after_detection(state: dict) -> str:
    return "gather_evidence" if state.get("triage_queue") else "narrate"


def build_graph(remediate: bool = False, checkpointer=None):
    g = StateGraph(GuardianState)
    g.add_node("orchestrator", workers.plan)
    g.add_node("discovery", workers.discovery)
    g.add_node("vuln_intel", workers.vuln_intel)
    g.add_node("detection", workers.detection)
    g.add_node("gather_evidence", workers.gather_evidence)
    g.add_node("triage_one", triage.triage_one)
    g.add_node("triage_join", triage.triage_join)
    g.add_node("narrate", narrator.narrate)
    g.add_node("report", workers.reporter)

    g.add_edge(START, "orchestrator")
    g.add_edge("orchestrator", "discovery")
    g.add_conditional_edges("discovery", _after_discovery, ["vuln_intel", "detection"])
    g.add_edge("vuln_intel", "detection")
    g.add_conditional_edges("detection", _after_detection, ["gather_evidence", "narrate"])
    g.add_conditional_edges("gather_evidence", triage.fan_out, ["triage_one"])
    g.add_edge("triage_one", "triage_join")
    g.add_conditional_edges("triage_join", triage.after_join, ["gather_evidence", "narrate"])
    g.add_edge("narrate", "report")

    if remediate:
        g.add_node("exploit_intel", prioritizer.exploit_intel)
        g.add_node("reachability_scan", prioritizer.reachability_scan)
        g.add_node("prioritize", prioritizer.prioritize)
        g.add_node("plan_remediation", remediator.plan_remediation)
        g.add_node("advise_remediation", remediator.advise_remediation)
        g.add_node("human_approval", remediation_flow.human_approval)
        g.add_node("validate", remediation_flow.validate)
        g.add_node("remediation_report", remediation_flow.remediation_report)
        g.add_edge("report", "exploit_intel")                     # these two run in parallel
        g.add_edge("report", "reachability_scan")
        g.add_edge(["exploit_intel", "reachability_scan"], "prioritize")   # join: waits for both
        g.add_edge("prioritize", "plan_remediation")
        g.add_edge("plan_remediation", "advise_remediation")
        g.add_edge("advise_remediation", "human_approval")        # interrupt: pauses until a human decides
        g.add_edge("human_approval", "validate")
        g.add_edge("validate", "remediation_report")
        g.add_edge("remediation_report", END)
    else:
        g.add_edge("report", END)
    return g.compile(checkpointer=checkpointer or MemorySaver())
