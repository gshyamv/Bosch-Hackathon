"""The orchestrator: a LangGraph StateGraph wiring the agents together.

    START -> orchestrator -> discovery -> vuln_intel -> detection --(nothing to judge)--> narrate
                                                   |
                                                   v
                       +------------------> gather_evidence --Send x N--> triage_one (parallel)
                       |                                                      |
                       +----(more evidence requested, round < max)---- triage_join
                                                                              |
                                                              narrate -> report -> END
                                       (--day2-preview: report -> prioritize -> propose_remediation
                                                         -> human_approval [interrupt] -> validate -> END)

Routing is deterministic (plain Python functions); LLMs only work inside the triage and narrator nodes.
A checkpointer is always attached so the human-approval interrupt can pause and resume the run.
"""
from __future__ import annotations

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from . import day2, narrator, triage, workers
from .state import GuardianState


def _after_discovery(state: dict) -> str:
    return "vuln_intel" if not state["options"].get("no_vulns") else "detection"


def _after_detection(state: dict) -> str:
    return "gather_evidence" if state.get("triage_queue") else "narrate"


def build_graph(day2_preview: bool = False, checkpointer=None):
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

    if day2_preview:
        g.add_node("prioritize", day2.prioritize)
        g.add_node("propose_remediation", day2.propose_remediation)
        g.add_node("human_approval", day2.human_approval)
        g.add_node("validate", day2.validate)
        g.add_edge("report", "prioritize")
        g.add_edge("prioritize", "propose_remediation")
        g.add_edge("propose_remediation", "human_approval")
        g.add_edge("human_approval", "validate")
        g.add_edge("validate", END)
    else:
        g.add_edge("report", END)
    return g.compile(checkpointer=checkpointer or MemorySaver())
