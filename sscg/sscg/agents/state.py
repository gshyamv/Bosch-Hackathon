"""The shared LangGraph state. JSON-safe only (it is checkpointed); live objects live in runtime.Runtime.

Fields written by parallel branches (the per-finding triage fan-out) use reducers, so branches merge instead of
overwriting each other. Remediation fields are declared up front so each node only has to fill its own.
"""
from __future__ import annotations

import operator
from typing import Annotated, TypedDict


def merge_dict(a: dict | None, b: dict | None) -> dict:
    return {**(a or {}), **(b or {})}


def merge_list_dict(a: dict | None, b: dict | None) -> dict:
    out = {k: list(v) for k, v in (a or {}).items()}
    for k, v in (b or {}).items():
        out[k] = out.get(k, []) + list(v)
    return out


class GuardianState(TypedDict, total=False):
    # ---- input
    run_id: str
    repo: str
    out: str
    options: dict                    # base, sbom, offline, no_vulns, focus, max_depth, why, remediation
    # ---- discover / detect: written by deterministic agents
    plan: dict                       # Orchestrator: what will run and why
    inventory: dict                  # Discovery: component counts, ecosystems, images, CI
    vuln_summary: dict               # Vulnerability Intel
    findings: list                   # Detection: findings (JSON-safe), F-001 ...
    change: dict | None              # Detection: "what changed" (diff.Change.as_dict)
    # ---- detect: agentic triage loop
    triage_queue: list               # finding IDs to (re)triage this round
    triage_round: int
    tool_evidence: Annotated[dict, merge_list_dict]   # finding_id -> [{id, tool, result}]
    triage: Annotated[dict, merge_dict]               # finding_id -> TriageAssessment (dict)
    narrative: dict                  # Narrator
    artifacts: dict                  # Reporter: files written
    # ---- analyze / remediate / validate (agents/prioritizer.py, agents/remediation_flow.py)
    exploitability: dict             # Exploit Intel: CISA KEV + EPSS per vulnerability finding
    reachability: dict               # Reachability: status per package node + network-service exposure
    priorities: list                 # [PriorityItem]
    proposals: list                  # [RemediationProposal]
    approvals: Annotated[list, operator.add]          # [ApprovalRecord]  (human decisions, never generated)
    validations: list                # [ValidationReport]
    # ---- audit trail
    agent_runs: Annotated[list, operator.add]         # one record per node / LLM call
    notes: Annotated[list, operator.add]
