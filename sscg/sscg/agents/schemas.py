"""Typed contracts between agents (pydantic). LLM replies are validated against these before they enter the state.

Day 1: TriageAssessment, Narrative.  Day 2 (already wired into the graph state): PriorityItem, RemediationProposal,
ApprovalRecord, ValidationReport. Fields marked "set by the system" are overwritten after the LLM call.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Verdict = Literal["likely_malicious", "suspicious", "likely_benign", "needs_human_review"]
Confidence = Literal["low", "medium", "high"]
ToolName = Literal["registry_metadata", "repo_file_context", "commit_history", "graph_context"]


class EvidenceRequest(BaseModel):
    tool: ToolName
    reason: str = Field("")


class TriageAssessment(BaseModel):
    """Triage agent output for one finding. Inference about the evidence, never a replacement for it."""
    finding_id: str
    verdict: Verdict = Field(description="likely_malicious only if the evidence shows malicious behaviour or a "
                                         "documented malicious package; otherwise suspicious / needs_human_review / "
                                         "likely_benign")
    confidence: Confidence
    rationale: str = Field(description="2-5 sentences that cite evidence IDs like F-012/E1, F-012/T2")
    cited_evidence: list[str] = Field(default_factory=list, description="evidence IDs used, e.g. ['F-012/E1']")
    matched_patterns: list[str] = Field(default_factory=list, description="attack pattern IDs from the knowledge base")
    benign_explanations: list[str] = Field(default_factory=list,
                                           description="plausible innocent explanations that were considered")
    recommended_next_step: str = Field("", description="what a human reviewer should check next")
    needs_more_evidence: bool = False
    evidence_requests: list[EvidenceRequest] = Field(default_factory=list)
    # set by the system, not by the LLM
    rule: str = ""
    generated_by: str = ""
    rounds: int = 1
    grounding: dict = Field(default_factory=dict)


class Concern(BaseModel):
    finding_id: str
    why: str = Field()


class Narrative(BaseModel):
    """Narrator agent output: the Day 1 checkpoint answer, in prose, citing finding IDs."""
    headline: str = Field()
    what_is_in_the_app: str = Field()
    what_changed: str = Field()
    what_appears_risky: str = Field()
    top_concerns: list[Concern] = Field(default_factory=list)
    caveats: list[str] = Field(default_factory=list)
    # set by the system
    generated_by: str = ""
    grounding: dict = Field(default_factory=dict)


# ------------------------------------------------------------------------------------------------ Day 2 contracts
Priority = Literal["P0", "P1", "P2", "P3"]
Action = Literal["upgrade", "replace", "pin", "remove", "mitigate", "block", "update_base_image", "escalate_review"]


class PriorityItem(BaseModel):
    finding_id: str
    priority: Priority
    score: float
    factors: dict = Field(default_factory=dict)       # severity, exploitability (KEV/EPSS), reachability, exposure ...
    explanation: str = ""
    confidence: Confidence = "medium"


class RemediationProposal(BaseModel):
    proposal_id: str
    finding_ids: list[str]
    action: Action
    component: str | None = None
    from_version: str | None = None
    to_version: str | None = None
    files_affected: list[str] = Field(default_factory=list)
    rationale: str = ""
    expected_risk_reduction: str = ""
    compatibility_impact: str = ""
    rollback: str = ""
    validation_plan: list[str] = Field(default_factory=list)
    generated_by: str = ""
    status: Literal["proposed", "approved", "rejected", "needs_changes", "risk_accepted", "pending"] = "proposed"


class ApprovalRecord(BaseModel):
    """Out-of-scope rule: nothing is merged, deployed or released without this record from a human."""
    proposal_id: str
    decision: Literal["approve", "reject", "request_changes", "accept_risk", "defer"]
    approver: str
    reason: str = ""
    decided_at: str
    expires_at: str | None = None


class ValidationReport(BaseModel):
    proposal_id: str
    verdict: Literal["verified", "failed", "not_run"]
    build_ok: bool | None = None
    tests_ok: bool | None = None
    before: dict = Field(default_factory=dict)        # finding counts / SBOM hash before the change
    after: dict = Field(default_factory=dict)
    new_findings: list[str] = Field(default_factory=list)
    notes: str = ""
