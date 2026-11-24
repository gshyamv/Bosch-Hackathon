"""Typed contracts between agents (pydantic). LLM replies are validated against these before they enter the state.

Detection: TriageAssessment, Narrative.  Remediation (wired into the graph state): PriorityItem, RemediationProposal,
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
    """Narrator agent output: what is in the app, what changed, what appears risky, in prose, citing finding IDs."""
    headline: str = Field()
    what_is_in_the_app: str = Field()
    what_changed: str = Field()
    what_appears_risky: str = Field()
    top_concerns: list[Concern] = Field(default_factory=list)
    caveats: list[str] = Field(default_factory=list)
    # set by the system
    generated_by: str = ""
    grounding: dict = Field(default_factory=dict)


# ------------------------------------------------------------------------------------- remediation contracts
Priority = Literal["P0", "P1", "P2", "P3"]
Action = Literal["upgrade", "replace", "pin", "remove", "mitigate", "block", "update_base_image", "escalate_review"]


class PriorityItem(BaseModel):
    """Explainable priority: initial risk + signed points per factor (agents/prioritizer.py)."""
    finding_id: str
    priority: Priority
    score: float
    urgent: bool = False                              # KEV + reachable, likely malicious, swapped hash ...
    bucket: str = ""                                  # fix now / fix this sprint / plan the fix / monitor
    title: str = ""
    category: str = ""
    component: str | None = None
    factors: dict = Field(default_factory=dict)       # {name: {value, points}}: KEV, EPSS, reachability, exposure, triage
    reasons: list[str] = Field(default_factory=list)  # one human-readable line per factor
    unknowns: list[str] = Field(default_factory=list) # what lowered the confidence
    explanation: str = ""
    confidence: Confidence = "medium"


class RemediationProposal(BaseModel):
    """One remediation, built by the deterministic planner (sscg/remediation.py). `ai_*` fields are LLM inference."""
    proposal_id: str
    finding_ids: list[str]
    action: Action
    component: str | None = None
    from_version: str | None = None
    to_version: str | None = None
    files_affected: list[str] = Field(default_factory=list)
    edits: list[dict] = Field(default_factory=list)       # exact operations the Validation agent applies
    diff: str = ""                                        # unified diff of the edits against the repository
    patchable: bool = False                               # False: manual / escalate_review, nothing to apply
    priority: str | None = None
    urgent: bool = False
    rationale: str = ""                                   # deterministic, from verified facts
    expected_risk_reduction: str = ""
    compatibility_level: Literal["low", "medium", "high"] = "low"
    compatibility_impact: str = ""
    residual_advisories: list[str] = Field(default_factory=list)
    residual_status: Literal["checked", "unknown"] = "checked"   # unknown: OSV could not be queried for the target
    rollback: str = ""
    validation_plan: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    ai_rationale: str = ""                                # Remediation Advisor (LLM), grounded, inference only
    ai_reviewer_checklist: list[str] = Field(default_factory=list)
    generated_by: str = ""
    status: Literal["proposed", "manual", "approved", "rejected", "needs_changes", "risk_accepted", "pending"] = "proposed"


class AdviceItem(BaseModel):
    proposal_id: str
    rationale: str = Field(description="2-3 sentences: why this action is the right one, the trade-off, cite F-/P- IDs")
    reviewer_checklist: list[str] = Field(default_factory=list, description="up to 3 concrete checks for the approver")


class Advice(BaseModel):
    items: list[AdviceItem]


class ApprovalRecord(BaseModel):
    """Out-of-scope rule: nothing is merged, deployed or released without this record from a human."""
    proposal_id: str
    decision: Literal["approve", "reject", "request_changes", "accept_risk", "defer"]
    approver: str
    reason: str = ""
    decided_at: str
    expires_at: str | None = None
    proposal_sha256: str | None = None    # the exact proposal (edits, diff) that was decided on
    source_sha256: str | None = None      # fingerprint of the reviewed repository files (sscg/snapshot.py)


class ValidationReport(BaseModel):
    """One sandbox validation of all approved, patchable proposals together (sscg/validation.py)."""
    proposal_ids: list[str] = Field(default_factory=list)
    verdict: Literal["verified", "partially_verified", "failed", "not_run"]
    confidence: Confidence = "low"
    reasons: list[str] = Field(default_factory=list)
    steps_before: list[dict] = Field(default_factory=list)   # baseline build / test of the unchanged repository
    steps_after: list[dict] = Field(default_factory=list)    # build / test of the remediated sandbox
    findings_before: int = 0
    findings_after: int = 0
    resolved: list[str] = Field(default_factory=list)        # finding IDs (of the original scan) that are gone
    remaining: list[str] = Field(default_factory=list)
    new: list[dict] = Field(default_factory=list)            # findings that only exist after the change
    per_proposal: dict = Field(default_factory=dict)
    sbom_diff: dict = Field(default_factory=dict)
    applied_files: list[str] = Field(default_factory=list)
    patch_file: str | None = None
    patch_sha256: str | None = None                          # hash of the exact patch that was built and rescanned
    validated_at: str | None = None
    workdir: str | None = None
    docker: bool = False
    scan: dict = Field(default_factory=dict)                 # rescan scope + whether vulnerabilities could be checked
    persisting: list[dict] = Field(default_factory=list)     # targeted advisories still present on the new version
    unverified: list[str] = Field(default_factory=list)      # vulnerability findings the after-scan could not check
    after_files: dict = Field(default_factory=dict)          # saved after-state evidence (findings, SBOM)
    risk_levels: dict = Field(default_factory=dict)          # measured: findings per risk level before / after
    image_scans: list[dict] = Field(default_factory=list)    # Trivy scans of the built images (summary; full list in files)
    branch: dict = Field(default_factory=dict)               # controlled git branch + bundle with the validated change
