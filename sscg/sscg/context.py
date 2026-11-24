"""Context store (SQLite): scans and typed notes shared by all agents. Notes are validated: every cited id must exist in
the scan. Invalid notes are stored as rejected and never rendered; they are not repaired. Each valid note is
materialised into the OKF bundle (okf.py). A storage problem never breaks a scan."""
from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from . import okf
from .cache import ROOT

DB = Path(os.getenv("SSCG_CONTEXT_DB") or ROOT / ".context" / "context.db")
SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (scan_id TEXT PRIMARY KEY, target TEXT, display TEXT, sha TEXT, started_at REAL);
CREATE TABLE IF NOT EXISTS facts (scan_id TEXT, fact_id TEXT, data TEXT, PRIMARY KEY (scan_id, fact_id));
CREATE TABLE IF NOT EXISTS notes (note_id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT, kind TEXT, note_key TEXT,
  payload TEXT, valid INTEGER, errors TEXT, created_at REAL);
"""


class FactBatch(BaseModel):
    clusters: list[dict]
    findings: list[dict]
    evidence_ids: list[str]


class TriageNote(BaseModel):
    finding_id: str
    verdict: str
    confidence: str
    verified_facts: list[str] = Field(min_length=1)      # evidence ids, never prose
    inferences: list[str] = []
    grounding: dict = {}
    generated_by: str = ""


class PriorityNote(BaseModel):
    finding_id: str
    priority: Literal["P0", "P1", "P2", "P3"]
    score: float
    factors: dict
    confidence: str


class RemediationPlan(BaseModel):
    proposal_id: str
    cluster_ids: list[str] = []
    finding_ids: list[str] = Field(min_length=1)
    action: str
    component: str | None = None
    to_version: str | None = None
    patch: str = ""
    risk_reduction: str = ""
    compatibility: str = ""
    rollback: str = ""
    rationale: str = ""


class ApprovalNote(BaseModel):
    proposal_id: str
    decision: str
    reviewer: str = Field(pattern=r"^human:.+")
    comment: str = ""
    decided_at: str


class ValidationResult(BaseModel):
    validation_id: str
    proposal_ids: list[str]
    verdict: str
    confidence: str
    reasons: list[str] = []
    steps: list[dict] = []
    resolved: list[str] = []
    new: list[dict] = []
    sbom_diff: dict = {}


KINDS = {m.__name__: m for m in (FactBatch, TriageNote, PriorityNote, RemediationPlan, ApprovalNote, ValidationResult)}
KEY = {"TriageNote": "finding_id", "PriorityNote": "finding_id", "RemediationPlan": "proposal_id",
       "ApprovalNote": "proposal_id", "ValidationResult": "validation_id"}


def errors_in(note: BaseModel, valid: set[str]) -> list[str]:
    cited: set[str] = set()
    for k in ("finding_id", "proposal_id"):
        if isinstance(note, RemediationPlan) and k == "proposal_id":
            continue
        if getattr(note, k, None):
            cited.add(getattr(note, k))
    for k in ("finding_ids", "evidence_ids", "verified_facts", "cluster_ids", "proposal_ids", "resolved"):
        cited |= set(getattr(note, k, None) or [])
    bad = sorted(cited - valid)
    return [f"ids that do not exist in this scan: {bad[:10]}"] if bad else []


class Context:
    def __init__(self, scan_id: str, path: Path | None = None, store: okf.Store | None = None):
        self.scan_id, path = scan_id, path or DB
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, timeout=30, check_same_thread=False)
        self.conn.executescript(SCHEMA)
        self.store = store or okf.Store()

    def close(self) -> None:
        self.conn.close()

    def start(self, target) -> None:
        self.target = target.name
        with self.conn:
            self.conn.execute("INSERT OR REPLACE INTO scans VALUES(?,?,?,?,?)",
                              (self.scan_id, target.name, target.display, target.sha, time.time()))
        okf.scan_concept(self.store, self.scan_id, target)

    def add_facts(self, ids: dict[str, dict]) -> None:
        with self.conn:
            self.conn.executemany("INSERT OR REPLACE INTO facts VALUES(?,?,?)",
                                  [(self.scan_id, k, json.dumps(v, default=str)) for k, v in ids.items()])

    def ids(self) -> set[str]:
        return {r[0] for r in self.conn.execute("SELECT fact_id FROM facts WHERE scan_id=?", (self.scan_id,))}

    def write(self, kind: str, payload: dict) -> list[str]:
        note, errs = None, []
        try:
            note = KINDS[kind].model_validate(payload)
            errs = errors_in(note, self.ids())
        except (KeyError, ValidationError) as e:
            errs = [f"schema: {str(e)[:300]}"]
        data = note.model_dump() if note else payload
        key = data.get(KEY.get(kind, ""), "") or ""
        with self.conn:
            self.conn.execute("INSERT INTO notes(scan_id,kind,note_key,payload,valid,errors,created_at) VALUES(?,?,?,?,?,?,?)",
                              (self.scan_id, kind, key, json.dumps(data, default=str), int(not errs), json.dumps(errs), time.time()))
        if not errs:
            if kind == "RemediationPlan":
                self.add_facts({data["proposal_id"]: {"kind": "proposal"}})
            okf.materialize(self.store, self.scan_id, kind, data)
        return errs

    def notes(self, kind: str | None = None, valid_only: bool = True) -> list[dict]:
        q = "SELECT kind, payload, valid, errors FROM notes WHERE scan_id=?" + (" AND valid=1" if valid_only else "") + " ORDER BY note_id"
        return [{"kind": k, "payload": json.loads(p), "valid": bool(v), "errors": json.loads(e)}
                for k, p, v, e in self.conn.execute(q, (self.scan_id,)) if kind in (None, k)]

    # ------------------------------------------------------------ hooks for the agent nodes
    def on_detection(self, findings: list, clusters: list) -> None:
        facts = {f["finding_id"]: {"kind": "finding", "title": f["title"]} for f in findings}
        for f in findings:
            facts |= {f"{f['finding_id']}/E{i}": e for i, e in enumerate(f.get("evidence", []), 1)}
        facts |= {c["cluster_id"]: {"kind": "cluster"} for c in clusters}
        self.add_facts(facts)
        self.write("FactBatch", {"clusters": clusters, "findings": findings, "evidence_ids": [f["finding_id"] for f in findings]})

    def on_triage(self, t: dict, tool_ids: list[str]) -> None:
        self.add_facts({i: {"kind": "tool"} for i in tool_ids})
        fid = t["finding_id"]
        facts = t["cited_evidence"] or [f"{fid}/E1" if f"{fid}/E1" in self.ids() else fid]
        errs = self.write("TriageNote", {**t, "verified_facts": facts, "inferences": [t["rationale"], *t["benign_explanations"]]})
        if errs:      # rules fallback: the finding itself, marked as such
            self.write("TriageNote", {"finding_id": fid, "verdict": "needs_human_review", "confidence": "low",
                                      "verified_facts": [fid], "inferences": [f"agent note rejected: {errs[0]}"],
                                      "generated_by": "rules-fallback"})


def open_safe(scan_id: str, log=print) -> Context | None:
    try:
        return Context(scan_id)
    except (sqlite3.Error, OSError) as e:
        log(f"context store unavailable: {e}")
        return None
