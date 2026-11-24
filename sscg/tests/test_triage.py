"""Triage scope (only suspicious changes, never vulnerabilities) and the structured reasoning shape."""
import threading
from types import SimpleNamespace

from sscg.agents import kb, runtime, schemas, triage, workers

VULN = {"finding_id": "F-001", "category": "vulnerability", "rule": "VULN", "type": "Vulnerable direct dependency",
        "title": "lodash@4.17.4: 3 known vulnerabilities", "component": {"id": "n1", "label": "lodash@4.17.4"},
        "evidence": [{"type": "advisory", "id": "GHSA-xxxx-yyyy-zzzz"}]}
SCRIPT = {"finding_id": "F-002", "category": "anomaly", "rule": "R03_INSTALL_SCRIPT", "type": "install_script",
          "title": "evil-pkg@1.0.0 declares a postinstall script", "location": "package.json:3",
          "component": {"id": "n2", "label": "evil-pkg@1.0.0", "ecosystem": "npm"}, "new_in_change": True,
          "classification": "heuristic", "confidence": "medium", "risk": {"level": "High", "score": 8.0},
          "evidence": [{"type": "file", "path": "package.json", "line": 3, "snippet": '"postinstall": "node x.js"',
                        "permalink": "https://github.com/o/r/blob/abc/package.json#L3"},
                       {"type": "fact", "detail": "lockfile marks evil-pkg@1.0.0 with hasInstallScript: true"}]}
CI = {"finding_id": "F-003", "category": "anomaly", "rule": "R15_CI_UNPINNED_ACTION", "type": "ci", "title": "t",
      "component": None, "evidence": []}


def _rt(monkeypatch, run_id="t", **kw):
    kw.setdefault("out", None)
    rt = SimpleNamespace(kb=kb.load(), ctx=None, labels={"evil-pkg@1.0.0", "lodash@4.17.4"}, log=lambda *a: None,
                         usable_llm=lambda: None, llm_disabled="", lock=threading.Lock(),
                         settings=SimpleNamespace(max_triage=10, max_rounds=2), note=lambda fn: None, **kw)
    monkeypatch.setitem(runtime._RUNTIMES, run_id, rt)
    return rt


def test_vulnerabilities_are_never_sent_to_triage(monkeypatch, tmp_path):
    rt = _rt(monkeypatch, dg=SimpleNamespace(G=SimpleNamespace(nodes=lambda data=False: [])), target=None)
    monkeypatch.setattr(workers, "detect", lambda target, dg, base: ([VULN, SCRIPT, CI], None))
    monkeypatch.setattr(workers.relevance, "clusters", lambda dg, fs: [])
    out = workers.detection({"run_id": "t", "plan": {"compare_with": None}})
    assert out["triage_queue"] == ["F-002"]                 # not the CVE, not the deterministic CI rule
    basis = triage.triage_basis([VULN, SCRIPT, CI], rt.kb, {})
    assert basis["F-001"] == triage.DETERMINISTIC_VULN == "deterministic: verified advisory"
    assert basis["F-003"] == triage.DETERMINISTIC_RULE


def test_rules_fallback_produces_the_structured_shape(monkeypatch, tmp_path):
    rt = _rt(monkeypatch, out=tmp_path)
    state = {"run_id": "t", "findings": [VULN, SCRIPT], "change": None, "tool_evidence": {"F-002": [
        {"id": "F-002/T1", "tool": "registry_metadata", "result": {"found": False, "note": "no such package"}}]}}
    packet = triage.packet_for(state, "F-002", 0, 2, rt.kb)
    t = triage.triage_one({"run_id": "t", "finding_id": "F-002", "round": 0, "packet": packet})["triage"]["F-002"]
    assert t["basis"] == "rules_fallback" and t["generated_by"] == "rules-fallback"
    assert t["verdict"] == "suspicious" and t["confidence"] == "low"       # registry miss escalates the default
    assert t["summary"].count(". ") == 0 and t["summary"].endswith(".")   # one sentence
    assert 1 <= len(t["reasons"]) <= schemas.MAX_REASONS and all(r["verified"] for r in t["reasons"])
    first = t["reasons"][0]
    assert first["evidence"] == "F-002/E1" and first["kind"] == "file" and first["label"] == "package.json:3"
    assert first["permalink"].endswith("#L3")
    assert {r["evidence"] for r in t["reasons"]} >= {"F-002/E1", "F-002/T1"}
    assert t["recommended_action"] and t["recommended_next_step"] == t["recommended_action"]
    assert t["rationale"].startswith("Rules-only assessment") and t["grounding"]["ok"]
    assert "F-002/T1" in t["cited_evidence"]


def test_model_reasons_are_resolved_capped_and_checked(monkeypatch):
    rt = _rt(monkeypatch)
    packet = triage.packet_for({"findings": [SCRIPT], "change": None, "tool_evidence": {}}, "F-002", 0, 2, rt.kb)
    a = schemas.TriageAssessment.model_validate({
        "finding_id": "x", "verdict": "suspicious", "confidence": "medium", "summary": "Suspicious install script.",
        "reasons": [{"text": "Runs node x.js on install.", "evidence": "package.json:3"},
                    {"text": "Lockfile agrees.", "evidence": "F-002/E2"},
                    {"text": "Made-up source.", "evidence": "F-002/T7"},
                    {"text": "Fourth reason is trimmed.", "evidence": "F-002/E1"}],
        "recommended_action": "Read x.js."})
    assert len(a.reasons) == 3
    a = triage.finalize(a, packet, "F-002", 0, rt.labels)
    assert [r.verified for r in a.reasons] == [True, True, False]
    assert a.reasons[0].evidence == "F-002/E1" and a.reasons[0].permalink and a.reasons[1].kind == "rule"
    assert a.grounding["unverified_reasons"] == ["F-002/T7"] and a.grounding["ok"] is False
    assert a.basis == "ai_inference" and "[package.json:3]" in a.rationale


def test_old_agentic_triage_still_loads():
    old = {"finding_id": "F-001", "verdict": "needs_human_review", "confidence": "low", "rationale": "r",
           "recommended_next_step": "check"}
    a = schemas.TriageAssessment.model_validate(old)
    assert a.reasons == [] and a.summary == ""
