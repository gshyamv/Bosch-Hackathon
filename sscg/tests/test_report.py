"""The single Guardian report: vulnerabilities and suspicious changes apart, before -> after numbers, one PDF."""
import json

from sscg import report


def _f(fid, category, rule, level, **kw):
    f = {"finding_id": fid, "category": category, "rule": rule, "type": rule, "title": f"{rule} finding {fid}",
         "component": {"label": "lodash@4.17.15", "ecosystem": "npm", "direct": True}, "location": "package.json:3",
         "evidence": [], "new_in_change": False, "risk": {"level": level, "score": 8.0}}
    return f | kw


def _doc():
    vuln = _f("F-001", "vulnerability", "VULN", "High", severity={"label": "HIGH", "cvss": 8.1},
              fixes={"upgrade_to_at_least": "4.17.21"},
              evidence=[{"type": "advisory", "id": "GHSA-35jh-r3h4-6jhm", "cves": ["CVE-2021-23337"],
                         "url": "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm"}])
    sus = _f("F-002", "anomaly", "R03_INSTALL_SCRIPT", "Critical")
    return {"scan": {"application": "demo", "tool": "sscg test", "scanned_at": "2026-11-24T00:00:00+00:00"},
            "counts": {"advisories": 1, "new_in_change": 0}, "change": None, "findings": [vuln, sus], "notes": []}


def test_single_report_before_and_after(tmp_path):
    (tmp_path / "findings.json").write_text(json.dumps(_doc()), encoding="utf-8")
    (tmp_path / "remediation").mkdir()
    (tmp_path / "remediation" / "remediation_report.md").write_text("old", encoding="utf-8")
    agentic = {"engine": "deepseek:deepseek-chat", "triage": {"F-002": {
        "verdict": "suspicious", "confidence": "high", "rationale": "Postinstall runs curl | sh. More text."}}}

    # end of scan: before-state only
    files = report.write(tmp_path, agentic=agentic)
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert files[:2] == ["report.md", "report.html"] and (tmp_path / "report.pdf").read_bytes()[:4] == b"%PDF"
    assert "Vulnerabilities" in md and "Suspicious changes" in md
    assert md.index("## 2. Vulnerabilities") < md.index("CVE-2021-23337") < md.index("## 3. Suspicious changes")
    assert md.index("## 3. Suspicious changes") < md.index("R03_INSTALL_SCRIPT") < md.index("## 4. Decisions")
    assert "remediation: not run" in md.lower() and "deepseek:deepseek-chat" in md
    assert not (tmp_path / "remediation" / "remediation_report.md").exists()     # only one report remains

    # end of remediation: rewritten with the after-state
    post = {"resolved": ["F-001"], "remaining": ["F-002"], "new": [], "verdict": "verified", "reasons": ["ok"],
            "sbom_diff": {"changed": ["npm:lodash 4.17.15 -> 4.17.21"]},
            "after_findings": [{"finding_id": "F-001", "category": "anomaly", "rule": "R03_INSTALL_SCRIPT",
                                "title": "x", "level": "Critical"}]}
    (tmp_path / "remediation" / "post_analysis.json").write_text(json.dumps(post), encoding="utf-8")
    (tmp_path / "remediation" / "remediation.patch").write_text("diff", encoding="utf-8")
    (tmp_path / "remediation" / "sandbox_trace.json").write_text(json.dumps({
        "sandbox": "sscg-abc", "docker_server": "27.0 linux/amd64",
        "containers": [{"container": "sscg-abc-1", "image": "node:20", "cmd": "npm ci", "exit": 0, "status": "ok"}]}),
        encoding="utf-8")
    state = {"proposals": [{"proposal_id": "P-001", "finding_ids": ["F-001"], "action": "upgrade",
                            "component": "lodash@4.17.15", "from_version": "4.17.15", "to_version": "4.17.21",
                            "status": "approved", "priority": "P1"}],
             "approvals": [{"proposal_id": "P-001", "decision": "approve", "approver": "alice", "reason": "fix it",
                            "decided_at": "2026-11-24T01:00:00+00:00"}],
             "validations": [{"verdict": "verified", "confidence": "high", "findings_before": 2, "findings_after": 1,
                              "resolved": ["F-001"], "remaining": ["F-002"]}]}
    report.write(tmp_path, agentic=agentic, rem=report.remediation_from(state, tmp_path))
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "| Vulnerabilities (vulnerable components) | 1 | 0 |" in md
    assert "| Suspicious changes | 1 | 1 |" in md and "| Total findings | 2 | 1 |" in md
    assert "**resolved**" in md and "alice" in md and "sscg-abc" in md and "remediation/remediation.patch" in md
    assert "verified" in md and not list(tmp_path.rglob("remediation_report.*"))
