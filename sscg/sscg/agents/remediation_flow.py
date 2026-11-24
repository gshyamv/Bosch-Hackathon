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

from .. import snapshot, validation
from .runtime import get, now, traced
from .schemas import ApprovalRecord, ValidationReport

STATUS = {"approve": "approved", "reject": "rejected", "request_changes": "needs_changes",
          "accept_risk": "risk_accepted", "defer": "pending"}


def approval_request(props: list, source: dict | None = None) -> dict:
    """What the human (CLI / dashboard) is asked to decide. `source` = fingerprint of the reviewed files: the paused
    run is only resumed if the repository still matches it (sscg/snapshot.py)."""
    return {"type": "approval_request", "source": source, "proposals": [
        {**{k: p.get(k) for k in ("proposal_id", "action", "component", "from_version", "to_version", "priority",
                                  "urgent", "patchable", "compatibility_level", "compatibility_impact", "rationale",
                                  "ai_rationale", "ai_reviewer_checklist", "expected_risk_reduction", "rollback",
                                  "residual_advisories", "residual_status", "notes", "finding_ids", "files_affected",
                                  "diff", "status")},
         "proposal_sha256": snapshot.proposal_hash(p)}
        for p in props]}


@traced("Human Approval", "human")
def human_approval(state: dict) -> dict:
    props = state.get("proposals", [])
    if not props:
        return {}
    rt = get(state["run_id"])
    source = snapshot.fingerprint(rt.repo, sorted({f for p in props for f in p.get("files_affected") or []}))
    answer = interrupt(approval_request(props, source))  # <- the graph stops here until a human answers
    ids = {p["proposal_id"] for p in props}
    by_id = {p["proposal_id"]: p for p in props}
    records = [ApprovalRecord(proposal_id=a["proposal_id"], decision=a["decision"],
                              approver=a.get("approver") or "unknown", reason=a.get("reason", ""),
                              decided_at=now(), expires_at=a.get("expires_at"),
                              proposal_sha256=snapshot.proposal_hash(by_id[a["proposal_id"]]),
                              source_sha256=source["sha256"]).model_dump()
               for a in (answer or []) if a.get("proposal_id") in ids and a.get("decision") in STATUS]
    dec = {r["proposal_id"]: r["decision"] for r in records}
    updated = [{**p, "status": STATUS[dec[p["proposal_id"]]] if p["proposal_id"] in dec else "pending"} for p in props]
    n = {s: sum(p["status"] == s for p in updated) for s in ("approved", "rejected", "risk_accepted", "pending")}
    rt.log("Human Approval", " · ".join(f"{k} {v}" for k, v in n.items()) + f" · source {source['sha256'][:12]}")
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
    res = validation.validate(rt.repo, state["findings"], rt.dg, props, base, workdir=work,
                              baseline=not state["options"].get("no_baseline"),
                              log=lambda m: rt.log("Validation", m), run_id=state["run_id"])
    v, conf, reasons = validation.verdict(res)
    out = rt.out / "remediation"
    out.mkdir(parents=True, exist_ok=True)
    patch = out / "remediation.patch"
    patch.write_text(res["patch"], encoding="utf-8")
    # after-state evidence, next to the baseline (out/<repo>/findings.json, sbom.cdx.json): reviewers can reproduce
    # every before/after claim from these files
    import json
    from ..sbom import write_cyclonedx
    after = out / "after"
    after.mkdir(exist_ok=True)
    (after / "findings.json").write_text(json.dumps({"scan": res["scan"], "findings": res["after_findings"]},
                                                    indent=1, default=str), encoding="utf-8")
    after_files = {"findings": "remediation/after/findings.json", "baseline_findings": "findings.json",
                   "baseline_sbom": "sbom.cdx.json"}
    try:
        write_cyclonedx(res["dg_after"], after / "sbom.cdx.json")
        after_files["sbom"] = "remediation/after/sbom.cdx.json"
    except Exception as e:  # noqa: BLE001  (missing after-SBOM is reported, never fatal)
        rt.log("Validation", f"after-SBOM not written: {type(e).__name__}: {e}")
    # built-image scans (full package and vulnerability lists) as files; the state keeps a summary
    import shutil
    summaries = []
    for sc in res.get("image_scans") or []:
        name = f"image-scan-{sc['label']}.json"
        target = after if sc["label"] == "after" else out
        (target / name).write_text(json.dumps(sc, indent=1, default=str), encoding="utf-8")
        after_files[f"image_scan_{sc['label']}"] = f"remediation/{'after/' if sc['label'] == 'after' else ''}{name}"
        summaries.append({**{k: v for k, v in sc.items() if k not in ("package_list", "vulnerabilities")},
                          "top": [v for v in sc.get("vulnerabilities", []) if v["severity"] in ("CRITICAL", "HIGH")][:15]})
    res["image_scans"] = summaries
    br = res.get("branch") or {}
    if br.get("bundle"):
        shutil.copyfile(br["bundle"], out / "remediation.bundle")
        br["bundle"] = "remediation/remediation.bundle"
        after_files["bundle"] = br["bundle"]
    rep = ValidationReport(proposal_ids=[p["proposal_id"] for p in approved], verdict=v, confidence=conf,
                           reasons=reasons, patch_file=str(patch), after_files=after_files, **{k: res[k] for k in (
                               "steps_before", "steps_after", "findings_before", "findings_after", "resolved",
                               "remaining", "new", "per_proposal", "sbom_diff", "applied_files", "workdir", "docker",
                               "scan", "persisting", "unverified", "validated_at", "patch_sha256", "risk_levels", "image_scans", "branch")})
    rt.log("Validation", f"{v.upper()} ({conf} confidence): resolved {len(res['resolved'])}, remaining "
                         f"{len(res['remaining'])}, new {len(res['new'])} · patch: {patch}")
    return {"validations": [rep.model_dump()], "_run": {"verdict": v, "resolved": len(res["resolved"]),
                                                        "new": len(res["new"])}}


@traced("Remediation Reporter", "deterministic")
def remediation_report(state: dict) -> dict:
    """remediation_report.md / .html / .pdf + machine-readable remediation.json in out/<repo>/remediation/."""
    import json

    from .. import remediation_report as render_mod
    from ..report_export import to_html, to_pdf
    rt = get(state["run_id"])
    out = rt.out / "remediation"
    out.mkdir(parents=True, exist_ok=True)
    s = {**state, "generated_at": now(), "engine": rt.settings.engine, "kb_version": rt.kb.version}
    md = render_mod.render(s, rt.repo.name)
    (out / "remediation_report.md").write_text(md, encoding="utf-8")
    files = ["remediation_report.md"]
    (out / "remediation_report.html").write_text(to_html(md), encoding="utf-8")
    files.append("remediation_report.html")
    try:
        (out / "remediation_report.pdf").write_bytes(to_pdf(md))
        files.append("remediation_report.pdf")
    except Exception as e:  # noqa: BLE001  (a PDF problem never breaks the run)
        rt.log("Remediation Reporter", f"PDF not written: {type(e).__name__}: {e}")
    doc = {"run_id": state["run_id"], "application": rt.repo.name, "generated_at": s["generated_at"],
           "exploitability_sources": (state.get("exploitability") or {}).get("sources"),
           "exposure": (state.get("reachability") or {}).get("exposure"),
           "reachability_summary": (state.get("reachability") or {}).get("summary"),
           **{k: state.get(k, []) for k in ("priorities", "proposals", "approvals", "validations")}}
    (out / "remediation.json").write_text(json.dumps(doc, indent=1, default=str), encoding="utf-8")
    files.append("remediation.json")
    if (out / "remediation.patch").exists():
        files.append("remediation.patch")
    rt.log("Remediation Reporter", f"wrote {', '.join(files)} to {out}")
    return {"artifacts": {**(state.get("artifacts") or {}), "remediation": [str(out / f) for f in files]}}
