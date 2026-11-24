"""Validate & report stage, "show the complete story" -> remediation/remediation_report.md (+ .html, .pdf).

Sections follow the problem statement: original finding + evidence, recommended and approved action, build and test
results, before-and-after risk status, remaining or accepted risk, final confidence and audit trail.
Verified facts and AI inference are kept apart; every AI text is labelled. Expected effects (estimates made before
validation) and measured effects (from the rescan) are labelled separately. Plain text status words only: the PDF
font has no emoji glyphs.
"""
from __future__ import annotations

COVERAGE_TEXT = {"tested": "tested", "started": "built and started (the container answered)", "built": "built",
                 "installed": "installed only (no build or test script)",
                 "rescan_only": "NOT executed: verified by the rescan only", "not_applicable":
                 "not executable locally (CI workflow): verified by the rescan only"}


def _c(s) -> str:
    return str(s if s is not None else "").replace("|", "/").replace("\n", " ")


def _cut(s, n: int) -> str:
    s = _c(s)
    return s if len(s) <= n else s[: n - 1].rsplit(" ", 1)[0] + "…"


def _name(step: dict) -> str:
    return step["step"].split(": ", 1)[1]


def render(s: dict, app: str) -> str:
    pri, props = s.get("priorities", []), s.get("proposals", [])
    val = (s.get("validations") or [{}])[-1]
    appr = {a["proposal_id"]: a for a in s.get("approvals", [])}
    fby = {f["finding_id"]: f for f in s.get("findings", [])}
    v = val.get("verdict", "not_run")
    repo_arg = (s.get("plan") or {}).get("repo") or app
    L = [f"# Guardian remediation report: {app}", "",
         f"*Run `{s.get('run_id')}` · {s.get('generated_at', '')} · AI engine {s.get('engine', '')}*", "",
         "**Prioritized risk → Recommended fix → Human approval → Build & test → Rescan → "
         f"{'Verified remediation' if v == 'verified' else 'Verification: ' + v.replace('_', ' ')}**", "",
         "## 1. Summary", "",
         f"- **Verdict:** **{v.replace('_', ' ').upper()}** (confidence {val.get('confidence', 'low')})"]
    L += [f"  - {r}" for r in val.get("reasons", [])]
    rl = val.get("risk_levels") or {}
    if v != "not_run" and val.get("findings_before") is not None:
        L.append(f"- **Measured (rescan):** {val.get('findings_before')} findings before → {val.get('findings_after')} "
                 f"after · resolved {len(val.get('resolved', []))} · new {len(val.get('new', []))}"
                 + (" · by level before/after: " + ", ".join(f"{k} {rl['before'].get(k, 0)}→{rl['after'].get(k, 0)}"
                                                           for k in ("Critical", "High", "Medium", "Low")) if rl else ""))
    n = {}
    for p in props:
        n[p["status"]] = n.get(p["status"], 0) + 1
    L += [f"- **Proposals:** {len(props)} · " + " · ".join(f"{k.replace('_', ' ')} {c}" for k, c in n.items()),
          (f"- **Validated patch:** `remediation.patch` (sha256 `{val.get('patch_sha256', '')[:16]}…`, validated "
           f"{val.get('validated_at', '')}): the exact change that was built and rescanned, including regenerated "
           f"lockfiles" if val.get("patch_file") else "- **Validated patch:** none (nothing was validated)"), ""]

    L += ["## 2. Prioritized risks", "",
          "*Initial risk + signed points for exploitability (CISA KEV, EPSS), static reachability, exposure indicators "
          "and the triage verdict. Deterministic: the same input gives the same order. Confidence drops for every "
          "missing or weak signal.*", "",
          "| Priority | Score | Finding | Component | Why | Confidence |", "|---|---|---|---|---|---|"]
    for p in pri[:20]:
        L.append(f"| {p['priority']}{' URGENT' if p['urgent'] else ''} | {p['score']} | {p['finding_id']} "
                 f"{_cut(p['title'], 90)} | {_c(p['component']) or '-'} | {_cut('; '.join(p['reasons'][1:4]), 240)} | "
                 f"{p['confidence']}{(' (' + ', '.join(p['unknowns'][:2]) + ')') if p.get('unknowns') else ''} |")
    if len(pri) > 20:
        L.append(f"| | | *{len(pri) - 20} more in remediation.json* | | | |")
    L.append("")

    L += ["## 3. Recommended fixes and decisions", "",
          "*The diff under each proposal is what the reviewer approved (manifest and file edits). Lockfiles are "
          "regenerated from the official registry during validation; the validated patch (section 4) contains them.*", ""]
    for p in props:
        a = appr.get(p["proposal_id"])
        L += [f"### {p['proposal_id']} · {p['status'].replace('_', ' ').upper()} · {p['action'].replace('_', ' ')} · "
              f"{_c(p['component'])}", "",
              "- **Findings:** " + "; ".join(f"{f} {_c(fby[f]['title'])}" for f in p["finding_ids"] if f in fby),
              f"- **Change:** {_c(p.get('from_version')) or '-'} → {_c(p.get('to_version')) or '-'}"
              + (f" in `{', '.join(p['files_affected'])}`" if p.get("files_affected") else ""),
              f"- **Why (verified facts):** {p['rationale']}"]
        if p.get("ai_rationale"):
            L.append(f"- **Advisor (AI inference):** {p['ai_rationale']}")
        if p.get("ai_reviewer_checklist"):
            L.append("- **Reviewer checklist (AI inference):** " + " · ".join(p["ai_reviewer_checklist"]))
        L += [f"- **Expected risk reduction (estimate before validation):** {p.get('expected_risk_reduction') or '-'}",
              f"- **Compatibility:** {p.get('compatibility_level')}: {p.get('compatibility_impact') or '-'}",
              f"- **Rollback:** {p.get('rollback') or '-'}"]
        if p.get("residual_status") == "unknown":
            L.append("- **Advisories on the target version:** UNKNOWN (OSV could not be queried)")
        elif p.get("residual_advisories"):
            L.append(f"- **Advisories remaining on the target version:** {', '.join(p['residual_advisories'])}")
        if p.get("notes"):
            L.append(f"- **Notes:** {'; '.join(x for x in p['notes'] if x)}")
        if a:
            L.append(f"- **Decision:** {a['decision']} by {a['approver']} at {a['decided_at']}"
                     + (f": {a['reason']}" if a.get("reason") else "")
                     + (f" (proposal sha256 `{a['proposal_sha256'][:12]}…`)" if a.get("proposal_sha256") else ""))
        pp = (val.get("per_proposal") or {}).get(p["proposal_id"])
        if pp:
            extra = []
            if pp.get("persisting"):
                extra.append("advisories still present on the new version: "
                             + "; ".join(f"{x['finding_id']} {', '.join(x['advisories'][:3])}" for x in pp["persisting"]))
            if pp.get("unverified"):
                extra.append("not checked (OSV unavailable in the after-scan): " + ", ".join(pp["unverified"]))
            L.append(f"- **Validation (measured):** {pp['status'].replace('_', ' ')} ({len(pp['resolved'])}/"
                     f"{len(pp['targeted'])} targeted findings resolved) · execution: "
                     f"{COVERAGE_TEXT.get(pp.get('coverage'), pp.get('coverage') or '-')}"
                     + ("; " + "; ".join(extra) if extra else ""))
        if p.get("diff"):
            L += ["", "```diff", p["diff"].rstrip()[:3000], "```"]
        L.append("")

    L += ["## 4. Validation: build, test and rescan", ""]
    if v == "not_run":
        L += [f"Not run: {'; '.join(val.get('reasons', [])) or 'no approved proposal'}.", ""]
    else:
        scan = val.get("scan") or {}
        before = {_name(x): x for x in val.get("steps_before", [])}
        L += [f"- **Where:** a temporary copy `{val.get('workdir')}` of the repository with the approved edits. Commands "
              "run as local processes with secrets removed from the environment and npm install scripts disabled; "
              "this is not an isolated sandbox.",
              f"- **Docker:** {'engine running: images were built (and removed afterwards)' if val.get('docker') else 'engine not running: image builds skipped'}",
              f"- **What was rescanned:** {scan.get('scope') or 'the remediated copy (source)'}",
              f"- **Vulnerability lookup in the rescan:** {'complete' if scan.get('vulns_checked', True) else 'UNAVAILABLE (OSV): vulnerability fixes are not proven'}"
              + (f" ({'; '.join(scan.get('notes', []))})" if scan.get("notes") else "")]
        for sc in val.get("image_scans") or []:
            if sc.get("status") == "ok":
                bs = sc.get("by_severity", {})
                L.append(f"- **Built image scan ({sc['label']}, {sc['dockerfile']}/Dockerfile, {sc.get('tool')}):** "
                         f"{sc.get('os') or 'image'}, {sc.get('packages')} packages; vulnerabilities: "
                         + ", ".join(f"{k.lower()} {bs.get(k, 0)}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")))
                for v in (sc.get("top") or [])[:5]:
                    L.append(f"  - {v['severity']} {v['id']} in {v['package']} {v['installed']}"
                             + (f" (fixed in {v['fixed']})" if v.get("fixed") else " (no fix published)"))
            else:
                L.append(f"- **Built image scan ({sc['label']}):** not completed: {_cut(sc.get('log') or '', 160)}")
        br = val.get("branch") or {}
        if br.get("status") == "ok":
            L.append(f"- **Controlled branch:** `{br['branch']}` (commit `{br['commit'][:12]}` on `{br['base'][:12]}`), "
                     f"{len(br.get('files', []))} file(s); exported as `remediation/remediation.bundle` "
                     f"(`git fetch <path>/remediation.bundle {br['branch']}`). Nothing was pushed or merged.")
        elif br:
            L.append(f"- **Controlled branch:** {br.get('status')}: {br.get('note') or '-'}")
        L += ["",
              "| Step | Kind | Before (unchanged) | After (remediated) | Compared with the baseline | Time |",
              "|---|---|---|---|---|---|"]
        for x in val.get("steps_after", []):
            b = before.get(_name(x), {})
            if x["status"] in ("failed", "timeout"):
                rel = ("REGRESSION: worked before" if b.get("status") == "ok" else
                       "failed before too (not caused by the fix)" if b.get("status") in ("failed", "timeout") else
                       "no baseline result: cannot tell")
            elif x["status"] == "ok":
                rel = "fixed by the change" if b.get("status") in ("failed", "timeout") else "ok"
            else:
                rel = _cut(x.get("log") or "skipped", 80)
            L.append(f"| {_c(_name(x))} | {x.get('kind', '-')} | {b.get('status', '-')} | {x['status']} | {rel} | "
                     f"{x['seconds']}s |")
        fails = [x for x in val.get("steps_after", []) + val.get("steps_before", []) if x["status"] in ("failed", "timeout")]
        for x in fails[:6]:
            L += ["", f"**Log tail: {_c(x['step'])} ({x['status']})**", "", "```", x.get("log", "")[-1500:], "```"]
        sd = val.get("sbom_diff") or {}
        L += ["", f"**SBOM before → after:** {len(sd.get('changed', []))} changed · {len(sd.get('added', []))} added · "
                  f"{len(sd.get('removed', []))} removed", ""]
        L += [f"- changed: {x}" for x in sd.get("changed", [])[:25]]
        L += [f"- added: {x}" for x in sd.get("added", [])[:15]]
        L += [f"- removed: {x}" for x in sd.get("removed", [])[:15]]
        L += ["", f"**Resolved findings:** {', '.join(val.get('resolved', [])) or 'none'}", ""]
        if val.get("persisting"):
            L += ["**Vulnerabilities NOT resolved: the package moved to a new version that keeps the same advisories:**", ""]
            L += [f"- {x['finding_id']} {x['component']}: {', '.join(x['advisories'])}" for x in val["persisting"]]
            L.append("")
        if val.get("new"):
            kinds = {"introduced": "NEW", "still_vulnerable": "other advisories on the new version",
                     "expected": "expected (e.g. the replacement package)"}
            L += ["**Findings that exist only after the change:**", ""]
            L += [f"- {kinds.get(x.get('kind'), x.get('kind'))} · {x['level']}: {_c(x['title'])} ({x['rule']})"
                  for x in val["new"][:20]]
            L.append("")
        af = val.get("after_files") or {}
        if af:
            L += ["**Machine-readable evidence:** before: `" + af.get("baseline_findings", "findings.json") + "`, `"
                  + af.get("baseline_sbom", "sbom.cdx.json") + "` · after: `" + af.get("findings", "-") + "`, `"
                  + af.get("sbom", "-") + "` · validation details: `remediation/remediation.json`", ""]

    L += ["## 5. Remaining and accepted risk", ""]
    if v != "not_run":
        remaining = val.get("remaining") or []
        rem_pri = [p for p in pri if p["finding_id"] in set(remaining)]
        L.append(f"Measured after the change: **{val.get('findings_after')} finding(s)** = {len(remaining)} original "
                 f"finding(s) still present + {len(val.get('new', []))} finding(s) that only exist after the change "
                 f"(section 4)." + (" Highest remaining: " + ", ".join(f"{p['finding_id']} ({p['priority']})"
                                                                         for p in rem_pri[:8]) + "." if rem_pri else ""))
    else:
        L.append(f"Nothing was changed: all {len(s.get('findings', []))} findings remain.")
    for p in props:
        a = appr.get(p["proposal_id"], {})
        if p["status"] == "risk_accepted":
            L.append(f"- accepted risk: {p['proposal_id']} {_c(p['component'])} by {a.get('approver')}: "
                     f"{a.get('reason') or '-'}")
        elif p["status"] in ("manual", "pending", "needs_changes", "rejected"):
            L.append(f"- {p['status'].replace('_', ' ')}: {p['proposal_id']} {p['action'].replace('_', ' ')} "
                     f"{_c(p['component'])}" + (f" ({a.get('reason')})" if a.get("reason") else ""))
    L.append("")
    redo = [p["proposal_id"] for p in props if p["status"] in ("needs_changes", "pending")]
    if redo or v in ("failed", "partially_verified"):
        L += ["**Next step (retry):** a finished run cannot be approved again. Start a new run and decide again:",
              "", "```", f"python -m sscg agent {repo_arg} --remediate --decisions later",
              f"python -m sscg approve {repo_arg} --approve <ids> --by \"<name>\"", "```", ""]

    L += ["## 6. Audit trail", "",
          f"- Knowledge base `{s.get('kb_version', '?')}` · AI engine {s.get('engine', '')} · nothing was merged, "
          "deployed or released; the original repository was not modified.",
          "- Approvals are bound to a fingerprint of the reviewed files (manifests, lockfiles, Dockerfiles, workflows, "
          "edited files): a changed repository is refused at resume." + (
              f" Source fingerprint `{next(iter(appr.values())).get('source_sha256', '')[:16]}…`."
              if appr and next(iter(appr.values())).get("source_sha256") else ""), "",
          "| Agent / step | Kind | Status | Seconds | Tokens in/out |", "|---|---|---|---|---|"]
    for r in s.get("agent_runs", []):
        if r["kind"] == "llm" and not r.get("llm_calls") and r["agent"] == "Triage":
            continue
        L.append(f"| {r['agent']} | {r['kind']} | {r.get('status', 'ok')} | {r['seconds']} | "
                 f"{r.get('input_tokens', 0)}/{r.get('output_tokens', 0)} |")
    for a in s.get("approvals", []):
        L.append(f"| Human approval | human | {a['decision']} {a['proposal_id']} by {_c(a['approver'])} | "
                 f"{a['decided_at']} | |")
    L.append("")
    return "\n".join(L)
