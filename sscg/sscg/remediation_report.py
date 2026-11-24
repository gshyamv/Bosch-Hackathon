"""Validate & report stage, "show the complete story" -> remediation/remediation_report.md (+ .html, .pdf).

Sections follow the slide: original finding + evidence, recommended and approved action, build and test results,
before-and-after risk status, remaining or accepted risk, final confidence and audit trail.
Verified facts and AI inference are kept apart; every AI text is labelled.
"""
from __future__ import annotations

ICON = {"verified": "✅", "partially_verified": "🟨", "failed": "❌", "not_run": "⏸️"}
STEP_ICON = {"ok": "✅", "failed": "❌", "timeout": "⏱️", "skipped": "➖", None: "·"}
STATUS_ICON = {"approved": "✅", "rejected": "🚫", "risk_accepted": "⚖️", "needs_changes": "✏️", "pending": "⏳",
               "manual": "👀", "proposed": "💡"}


def _c(s) -> str:
    return str(s if s is not None else "").replace("|", "/").replace("\n", " ")


def render(s: dict, app: str) -> str:
    pri, props = s.get("priorities", []), s.get("proposals", [])
    val = (s.get("validations") or [{}])[-1]
    appr = {a["proposal_id"]: a for a in s.get("approvals", [])}
    fby = {f["finding_id"]: f for f in s.get("findings", [])}
    v = val.get("verdict", "not_run")
    L = [f"# Guardian remediation report: {app}", "",
         f"*Run `{s.get('run_id')}` · {s.get('generated_at', '')} · engine {s.get('engine', '')}*", "",
         "**Prioritized risk → Recommended fix → Human approval → Build & test → Rescan → "
         f"{'Verified remediation ✔' if v == 'verified' else 'Verification: ' + v.replace('_', ' ')}**", "",
         "## 1. Summary", "",
         f"- **Verdict:** {ICON.get(v, '')} **{v.replace('_', ' ')}** (confidence {val.get('confidence', 'low')})"]
    L += [f"  - {r}" for r in val.get("reasons", [])]
    if val.get("findings_before") is not None and v != "not_run":
        L.append(f"- **Findings:** {val.get('findings_before')} before → {val.get('findings_after')} after · resolved "
                 f"{len(val.get('resolved', []))} · new {len(val.get('new', []))}")
    n = {k: sum(p["status"] == k for p in props) for k in STATUS_ICON}
    L += [f"- **Proposals:** {len(props)} · " + " · ".join(f"{k.replace('_', ' ')} {c}" for k, c in n.items() if c),
          f"- **Patch:** `{val['patch_file']}`" if val.get("patch_file") else "- **Patch:** none (nothing validated)", ""]

    L += ["## 2. Prioritized risks", "",
          "*Initial risk + signed points for exploitability (CISA KEV, EPSS), reachability, exposure and the "
          "triage verdict. Deterministic: the same input gives the same order.*", "",
          "| Priority | Score | Finding | Component | Why | Confidence |", "|---|---|---|---|---|---|"]
    for p in pri[:20]:
        L.append(f"| {p['priority']}{' 🔥' if p['urgent'] else ''} | {p['score']} | {p['finding_id']} {_c(p['title'])[:70]} | "
                 f"{_c(p['component']) or '-'} | {_c('; '.join(p['reasons'][1:4]))[:220]} | {p['confidence']} |")
    if len(pri) > 20:
        L.append(f"| | | *{len(pri) - 20} more in remediation.json* | | | |")
    L.append("")

    L += ["## 3. Recommended fixes and decisions", ""]
    for p in props:
        a = appr.get(p["proposal_id"])
        L += [f"### {p['proposal_id']} · {STATUS_ICON.get(p['status'], '')} {p['status'].replace('_', ' ')} · "
              f"{p['action'].replace('_', ' ')} · {_c(p['component'])}", "",
              f"- **Findings:** " + "; ".join(f"{f} {_c(fby[f]['title'])[:90]}" for f in p["finding_ids"] if f in fby),
              f"- **Change:** {_c(p.get('from_version')) or '-'} → {_c(p.get('to_version')) or '-'}"
              + (f" in `{', '.join(p['files_affected'])}`" if p.get("files_affected") else ""),
              f"- **Why (verified facts):** {p['rationale']}"]
        if p.get("ai_rationale"):
            L.append(f"- **Advisor (AI inference):** {p['ai_rationale']}")
        if p.get("ai_reviewer_checklist"):
            L.append("- **Reviewer checklist (AI):** " + " · ".join(p["ai_reviewer_checklist"]))
        L += [f"- **Expected risk reduction:** {p.get('expected_risk_reduction') or '-'}",
              f"- **Compatibility:** {p.get('compatibility_level')}: {p.get('compatibility_impact') or '-'}",
              f"- **Rollback:** {p.get('rollback') or '-'}"]
        if p.get("residual_advisories"):
            L.append(f"- **Residual advisories on the target:** {', '.join(p['residual_advisories'])}")
        if p.get("notes"):
            L.append(f"- **Notes:** {'; '.join(p['notes'])}")
        if a:
            L.append(f"- **Decision:** {a['decision']} by {a['approver']} at {a['decided_at']}"
                     + (f": {a['reason']}" if a.get("reason") else ""))
        pp = (val.get("per_proposal") or {}).get(p["proposal_id"])
        if pp:
            L.append(f"- **Validation:** {pp['status'].replace('_', ' ')} ({len(pp['resolved'])}/{len(pp['targeted'])} "
                     f"findings gone after the rescan)")
        if p.get("diff"):
            L += ["", "```diff", p["diff"].rstrip()[:3000], "```"]
        L.append("")

    L += ["## 4. Validation: build, test and rescan", ""]
    if v == "not_run":
        L += [f"Not run: {'; '.join(val.get('reasons', [])) or 'no approved proposal'}.", ""]
    else:
        before = {x["step"].split(": ", 1)[1]: x for x in val.get("steps_before", [])}
        L += [f"Sandbox `{val.get('workdir')}` · Docker: {'used' if val.get('docker') else 'not running (image build skipped)'}", "",
              "| Step | Before (unchanged) | After (remediated) | Time |", "|---|---|---|---|"]
        for x in val.get("steps_after", []):
            name = x["step"].split(": ", 1)[1]
            b = before.get(name, {})
            L.append(f"| {_c(name)} | {STEP_ICON.get(b.get('status'))} {b.get('status', '-')} | "
                     f"{STEP_ICON.get(x['status'])} {x['status']} | {x['seconds']}s |")
        fails = [x for x in val.get("steps_after", []) + val.get("steps_before", []) if x["status"] in ("failed", "timeout")]
        for x in fails[:6]:
            L += ["", f"<details><summary>{_c(x['step'])}: {x['status']} (log tail)</summary>", "", "```",
                  x.get("log", "")[-1500:], "```", "</details>"]
        sd = val.get("sbom_diff") or {}
        L += ["", f"**SBOM before → after:** {len(sd.get('changed', []))} changed · {len(sd.get('added', []))} added · "
                  f"{len(sd.get('removed', []))} removed", ""]
        L += [f"- changed: {x}" for x in sd.get("changed", [])[:25]]
        L += [f"- added: {x}" for x in sd.get("added", [])[:15]]
        L += [f"- removed: {x}" for x in sd.get("removed", [])[:15]]
        L += ["", f"**Resolved findings:** {', '.join(val.get('resolved', [])) or 'none'}", ""]
        if val.get("new"):
            L += ["**Newly introduced findings (after the change):**", ""]
            L += [f"- {n['level']}: {_c(n['title'])} ({n['rule']})" for n in val["new"][:20]]
            L.append("")

    L += ["## 5. Remaining and accepted risk", ""]
    remaining = val.get("remaining") if v != "not_run" else [f["finding_id"] for f in s.get("findings", [])]
    rem_pri = [p for p in pri if p["finding_id"] in set(remaining or [])]
    accepted = [p for p in props if p["status"] == "risk_accepted"]
    L.append(f"{len(remaining or [])} finding(s) remain"
             + (f"; highest: " + ", ".join(f"{p['finding_id']} ({p['priority']})" for p in rem_pri[:8]) if rem_pri else "") + ".")
    for p in accepted:
        a = appr.get(p["proposal_id"], {})
        L.append(f"- ⚖️ accepted: {p['proposal_id']} {_c(p['component'])} by {a.get('approver')}: {a.get('reason') or '-'}")
    for p in props:
        if p["status"] in ("manual", "pending", "needs_changes", "rejected"):
            L.append(f"- {STATUS_ICON[p['status']]} {p['status'].replace('_', ' ')}: {p['proposal_id']} "
                     f"{p['action'].replace('_', ' ')} {_c(p['component'])}")
    L.append("")

    L += ["## 6. Audit trail", "",
          f"- Knowledge base `{s.get('kb_version', '?')}` · LLM engine {s.get('engine', '')} · nothing was merged, "
          "deployed or released; the original repository was not modified.", "",
          "| Agent | Kind | Status | Seconds | Tokens in/out |", "|---|---|---|---|---|"]
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
