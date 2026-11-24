"""The ONE human-readable Guardian report: out/<repo>/report.md, rendered to report.html and report.pdf.

It is written at the end of the scan (before-state only, remediation "not run" / "awaiting approval") and rewritten
when remediation ends, with the after-state from remediation/post_analysis.json and remediation/sandbox_trace.json.

Two kinds of finding are kept strictly apart (finding `category`):
  vulnerability  a published advisory (CVE / GHSA / OSV) on the exact version of a dependency: fixed by upgrading
  anomaly        suspicious supply-chain behaviour with no CVE: install scripts, untrusted sources, typosquats,
                 CI workflow issues, live-page SRI ...: judged by rules + AI triage, fixed by removing or pinning
Machine-readable data stays in findings.json, agentic.json and remediation/*.json; this report only summarises.
"""
from __future__ import annotations

import json
from pathlib import Path

ICON = {"Critical": "🟥", "High": "🟧", "Medium": "🟨", "Low": "🟦", "Info": "⬜"}
LEVEL_ORDER = ["Critical", "High", "Medium", "Low", "Info", "Unknown"]
TABLE_LIMIT = 80                  # rows per findings table; everything is in findings.json
LEGACY = ["remediation/remediation_report.md", "remediation/remediation_report.html",
          "remediation/remediation_report.pdf"]


def _c(s) -> str:
    return str(s if s is not None else "").replace("|", "/").replace("\n", " ").strip()


def _cut(s, n: int) -> str:
    s = _c(s)
    return s if len(s) <= n else s[:n - 1].rstrip() + "…"


def _first_sentence(s: str) -> str:
    s = _c(s)
    i = s.find(". ")
    return s[:i + 1] if 0 < i < 220 else s


def _lv(f: dict) -> str:
    """Level used for before / after counts: official severity for vulnerabilities, Guardian risk otherwise
    (the same rule remediation_flow.validate uses for post_analysis.json)."""
    v = ((f.get("severity") or {}).get("label") if f.get("category") == "vulnerability" else None) \
        or f.get("level") or (f.get("risk") or {}).get("level") or "unknown"
    v = str(v).capitalize()
    return "Medium" if v == "Moderate" else v


def _by_level(fs: list) -> dict:
    c: dict = {}
    for f in fs:
        c[_lv(f)] = c.get(_lv(f), 0) + 1
    return c


def _read(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


# ------------------------------------------------------------------------------------------------ remediation view
def remediation_from(state: dict, out: Path) -> dict:
    """What the report needs from the remediation part of the graph state (+ post_analysis / sandbox_trace on disk).
    The on-disk files are used only when this run actually validated something (they could be from an older run)."""
    val = (state.get("validations") or [None])[-1]
    validated = bool(val) and val.get("verdict") not in (None, "not_run")
    rd = out / "remediation"
    from datetime import datetime, timezone
    return {"generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "priorities": state.get("priorities") or [], "proposals": state.get("proposals") or [],
            "approvals": state.get("approvals") or [], "validation": val,
            "post": _read(rd / "post_analysis.json") if validated else None,
            "trace": _read(rd / "sandbox_trace.json") if validated else None,
            "patch": "remediation/remediation.patch" if validated and (rd / "remediation.patch").is_file() else None}


def _status(rem: dict | None) -> tuple[str, str]:
    """(key, sentence) for the remediation state."""
    if not rem or not (rem.get("proposals") or rem.get("validation")):
        return "not_run", "Remediation: not run. Only the before-state is shown; this report is rewritten with the " \
                          "after-state when a remediation run finishes."
    val = rem.get("validation")
    if not val:
        if not rem.get("approvals"):
            return "awaiting", f"Remediation: awaiting human approval of {len(rem['proposals'])} proposal(s). " \
                               "Nothing has been changed yet."
        return "decided", "Remediation: decided, not validated yet."
    v = val.get("verdict", "not_run")
    if v == "not_run":
        return "not_validated", "Remediation: decisions recorded, nothing validated (" + \
            ("; ".join(val.get("reasons") or []) or "no approved proposal with a patch") + ")."
    return "validated", f"Remediation: validated in the sandbox, verdict **{v.replace('_', ' ')}** " \
                        f"(confidence {val.get('confidence', 'low')})."


def _finding_status(fid: str, rem: dict | None, by_prop: dict) -> str:
    val = (rem or {}).get("validation") or {}
    post = (rem or {}).get("post") or {}
    resolved = set(post.get("resolved") or val.get("resolved") or [])
    remaining = set(post.get("remaining") or val.get("remaining") or [])
    p = by_prop.get(fid)
    if resolved or remaining:
        if fid in resolved:
            return "**resolved**"
        if p and p["status"] == "risk_accepted":
            return "remaining (risk accepted)"
        return "remaining"
    if p:
        return {"approved": "approved, not validated", "rejected": "remaining (rejected)",
                "risk_accepted": "remaining (risk accepted)", "needs_changes": "remaining (changes requested)",
                "pending": "awaiting decision", "proposed": "awaiting decision",
                "manual": "manual fix needed"}.get(p["status"], p["status"])
    return "not remediated" if rem and rem.get("proposals") else "-"


def _suggestion(p: dict) -> dict | None:
    try:
        from .agents.remediation_flow import system_suggestion
        return system_suggestion(p)
    except Exception:  # noqa: BLE001  (langgraph missing etc.: the column just stays empty)
        return None


# ------------------------------------------------------------------------------------------------ render
def render(doc: dict, summary: dict | None = None, agentic: dict | None = None, rem: dict | None = None) -> str:
    s, ch = doc["scan"], doc.get("change")
    fs = doc["findings"]
    vulns = [f for f in fs if f["category"] == "vulnerability"]
    sus = [f for f in fs if f["category"] != "vulnerability"]
    agentic = agentic or {}
    tri = agentic.get("triage") or {}
    rem = rem or None
    key, status_line = _status(rem)
    post = (rem or {}).get("post") or {}
    val = (rem or {}).get("validation") or {}
    prio = {p["finding_id"]: p for p in (rem or {}).get("priorities", [])}
    by_prop: dict = {}
    for p in (rem or {}).get("proposals", []):
        for fid in p.get("finding_ids", []):
            by_prop.setdefault(fid, p)
    after_fs = post.get("after_findings")
    validated = key == "validated"

    target = (s.get("target") or {}).get("display") or s["application"]
    llm = agentic.get("engine") or "none (plain scan, no AI agents)"
    head = s.get("head")
    L = [f"# Guardian supply-chain report: {s['application']}", "",
         f"*Scanned {s['scanned_at']} with {s['tool']}" + (f" · HEAD `{head['short']}`" if head else "")
         + (f" · remediation updated {rem['generated_at']}" if rem and rem.get("generated_at") else "") + "*", ""]

    # 1 ------------------------------------------------------------------ executive summary
    L += ["## 1. Executive summary", "", "| | |", "|---|---|",
          f"| Target | `{_c(target)}` |",
          f"| Scan date | {s['scanned_at']} |",
          f"| LLM used | {_c(llm)} |"]
    if summary:
        L.append(f"| Components | {summary.get('components_total')} ({summary.get('direct')} direct, "
                 f"{summary.get('transitive')} transitive) |")
    if ch:
        L.append(f"| Latest change | `{ch['base']['short']}` → `{ch['head']['short']}` by {_c(ch['head']['author'])}"
                 + (" (first-time contributor)" if ch.get("first_time_author") else "")
                 + f": {doc['counts'].get('new_in_change', 0)} new finding(s) |")
    L += [f"| Remediation | {status_line.removeprefix('Remediation: ')} |", ""]
    nar = agentic.get("narrative") or {}
    if nar.get("headline") or nar.get("what_appears_risky"):
        L += [f"**AI summary** *(inference by {_c(llm)}, not evidence)*: {_c(nar.get('headline'))} "
              f"{_c(nar.get('what_appears_risky'))}".rstrip(), ""]

    def hi(fl):
        return sum(1 for f in fl if _lv(f) in ("Critical", "High"))
    if validated and after_fs is not None:
        av = [f for f in after_fs if f.get("category") == "vulnerability"]
        an = [f for f in after_fs if f.get("category") != "vulnerability"]
        after = [len(av), len(an), hi(after_fs), len(after_fs)]
    elif validated:
        after = ["?", "?", "?", val.get("findings_after", "?")]
    else:
        after = ["not run"] * 4
    L += ["| Headline | Before | After |", "|---|---|---|",
          f"| Vulnerabilities (vulnerable components) | {len(vulns)} | {after[0]} |",
          f"| Suspicious changes | {len(sus)} | {after[1]} |",
          f"| Critical + High | {hi(fs)} | {after[2]} |",
          f"| Total findings | {len(fs)} | {after[3]} |"]
    if validated:
        new = post.get("new") if post else val.get("new")
        L.append(f"| Resolved / newly introduced | | {len(post.get('resolved') or val.get('resolved') or [])} / "
                 f"{sum(1 for n in new or [] if n.get('kind', 'introduced') == 'introduced')} |")
    L.append("")

    # 2 ------------------------------------------------------------------ vulnerabilities
    L += ["## 2. Vulnerabilities (known advisories in dependencies)", "",
          "> A **vulnerability** is a published flaw (CVE / GHSA / OSV advisory) in the exact version of a "
          "third-party component. The severity is the official one from the advisory. It is fixed by upgrading to "
          "the fixed version. These are *not* signs of an attack; the suspicious changes in section 3 are.", ""]
    if not vulns:
        L += ["No known vulnerabilities in the dependencies (OSV.dev).", ""]
    else:
        L += [f"{len(vulns)} vulnerable component(s), {doc['counts'].get('advisories', 0)} advisories.", "",
              "| ID | Component | Ecosystem | Severity | Advisories | Fixed version | Priority | Status after |",
              "|---|---|---|---|---|---|---|---|"]
        for f in vulns[:TABLE_LIMIT]:
            comp, sv = f.get("component") or {}, f.get("severity") or {}
            advs = [e for e in f["evidence"] if e.get("type") == "advisory"]
            ids = []
            for e in advs:
                name = (e.get("cves") or [e["id"]])[0]
                if name not in [i[0] for i in ids]:
                    ids.append((name, e.get("url")))
            adv = ", ".join(f"[{n}]({u})" if u else n for n, u in ids[:3]) + (f" +{len(ids) - 3}" if len(ids) > 3 else "")
            fx = f.get("fixes") or {}
            p = prio.get(f["finding_id"])
            lvl = _lv(f)
            L.append(f"| {f['finding_id']}{' 🆕' if f.get('new_in_change') else ''} | `{_c(comp.get('label') or f['title'])}`"
                     f"{' (direct)' if comp.get('direct') else ''} | {_c(comp.get('ecosystem'))} | "
                     f"{ICON.get(lvl, '')} {lvl}" + (f" {sv['cvss']}" if sv.get("cvss") else "") + f" | {adv or '-'} | "
                     f"{_c(fx.get('upgrade_to_at_least')) or 'no fix published'} | "
                     f"{(p['priority'] + (' urgent' if p.get('urgent') else '')) if p else '-'} | "
                     f"{_finding_status(f['finding_id'], rem, by_prop)} |")
        if len(vulns) > TABLE_LIMIT:
            L.append(f"| | *{len(vulns) - TABLE_LIMIT} more in findings.json* | | | | | | |")
        L.append("")

    # 3 ------------------------------------------------------------------ suspicious changes
    L += ["## 3. Suspicious changes (supply-chain behaviour, no CVE)", "",
          "> A **suspicious change** is behaviour that can indicate a supply-chain attack or a weak build path, "
          "even when no advisory exists: install / lifecycle scripts, dependencies from untrusted sources, "
          "typosquat-like names, known-malicious packages, lockfile drift, risky CI workflows, missing SRI on a live "
          "page. Risk is the Guardian heuristic (0-10, not CVSS); the triage verdict is AI inference over the evidence.",
          ""]
    if not sus:
        L += ["No suspicious changes detected.", ""]
    else:
        L += ["| ID | Rule | Finding | Location | Risk | Triage verdict + reasoning | Status after |",
              "|---|---|---|---|---|---|---|"]
        for f in sus[:TABLE_LIMIT]:
            r, t = f["risk"], tri.get(f["finding_id"])
            verdict = (f"**{t['verdict'].replace('_', ' ')}** ({t.get('confidence', '?')}): "
                       f"{_cut(_first_sentence(t.get('rationale', '')), 200)}") if t else "not triaged (rule-based)"
            L.append(f"| {f['finding_id']}{' 🆕' if f.get('new_in_change') else ''} | {_c(f['rule'])} | "
                     f"{_cut(f['title'], 140)} | `{_cut(f.get('location') or '-', 70)}` | "
                     f"{ICON.get(r['level'], '')} {r['level']} ({r['score']}) | {verdict} | "
                     f"{_finding_status(f['finding_id'], rem, by_prop)} |")
        if len(sus) > TABLE_LIMIT:
            L.append(f"| | | *{len(sus) - TABLE_LIMIT} more in findings.json* | | | | |")
        L.append("")

    # 4 ------------------------------------------------------------------ decisions
    L += ["## 4. Decisions", ""]
    props = (rem or {}).get("proposals", [])
    appr = {a["proposal_id"]: a for a in (rem or {}).get("approvals", [])}
    if not props:
        L += ["No remediation proposals yet (remediation not run).", ""]
    else:
        L += ["| Proposal | Action | Component | Change | Priority | Findings | System suggestion | Human decision | Approver |",
              "|---|---|---|---|---|---|---|---|---|"]
        for p in props:
            a, sg = appr.get(p["proposal_id"]), _suggestion(p)
            change = f"{_c(p.get('from_version')) or '-'} → {_c(p.get('to_version')) or '-'}"
            fids = p.get("finding_ids", [])
            dec = (f"**{a['decision'].replace('_', ' ')}**" + (f": {_cut(a['reason'], 120)}" if a.get("reason") else "")) \
                if a else p.get("status", "pending").replace("_", " ")
            L.append(f"| {p['proposal_id']} | {_c(p.get('action')).replace('_', ' ')} | {('`' + _cut(p['component'], 60) + '`') if p.get('component') else '-'} | "
                     f"{change} | {_c(p.get('priority')) or '-'}{' urgent' if p.get('urgent') else ''} | "
                     f"{', '.join(fids[:4])}{f' +{len(fids) - 4}' if len(fids) > 4 else ''} | "
                     f"{(sg['decision'].replace('_', ' ') + ' (' + sg['confidence'] + ')') if sg else '-'} | {dec} | "
                     f"{(_c(a['approver']) + ', ' + _c(a.get('decided_at'))) if a else '-'} |")
        L.append("")

    # 5 ------------------------------------------------------------------ before / after
    L += ["## 5. Before / after", ""]
    if not validated:
        L += [status_line, "", "| Level | Before | After |", "|---|---|---|"]
        bl = _by_level(fs)
        L += [f"| {ICON.get(k, '')} {k} | {bl[k]} | - |" for k in sorted(bl, key=lambda k: (k not in LEVEL_ORDER, LEVEL_ORDER.index(k) if k in LEVEL_ORDER else 0, k))]
        L += ["", "*Level = official severity for vulnerabilities, Guardian risk for suspicious changes.*", ""]
    else:
        bl = _by_level(fs)
        al = _by_level(after_fs) if after_fs is not None else (post.get("after") or {}).get("by_level") or {}
        keys = sorted(set(bl) | set(al), key=lambda k: (k not in LEVEL_ORDER, LEVEL_ORDER.index(k) if k in LEVEL_ORDER else 0, k))
        L += [f"Verdict **{val.get('verdict', '').replace('_', ' ')}** (confidence {val.get('confidence', 'low')}).", ""]
        L += [f"- {_c(r)}" for r in (post.get("reasons") or val.get("reasons") or [])]
        L += ["", "| Level | Before | After |", "|---|---|---|"]
        L += [f"| {ICON.get(k, '')} {k} | {bl.get(k, 0)} | {al.get(k, 0) if al else '?'} |" for k in keys]
        L += [f"| **Total** | **{len(fs)}** | **{len(after_fs) if after_fs is not None else val.get('findings_after', '?')}** |",
              "", "*Level = official severity for vulnerabilities, Guardian risk for suspicious changes.*", ""]
        resolved = post.get("resolved") or val.get("resolved") or []
        remaining = post.get("remaining") or val.get("remaining") or []
        new = (post.get("new") if post else None) or val.get("new") or []
        L += [f"- **Resolved ({len(resolved)}):** {', '.join(resolved) or 'none'}",
              f"- **Remaining ({len(remaining)}):** {', '.join(remaining[:40]) or 'none'}"
              + (f" … +{len(remaining) - 40}" if len(remaining) > 40 else "")]
        groups = {"introduced": "Newly introduced", "still_vulnerable": "Still vulnerable (upgraded, advisories remain)",
                  "expected": "Expected (the replacement itself)"}
        for kind, label in groups.items():
            items = [n for n in new if n.get("kind", "introduced") == kind]
            if items or kind == "introduced":
                L.append(f"- **{label} ({len(items)}):** " + ("; ".join(
                    f"{_c(n.get('level'))} {_cut(n.get('title'), 100)} ({_c(n.get('rule'))})" for n in items[:15]) or "none"))
        sd = post.get("sbom_diff") or val.get("sbom_diff") or {}
        L += [f"- **SBOM diff:** {len(sd.get('changed', []))} changed · {len(sd.get('added', []))} added · "
              f"{len(sd.get('removed', []))} removed"]
        L += [f"  - changed: `{_c(x)}`" for x in sd.get("changed", [])[:15]]
        L += [f"  - added: `{_c(x)}`" for x in sd.get("added", [])[:8]]
        L += [f"  - removed: `{_c(x)}`" for x in sd.get("removed", [])[:8]]
        steps_b = {x["step"].split(": ", 1)[-1]: x for x in val.get("steps_before", [])}
        if val.get("steps_after"):
            L += ["", "| Build / test step | Before (unchanged) | After (remediated) |", "|---|---|---|"]
            for x in val["steps_after"]:
                name = x["step"].split(": ", 1)[-1]
                b = steps_b.get(name, {})
                L.append(f"| {_cut(name, 80)} | {b.get('status', '-')} | {x.get('status')} |")
        L.append("")

    # 6 ------------------------------------------------------------------ sandbox evidence
    L += ["## 6. Sandbox evidence", ""]
    trace = (rem or {}).get("trace") or {}
    if not validated:
        L += ["No sandbox run yet: repository code has not been built or executed.", ""]
    elif not trace.get("containers"):
        L += [f"Docker: {'used' if val.get('docker') or post.get('docker') else 'not available'}; no container "
              "trace was recorded (lockfile regeneration + rescan only; repository code never runs on the host).", ""]
    else:
        L += [f"- **Docker engine:** {_c(trace.get('docker_server')) or 'unknown'}",
              f"- **Sandbox id:** `{_c(trace.get('sandbox'))}` · volume `{_c(trace.get('volume'))}` · "
              f"network `{_c(trace.get('network'))}`", "",
              "| Container | Image | Command | Network | Exit code | Status | Seconds |", "|---|---|---|---|---|---|---|"]
        for x in trace["containers"][:40]:
            L.append(f"| `{_c(x.get('container'))}` | `{_cut(x.get('image'), 60)}` | `{_cut(x.get('cmd'), 80)}` | "
                     f"{_c(x.get('network'))} | {_c(x.get('exit'))} | {_c(x.get('status'))} | {_c(x.get('seconds'))} |")
        L.append("")

    # 7 ------------------------------------------------------------------ appendix
    patch = (rem or {}).get("patch")
    L += ["## 7. Appendix", "",
          f"- **Patch:** `{patch}` (every approved change as one unified diff; nothing was merged, deployed or "
          "released, the original repository was not modified)" if patch else "- **Patch:** none",
          "- **Machine-readable data:** `findings.json` (all findings with full evidence), `sbom.cdx.json`, "
          "`agentic.json` (AI triage, audit trail), `remediation/remediation.json`, "
          "`remediation/post_analysis.json`, `remediation/sandbox_trace.json`."]
    notes = doc.get("notes") or []
    if notes:
        L.append("- **Scan notes:** " + "; ".join(_cut(n, 160) for n in notes[:8])
                 + (f" (+{len(notes) - 8} more in findings.json)" if len(notes) > 8 else ""))
    L.append("")
    return "\n".join(L)


# ------------------------------------------------------------------------------------------------ write
def write(out: Path, doc: dict | None = None, summary: dict | None = None, agentic=...,
          rem: dict | None = None) -> list[str]:
    """(Re)write report.md + report.html + report.pdf in out/. Inputs left out are read from out/ (findings.json,
    summary.json; agentic.json only when `agentic` is not passed at all, None means "no AI ran").
    Removes the old separate remediation report files. Returns the names written."""
    from .report_export import write_all
    out = Path(out)
    doc = doc if doc is not None else _read(out / "findings.json")
    if doc is None:
        return []
    summary = summary if summary is not None else _read(out / "summary.json")
    agentic = _read(out / "agentic.json") if agentic is ... else agentic
    md = render(doc, summary, agentic, rem)
    (out / "report.md").write_text(md, encoding="utf-8")
    for old in LEGACY:
        try:
            (out / old).unlink(missing_ok=True)
        except OSError:
            pass
    return ["report.md", *write_all(md, out)]
