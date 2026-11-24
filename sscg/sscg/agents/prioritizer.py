"""Analyze stage, "Prioritize risks: focus on what truly matters".

Three nodes, the first two run in parallel:
  exploit_intel     CISA KEV + FIRST EPSS for every CVE of every vulnerability finding      (intel.py)
  reachability_scan import-level reachability of every package + network-service exposure  (reachability.py)
  prioritize        explainable score = initial risk + signed points per factor -> P0..P3, urgent flag,
                    confidence. Deterministic: same input, same ranking. Every point is listed with its reason.

Works for any scanned application: npm, PyPI, Maven code imports; containers / CI fall back to "unknown".
"""
from __future__ import annotations

from .. import intel, reachability
from .runtime import get, traced
from .schemas import PriorityItem

INSTALL_TIME = {"R01_TYPOSQUAT", "R02_KNOWN_MALICIOUS", "R03_INSTALL_SCRIPT", "R04_INSTALL_SCRIPT_CONTENT",
                "R05_LOCKFILE_UNTRUSTED_SOURCE", "R06_LOCKFILE_INTEGRITY_CHANGED", "R07_LOCKFILE_DRIFT",
                "R19_SUSPICIOUS_UPDATE"}         # risk materialises at install time, imports do not matter
ALWAYS_URGENT = {"R02_KNOWN_MALICIOUS", "R06_LOCKFILE_INTEGRITY_CHANGED"}
NON_PROD = {"dev", "test", "build"}
REACH_POINTS = {"imported": (0.5, "imported by application code"),
                "referenced": (0.0, "named in application code (loaded by name)"),
                "transitive": (0.0, "pulled in by an imported dependency (potentially reachable)"),
                "tests_only": (-1.5, "imported only from tests"),
                "not_imported": (-2.0, "not imported by application code"),
                "unknown": (0.0, "reachability unknown")}
VERDICT_POINTS = {"likely_malicious": 1.0, "suspicious": 0.5, "needs_human_review": 0.0, "likely_benign": -2.0}
BUCKET = {"P0": "fix now", "P1": "fix this sprint", "P2": "plan the fix", "P3": "monitor / accept"}


@traced("Exploit Intel", "deterministic")
def exploit_intel(state: dict) -> dict:
    rt = get(state["run_id"])
    res = intel.for_findings(state["findings"])
    src = res["sources"]
    kev_hits = sum(1 for v in res["per_finding"].values() if v["kev"])
    rt.log("Exploit Intel", f"CISA KEV {'(' + str(src['kev']['date']) + ')' if src['kev']['available'] else 'unavailable'}"
                            f": {kev_hits} finding(s) known exploited · EPSS scored {src['epss']['scored_cves']}"
                            f"/{src['epss']['cves_queried']} CVEs")
    return {"exploitability": res, "_run": {"kev_findings": kev_hits}}


@traced("Reachability", "deterministic")
def reachability_scan(state: dict) -> dict:
    rt = get(state["run_id"])
    res = reachability.analyze(rt.repo, rt.dg)
    rt.log("Reachability", f"{res['summary']} · network service: {res['exposure']['network_service']}")
    return {"reachability": res, "_run": res["summary"]}


# Calibrated on the three sample apps (2026-11-24): P0 = urgent or clearly above the initial-risk maximum of 10.
TIERS = (("P0", 10.5), ("P1", 8.5), ("P2", 5.5))


def _tier(score: float, urgent: bool) -> str:
    if urgent:
        return "P0"
    return next((p for p, t in TIERS if score >= t), "P3")


def score_finding(f: dict, ex: dict, reach: dict, tri: dict | None, exposure: dict) -> PriorityItem:
    base = f["risk"]["score"]
    factors = {"initial_risk": {"value": f["risk"]["level"], "points": base}}
    reasons, unknowns, urgent = [f"initial risk {base}"], [], False
    comp = f.get("component") or {}
    scope = comp.get("scope")

    def add(name, value, pts, why):
        factors[name] = {"value": value, "points": pts}
        reasons.append(f"{why} ({pts:+g})" if pts else why)

    if f["category"] == "vulnerability":
        e = ex.get("per_finding", {}).get(f["finding_id"], {})
        if e.get("kev"):
            pts = 2.5 if e.get("kev_ransomware") else 2.0
            add("known_exploited", ", ".join(e["kev"]), pts,
                "listed in CISA KEV: exploited in the wild" + (", used in ransomware" if e.get("kev_ransomware") else ""))
        elif not ex.get("sources", {}).get("kev", {}).get("available"):
            unknowns.append("KEV unavailable")
        p = e.get("epss_max")
        if p is not None:
            pts = 1.0 if p >= 0.5 else 0.5 if p >= 0.1 else -0.5 if p < 0.01 else 0.0
            add("epss", p, pts, f"EPSS {p:.3f} for {e['epss_cve']} ({e['epss_percentile']:.0%} percentile)")
        elif e.get("cves"):
            unknowns.append("EPSS unavailable")
        else:
            reasons.append("no CVE alias: exploitability data not available")
            unknowns.append("no CVE")
        r = reach.get(comp.get("id"), {"status": "unknown"})
        pts, why = REACH_POINTS[r["status"]]
        add("reachability", r["status"], pts, why + (f" ({', '.join(r['evidence'][:2])})" if r.get("evidence") else ""))
        if r["status"] == "unknown":
            unknowns.append("reachability unknown")
        if scope in NON_PROD:
            add("exposure", scope, -1.5, f"{scope}-only dependency, not shipped")
        elif exposure.get("network_service"):
            add("exposure", "network service", 0.5, "shipped in a network-facing service")
        urgent = bool(e.get("kev")) and r["status"] in ("imported", "referenced", "transitive")
        if f["risk"].get("factors", {}).get("introduced_in_latest_change"):
            reasons.append("introduced in the latest change")
        if f.get("fixes", {}).get("upgrade_to_at_least"):
            reasons.append(f"fix available: upgrade to >= {f['fixes']['upgrade_to_at_least']}")
        else:
            reasons.append("no fixed version published")
        if f.get("confidence") == "medium":
            unknowns.append("version estimated without lockfile")
    else:
        if f["rule"] in INSTALL_TIME:
            reasons.append("install-time risk: runs on every install, whether or not code imports it")
        if tri:
            pts = VERDICT_POINTS[tri["verdict"]]
            grounded = tri.get("grounding", {}).get("ok", True)
            if tri["verdict"] == "likely_benign" and (tri["confidence"] == "low" or not grounded):
                pts = -1.0
            add("ai_triage", f"{tri['verdict']} ({tri['confidence']}, {tri.get('generated_by', '?')})", pts,
                f"triage: {tri['verdict'].replace('_', ' ')}, {tri['confidence']} confidence (AI inference)")
            if tri.get("generated_by", "").startswith("rules"):
                unknowns.append("triage by rules-only fallback")
            urgent = tri["verdict"] == "likely_malicious" and tri["confidence"] in ("medium", "high")
        urgent = urgent or f["rule"] in ALWAYS_URGENT
    # no upper cap: context must be able to separate findings that all start at the initial-risk maximum of 10
    score = round(max(0.0, base + sum(v["points"] for k, v in factors.items() if k != "initial_risk")), 1)
    pr = _tier(score, urgent)
    conf = "high" if not unknowns else "medium" if len(unknowns) == 1 else "low"
    return PriorityItem(finding_id=f["finding_id"], priority=pr, score=score, urgent=urgent, bucket=BUCKET[pr],
                        title=f["title"], category=f["category"], component=comp.get("label"),
                        factors=factors, reasons=reasons, unknowns=unknowns, confidence=conf,
                        explanation="; ".join(reasons))


@traced("Prioritizer", "deterministic")
def prioritize(state: dict) -> dict:
    rt = get(state["run_id"])
    ex, rc = state.get("exploitability", {}), state.get("reachability", {})
    reach, exposure = rc.get("per_node", {}), rc.get("exposure", {})
    tri = state.get("triage", {})
    items = [score_finding(f, ex, reach, tri.get(f["finding_id"]), exposure) for f in state["findings"]]
    items.sort(key=lambda i: (-int(i.urgent), -i.score, i.finding_id))
    for i in items:
        rt.note(lambda c, d=i.model_dump(): c.write("PriorityNote", d))
    n = {p: sum(i.priority == p for i in items) for p in ("P0", "P1", "P2", "P3")}
    rt.log("Prioritizer", " · ".join(f"{p} {c}" for p, c in n.items())
           + f" · urgent {sum(i.urgent for i in items)}")
    return {"priorities": [i.model_dump() for i in items], "_run": n}
