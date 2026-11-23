"""Column 5: Present evidence.

Every finding answers the slide's five questions:
  what was detected (title, type, rule) · which component (component, location) · dependency path
  · supporting evidence (file:line, advisory, lockfile change, commit) · initial risk level.
Official severity (CVSS / advisory label) and the Guardian's heuristic risk are kept in separate fields.
"""
from __future__ import annotations

import itertools
from datetime import datetime, timezone

import networkx as nx

from . import cvss
from .versions import sort_versions

LEVEL_SCORE = {"Critical": 9.5, "High": 8.0, "Medium": 5.5, "Low": 3.0, "Info": 1.0}
SEV_SCORE = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 3.0}
SEV_ORDER = ["UNKNOWN", "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
LEVELS = ["Critical", "High", "Medium", "Low", "Info"]
RISK_LABEL = "Guardian initial risk (heuristic, 0-10); not a CVSS score"
NEW_BONUS = 1.0


def level_of(score: float) -> str:
    return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else \
        "Low" if score >= 2 else "Info"


def dependency_paths(dg, n, k: int = 3) -> list[list[str]]:
    G = dg.G
    if n is None or n not in G or not nx.has_path(G, dg.top, n):
        return []
    return [[G.nodes[x]["label"] for x in p[1:]] for p in itertools.islice(nx.shortest_simple_paths(G, dg.top, n), k)]


def _component(dg, n) -> dict | None:
    if n is None or n not in dg.G:
        return None
    a = dg.G.nodes[n]
    return {"id": n, "purl": n if n.startswith("pkg:") else None, "name": a["name"], "version": a.get("version"),
            "ecosystem": a["ecosystem"], "label": a["label"], "scope": a.get("scope"), "direct": a.get("direct"),
            "resolution": a.get("resolution"), "origin": a.get("resolved")}


def vulnerability_raws(dg) -> list:
    out = []
    for n, a in dg.G.nodes(data=True):
        advs = [x for x in a.get("advisories", []) if not x["malicious"]]
        if not advs:
            continue
        scores = [x["cvss_score"] for x in advs if x["cvss_score"] is not None]
        worst = max((x["severity"] for x in advs), key=SEV_ORDER.index)
        if scores and SEV_ORDER.index(cvss.label(max(scores))) >= SEV_ORDER.index(worst):
            sev = {"label": cvss.label(max(scores)), "cvss": max(scores), "source": "OSV CVSS v3 vector (score computed)"}
        else:
            sev = {"label": worst, "cvss": max(scores) if scores else None, "source": "advisory severity label (OSV)"}
        fixes = [x["fixed_in"] for x in advs if x["fixed_in"]]
        no_fix = [x["id"] for x in advs if not x["fixed_in"]]
        approx = a.get("resolution") == "deps.dev-approx"
        noun = "vulnerability" if len(advs) == 1 else "vulnerabilities"
        worst_txt = sev["label"] + (f", CVSS {sev['cvss']}" if sev["cvss"] else "")
        out.append({
            "rule": "VULN", "category": "vulnerability",
            "type": "Vulnerable direct dependency" if a.get("direct") else "Vulnerable transitive dependency",
            "title": f"{a['label']}: {len(advs)} known {noun} (highest {worst_txt})",
            "level": None, "node": n, "location": a.get("source"), "key": ("VULN", a["ecosystem"], a["name"], a["version"]),
            "classification": "verified_fact", "confidence": "medium" if approx else "high", "new": None,
            "why": "Published advisories affect this exact version.",
            "severity": sev,
            "fixes": {"per_advisory": {x["id"]: x["fixed_in"] for x in advs},
                      "upgrade_to_at_least": sort_versions(fixes)[-1] if fixes else None,
                      "advisories_without_fix": no_fix},
            "evidence": [{"type": "advisory", "id": x["id"], "cves": x["cves"], "severity": x["severity"],
                          "cvss_score": x["cvss_score"], "cvss_vector": x["cvss_vector"], "fixed_in": x["fixed_in"],
                          "summary": x["summary"], "url": x["url"]}
                         for x in sorted(advs, key=lambda x: (-(x["cvss_score"] or SEV_SCORE.get(x["severity"], 0)), x["id"]))],
        })
    return out


def _risk(f: dict, new: bool) -> dict:
    reasons, factors = [], {}
    if f["category"] == "vulnerability":
        sev = f["severity"]
        base = sev["cvss"] if sev["cvss"] is not None else SEV_SCORE.get(sev["label"], 5.5)
        factors["severity"] = base
        reasons.append(f"highest advisory severity {sev['label']}" + (f" (CVSS {sev['cvss']})" if sev["cvss"] else "")
                       if sev["label"] != "UNKNOWN" else "severity not published: treated as Medium")
        if f["fixes"]["advisories_without_fix"]:
            reasons.append(f"{len(f['fixes']['advisories_without_fix'])} advisory(ies) without a published fix")
        if f["confidence"] == "medium":
            reasons.append("version estimated without a lockfile (deps.dev)")
    else:
        base = LEVEL_SCORE[f["level"]]
        factors["rule_level"] = f["level"]
        reasons.append(f"{f['rule']} default level {f['level']}")
    score = base
    if new:
        score += NEW_BONUS
        factors["introduced_in_latest_change"] = NEW_BONUS
        reasons.append("introduced in the latest change")
    score = round(min(score, 10.0), 1)
    return {"score": score, "level": level_of(score), "factors": factors, "reasons": reasons, "label": RISK_LABEL}


def build(dg, raws: list, change, base_keys: set | None) -> list:
    """raws = vulnerability_raws + rule findings. Adds paths, newness, risk; sorts; assigns F-001 ..."""
    out = []
    for r in raws:
        new = r["new"] if r["new"] is not None else (change is not None and base_keys is not None
                                                      and r["key"] not in base_keys)
        comp = _component(dg, r["node"])
        paths = dependency_paths(dg, r["node"])
        f = {
            "finding_id": None,
            "category": r.get("category", "anomaly"),
            "type": r["type"], "rule": r["rule"], "title": r["title"],
            "component": comp, "is_direct": comp["direct"] if comp else None,
            "location": r["location"],
            "dependency_paths": paths,
            "introduced_by": sorted({p[1] for p in paths if len(p) > 2}) if paths else [],
            "evidence": [e for e in r["evidence"] if e],
            "why_it_matters": r["why"],
            "classification": r["classification"], "confidence": r["confidence"],
            "new_in_change": bool(new),
            "introduced_in": (change.head["short"] + (" (+ uncommitted changes)" if change.head_dirty else ""))
                             if new and change else None,
            "level": r["level"],
        }
        if f["category"] == "vulnerability":
            f["severity"], f["fixes"] = r["severity"], r["fixes"]
        f["risk"] = _risk(f, bool(new))
        f.pop("level")
        f["_key"] = r["key"]
        out.append(f)
    out.sort(key=lambda f: (-f["risk"]["score"], f["category"] != "anomaly", f["title"]))
    for i, f in enumerate(out, 1):
        f["finding_id"] = f"F-{i:03d}"
        if f["component"]:
            node = dg.G.nodes[f["component"]["id"]]
            node.setdefault("findings", []).append(f["finding_id"])
            if f["category"] == "anomaly":
                node["suspicious"] = True
    return out


def counts(findings: list) -> dict:
    by = lambda key: dict(sorted(((k, sum(1 for f in findings if key(f) == k)) for k in {key(f) for f in findings}),
                                 key=lambda kv: -kv[1]))
    return {
        "total": len(findings),
        "vulnerabilities": sum(1 for f in findings if f["category"] == "vulnerability"),
        "anomalies": sum(1 for f in findings if f["category"] == "anomaly"),
        "new_in_change": sum(1 for f in findings if f["new_in_change"]),
        "by_level": {l: sum(1 for f in findings if f["risk"]["level"] == l) for l in LEVELS},
        "by_type": by(lambda f: f["type"]),
        "by_rule": by(lambda f: f["rule"]),
        "advisories": sum(len(f["evidence"]) for f in findings if f["category"] == "vulnerability"),
    }


def document(repo_name: str, dg, findings: list, change, version: str) -> dict:
    return {
        "scan": {"application": repo_name, "tool": f"sscg {version}",
                 "scanned_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                 "head": change.head if change else None, "base": change.base if change else None,
                 "risk_label": RISK_LABEL},
        "counts": counts(findings),
        "change": change.as_dict() if change else None,
        "findings": [{k: v for k, v in f.items() if not k.startswith("_")} for f in findings],
        "notes": dg.notes,
    }
