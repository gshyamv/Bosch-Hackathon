"""Detect vulnerabilities with OSV.dev.

1. querybatch: which advisory IDs affect each package version
2. details:    for every advisory: CVE aliases, CVSS vector + score / severity label, fixed version
3. dedupe:     the same issue published as GHSA + PYSEC + CVE is counted once
Results are stored on the graph node as `advisories`; MAL-* (known malicious package) records are kept apart.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

from . import cvss
from .cache import http_json
from .model import DepGraph
from .versions import fixed_for, sort_versions

OSV = "https://api.osv.dev/v1"
OSV_ECO = {"npm": "npm", "pypi": "PyPI", "maven": "Maven", "rubygems": "RubyGems", "cargo": "crates.io",
           "go": "Go", "nuget": "NuGet"}
LABELS = {"LOW": "LOW", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "CRITICAL"}


def _norm(eco: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if eco == "pypi" else name.lower()


def _ver(eco: str, version: str) -> str:
    return version.removeprefix("v") if eco == "go" else version      # OSV writes Go versions without the v


def osv_overlay(dg: DepGraph) -> bool:
    """Step 1: advisory IDs per package version (node attribute `vulns`). False if OSV is unreachable."""
    G = dg.G
    pk = [(n, a) for n, a in G.nodes(data=True) if a["kind"] == "package"
          and a["ecosystem"] in OSV_ECO and re.match(r"\d", _ver(a["ecosystem"], str(a.get("version", ""))))]
    for i in range(0, len(pk), 500):
        batch = pk[i:i + 500]
        q = {"queries": [{"package": {"ecosystem": OSV_ECO[a["ecosystem"]], "name": a["name"]},
                          "version": _ver(a["ecosystem"], a["version"])} for _, a in batch]}
        res = http_json("POST", f"{OSV}/querybatch", q)
        if not res:
            dg.notes.append("OSV unavailable (offline / network): vulnerabilities not checked")
            return False
        for (n, _), r in zip(batch, res.get("results", [])):
            ids = [v["id"] for v in r.get("vulns", [])]
            if ids:
                G.nodes[n]["vulns"] = ids
    return True


def _advisory(d: dict, eco: str, name: str, version: str) -> dict:
    vectors = {s["type"]: s["score"] for s in d.get("severity", []) if "score" in s}
    vec = vectors.get("CVSS_V3") or vectors.get("CVSS_V4") or vectors.get("CVSS_V2")
    score = cvss.base_score(vectors.get("CVSS_V3", ""))
    db_label = LABELS.get(str((d.get("database_specific") or {}).get("severity", "")).upper())
    if score is not None:
        sev, src = cvss.label(score), "CVSS v3 vector (OSV), score computed"
    elif db_label:
        sev, src = db_label, f"{d['id'].split('-')[0]} severity label (OSV)"
    else:
        sev, src = "UNKNOWN", "no severity published"
    inside, fixed, all_fixed = False, None, set()
    for aff in d.get("affected", []):
        p = aff.get("package", {})
        if _norm(eco, p.get("name", "")) != _norm(eco, name):
            continue
        for r in aff.get("ranges", []):
            if r.get("type") == "GIT":
                continue
            all_fixed |= {e["fixed"] for e in r.get("events", []) if "fixed" in e}
            hit, fx = fixed_for(version, r.get("events", []))
            if hit:
                inside = True
                fixed = fx or fixed
        if version in aff.get("versions", []):
            inside = True
    cves = sorted({a for a in [d["id"], *d.get("aliases", [])] if a.startswith("CVE-")})
    return {
        "id": d["id"], "aliases": d.get("aliases", []), "cves": cves,
        "summary": d.get("summary") or (d.get("details") or "")[:200],
        "published": d.get("published"), "modified": d.get("modified"),
        "severity": sev, "severity_source": src, "cvss_score": score, "cvss_vector": vec,
        "fixed_in": fixed, "fixed_versions": sort_versions(all_fixed), "version_in_range": inside,
        "malicious": d["id"].startswith("MAL-"),
        "url": f"https://osv.dev/vulnerability/{d['id']}",
    }


def _dedupe(advs: list) -> list:
    """GHSA-x and PYSEC-y describing the same CVE count once; keep the record with the most severity data."""
    rank = lambda a: (a["cvss_score"] is not None, a["severity"] != "UNKNOWN", a["fixed_in"] is not None)
    out, seen = [], []
    for a in sorted(advs, key=rank, reverse=True):
        ids = {a["id"], *a["aliases"]}
        hit = next((s for s in seen if s & ids), None)
        if hit is not None:
            hit |= ids
            continue
        seen.append(ids)
        out.append(a)
    return out


def enrich(dg: DepGraph) -> int:
    """Step 2+3: fetch advisory details (cached, in parallel) and attach `advisories` to each node."""
    G = dg.G
    ids = sorted({v for _, a in G.nodes(data=True) for v in a.get("vulns", [])})
    with ThreadPoolExecutor(max_workers=8) as ex:
        details = dict(zip(ids, ex.map(lambda i: http_json("GET", f"{OSV}/vulns/{i}"), ids)))
    missing = [i for i, d in details.items() if not d]
    if missing:
        dg.notes.append(f"OSV details unavailable for {len(missing)} advisories (offline / network)")
    for n, a in G.nodes(data=True):
        if not a.get("vulns"):
            continue
        advs = [_advisory(details[i], a["ecosystem"], a["name"], _ver(a["ecosystem"], a["version"])) for i in a["vulns"] if details.get(i)]
        a["advisories"] = _dedupe(advs)
    return len(ids)
