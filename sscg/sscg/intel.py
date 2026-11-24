"""Analyze stage: exploitability intelligence for CVEs (free, no key, read-only).

* CISA KEV  - Known Exploited Vulnerabilities catalog: the CVE is being exploited in the wild.
* FIRST EPSS - Exploit Prediction Scoring System: probability (0-1) of exploitation in the next 30 days.

Both are daily feeds, cached per day (cache.http_json_daily); offline the newest cached copy is used.
"""
from __future__ import annotations

from .cache import http_json_daily

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
EPSS_BATCH = 50


def kev() -> tuple[dict, str | None]:
    """{CVE: {date_added, ransomware, name}} and the date of the catalog used ({} and None if unavailable)."""
    data, day = http_json_daily(KEV_URL)
    if not data:
        return {}, None
    return {v["cveID"].upper(): {"date_added": v.get("dateAdded"),
                                 "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
                                 "name": v.get("vulnerabilityName")}
            for v in data.get("vulnerabilities", [])}, data.get("dateReleased", day)


def epss(cves: list[str]) -> tuple[dict, str | None]:
    """{CVE: {epss, percentile}} for the given CVEs, and the score date."""
    out, day = {}, None
    ids = sorted({c.upper() for c in cves if c.upper().startswith("CVE-")})
    for i in range(0, len(ids), EPSS_BATCH):
        data, _ = http_json_daily(EPSS_URL + ",".join(ids[i:i + EPSS_BATCH]))
        for row in (data or {}).get("data", []):
            out[row["cve"].upper()] = {"epss": float(row["epss"]), "percentile": float(row["percentile"])}
            day = row.get("date", day)
    return out, day


def for_findings(findings: list) -> dict:
    """Exploitability per vulnerability finding: worst KEV / EPSS over its advisories' CVE aliases."""
    cves_by_f = {f["finding_id"]: sorted({c.upper() for e in f.get("evidence", []) if e.get("type") == "advisory"
                                          for c in (e.get("cves") or [])})
                 for f in findings if f["category"] == "vulnerability"}
    all_cves = sorted({c for cs in cves_by_f.values() for c in cs})
    kev_map, kev_date = kev() if all_cves else ({}, None)
    epss_map, epss_date = epss(all_cves) if all_cves else ({}, None)
    per = {}
    for fid, cves in cves_by_f.items():
        in_kev = [c for c in cves if c in kev_map]
        scored = [(epss_map[c]["epss"], c) for c in cves if c in epss_map]
        top = max(scored) if scored else None
        per[fid] = {"cves": cves, "kev": in_kev, "kev_ransomware": any(kev_map[c]["ransomware"] for c in in_kev),
                    "epss_max": round(top[0], 5) if top else None, "epss_cve": top[1] if top else None,
                    "epss_percentile": epss_map[top[1]]["percentile"] if top else None}
    return {"per_finding": per,
            "sources": {"kev": {"available": bool(kev_map), "date": kev_date, "entries": len(kev_map)},
                        "epss": {"available": bool(epss_map) or not all_cves, "date": epss_date,
                                 "scored_cves": len(epss_map), "cves_queried": len(all_cves)}}}
