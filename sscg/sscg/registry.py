"""Read-only registry lookups used to recommend a safe change (all cached via cache.http_json).

  versions(eco, name)        published, non-prerelease, non-yanked/deprecated versions (npm, PyPI, Maven)
  remaining_advisories(...)  OSV advisories still affecting candidate versions (one querybatch call)
  safe_version(...)          the smallest change that fixes the finding with the fewest remaining advisories
  official_image(...)        official Docker Hub equivalent of an image, pinned by digest
  action_sha(...)            commit SHA for a GitHub Action tag / branch
"""
from __future__ import annotations

import re
from urllib.parse import quote

from packaging.tags import sys_tags
from packaging.utils import InvalidWheelFilename, parse_wheel_filename
from packaging.version import InvalidVersion, Version

from .cache import http_json
from .versions import compare, sort_versions

OSV_ECO = {"npm": "npm", "pypi": "PyPI", "maven": "Maven"}
PRE_RE = re.compile(r"(alpha|beta|rc|snapshot|preview|dev|canary|next|nightly|insiders|-m\d|\.m\d|ea\b|cr\d)", re.I)
MAX_CANDIDATES = 60


def _stable(eco: str, v: str) -> bool:
    if eco == "npm" and "-" in v:
        return False
    if eco == "pypi":
        try:
            return not Version(v).is_prerelease
        except InvalidVersion:
            return False
    return not PRE_RE.search(v)


def versions(eco: str, name: str) -> list[str]:
    """Stable versions, ascending. [] if the registry is unreachable / offline cache miss."""
    out = []
    if eco == "npm":
        doc = http_json("GET", f"https://registry.npmjs.org/{quote(name, safe='@')}") or {}
        out = [v for v, meta in (doc.get("versions") or {}).items() if not (meta or {}).get("deprecated")]
    elif eco == "pypi":
        doc = http_json("GET", f"https://pypi.org/pypi/{quote(name)}/json") or {}
        out = [v for v, files in (doc.get("releases") or {}).items()
               if files and not all(f.get("yanked") for f in files)]
    elif eco == "maven":    # deps.dev (fast, has deprecation flags); Maven Central search as a fallback
        doc = http_json("GET", f"https://api.deps.dev/v3/systems/maven/packages/{quote(name, safe='')}") or {}
        out = [v["versionKey"]["version"] for v in doc.get("versions", []) if not v.get("isDeprecated")]
        if not out:
            g, _, a = name.partition(":")
            doc = http_json("GET", f"https://search.maven.org/solrsearch/select?q=g:%22{quote(g)}%22+AND+"
                                   f"a:%22{quote(a)}%22&core=gav&rows=300&wt=json") or {}
            out = [d["v"] for d in (doc.get("response") or {}).get("docs", [])]
    return sort_versions({v for v in out if _stable(eco, v)})


_TAGS = None


def pypi_installable(name: str) -> set[str]:
    """PyPI versions with a wheel this Python can install (so validation does not need to compile sdists)."""
    global _TAGS
    _TAGS = _TAGS or set(sys_tags())
    doc = http_json("GET", f"https://pypi.org/pypi/{quote(name)}/json") or {}
    ok = set()
    for v, files in (doc.get("releases") or {}).items():
        for f in files:
            if f.get("packagetype") != "bdist_wheel" or f.get("yanked"):
                continue
            try:
                if set(parse_wheel_filename(f["filename"])[3]) & _TAGS:
                    ok.add(v)
                    break
            except (InvalidWheelFilename, InvalidVersion):
                continue
    return ok


def major(v: str) -> str:
    m = re.match(r"\d+", v or "")
    return m.group(0) if m else ""


def remaining_advisories(eco: str, name: str, candidates: list[str]) -> dict:
    """{version: [advisory ids]} from OSV (MAL-* malicious records included). {} if OSV is unreachable."""
    if eco not in OSV_ECO or not candidates:
        return {}
    res = http_json("POST", "https://api.osv.dev/v1/querybatch",
                    {"queries": [{"package": {"ecosystem": OSV_ECO[eco], "name": name}, "version": v}
                                 for v in candidates]})
    if not res:
        return {}
    return {v: sorted(x["id"] for x in (r.get("vulns") or [])) for v, r in zip(candidates, res.get("results", []))}


def safe_version(eco: str, name: str, current: str | None, min_fix: str | None) -> dict:
    """Pick the target version. Preference: fewest remaining advisories, then same major as now, then smallest.

    Returns {version, remaining, major_change, candidates_checked, note} or {version: None, note} when unknown.
    """
    vs = versions(eco, name)
    if not vs:
        return {"version": None, "note": f"no version list from the {eco} registry (offline or unknown package)"}
    floor = min_fix or current
    cands = [v for v in vs if floor is None or compare(v, floor) >= 0]
    if current:
        cands = [v for v in cands if compare(v, current) > 0] or cands
    if not cands:
        return {"version": None, "note": f"no published version >= {floor}"}
    note = ""
    if eco == "pypi":      # prefer versions that install as a wheel on this Python (no sdist compile)
        inst = pypi_installable(name)
        if inst & set(cands):
            cands = [v for v in cands if v in inst]
        else:
            note = "no candidate has a wheel for this Python: installation may need a compiler"
    if len(cands) > MAX_CANDIDATES:      # keep the smallest changes and the newest releases
        cands = cands[:20] + cands[-(MAX_CANDIDATES - 20):]
    rem = remaining_advisories(eco, name, cands)
    cur_major = major(current or "")
    # upgrading: the smallest change; adding a new / replacement package (no current version): the newest
    order = (lambda v: cands.index(v)) if current else (lambda v: -cands.index(v))
    ranked = sorted(cands, key=lambda v: (len(rem.get(v, [])) if rem else 0, major(v) != cur_major, order(v)))
    best = ranked[0]
    return {"version": best, "remaining": rem.get(best, []) if rem else None,
            "major_change": bool(cur_major) and major(best) != cur_major, "candidates_checked": len(cands),
            "latest": vs[-1],
            "note": "; ".join(x for x in (note, "OSV not reachable: remaining advisories unknown" if not rem else "") if x)}


def official_image(repository: str, tag: str | None) -> dict | None:
    """'fastbuilds42/node' -> docker.io/library/node:<tag>@sha256:... if Docker Hub has an official image."""
    name = repository.rsplit("/", 1)[-1]
    tag = tag if tag and tag != "latest" else None
    for t in ([tag] if tag else []) + ["lts-slim", "lts", "stable-slim", "stable", "latest"]:
        doc = http_json("GET", f"https://hub.docker.com/v2/repositories/library/{quote(name)}/tags/{quote(t)}")
        if doc and doc.get("name"):
            digest = doc.get("digest") or ""
            return {"image": f"docker.io/library/{name}", "tag": t, "digest": digest,
                    "ref": f"{name}:{t}@{digest}" if digest else f"{name}:{t}"}
    return None


def action_sha(action: str, ref: str) -> str | None:
    """'actions/checkout', 'v4' -> 40-char commit SHA (GitHub API, unauthenticated, cached)."""
    owner_repo = "/".join(action.split("/")[:2])
    doc = http_json("GET", f"https://api.github.com/repos/{owner_repo}/commits/{quote(ref)}")
    sha = (doc or {}).get("sha")
    return sha if sha and re.fullmatch(r"[0-9a-f]{40}", sha) else None
