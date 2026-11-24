"""OpenSSF Malicious Packages (github.com/ossf/malicious-packages, Apache-2.0) as a local knowledge source.

`python -m sscg knowledge update` builds an index of every published report WITHOUT downloading the reports:
a blob-less, shallow git clone gives the file list osv/malicious/<ecosystem>/<package>/<MAL-id>.json, which
already names the ecosystem, the package and the report id. The index lands in .cache/ossf_malicious.json,
recording the commit it was built from.

At scan time rule R02 looks a package up by name (offline, from the index). Only for a name match is the single
report fetched (pinned to that commit, cached) to check whether the scanned VERSION is affected. If the report
cannot be fetched, the match is still reported, marked "version not checked".
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from functools import lru_cache

from . import cache

REPO = "https://github.com/ossf/malicious-packages"
INDEX = cache.CACHE / "ossf_malicious.json"
ECO = {"npm": "npm", "pypi": "pypi", "maven": "maven", "cargo": "crates.io", "go": "go", "golang": "go",
       "nuget": "nuget", "gem": "rubygems", "rubygems": "rubygems"}


def norm(eco: str, name: str) -> str:
    n = name.lower()
    return re.sub(r"[-_.]+", "-", n) if eco == "pypi" else n


def parse_paths(paths) -> dict:
    """['osv/malicious/npm/@a/b/MAL-2024-1.json', ...] -> {ecosystem: {normalised name: [[folder name, id]]}}"""
    out: dict = {}
    for p in paths:
        parts = p.strip().split("/")
        if len(parts) < 5 or parts[:2] != ["osv", "malicious"] or not parts[-1].endswith(".json"):
            continue
        eco, name, rid = parts[2], "/".join(parts[3:-1]), parts[-1][:-5]
        out.setdefault(eco, {}).setdefault(norm(eco, name), []).append([name, rid])
    return out


def update(log=print) -> dict:
    """Rebuild the index from the current upstream commit. Needs git and network."""
    tmp = tempfile.mkdtemp(prefix="sscg-ossf-")
    try:
        git = ["git", "-c", "core.longpaths=true"]
        log(f"fetching the file list of {REPO} (no report contents) ...")
        subprocess.run([*git, "clone", "--quiet", "--depth", "1", "--filter=blob:none", "--no-checkout", REPO, tmp],
                       check=True, timeout=900)
        sha = subprocess.run([*git, "-C", tmp, "rev-parse", "HEAD"], check=True, capture_output=True,
                             text=True).stdout.strip()
        files = subprocess.run([*git, "-C", tmp, "ls-tree", "-r", "--name-only", "HEAD", "--", "osv/malicious"],
                               check=True, capture_output=True, text=True, encoding="utf-8", timeout=300).stdout
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    eco = parse_paths(files.splitlines())
    doc = {"source": REPO, "licence": "Apache-2.0", "commit": sha,
           "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "counts": {e: len(v) for e, v in sorted(eco.items())}, "ecosystems": eco}
    cache.CACHE.mkdir(exist_ok=True)
    INDEX.write_text(json.dumps(doc), encoding="utf-8")
    index.cache_clear()
    log(f"OpenSSF malicious packages @ {sha[:10]}: " + ", ".join(f"{e} {n}" for e, n in doc["counts"].items()))
    return doc


@lru_cache(maxsize=1)
def index() -> dict | None:
    try:
        return json.loads(INDEX.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def info() -> dict | None:
    d = index()
    return {k: d[k] for k in ("source", "licence", "commit", "built_at", "counts")} if d else None


def _affected(report: dict, version: str) -> bool | None:
    """True / False when the report says, None when it can't be decided here."""
    for a in report.get("affected", []):
        if version in (a.get("versions") or []):
            return True
        for r in a.get("ranges") or []:
            ev = r.get("events") or []
            if any(e.get("introduced") == "0" for e in ev) and not any("fixed" in e or "last_affected" in e for e in ev):
                return True          # every version
        if a.get("versions") and not a.get("ranges"):
            return False             # explicit list that doesn't contain this version
    return None


def lookup(ecosystem: str, name: str, version: str | None) -> list[dict]:
    """Reports on this package that (may) cover this version: [{id, url, summary, version_checked}]."""
    d, oe = index(), ECO.get(ecosystem)
    if not d or not oe:
        return []
    out = []
    for folder, rid in d["ecosystems"].get(oe, {}).get(norm(oe, name), []):
        path = f"osv/malicious/{oe}/{folder}/{rid}.json"
        rep = cache.http_json("GET", f"https://raw.githubusercontent.com/ossf/malicious-packages/{d['commit']}/{path}")
        hit = _affected(rep, version) if rep and version else None
        if hit is False:
            continue
        out.append({"id": rid, "url": f"{REPO}/blob/{d['commit']}/{path}",
                    "summary": ((rep or {}).get("summary") or (rep or {}).get("details") or "")[:300],
                    "version_checked": hit is True})
    return out
