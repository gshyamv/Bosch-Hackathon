"""Version comparison good enough for npm (semver), PyPI (PEP 440) and Maven, used to pick the fix for a version."""
from __future__ import annotations

import re
from functools import cmp_to_key

from packaging.version import InvalidVersion, Version


def _fallback(v: str) -> list:
    out = []
    for part in re.split(r"[.\-+_]", v.lower()):
        m = re.match(r"^(\d+)(.*)$", part)
        out.append((1, int(m.group(1)), m.group(2)) if m else (0, 0, part))
    return out


def compare(a: str, b: str) -> int:
    """-1 / 0 / 1. '0' (OSV 'introduced: 0') is lower than everything."""
    if a == b:
        return 0
    if a == "0":
        return -1
    if b == "0":
        return 1
    try:
        va, vb = Version(a), Version(b)
        return (va > vb) - (va < vb)
    except InvalidVersion:
        fa, fb = _fallback(a), _fallback(b)
        return (fa > fb) - (fa < fb)


def sort_versions(vs):
    return sorted(vs, key=cmp_to_key(compare))


def fixed_for(version: str, events: list) -> tuple[bool, str | None]:
    """OSV range events -> (version is inside this range, fixed version or None)."""
    order = {"introduced": 0, "fixed": 1, "last_affected": 1, "limit": 2}
    evs = [(k, v) for e in events for k, v in e.items() if k in order]
    evs.sort(key=cmp_to_key(lambda x, y: compare(x[1], y[1]) or order[x[0]] - order[y[0]]))
    lo = None
    for kind, v in evs:
        if kind == "introduced":
            lo = v
        elif lo is not None and kind in ("fixed", "last_affected"):
            if compare(version, lo) >= 0:
                if kind == "fixed" and compare(version, v) < 0:
                    return True, v
                if kind == "last_affected" and compare(version, v) <= 0:
                    return True, None
            lo = None
    if lo is not None and compare(version, lo) >= 0:
        return True, None  # open-ended: no fix published
    return False, None
