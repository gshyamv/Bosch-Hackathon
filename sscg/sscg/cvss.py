"""CVSS v3.0 / v3.1 base score from a vector string (FIRST specification, section 7)."""
from __future__ import annotations

import math

W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def base_score(vector: str) -> float | None:
    """'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' -> 9.8. None for other versions or bad vectors."""
    if not vector or not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    try:
        m = dict(p.split(":", 1) for p in vector.split("/")[1:])
        s = m["S"]
        iss = 1 - (1 - W["C"][m["C"]]) * (1 - W["I"][m["I"]]) * (1 - W["A"][m["A"]])
        impact = 6.42 * iss if s == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        expl = 8.22 * W["AV"][m["AV"]] * W["AC"][m["AC"]] * PR[s][m["PR"]] * W["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    return _roundup(min(impact + expl, 10)) if s == "U" else _roundup(min(1.08 * (impact + expl), 10))


def label(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else \
        "LOW" if score > 0 else "NONE"
