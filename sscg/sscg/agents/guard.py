"""Responsible-AI guards around every LLM call.

redact()  - before the call: secret values in evidence (tokens, keys, passwords, URL credentials) are masked.
            References such as ${{ secrets.NPM_TOKEN }} are kept: they are evidence, not secrets.
ground()  - after the call: every finding ID, evidence ID, advisory ID and package@version the model mentions must
            exist in the evidence it was given. Unknown IDs are reported, uncited evidence IDs are dropped, and the
            assessment is downgraded to needs_human_review / low confidence.
"""
from __future__ import annotations

import json
import re

SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED PRIVATE KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED AWS KEY]"),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})\b"), "[REDACTED GITHUB TOKEN]"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"), "[REDACTED NPM TOKEN]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED SLACK TOKEN]"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "[REDACTED GOOGLE KEY]"),
    (re.compile(r"\b(?:sk-ant-|sk-|xai-)[A-Za-z0-9_\-]{20,}\b"), "[REDACTED API KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[REDACTED JWT]"),
    (re.compile(r"(://)[^/\s:@\"']+:[^/\s@\"']+@"), r"\1[REDACTED]:[REDACTED]@"),
    # NAME_TOKEN=value / "password": "value" / _authToken=value inside a text value (file excerpt, snippet ...).
    # Values starting with $ { [ are references (e.g. ${{ secrets.X }}), not secrets, and are kept.
    (re.compile(r"(?i)(\b[\w.-]*(?:secret|token|passw(?:or)?d|api[_-]?key|private[_-]?key|credential)[\w.-]*"
                r"[\"']?\s*[:=]\s*[\"']?)(?![$\{\[])([^\s\"',;]{6,})"), r"\1[REDACTED]"),
]


def _redact_text(s: str) -> tuple[str, int]:
    total = 0
    for pat, repl in SECRET_PATTERNS:
        s, n = pat.subn(repl, s)
        total += n
    return s, total


def redact(obj):
    """Return (redacted copy, number of replacements) of any JSON-like structure.

    Only string VALUES are scanned (never keys, numbers or the JSON syntax itself), so the packet stays valid.
    """
    count = 0

    def walk(x):
        nonlocal count
        if isinstance(x, str):
            x, n = _redact_text(x)
            count += n
            return x
        if isinstance(x, dict):
            return {k: walk(v) for k, v in x.items()}
        if isinstance(x, list):
            return [walk(v) for v in x]
        return x

    return walk(json.loads(json.dumps(obj, default=str))), count


ID_RE = {
    "finding": re.compile(r"\bF-\d{3,}\b(?!/)"),
    "evidence": re.compile(r"\bF-\d{3,}/[ET]\d+\b"),
    "advisory": re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[a-z0-9]{4}){3}|MAL-\d{4}-\d+|PYSEC-\d{4}-\d+)\b", re.I),
    "package": re.compile(r"(?<![\w@/.-])(@?[a-z0-9][\w.-]*(?:/[\w.-]+)?@\d[\w.+-]*)", re.I),
}


def known_ids(packet) -> set:
    """Every identifier present anywhere in the evidence packet (the only things the model may cite)."""
    text = json.dumps(packet, default=str)
    found = set()
    for pat in ID_RE.values():
        found |= {m.upper() if pat is ID_RE["advisory"] else m for m in pat.findall(text)}
    return found


HYPHENS = re.compile(r"[‐-―−﹣－]")   # models sometimes write non-ASCII hyphens


def ground(texts: list[str], cited: list[str], allowed: set, labels: set) -> dict:
    """Check model output. `allowed` = IDs in the packet, `labels` = every component label in the scan."""
    blob = HYPHENS.sub("-", " ".join(t for t in texts if t))
    unknown = set()
    for kind, pat in ID_RE.items():
        for m in pat.findall(blob):
            v = m.upper() if kind == "advisory" else m.rstrip(".,;:)")
            if kind == "package":
                if v not in labels and v not in allowed:
                    unknown.add(v)
            elif v not in allowed:
                unknown.add(v)
    kept = [c for c in cited if c in allowed]
    dropped = [c for c in cited if c not in allowed]
    return {"ok": not unknown and not dropped, "unknown_ids": sorted(unknown), "dropped_citations": dropped,
            "cited": kept}
