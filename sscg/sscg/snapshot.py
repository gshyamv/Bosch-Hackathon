"""Bind a human approval to exactly what was reviewed.

When a remediation run pauses for approval, `fingerprint()` records a SHA-256 per file that decides what gets built
and installed (manifests, lockfiles, Dockerfiles, CI workflows, install scripts) plus every file a proposal edits,
and the git HEAD. File contents are hashed, so uncommitted edits count too. Before the paused run is resumed, the
fingerprint is taken again; if anything changed, the approval is refused and a new run is needed.
`proposal_hash()` identifies the exact proposal (edits and diff) a decision was made on.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from . import gitutil

RELEVANT = re.compile(r"(^|/)(package(-lock)?\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock"
                      r"|pyproject\.toml|Pipfile(\.lock)?|requirements[\w.-]*\.txt|setup\.(py|cfg)|pom\.xml"
                      r"|build\.gradle(\.kts)?|(Docker|Container)file[\w.-]*|[\w.-]*\.dockerfile"
                      r"|(docker-)?compose[\w.-]*\.ya?ml)$|^\.github/workflows/|(^|/)scripts/", re.I)
SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "target", ".sscg-state"}


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def fingerprint(repo: Path, extra: list[str] = ()) -> dict:
    files = set(extra)
    for p in repo.rglob("*"):
        rel = p.relative_to(repo)
        if p.is_file() and not (set(rel.parts) & SKIP) and RELEVANT.search(rel.as_posix()):
            files.add(rel.as_posix())
    per = {}
    for f in sorted(files):
        fp = repo / f
        per[f] = _sha(fp.read_bytes()) if fp.is_file() else None      # None: the file does not exist
    head = gitutil.git(repo, "rev-parse", "HEAD")
    return {"head": head, "files": per,
            "sha256": _sha(json.dumps({"head": head, "files": per}, sort_keys=True).encode())}


def changes(old: dict, new: dict) -> list[str]:
    """Human-readable differences between two fingerprints (empty = unchanged)."""
    out = []
    if old.get("head") != new.get("head"):
        out.append(f"git HEAD {str(old.get('head'))[:10]} -> {str(new.get('head'))[:10]}")
    a, b = old.get("files", {}), new.get("files", {})
    out += [f"changed: {f}" for f in sorted(a.keys() & b.keys()) if a[f] != b[f]]
    out += [f"removed: {f}" for f in sorted(a.keys() - b.keys())]
    out += [f"added: {f}" for f in sorted(b.keys() - a.keys())]
    return out


def proposal_hash(p: dict) -> str:
    keys = ("proposal_id", "action", "component", "from_version", "to_version", "files_affected", "edits", "diff")
    return _sha(json.dumps({k: p.get(k) for k in keys}, sort_keys=True, default=str).encode())
