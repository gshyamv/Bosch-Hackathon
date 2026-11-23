"""Pillar 1 (Discover components) + container / CI inspection: walk the repo, dispatch each file."""
from __future__ import annotations

import collections
import re
from pathlib import Path

from . import docker, gha, maven, npm, pypi

SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "env", "target", "dist", "build",
             "__pycache__", "bower_components", "vendor", ".tox", "site-packages"}


def discover(repo: Path, dg) -> collections.Counter:
    found = collections.Counter()
    for p in sorted(repo.rglob("*")):
        parts = p.relative_to(repo).parts
        if any(part in SKIP_DIRS for part in parts[:-1]) or not p.is_file():
            continue
        try:
            if p.name == "package.json":
                npm.scan(dg, repo, p); found["npm"] += 1
            elif p.name == "poetry.lock":
                pypi.scan_poetry(dg, repo, p); found["poetry"] += 1
            elif re.fullmatch(r"requirements[\w.-]*\.txt", p.name) and not (p.parent / "poetry.lock").exists():
                pypi.scan_requirements(dg, repo, p); found["requirements"] += 1
            elif p.name == "pom.xml":
                maven.scan(dg, repo, p); found["maven"] += 1
            elif docker.is_dockerfile(p.name):
                docker.scan_dockerfile(dg, repo, p); found["dockerfile"] += 1
            elif docker.is_compose(p.name):
                docker.scan_compose(dg, repo, p); found["compose"] += 1
            elif gha.is_workflow(parts):
                gha.scan(dg, repo, p); found["workflow"] += 1
        except Exception as e:  # never let one bad file kill the scan
            dg.notes.append(f"error in {p.relative_to(repo).as_posix()}: {type(e).__name__}: {e}")
    return found
