"""Detect suspicious changes. Every detector is deterministic and returns findings with evidence."""
from __future__ import annotations

from . import cicd, container, livepage, lockfile, packages, provenance
from .common import RULES, Ctx

DETECTORS = [packages.typosquat, packages.known_malicious, packages.install_scripts, packages.unpinned,
             lockfile.untrusted_source, lockfile.changes, container.images, container.dockerfiles,
             cicd.workflows, provenance.new_author, livepage.page]


def run_all(ctx: Ctx) -> list:
    out = []
    for det in DETECTORS:
        try:
            out += det(ctx)
        except Exception as e:  # one broken detector must not hide the others
            ctx.dg.notes.append(f"detector {det.__module__}.{det.__name__} failed: {type(e).__name__}: {e}")
    return out


__all__ = ["RULES", "Ctx", "run_all"]
