"""R18: a first-time contributor changed files that decide what gets built and installed."""
from __future__ import annotations

import re

from .common import Ctx, mk

SENSITIVE = re.compile(r"(^|/)(package(-lock)?\.json|npm-shrinkwrap\.json|yarn\.lock|poetry\.lock|requirements[\w.-]*\.txt"
                       r"|pom\.xml|Dockerfile[\w.-]*|[\w.-]*\.dockerfile|(docker-)?compose[\w.-]*\.ya?ml)$"
                       r"|^\.github/workflows/|^scripts/", re.I)


def new_author(ctx: Ctx) -> list:
    ch = ctx.change
    if not ch or not ch.first_time_author:
        return []
    touched = [f"{s} {p}" for s, p in ch.files if SENSITIVE.search(p)]
    if not touched:
        return []
    h = ch.head
    return [mk("R18_NEW_AUTHOR_SENSITIVE_CHANGE",
               f"first-time contributor {h['author']} changed {len(touched)} build/dependency files in "
               f"{h['short']} (\"{h['message']}\")", location=f"commit {h['short']}", key=(h["sha"],),
               classification="verified_fact", new=True,
               evidence=[{"type": "commit", "sha": h["short"], "author": h["author"], "email": h["email"],
                          "date": h["date"], "message": h["message"], "first_time_author": True},
                         {"type": "fact", "detail": "changed: " + ", ".join(touched)}])]
