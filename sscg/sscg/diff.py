"""Column 4 input: "what changed" between a base commit and the scanned working tree.

The base commit is extracted to a temp folder and scanned with the same discovery code, so both sides are
compared component by component (name, version, download URL, integrity hash, install script).
"""
from __future__ import annotations

import collections
from dataclasses import dataclass, field
from pathlib import Path

from . import gitutil
from .discover import discover
from .graph import compute_depth
from .model import DepGraph

COMPARED = ("resolved", "integrity", "install_script")


@dataclass
class Change:
    base_rev: str
    base: dict                     # commit info of the base
    head: dict                     # commit info of HEAD
    head_dirty: bool               # uncommitted changes in the working tree?
    first_time_author: bool | None
    files: list                    # [(status, path)]
    base_dg: DepGraph
    base_dir: Path
    added: list = field(default_factory=list)     # [node attrs]
    removed: list = field(default_factory=list)
    changed: list = field(default_factory=list)   # [{"name","ecosystem","base":attrs,"head":attrs,"fields":[...]}]

    def as_dict(self) -> dict:
        lbl = lambda a: {"label": a["label"], "ecosystem": a["ecosystem"], "scope": a.get("scope"),
                         "direct": a.get("direct"), "source": a.get("source")}
        return {
            "base": self.base, "head": self.head, "head_dirty": self.head_dirty,
            "first_time_author": self.first_time_author,
            "files": [{"status": s, "path": p} for s, p in self.files],
            "added": [lbl(a) for a in self.added], "removed": [lbl(a) for a in self.removed],
            "changed": [{"component": f"{c['ecosystem']}:{c['name']}", "base": c["base"]["label"],
                         "head": c["head"]["label"], "fields": c["fields"],
                         "detail": {f: {"base": c["base"].get(f), "head": c["head"].get(f)} for f in c["fields"]}}
                        for c in self.changed],
        }


def _index(dg: DepGraph) -> dict:
    idx = collections.defaultdict(dict)
    for n, a in dg.G.nodes(data=True):
        if a["kind"] == "package":
            idx[(a["ecosystem"], a["name"])][a["version"]] = dict(a, id=n)
    return idx


def compute(repo: Path, dg: DepGraph, base_rev: str, workdir: Path) -> Change | None:
    """None (with a note) when the repo has no git history for `base_rev`."""
    if not gitutil.is_repo_root(repo):
        dg.notes.append("what changed: not a git repository root, change analysis skipped")
        return None
    base_sha = gitutil.resolve(repo, base_rev)
    if not base_sha:
        dg.notes.append(f"what changed: base revision '{base_rev}' not found (shallow clone or first commit), "
                        "change analysis skipped")
        return None
    head = gitutil.commit_info(repo, "HEAD")
    base = gitutil.commit_info(repo, base_sha)
    base_dir = workdir / "base"
    base_dir.mkdir(parents=True, exist_ok=True)
    if not gitutil.extract(repo, base_sha, base_dir):
        dg.notes.append("what changed: could not extract the base commit, change analysis skipped")
        return None
    base_dg = DepGraph(repo.name)
    discover(base_dir, base_dg)
    compute_depth(base_dg)

    ch = Change(base_rev=base_rev, base=base, head=head, head_dirty=gitutil.is_dirty(repo),
                first_time_author=gitutil.first_time_author(repo, head["sha"], head["email"]),
                files=gitutil.changed_files(repo, base_sha), base_dg=base_dg, base_dir=base_dir)
    b, h = _index(base_dg), _index(dg)
    for key in sorted(h.keys() - b.keys()):
        ch.added += list(h[key].values())
    for key in sorted(b.keys() - h.keys()):
        ch.removed += list(b[key].values())
    for key in sorted(b.keys() & h.keys()):
        bv, hv = b[key], h[key]
        if set(bv) == set(hv):  # same versions: did the artifact behind a version change?
            for v in bv:
                fields = [f for f in COMPARED if bool(bv[v].get(f)) != bool(hv[v].get(f))
                          or (bv[v].get(f) and hv[v].get(f) and bv[v].get(f) != hv[v].get(f))]
                if fields:
                    ch.changed.append({"ecosystem": key[0], "name": key[1], "base": bv[v], "head": hv[v],
                                       "fields": fields})
        elif len(bv) == 1 and len(hv) == 1:  # one version replaced by another
            (b1,), (h1,) = bv.values(), hv.values()
            fields = ["version"] + [f for f in COMPARED if b1.get(f) != h1.get(f)]
            ch.changed.append({"ecosystem": key[0], "name": key[1], "base": b1, "head": h1, "fields": fields})
        else:  # several versions on one side: report version-level adds / removes
            ch.added += [hv[v] for v in hv.keys() - bv.keys()]
            ch.removed += [bv[v] for v in bv.keys() - hv.keys()]
    return ch
