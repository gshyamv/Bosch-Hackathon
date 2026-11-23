"""deps.dev: transitive resolution when there is no lockfile (PyPI, Maven, npm without lock)."""
from __future__ import annotations

import re
from urllib.parse import quote

from ..cache import http_json
from ..model import DepGraph

DEPSDEV = "https://api.deps.dev/v3"


def depsdev_default_version(system: str, name: str):
    d = http_json("GET", f"{DEPSDEV}/systems/{system}/packages/{quote(name, safe='')}")
    for v in (d or {}).get("versions", []):
        if v.get("isDefault"):
            return v["versionKey"]["version"]
    return None


def attach_depsdev(dg: DepGraph, parent: str, system: str, eco: str, name: str, version: str | None,
                   spec: str, scope: str, src: str, approx: bool):
    """Resolve the transitive closure of name@version via deps.dev and attach it under parent."""
    if not version:
        version, approx = depsdev_default_version(system, name), True
    d = None
    if version:
        d = http_json("GET", f"{DEPSDEV}/systems/{system}/packages/{quote(name, safe='')}"
                             f"/versions/{quote(version, safe='')}:dependencies")
    if not d or not d.get("nodes"):
        nid = dg.pkg(eco, name, version or "unknown", scope=scope, source=src, resolution="unresolved")
        dg.dep(parent, nid, spec, direct=True)
        return
    res = "deps.dev-approx" if approx else "deps.dev"
    ids = [dg.pkg(eco, n["versionKey"]["name"], n["versionKey"]["version"], scope=scope,
                  source=src, resolution=res) for n in d["nodes"]]
    dg.dep(parent, ids[0], spec, direct=True)  # node 0 is SELF
    for e in d.get("edges", []):
        dg.dep(ids[e["fromNode"]], ids[e["toNode"]], e.get("requirement", ""))


def approx_version(spec: str | None, eco: str):
    """Lower bound of a range ('^4.17' -> '4.17.0'). Labelled 'approx' in the graph."""
    m = re.search(r"\d+(?:\.\d+){0,2}", spec or "")
    if not m:
        return None
    v = m.group(0)
    if eco == "npm":
        v = ".".join((v.split(".") + ["0", "0"])[:3])
    return v
