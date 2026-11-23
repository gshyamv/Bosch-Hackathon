"""PyPI: requirements*.txt (deps.dev transitive) and poetry.lock (offline, full graph)."""
from __future__ import annotations

import json
import re
from pathlib import Path

from .depsdev import approx_version, attach_depsdev

REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(===|==|>=|<=|~=|>|<|!=)?\s*([^\s;,#]*)")


def pep503(n: str) -> str:
    return re.sub(r"[-_.]+", "-", n).lower()


def read_requirements(path: Path, seen=None):
    seen = seen or set()
    if path in seen or not path.exists():
        return []
    seen.add(path)
    out = []
    for i, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw.split(" #")[0].strip()
        if line.startswith(("-r ", "--requirement ")):
            out += read_requirements(path.parent / line.split(None, 1)[1], seen)
            continue
        if not line or line.startswith(("#", "-", "git+", "http", ".")):
            continue
        m = REQ_RE.match(line)
        if m:
            out.append((pep503(m.group(1)), m.group(3), m.group(4), i))
    return out


def scan_requirements(dg, repo: Path, req: Path):
    rel = req.relative_to(repo).as_posix()
    rid = dg.app(rel, "pypi", req.parent.name if req.parent != repo else repo.name)
    scope = "dev" if re.search(r"dev|test|lint|doc", req.name) else "prod"
    for name, op, ver, line in read_requirements(req):
        pinned = op in ("==", "===") and "*" not in ver
        version = ver if pinned else approx_version(ver, "pypi") if op in (">=", "~=") else None
        attach_depsdev(dg, rid, "pypi", "pypi", name, version, f"{op or ''}{ver}", scope,
                       f"{rel}:{line}", approx=not pinned)


def scan_poetry(dg, repo: Path, lock: Path):
    import tomllib
    rel = lock.relative_to(repo).as_posix()
    data = tomllib.loads(lock.read_text(encoding="utf-8"))
    rid = dg.app(rel, "pypi", lock.parent.name)
    ids = {}
    for p in data.get("package", []):
        ids[pep503(p["name"])] = dg.pkg("pypi", pep503(p["name"]), p["version"], source=rel,
                                        scope="dev" if p.get("category") == "dev" else "prod",
                                        resolution="lockfile")
    for p in data.get("package", []):
        for dep, spec in (p.get("dependencies") or {}).items():
            if pep503(dep) in ids:
                dg.dep(ids[pep503(p["name"])], ids[pep503(dep)], spec if isinstance(spec, str) else json.dumps(spec))
    direct = set()
    pyproject = lock.parent / "pyproject.toml"
    if pyproject.exists():
        pp = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        tp = pp.get("tool", {}).get("poetry", {})
        for sect in [tp.get("dependencies", {}), tp.get("dev-dependencies", {})] + \
                    [g.get("dependencies", {}) for g in tp.get("group", {}).values()]:
            direct |= {pep503(k) for k in sect}
        direct |= {pep503(REQ_RE.match(s).group(1)) for s in pp.get("project", {}).get("dependencies", []) if REQ_RE.match(s)}
    if not direct:  # fallback: packages nobody depends on
        direct = {n for n, nid in ids.items() if dg.G.in_degree(nid) == 0}
    for n in direct:
        if n in ids:
            dg.dep(rid, ids[n], direct=True)
