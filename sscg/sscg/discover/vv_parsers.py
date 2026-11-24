"""Parsers ported from VulnerabilityVision: Gemfile.lock, Cargo.lock, go.mod, csproj, uv.lock. Pure, no network."""
from __future__ import annotations

import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


def pypi_norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass
class Pkg:
    key: str  # unique within the project, e.g. "flask@2.0.0"
    name: str
    version: str | None
    evidence: dict  # {file, line?, key?}
    scope: str = "prod"  # prod | dev | optional | peer | indirect | test | provided | runtime
    direct: bool = False
    extra: dict = field(default_factory=dict)  # resolved, source, checksum, approximate, ...


@dataclass
class Edge:
    src: str | None  # None = the project itself
    dst: str
    scope: str = "prod"
    range: str | None = None
    evidence: dict | None = None


@dataclass
class Parsed:
    ecosystem: str
    confidence: str  # exact | resolved | approximate | inventory | declared-only
    source_file: str  # the file the graph was built from
    packages: list[Pkg] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)  # declared deps without an exact version


# ------------------------------------------------------------------ Ruby
_SPEC = re.compile(r"^    ([^ (]+) \(([^)]+)\)$")
_SPEC_DEP = re.compile(r"^      ([^ (]+)(?: \(([^)]+)\))?$")
_TOP_DEP = re.compile(r"^  ([^ (!]+)(!)?(?: \(([^)]+)\))?$")


def parse_gemfile_lock(path: Path, rel: str) -> Parsed:
    out = Parsed("rubygems", "exact", rel)
    section, remote, current = None, None, None
    specs: dict[str, str] = {}  # name -> key (first platform variant wins)
    pending: list[tuple[str, str, str | None, int]] = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line and not line.startswith(" "):
            section, current = line.strip(), None
            continue
        if section in ("GEM", "GIT", "PATH"):
            if line.startswith("  remote: "):
                remote = line.split(": ", 1)[1]
                continue
            m = _SPEC.match(line)
            if m:
                name, ver = m.groups()
                base_ver = re.sub(r"-(x86|x64|arm|aarch64|java|universal|mingw|mswin|darwin|linux)[\w.-]*$", "", ver)
                key = f"{name}@{base_ver}"
                current = key
                if name not in specs:
                    specs[name] = key
                    extra = {"source": section.lower(), "platform_variant": ver if ver != base_ver else None}
                    if section != "GEM" or (remote and "rubygems.org" not in remote):
                        extra["resolved"] = remote
                    out.packages.append(Pkg(key, name, base_ver, {"file": rel, "line": i, "key": f"{section} specs"},
                                            extra=extra))
                continue
            m = _SPEC_DEP.match(line)
            if m and current:
                pending.append((current, m.group(1), m.group(2), i))
        elif section == "DEPENDENCIES":
            m = _TOP_DEP.match(line)
            if m:
                pending.append(("", m.group(1), m.group(3), i))
    for src, name, rng, i in pending:
        if name in specs and specs[name] != src:
            out.edges.append(Edge(src or None, specs[name], "prod", rng, {"file": rel, "line": i}))
    for p in out.packages:
        p.direct = any(e.src is None and e.dst == p.key for e in out.edges)
    out.notes.append("Gemfile groups (development/test) are not recorded in Gemfile.lock; scope shown as prod")
    return out


# ------------------------------------------------------------------ Rust
def parse_cargo_lock(path: Path, rel: str) -> Parsed:
    text = path.read_text(encoding="utf-8")
    data = tomllib.loads(text)
    starts = [i for i, l in enumerate(text.splitlines(), 1) if l.strip() == "[[package]]"]
    out = Parsed("cargo", "exact", rel)
    pkgs = data.get("package", [])
    by_name: dict[str, list[dict]] = {}
    for i, p in enumerate(pkgs):
        p["_line"] = starts[i] if i < len(starts) else None
        by_name.setdefault(p["name"], []).append(p)
    roots = [p for p in pkgs if "source" not in p]  # workspace members / local path crates
    root_keys = {f"{p['name']}@{p['version']}" for p in roots}

    def resolve(spec: str) -> str | None:
        parts = spec.split(" ")
        cands = by_name.get(parts[0], [])
        if len(parts) > 1:
            cands = [c for c in cands if c["version"] == parts[1]] or cands
        return f"{cands[0]['name']}@{cands[0]['version']}" if cands else None

    for p in pkgs:
        k = f"{p['name']}@{p['version']}"
        if k in root_keys:
            continue
        src = p.get("source", "")
        out.packages.append(Pkg(k, p["name"], p["version"], {"file": rel, "line": p["_line"], "key": f"package {p['name']}"},
                                extra={"checksum": p.get("checksum"),
                                       "resolved": src if src and "crates.io" not in src else None}))
    for p in pkgs:
        k = f"{p['name']}@{p['version']}"
        for spec in p.get("dependencies", []):
            t = resolve(spec)
            if t and t not in root_keys:
                out.edges.append(Edge(None if k in root_keys else k, t, "prod"))
    for pk in out.packages:
        pk.direct = any(e.src is None and e.dst == pk.key for e in out.edges)
    if len(roots) > 1:
        out.notes.append(f"workspace with {len(roots)} member crates; their dependencies are all attached to this project")
    out.notes.append("Cargo.lock does not separate dev-dependencies; scope shown as prod")
    return out


# ------------------------------------------------------------------ Go
_REQ_LINE = re.compile(r"^\s*([^\s]+)\s+(v[^\s]+)(\s*//\s*indirect)?")


def parse_go_mod(path: Path, rel: str) -> Parsed:
    out = Parsed("go", "inventory", rel)
    in_block = False
    replaces: dict[str, str] = {}
    lines = path.read_text(encoding="utf-8").splitlines()
    for raw in lines:  # first pass: replace directives may come after the requires
        m = re.match(r"\s*replace\s+(\S+)(?:\s+v\S+)?\s+=>\s+(\S+)(?:\s+(\S+))?", raw)
        if m:
            replaces[m.group(1)] = f"{m.group(2)} {m.group(3) or ''}".strip()
    for i, raw in enumerate(lines, 1):
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        target = line[len("require "):] if line.startswith("require ") and "(" not in line else (line if in_block else None)
        if not target:
            continue
        m = _REQ_LINE.match(target)
        if not m:
            continue
        mod, ver, indirect = m.group(1), m.group(2), bool(m.group(3))
        k = f"{mod}@{ver}"
        out.packages.append(Pkg(k, mod, ver, {"file": rel, "line": i}, "indirect" if indirect else "prod", not indirect,
                                {"replaced_by": replaces.get(mod), "inventory_only": True}))
        out.edges.append(Edge(None, k, "indirect" if indirect else "prod", ver))
    out.notes.append("go.mod lists every module in the build list; indirect modules are attached to the project "
                     "(module-to-module edges are not in go.mod)")
    return out


# ------------------------------------------------------------------ .NET
def _strip_ns(root: ET.Element) -> None:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]


def _xml(path: Path) -> ET.Element:
    root = ET.fromstring(path.read_bytes())  # stdlib parser: no external entities are fetched
    _strip_ns(root)
    return root


def _line_of(text_lines: list[str], needle: str) -> int | None:
    return next((i for i, l in enumerate(text_lines, 1) if needle in l), None)


def parse_dotnet(central: Path | None, csprojs: list[Path], rel_of) -> Parsed:
    out = Parsed("nuget", "declared-only", rel_of(central) if central else ", ".join(rel_of(c) for c in csprojs[:3]))
    versions: dict[str, tuple[str, int | None]] = {}
    if central and central.is_file():
        lines = central.read_text(encoding="utf-8-sig").splitlines()
        for el in _xml(central).iter("PackageVersion"):
            name, ver = el.get("Include"), el.get("Version")
            if name and ver:
                versions[name.lower()] = (ver, _line_of(lines, f'"{name}"'))
    seen = set()
    for cp in csprojs:
        lines = cp.read_text(encoding="utf-8-sig").splitlines()
        for el in _xml(cp).iter("PackageReference"):
            name = el.get("Include") or el.get("Update")
            if not name:
                continue
            ver = el.get("Version") or el.get("VersionOverride") or (el.findtext("Version") or None)
            src_file, line = rel_of(cp), _line_of(lines, f'"{name}"')
            if not ver and name.lower() in versions:
                ver, cline = versions[name.lower()]
                ev = {"file": rel_of(central), "line": cline, "key": f"PackageVersion {name} (used by {rel_of(cp)})"}
            else:
                ev = {"file": src_file, "line": line, "key": f"PackageReference {name}"}
            exact = ver if ver and re.fullmatch(r"[0-9][\w.+-]*", ver) else None
            k = f"{name}@{exact or 'unresolved'}"
            if k in seen:
                continue
            seen.add(k)
            if not exact:
                out.unresolved.append(f"{name} {ver or '(no version)'}")
            scope = "dev" if (el.get("PrivateAssets") or el.findtext("PrivateAssets") or "").lower() == "all" else "prod"
            out.packages.append(Pkg(k, name, exact, ev, scope, True, {"declared_range": ver}))
            out.edges.append(Edge(None, k, scope, ver))
    out.notes.append(f"{len(csprojs)} project file(s); declared PackageReferences only (no packages.lock.json)")
    return out


def _blocks(text: str, header: str = "[[package]]") -> list[int]:
    return [i for i, l in enumerate(text.splitlines(), 1) if l.strip() == header]


def parse_uv_lock(path: Path, rel: str) -> Parsed:
    text = path.read_text(encoding="utf-8")
    data = tomllib.loads(text)
    starts = _blocks(text)
    pkgs = data.get("package", [])
    out = Parsed("pypi", "exact", rel)
    roots = []
    by_name: dict[str, list[dict]] = {}
    for i, p in enumerate(pkgs):
        p["_line"] = starts[i] if i < len(starts) else None
        by_name.setdefault(pypi_norm(p["name"]), []).append(p)
        src = p.get("source", {})
        if "editable" in src or "virtual" in src:
            roots.append(p)

    def key(p):
        return f"{pypi_norm(p['name'])}@{p.get('version', '0')}"

    def target(dep: dict) -> dict | None:
        cands = by_name.get(pypi_norm(dep["name"]), [])
        if dep.get("version"):
            cands = [c for c in cands if c.get("version") == dep["version"]] or cands
        return cands[0] if cands else None

    root_keys = {key(r) for r in roots}
    for p in pkgs:
        if key(p) in root_keys:
            continue
        src = p.get("source", {})
        extra = {"source": next(iter(src), None), "resolved": src.get("url") or src.get("git")}
        if src.get("registry") and "pypi.org" not in src["registry"]:
            extra["resolved"] = src["registry"]
        out.packages.append(Pkg(key(p), pypi_norm(p["name"]), p.get("version"),
                                {"file": rel, "line": p["_line"], "key": f"package {p['name']}=={p.get('version')}"},
                                extra=extra))

    def add_deps(src_pkg: dict, src_key: str | None, groups: dict[str, str]):
        for field, scope in groups.items():
            val = src_pkg.get(field)
            lists = [val] if isinstance(val, list) else list((val or {}).values()) if isinstance(val, dict) else []
            for lst in lists:
                for dep in lst or []:
                    t = target(dep)
                    if t is not None and key(t) not in root_keys:
                        out.edges.append(Edge(src_key, key(t), scope, dep.get("marker")))

    for r in roots:
        add_deps(r, None, {"dependencies": "prod", "optional-dependencies": "optional", "dev-dependencies": "dev"})
    for p in pkgs:
        if key(p) not in root_keys:
            add_deps(p, key(p), {"dependencies": "prod", "optional-dependencies": "optional"})
    # scope propagation: a package only reachable through dev edges is dev
    _propagate_scope(out)
    if not roots:
        out.notes.append("no editable/virtual root package in uv.lock; direct dependencies unknown")
    return out


def _propagate_scope(out: Parsed) -> None:
    children: dict[str | None, list[Edge]] = {}
    for e in out.edges:
        children.setdefault(e.src, []).append(e)
    best: dict[str, str] = {}
    rank = {"prod": 0, "optional": 1, "dev": 2}
    stack = [(e.dst, e.scope) for e in children.get(None, [])]
    while stack:
        k, s = stack.pop()
        if k in best and rank.get(best[k], 3) <= rank.get(s, 3):
            continue
        best[k] = s
        stack.extend((e.dst, s if s != "prod" else "prod") for e in children.get(k, []))
    for p in out.packages:
        if p.key in best:
            p.scope = best[p.key]
    direct = {e.dst for e in children.get(None, [])}
    for p in out.packages:
        p.direct = p.key in direct


