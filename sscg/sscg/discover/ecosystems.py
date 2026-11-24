"""Adapter: VulnerabilityVision parsers (Ruby, Rust, Go, .NET, uv) -> SSCG's purl-keyed DepGraph."""
from __future__ import annotations

from pathlib import Path

from . import vv_parsers as vv

FILES = {"Gemfile.lock": vv.parse_gemfile_lock, "Cargo.lock": vv.parse_cargo_lock, "go.mod": vv.parse_go_mod,
         "uv.lock": vv.parse_uv_lock}
RESOLUTION = {"exact": "lockfile", "inventory": "manifest-inventory", "declared-only": "declared"}


def _central(p: Path) -> bool:
    return any((d / "Directory.Packages.props").exists() for d in list(p.parents)[:6])


def handles(p: Path) -> bool:
    return p.name in FILES or p.name == "Directory.Packages.props" or (p.suffix == ".csproj" and not _central(p))


def add_parsed(dg, manifest: str, parsed: vv.Parsed, name: str) -> None:
    app = dg.app(manifest, parsed.ecosystem, name)
    ids = {}
    for p in parsed.packages:
        ev = p.evidence
        src = ev.get("file", manifest) + (f":{ev['line']}" if ev.get("line") else "")
        ids[p.key] = dg.pkg(parsed.ecosystem, p.name, p.version or "unresolved", source=src,
                            scope=p.scope if p.scope in ("dev", "optional", "test") else "prod",
                            resolved=p.extra.get("resolved"), resolution=RESOLUTION.get(parsed.confidence, parsed.confidence))
    for e in parsed.edges:
        if e.dst in ids and (e.src is None or e.src in ids):
            direct = e.src is None and e.scope != "indirect"
            dg.dep(app if e.src is None else ids[e.src], ids[e.dst], e.range or "", direct=direct,
                   location=f"{e.evidence['file']}:{e.evidence['line']}" if e.evidence and e.evidence.get("line") else "")
    dg.notes += [f"{manifest}: {n}" for n in parsed.notes]
    if parsed.unresolved:
        dg.notes.append(f"{manifest}: {len(parsed.unresolved)} dependencies without an exact version were not checked")


def scan(dg, repo: Path, p: Path) -> None:
    rel = p.relative_to(repo).as_posix()
    if p.name in FILES:
        parsed = FILES[p.name](p, rel)
    else:
        central = p if p.name == "Directory.Packages.props" else None
        projs = sorted(p.parent.rglob("*.csproj")) if central else [p]
        parsed = vv.parse_dotnet(central, projs, lambda x: x.relative_to(repo).as_posix())
    add_parsed(dg, rel, parsed, p.parent.name if p.parent != repo else dg.top.removeprefix("repo:"))
