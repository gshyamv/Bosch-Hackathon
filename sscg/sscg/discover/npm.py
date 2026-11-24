"""npm: package-lock.json v1/v2/v3, npm-shrinkwrap.json, yarn.lock v1, package.json only (deps.dev)."""
from __future__ import annotations

import json
from pathlib import Path

from .depsdev import approx_version, attach_depsdev


def _npm_scope(meta: dict) -> str:
    return "dev" if meta.get("dev") else "optional" if meta.get("optional") else "prod"


def npm_lock_v2(dg, rid, manifest, lock, src):
    pkgs = lock.get("packages", {})

    def target(key):  # workspace symlinks
        m = pkgs.get(key, {})
        return m.get("resolved") if m.get("link") else key

    def resolve(parent_key, dep):  # node_modules resolution: own folder first, then walk up
        base = parent_key
        while True:
            cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
            if cand in pkgs:
                return target(cand)
            if not base:
                return None
            i = base.rfind("/node_modules/")
            base = base[:i] if i != -1 else ""

    key2id = {"": rid}
    for key, meta in pkgs.items():
        if not key or meta.get("link") or "version" not in meta:
            continue
        name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
        key2id[key] = dg.pkg("npm", name, meta["version"], scope=_npm_scope(meta), source=src,
                             resolved=meta.get("resolved"), integrity=meta.get("integrity"),
                             install_script=bool(meta.get("hasInstallScript")), resolution="lockfile")
    for key, meta in pkgs.items():
        if key not in key2id:
            continue
        fields = ["dependencies", "optionalDependencies"] + (["devDependencies"] if key == "" else [])
        for f in fields:
            for dep, spec in (meta.get(f) or {}).items():
                child = resolve(key, dep)
                if child in key2id:
                    dg.dep(key2id[key], key2id[child], spec, direct=(key == ""))


def npm_lock_v1(dg, rid, manifest, lock, src):
    def mk(name, meta):
        return dg.pkg("npm", name, meta.get("version", "unknown"), scope=_npm_scope(meta), source=src,
                      resolved=meta.get("resolved"), integrity=meta.get("integrity"), resolution="lockfile")

    def visit(deps_map, chain):
        level = {n: mk(n, m) for n, m in deps_map.items()}
        chain = chain + [level]
        for n, m in deps_map.items():
            own = visit(m["dependencies"], chain) if m.get("dependencies") else {}
            lookup = [own] + chain[::-1]
            reqs = m.get("requires") if isinstance(m.get("requires"), dict) else {}
            for req, spec in reqs.items():
                tgt = next((lvl[req] for lvl in lookup if req in lvl), None)
                if tgt:
                    dg.dep(level[n], tgt, spec)
        return level

    top = visit(lock.get("dependencies", {}), [])
    for name, spec in _direct_specs(manifest).items():
        if name in top:
            dg.dep(rid, top[name], spec, direct=True)


def parse_yarn_v1(text: str) -> dict:
    entries, cur, section = {}, None, None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            specs = [s.strip().strip('"') for s in line.rstrip().rstrip(":").split(",")]
            cur, section = {"deps": {}}, None
            for s in specs:
                entries[s] = cur
        elif line.startswith("    ") and section in ("dependencies", "optionalDependencies"):
            k, _, v = line.strip().partition(" ")
            cur["deps"][k.strip('"')] = v.strip().strip('"')
        else:
            k, _, v = line.strip().partition(" ")
            if k.endswith(":") and not v:
                section = k[:-1]
            else:
                cur[k] = v.strip().strip('"')
                section = None
    return entries


def npm_yarn_v1(dg, rid, manifest, text, src):
    entries = parse_yarn_v1(text)
    ids = {}
    for spec, e in entries.items():
        name = spec.rsplit("@", 1)[0] if spec.count("@") > (1 if spec.startswith("@") else 0) else spec
        if id(e) not in ids and "version" in e:
            ids[id(e)] = dg.pkg("npm", name, e["version"], source=src, resolved=e.get("resolved"),
                                integrity=e.get("integrity"), resolution="lockfile")
    for e in {id(e): e for e in entries.values()}.values():
        if id(e) not in ids:
            continue
        for dep, rng in e["deps"].items():
            t = entries.get(f"{dep}@{rng}")
            if t is not None and id(t) in ids:
                dg.dep(ids[id(e)], ids[id(t)], rng)
    for name, rng in _direct_specs(manifest).items():
        t = entries.get(f"{name}@{rng}")
        if t is not None and id(t) in ids:
            dg.dep(rid, ids[id(t)], rng, direct=True)
    for name in manifest.get("devDependencies", {}):
        t = entries.get(f"{name}@{manifest['devDependencies'][name]}")
        if t is not None and id(t) in ids:
            dg.G.nodes[ids[id(t)]]["scope"] = "dev"


def _direct_specs(manifest: dict) -> dict:
    out = {}
    for f in ("devDependencies", "optionalDependencies", "dependencies"):  # prod last = wins
        out.update(manifest.get(f) or {})
    return out


RESOLVE = False     # --resolve-npm


def resolve_lock(pkg_json: Path, manifest: dict) -> dict | None:
    """npm install --package-lock-only in the sandbox container; answer cached by package.json content."""
    import hashlib

    from .. import cache, sandbox
    text = json.dumps({k: manifest[k] for k in ("name", "version", "dependencies", "devDependencies", "optionalDependencies",
                                                "overrides") if k in manifest}, sort_keys=True)
    f = cache.CACHE / f"npm-resolve-{hashlib.sha1(text.encode()).hexdigest()}.json"
    if f.exists():
        return json.loads(f.read_text(encoding="utf-8"))
    if cache.OFFLINE or not sandbox.available():
        return None
    import tempfile
    try:
        with tempfile.TemporaryDirectory() as tmp, sandbox.Sandbox() as sb:
            (Path(tmp) / "package.json").write_text(text, encoding="utf-8")
            sb.put(Path(tmp), "r")
            r = sb.run("npm", ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
                               "--legacy-peer-deps"], "r", net=True)
            lock = json.loads(sb.read("r/package-lock.json") or "null") if r["status"] == "ok" else None
    except (RuntimeError, OSError, ValueError):
        return None
    if lock:
        cache.CACHE.mkdir(exist_ok=True)
        f.write_text(json.dumps(lock), encoding="utf-8")
    return lock


def scan(dg, repo: Path, pkg_json: Path):
    rel = pkg_json.relative_to(repo).as_posix()
    try:
        manifest = json.loads(pkg_json.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError):
        dg.notes.append(f"skip {rel}: invalid JSON")
        return
    rid = dg.app(rel, "npm", manifest.get("name", pkg_json.parent.name), manifest.get("version", ""))
    folder = pkg_json.parent
    for lock_name in ("package-lock.json", "npm-shrinkwrap.json"):
        lf = folder / lock_name
        if lf.exists():
            lock = json.loads(lf.read_text(encoding="utf-8"))
            src = lf.relative_to(repo).as_posix()
            if lock.get("lockfileVersion", 1) >= 2 and "packages" in lock:
                npm_lock_v2(dg, rid, manifest, lock, src)
            else:
                npm_lock_v1(dg, rid, manifest, lock, src)
            return
    yl = folder / "yarn.lock"
    if yl.exists():
        text = yl.read_text(encoding="utf-8")
        if "__metadata:" not in text:
            npm_yarn_v1(dg, rid, manifest, text, yl.relative_to(repo).as_posix())
            return
        dg.notes.append(f"{rel}: yarn berry lockfile not supported -> deps.dev fallback")
    lock = resolve_lock(pkg_json, manifest) if RESOLVE else None
    if lock:
        npm_lock_v2(dg, rid, manifest, lock, rel)
        for _, a in dg.G.nodes(data=True):
            if a.get("source") == rel and a.get("resolution") == "lockfile":
                a["resolution"] = "npm-resolved"
        dg.notes.append(f"{rel}: no lockfile -> resolved exactly with npm in the sandbox container")
        return
    dg.notes.append(f"{rel}: no lockfile -> transitive deps resolved via deps.dev (approximate)")
    dev = set(manifest.get("devDependencies") or {})
    for name, spec in _direct_specs(manifest).items():
        if not isinstance(spec, str) or spec.startswith(("file:", "link:", "git", "http", "workspace:")):
            continue
        attach_depsdev(dg, rid, "npm", "npm", name, approx_version(spec, "npm"), spec,
                       "dev" if name in dev else "prod", rel, approx=True)
