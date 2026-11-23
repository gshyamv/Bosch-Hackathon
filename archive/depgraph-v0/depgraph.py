#!/usr/bin/env python3
"""
depgraph.py - Supply Chain Guardian: multi-ecosystem dependency graph builder (Day 1).

Usage:
  python depgraph.py <repo_dir> [--out out] [--osv] [--offline] [--why NAME ...]
                     [--focus NAME] [--max-depth N] [--sbom bom.cdx.json]

Supports:
  npm   : package-lock.json v1/v2/v3, npm-shrinkwrap.json, yarn.lock v1, package.json only (deps.dev)
  PyPI  : requirements*.txt (deps.dev transitive), poetry.lock (offline, full graph)
  Maven : pom.xml (${props}, dependencyManagement, parent version; deps.dev transitive)
  Any   : CycloneDX JSON SBOM import (--sbom, e.g. from Syft/cdxgen)

Outputs (in --out):
  graph.json   nodes + edges + attributes (input for UI / AI agent)
  graph.html   interactive graph (pyvis, offline, works inside Streamlit)
  graph.mmd    Mermaid diagram (only for small graphs)
  summary.json stats: counts, depth, blast radius, duplicates, origins, vulnerable paths
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import itertools
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import quote, urlparse

import networkx as nx
import requests

CACHE = Path(".cache")
OFFLINE = False
DEPSDEV = "https://api.deps.dev/v3"
SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "env", "target", "dist", "build",
             "__pycache__", "bower_components", "vendor", ".tox", "site-packages"}
TRUSTED_NPM_HOSTS = {"registry.npmjs.org", "registry.yarnpkg.com"}


# ----------------------------------------------------------------------------- HTTP + cache
def http_json(method: str, url: str, body=None):
    """GET/POST JSON with an on-disk cache so the demo also works offline."""
    key = hashlib.sha1(f"{method} {url} {json.dumps(body, sort_keys=True)}".encode()).hexdigest()
    path = CACHE / f"{key}.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    if OFFLINE:
        return None
    try:
        r = requests.request(method, url, json=body, timeout=30)
        data = r.json() if r.status_code == 200 else None
    except (requests.RequestException, ValueError):
        return None  # transient error: don't cache
    CACHE.mkdir(exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return data


# ----------------------------------------------------------------------------- graph model
def purl(eco: str, name: str, version: str) -> str:
    if eco == "npm":
        return f"pkg:npm/{quote(name, safe='/')}@{version}"
    if eco == "pypi":
        return f"pkg:pypi/{name}@{version}"
    if eco == "maven":
        g, _, a = name.partition(":")
        return f"pkg:maven/{g}/{a}@{version}"
    return f"pkg:{eco}/{name}@{version}"


class DepGraph:
    """Directed graph: repo -> app (one per manifest) -> package -> package ..."""

    def __init__(self, repo_name: str):
        self.G = nx.DiGraph()
        self.top = f"repo:{repo_name}"
        self.G.add_node(self.top, kind="repo", label=repo_name, ecosystem="-")
        self.notes: list[str] = []

    def app(self, manifest_rel: str, eco: str, name: str, version: str = "") -> str:
        rid = f"app:{manifest_rel}"
        self.G.add_node(rid, kind="app", ecosystem=eco, name=name, version=version,
                        label=f"{name}@{version}" if version else name, source=manifest_rel)
        self.G.add_edge(self.top, rid)
        return rid

    def pkg(self, eco: str, name: str, version: str, nid: str | None = None, **attrs) -> str:
        nid = nid or purl(eco, name, version)
        scope = attrs.pop("scope", "prod")
        if nid not in self.G:
            self.G.add_node(nid, kind="package", ecosystem=eco, name=name, version=version,
                            label=f"{name}@{version}", direct=False, scope=scope, **attrs)
        else:
            node = self.G.nodes[nid]
            if scope == "prod":
                node["scope"] = "prod"  # prod anywhere wins over dev/test
            for k, v in attrs.items():
                node.setdefault(k, v)
        return nid

    def dep(self, parent: str, child: str, spec: str = "", direct: bool = False):
        if parent == child:
            return
        self.G.add_edge(parent, child, spec=spec or "")
        if direct:
            self.G.nodes[child]["direct"] = True


# ----------------------------------------------------------------------------- deps.dev
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


# ----------------------------------------------------------------------------- npm
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


def scan_npm(dg, repo: Path, pkg_json: Path):
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
    dg.notes.append(f"{rel}: no lockfile -> transitive deps resolved via deps.dev (approximate)")
    dev = set(manifest.get("devDependencies") or {})
    for name, spec in _direct_specs(manifest).items():
        if not isinstance(spec, str) or spec.startswith(("file:", "link:", "git", "http", "workspace:")):
            continue
        attach_depsdev(dg, rid, "npm", "npm", name, approx_version(spec, "npm"), spec,
                       "dev" if name in dev else "prod", rel, approx=True)


# ----------------------------------------------------------------------------- PyPI
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


# ----------------------------------------------------------------------------- Maven
def scan_pom(dg, repo: Path, pom: Path):
    rel = pom.relative_to(repo).as_posix()
    try:
        root = ET.fromstring(pom.read_text(encoding="utf-8"))
    except ET.ParseError:
        dg.notes.append(f"skip {rel}: invalid XML")
        return
    for el in root.iter():  # drop namespaces
        if isinstance(el.tag, str):
            el.tag = el.tag.split("}")[-1]
    props_el = root.find("properties")
    props = {c.tag: (c.text or "").strip() for c in props_el} if props_el is not None else {}
    gid = root.findtext("groupId") or root.findtext("parent/groupId") or ""
    ver = root.findtext("version") or root.findtext("parent/version") or ""
    props.update({"project.version": ver, "project.groupId": gid, "version": ver, "pom.version": ver,
                  "project.parent.version": root.findtext("parent/version") or ""})

    def sub(s):
        s = (s or "").strip()
        for _ in range(5):
            s2 = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), s)
            if s2 == s:
                break
            s = s2
        return s

    managed = {}
    for d in root.findall("dependencyManagement/dependencies/dependency"):
        managed[f"{sub(d.findtext('groupId'))}:{sub(d.findtext('artifactId'))}"] = sub(d.findtext("version"))
    rid = dg.app(rel, "maven", f"{gid}:{root.findtext('artifactId')}", ver)
    parent_ga = f"{root.findtext('parent/groupId')}:{root.findtext('parent/artifactId')}"
    for d in root.findall("dependencies/dependency"):
        g, a = sub(d.findtext("groupId")), sub(d.findtext("artifactId"))
        v = sub(d.findtext("version")) or managed.get(f"{g}:{a}", "")
        scope = {"test": "test", "provided": "build"}.get(d.findtext("scope") or "", "prod")
        name = f"{g}:{a}"
        if g == gid and gid:  # sibling module of the same project
            nid = dg.pkg("maven", name, v or ver, scope=scope, source=rel, resolution="internal-module")
            dg.dep(rid, nid, v, direct=True)
        elif not v or "${" in v:
            nid = dg.pkg("maven", name, "managed-by-parent", scope=scope, source=rel, resolution="unresolved")
            dg.dep(rid, nid, f"version from {parent_ga}", direct=True)
        else:
            attach_depsdev(dg, rid, "maven", "maven", name, v, v, scope, rel, approx=False)


# ----------------------------------------------------------------------------- CycloneDX import
def scan_cyclonedx(dg, path: Path):
    try:
        bom = json.loads(path.read_text(encoding="utf-8-sig"))
    except (ValueError, OSError) as e:
        sys.exit(f"cannot read SBOM {path}: {e} (is it CycloneDX JSON? did Syft/Docker fail?)")
    meta = bom.get("metadata", {}).get("component", {})
    rid = dg.app(path.name, "sbom", meta.get("name", "sbom"), meta.get("version", ""))
    ref2id = {meta["bom-ref"]: rid} if meta.get("bom-ref") else {}
    for c in bom.get("components", []):
        p = c.get("purl") or f"pkg:generic/{c.get('name')}@{c.get('version', '')}"
        eco = p[4:].split("/")[0]
        nid = dg.pkg(eco, c.get("name", "?"), c.get("version", ""), nid=p.split("?")[0],
                     source=path.name, resolution="sbom")
        ref2id[c.get("bom-ref", p)] = nid
    for d in bom.get("dependencies", []):
        for t in d.get("dependsOn", []):
            if d.get("ref") in ref2id and t in ref2id:
                dg.dep(ref2id[d["ref"]], ref2id[t], direct=(ref2id[d["ref"]] == rid))
    if dg.G.out_degree(rid) == 0:  # no dependency info: hang roots under the app
        for nid in set(ref2id.values()) - {rid}:
            if dg.G.in_degree(nid) == 0:
                dg.dep(rid, nid, direct=True)


# ----------------------------------------------------------------------------- discovery
def discover(repo: Path, dg: DepGraph):
    found = collections.Counter()
    for p in sorted(repo.rglob("*")):
        if any(part in SKIP_DIRS for part in p.relative_to(repo).parts[:-1]) or not p.is_file():
            continue
        try:
            if p.name == "package.json":
                scan_npm(dg, repo, p); found["npm"] += 1
            elif p.name == "poetry.lock":
                scan_poetry(dg, repo, p); found["poetry"] += 1
            elif re.fullmatch(r"requirements[\w.-]*\.txt", p.name) and not (p.parent / "poetry.lock").exists():
                scan_requirements(dg, repo, p); found["requirements"] += 1
            elif p.name == "pom.xml":
                scan_pom(dg, repo, p); found["maven"] += 1
        except Exception as e:  # never let one bad manifest kill the scan
            dg.notes.append(f"error in {p.relative_to(repo).as_posix()}: {type(e).__name__}: {e}")
    return found


# ----------------------------------------------------------------------------- enrichment
OSV_ECO = {"npm": "npm", "pypi": "PyPI", "maven": "Maven"}


def osv_overlay(dg: DepGraph):
    G = dg.G
    pk = [(n, a) for n, a in G.nodes(data=True) if a["kind"] == "package"
          and a["ecosystem"] in OSV_ECO and re.match(r"\d", str(a.get("version", "")))]
    for i in range(0, len(pk), 500):
        batch = pk[i:i + 500]
        q = {"queries": [{"package": {"ecosystem": OSV_ECO[a["ecosystem"]], "name": a["name"]},
                          "version": a["version"]} for _, a in batch]}
        res = http_json("POST", "https://api.osv.dev/v1/querybatch", q)
        if not res:
            dg.notes.append("OSV unavailable (offline / network)")
            return
        for (n, _), r in zip(batch, res.get("results", [])):
            ids = [v["id"] for v in r.get("vulns", [])]
            if ids:
                G.nodes[n]["vulns"] = ids


def compute_depth(dg: DepGraph):
    dist = nx.single_source_shortest_path_length(dg.G, dg.top)
    for n, a in dg.G.nodes(data=True):
        if a["kind"] == "package":
            a["depth"] = dist[n] - 1 if n in dist else None  # 1 = direct dependency
            a["dependents"] = dg.G.in_degree(n)


def find_nodes(G, query: str):
    q = query.lower()
    return [n for n, a in G.nodes(data=True) if a["kind"] == "package"
            and (str(a.get("name", "")).lower() == q or str(a.get("label", "")).lower() == q or n.lower() == q)]


def why(dg: DepGraph, query: str, k: int = 5):
    """All (up to k) shortest dependency paths that pull `query` into the application."""
    out = {}
    for n in find_nodes(dg.G, query):
        paths = itertools.islice(nx.shortest_simple_paths(dg.G, dg.top, n), k) if nx.has_path(dg.G, dg.top, n) else []
        out[n] = [[dg.G.nodes[x]["label"] for x in p[1:]] for p in paths]
    return out


def summarize(dg: DepGraph) -> dict:
    G = dg.G
    pk = [n for n, a in G.nodes(data=True) if a["kind"] == "package"]
    A = lambda n: G.nodes[n]
    pkg_set = set(pk)
    by_name = collections.defaultdict(set)
    for n in pk:
        by_name[(A(n)["ecosystem"], A(n)["name"])].add(A(n)["version"])
    blast = sorted(((len(nx.ancestors(G, n) & pkg_set), A(n)["label"]) for n in pk), reverse=True)[:10]
    heavy = sorted(((len(nx.descendants(G, n)), A(n)["label"]) for n in pk if A(n).get("direct")), reverse=True)[:10]
    hosts = collections.Counter(urlparse(A(n)["resolved"]).hostname or "local"
                                for n in pk if A(n).get("resolved"))
    vulnerable = [n for n in pk if A(n).get("vulns")]
    vuln_paths = []
    for n in sorted(vulnerable, key=lambda n: (A(n).get("depth") or 0), reverse=True):
        if nx.has_path(G, dg.top, n):
            p = nx.shortest_path(G, dg.top, n)
            vuln_paths.append({"package": A(n)["label"], "depth": A(n).get("depth"), "advisories": len(A(n)["vulns"]),
                               "path": " -> ".join(A(x)["label"] for x in p[1:])})
    return {
        "apps": [G.nodes[n]["label"] + f"  ({G.nodes[n]['source']})" for n in G.successors(dg.top)],
        "packages": len(pk),
        "edges": G.number_of_edges(),
        "by_ecosystem": dict(collections.Counter(A(n)["ecosystem"] for n in pk)),
        "direct": sum(1 for n in pk if A(n).get("direct")),
        "transitive": sum(1 for n in pk if not A(n).get("direct")),
        "max_depth": max((A(n).get("depth") or 0 for n in pk), default=0),
        "depth_histogram": dict(sorted(collections.Counter(A(n).get("depth") for n in pk
                                                           if A(n).get("depth") is not None).items())),
        "by_scope": dict(collections.Counter(A(n).get("scope") for n in pk)),
        "resolution": dict(collections.Counter(A(n).get("resolution") for n in pk)),
        "origins": dict(hosts),
        "untrusted_origins": [A(n)["label"] + " <- " + A(n)["resolved"] for n in pk if A(n).get("resolved")
                              and (urlparse(A(n)["resolved"]).hostname or "") not in TRUSTED_NPM_HOSTS
                              and A(n)["ecosystem"] == "npm"],
        "install_scripts": [A(n)["label"] for n in pk if A(n).get("install_script")],
        "duplicates": {f"{e}:{nm}": sorted(v) for (e, nm), v in by_name.items() if len(v) > 1},
        "top_blast_radius": [{"package": l, "dependents_transitive": c} for c, l in blast],
        "heaviest_direct_deps": [{"package": l, "brings_in": c} for c, l in heavy],
        "vulnerable_packages": len(vulnerable),
        "vulnerable_paths": vuln_paths[:50],
        "cycles": len(list(itertools.islice(nx.simple_cycles(G), 100))),
        "notes": dg.notes,
    }


# ----------------------------------------------------------------------------- exports
ECO_COLOR = {"npm": "#e8a33d", "pypi": "#4b8bbe", "maven": "#8e6bbf"}


def view(dg: DepGraph, focus: str | None, max_depth: int | None, limit: int = 600) -> nx.DiGraph:
    G = dg.G
    if focus:
        keep = set()
        for n in find_nodes(G, focus):
            keep |= nx.ancestors(G, n) | nx.descendants(G, n) | {n}
        return G.subgraph(keep).copy()
    if max_depth is None and G.number_of_nodes() > limit:
        max_depth = 2
        dg.notes.append(f"graph.html limited to depth {max_depth} + vulnerable paths "
                        f"({G.number_of_nodes()} nodes); use --focus/--max-depth")
    if max_depth is None:
        return G
    keep = {n for n, a in G.nodes(data=True) if a["kind"] != "package" or (a.get("depth") or 99) <= max_depth}
    for n, a in G.nodes(data=True):  # always keep vulnerable nodes and their path
        if a.get("vulns") and nx.has_path(G, dg.top, n):
            keep |= set(nx.shortest_path(G, dg.top, n))
    return G.subgraph(keep).copy()


def _safe(s) -> str:
    """Scanned repos are hostile: a lockfile 'version' could contain </script>. Neutralise HTML."""
    return str(s).replace("<", "‹").replace(">", "›").replace("&", "＆")


def export_html(H: nx.DiGraph, path: Path):
    from pyvis.network import Network
    net = Network(height="800px", width="100%", directed=True, cdn_resources="in_line")
    num = {n: i for i, n in enumerate(H.nodes)}  # numeric ids: no repo text in ids
    for n, a in H.nodes(data=True):
        a = {k: (_safe(v) if isinstance(v, str) else v) for k, v in a.items()}
        if a["kind"] == "repo":
            net.add_node(num[n], label=a["label"], shape="star", color="#333333", size=30)
            continue
        if a["kind"] == "app":
            net.add_node(num[n], label=a["label"], shape="box", color="#2ca02c", title=f"manifest: {a['source']}")
            continue
        untrusted = a.get("resolved") and (urlparse(a["resolved"]).hostname or "") not in TRUSTED_NPM_HOSTS \
            and a["ecosystem"] == "npm"
        color = "#d62728" if a.get("vulns") else ECO_COLOR.get(a["ecosystem"], "#7f8c8d")
        tip = "\n".join(filter(None, [  # all values already passed through _safe()
            a["label"], f"ecosystem: {a['ecosystem']}  scope: {a.get('scope')}",
            f"{'DIRECT' if a.get('direct') else 'transitive'}  depth: {a.get('depth')}  dependents: {a.get('dependents')}",
            f"resolution: {a.get('resolution')}", f"origin: {a.get('resolved')}" if a.get("resolved") else "",
            f"source: {a.get('source')}", "INSTALL SCRIPT" if a.get("install_script") else "",
            f"UNTRUSTED ORIGIN" if untrusted else "",
            f"{len(a['vulns'])} advisories: {', '.join(a['vulns'][:6])}" if a.get("vulns") else ""]))
        net.add_node(num[n], label=a["label"], title=tip, color=color, size=20 if a.get("direct") else 10,
                     shape="diamond" if (untrusted or a.get("install_script")) else "dot",
                     borderWidth=3 if a.get("direct") else 1)
    for u, v, e in H.edges(data=True):
        net.add_edge(num[u], num[v], title=_safe(e.get("spec", "")), color="#bbbbbb", arrows="to")
    net.set_options('{"physics":{"solver":"forceAtlas2Based","stabilization":{"iterations":250}},'
                    '"interaction":{"hover":true,"navigationButtons":true}}')
    path.write_text(net.generate_html(notebook=False), encoding="utf-8")


def export_mermaid(H: nx.DiGraph, path: Path, max_nodes: int = 80) -> bool:
    if H.number_of_nodes() > max_nodes:
        return False
    ids = {n: f"n{i}" for i, n in enumerate(H.nodes)}
    lines = ["graph LR"]
    for n, a in H.nodes(data=True):
        label = _safe(a["label"]).replace('"', "'")
        lines.append(f'  {ids[n]}["{label}"]' + (":::vuln" if a.get("vulns") else ""))
    lines += [f"  {ids[u]} --> {ids[v]}" for u, v in H.edges]
    lines.append("  classDef vuln fill:#f8d7da,stroke:#d62728")
    path.write_text("\n".join(lines), encoding="utf-8")
    return True


def export_json(G: nx.DiGraph, path: Path):
    path.write_text(json.dumps({
        "nodes": [{"id": n, **a} for n, a in G.nodes(data=True)],
        "edges": [{"source": u, "target": v, **e} for u, v, e in G.edges(data=True)],
    }, indent=1, default=str), encoding="utf-8")


# ----------------------------------------------------------------------------- main
def build(repo: Path, sbom: Path | None = None, osv: bool = False) -> DepGraph:
    dg = DepGraph(repo.name)
    if sbom:
        scan_cyclonedx(dg, sbom)
    else:
        found = discover(repo, dg)
        if not found:
            dg.notes.append("no supported manifests found")
    if osv:
        osv_overlay(dg)
    compute_depth(dg)
    return dg


def main(argv=None):
    global OFFLINE
    ap = argparse.ArgumentParser(description="Build a dependency graph for a repository")
    ap.add_argument("repo", type=Path)
    ap.add_argument("--out", type=Path, default=Path("out"))
    ap.add_argument("--sbom", type=Path, help="build from a CycloneDX JSON SBOM instead of manifests")
    ap.add_argument("--osv", action="store_true", help="colour vulnerable packages (OSV.dev)")
    ap.add_argument("--offline", action="store_true", help="use .cache only")
    ap.add_argument("--why", nargs="*", default=[], help="explain why package(s) are present")
    ap.add_argument("--focus", help="html shows only this package's ancestors + descendants")
    ap.add_argument("--max-depth", type=int)
    args = ap.parse_args(argv)
    OFFLINE = args.offline
    repo = args.repo.resolve()
    args.out.mkdir(parents=True, exist_ok=True)

    dg = build(repo, args.sbom, args.osv)
    s = summarize(dg)
    H = view(dg, args.focus, args.max_depth)
    export_json(dg.G, args.out / "graph.json")
    export_html(H, args.out / "graph.html")
    has_mmd = export_mermaid(H, args.out / "graph.mmd")
    s["notes"] = dg.notes
    s["why"] = {q: why(dg, q) for q in args.why}
    (args.out / "summary.json").write_text(json.dumps(s, indent=2), encoding="utf-8")

    print(f"\n=== Dependency graph: {repo.name} ===")
    for k in ("apps", "packages", "edges", "by_ecosystem", "direct", "transitive", "max_depth",
              "depth_histogram", "by_scope", "resolution", "origins", "vulnerable_packages", "cycles"):
        print(f"{k:>18}: {s[k]}")
    for k in ("untrusted_origins", "install_scripts", "duplicates"):
        if s[k]:
            print(f"{k:>18}: {s[k]}")
    print("   top blast radius:", ", ".join(f"{x['package']}({x['dependents_transitive']})" for x in s["top_blast_radius"][:5]))
    print("  heaviest direct  :", ", ".join(f"{x['package']}(+{x['brings_in']})" for x in s["heaviest_direct_deps"][:5]))
    for vp in s["vulnerable_paths"][:8]:
        print(f"  VULN path (depth {vp['depth']}, {vp['advisories']} adv): {vp['path']}")
    for q, res in s["why"].items():
        for node, paths in res.items():
            print(f"  WHY {node}:")
            for p in paths:
                print("     " + " -> ".join(p))
    for n in dg.notes:
        print("  note:", n)
    print(f"\nwrote {args.out/'graph.json'}, {args.out/'graph.html'}, {args.out/'summary.json'}"
          + (f", {args.out/'graph.mmd'}" if has_mmd else ""))


if __name__ == "__main__":
    sys.exit(main())
