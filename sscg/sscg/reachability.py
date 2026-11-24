"""Day 2 column 1 (and stretch goal 1): is a vulnerable package actually used by the application's code?

Static, import-level analysis for any repository (nothing is executed):
  npm   : require('x') / import ... from 'x' / import('x') in .js .mjs .cjs .jsx .ts .tsx .vue
  PyPI  : import x / from x import ... in .py   (distribution -> module name mapping, e.g. PyYAML -> yaml)
  Maven : import a.b.c in .java .kt .scala     (groupId / artifactId -> package prefix heuristics)

Status per package node of the dependency graph:
  imported      a direct dependency imported by application (non-test) code         -> reachable
  referenced    not imported, but its name is a string in application code (view engines, plugins
                loaded by name, e.g. app.set('view engine', 'ejs'))                  -> potentially reachable
  tests_only    imported only from test code                                         -> lower exposure
  transitive    not imported itself, but pulled in by an imported dependency         -> potentially reachable
  not_imported  declared (or pulled in) but no application code imports it or a parent -> unlikely reachable
  unknown       ecosystem not analysable here (containers, CI actions, URLs) or no source files found

Function-level reachability (is the vulnerable *function* called?) is not attempted: import level is the
honest, explainable granularity for a hackathon. Evidence (file:line) is kept for every "imported" verdict.
"""
from __future__ import annotations

import collections
import os
import re
from pathlib import Path

import networkx as nx

SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", "vendor", "bower_components", ".venv", "venv",
             "env", "__pycache__", "target", ".next", ".nuxt", "out", ".tox", "site-packages", ".cache"}
TEST_DIR = re.compile(r"(^|/)(tests?|__tests__|spec|specs|cypress|e2e|testing|fixtures?)(/|$)", re.I)
TEST_FILE = re.compile(r"(\.(spec|test)\.[jt]sx?$|(^|/)test_[^/]*\.py$|_test\.py$|Test\.java$|Tests?\.kt$)", re.I)
MAX_FILES, MAX_BYTES = 20000, 2_000_000

LANG = {"npm": (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue"), "pypi": (".py",),
        "maven": (".java", ".kt", ".scala")}
JS_RE = re.compile(r"""(?:require\s*\(\s*|import\s*\(\s*|\bfrom\s+|^\s*import\s+)['"]([^'"\s]+)['"]""", re.M)
PY_RE = re.compile(r"^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import\b|import\s+([A-Za-z_][\w.]*(?:\s*,\s*[A-Za-z_][\w.]*)*))",
                   re.M)
JAVA_RE = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)", re.M)
STR_RE = re.compile(r"""['"]([@a-zA-Z0-9][\w.@/-]{0,80})['"]""")   # string literals (packages loaded by name)

# distribution name -> import name(s), for the common cases where they differ
PY_MODULES = {"pyyaml": ["yaml"], "python-dateutil": ["dateutil"], "beautifulsoup4": ["bs4"], "pillow": ["PIL"],
              "scikit-learn": ["sklearn"], "opencv-python": ["cv2"], "opencv-python-headless": ["cv2"],
              "protobuf": ["google.protobuf"], "attrs": ["attr", "attrs"], "pyjwt": ["jwt"],
              "psycopg2-binary": ["psycopg2"], "python-jose": ["jose"], "pycryptodome": ["Crypto"],
              "pycrypto": ["Crypto"], "pyopenssl": ["OpenSSL"], "dnspython": ["dns"], "pyserial": ["serial"],
              "pyzmq": ["zmq"], "websocket-client": ["websocket"], "python-multipart": ["multipart"],
              "djangorestframework": ["rest_framework"], "typing-extensions": ["typing_extensions"],
              "setuptools": ["setuptools", "pkg_resources"], "msgpack-python": ["msgpack"],
              "google-cloud-storage": ["google.cloud.storage"], "python-magic": ["magic"], "pymongo": ["pymongo", "bson"]}

NODE_BUILTINS = {"fs", "path", "http", "https", "os", "url", "util", "crypto", "stream", "events", "child_process",
                 "net", "tls", "zlib", "buffer", "querystring", "readline", "assert", "dns", "cluster", "vm"}
SERVICE_PATTERNS = [
    (re.compile(r"\bcreateServer\s*\(|\bexpress\s*\(\s*\)|\.listen\s*\(\s*(?:process\.env\.PORT|\d{2,5})"), "Node HTTP server"),
    (re.compile(r"\bFlask\s*\(|\bFastAPI\s*\(|\buvicorn\.run\s*\(|\bdjango\b"), "Python web framework"),
    (re.compile(r"@SpringBootApplication|@RestController|@Controller\b"), "Java web controller"),
]
EXPOSE_RE = re.compile(r"^\s*EXPOSE\s+(\S+)", re.M | re.I)


def _files(repo: Path):
    n = 0
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for name in files:
            p = Path(root) / name
            if n >= MAX_FILES:
                return
            n += 1
            yield p


def _npm_name(spec: str) -> str | None:
    if spec.startswith((".", "/", "node:")) or "://" in spec:
        return None
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") and len(parts) > 1 else parts[0]


def scan_imports(repo: Path) -> dict:
    """{ecosystem: {imported_name: [(rel_path, line, is_test)]}} plus exposure signals."""
    found = {eco: collections.defaultdict(list) for eco in LANG}
    strings = {eco: collections.defaultdict(list) for eco in ("npm", "pypi")}
    service, expose = [], []
    counts = collections.Counter()
    for p in _files(repo):
        rel = p.relative_to(repo).as_posix()
        if p.name.lower().startswith(("dockerfile", "containerfile")):
            try:
                expose += [f"{rel}: EXPOSE {m}" for m in EXPOSE_RE.findall(p.read_text(encoding="utf-8", errors="replace"))]
            except OSError:
                pass
            continue
        eco = next((e for e, exts in LANG.items() if p.suffix.lower() in exts), None)
        if not eco or p.name.endswith(".min.js"):
            continue
        try:
            if p.stat().st_size > MAX_BYTES:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        counts[eco] += 1
        is_test = bool(TEST_DIR.search(rel) or TEST_FILE.search(rel))
        line_of = lambda pos: text.count("\n", 0, pos) + 1  # noqa: E731
        if eco == "npm":
            for m in JS_RE.finditer(text):
                name = _npm_name(m.group(1))
                if name and name not in NODE_BUILTINS:
                    found[eco][name].append((rel, line_of(m.start()), is_test))
        if eco in strings and not is_test:
            for m in STR_RE.finditer(text):
                if len(strings[eco][m.group(1)]) < 3:
                    strings[eco][m.group(1)].append((rel, line_of(m.start()), False))
        if eco == "pypi":
            for m in PY_RE.finditer(text):
                mods = [m.group(1)] if m.group(1) else [x.strip() for x in m.group(2).split(",")]
                for mod in mods:
                    found[eco][mod].append((rel, line_of(m.start()), is_test))
        else:
            for m in JAVA_RE.finditer(text):
                found[eco][m.group(1)].append((rel, line_of(m.start()), is_test))
        if not is_test and len(service) < 3:
            for pat, label in SERVICE_PATTERNS:
                m = pat.search(text)
                if m:
                    service.append(f"{rel}:{line_of(m.start())} ({label})")
                    break
    return {"imports": found, "strings": strings, "source_files": dict(counts), "service": service,
            "expose": expose}


def _py_match(dist: str, imports: dict) -> list:
    names = PY_MODULES.get(dist.lower(), [re.sub(r"[-.]", "_", dist.lower())])
    hits = []
    for mod, locs in imports.items():
        for n in names:
            if mod == n or mod.startswith(n + ".") or mod.lower() == n.lower():
                hits += locs
    return hits


def _java_match(name: str, imports: dict) -> list:
    group, _, artifact = name.partition(":")
    token = artifact.split("-")[-1].rstrip("0123456789") or artifact
    parent = group.rsplit(".", 1)[0]
    prefixes = {f"{group}.{token}.", f"{parent}.{token}."}
    if group.count(".") >= 3:          # specific group ids (org.apache.logging.log4j) identify the library
        prefixes.add(group + ".")
    return [loc for imp, locs in imports.items() for loc in locs if any((imp + ".").startswith(p) for p in prefixes)]


def analyze(repo: Path, dg) -> dict:
    """Reachability status for every package node: {node_id: {status, evidence, reason}} + summary."""
    scan = scan_imports(repo)
    G = dg.G
    status = {}
    imported_direct = set()
    for n, a in G.nodes(data=True):
        if a.get("kind") != "package":
            continue
        eco = a.get("ecosystem")
        if eco not in LANG:
            status[n] = {"status": "unknown", "reason": f"{eco} components are not code imports"}
            continue
        if not scan["source_files"].get(eco):
            status[n] = {"status": "unknown", "reason": f"no {eco} source files found in the repository"}
            continue
        imports = scan["imports"][eco]
        locs = (imports.get(a["name"], []) if eco == "npm" else
                _py_match(a["name"], imports) if eco == "pypi" else _java_match(a["name"], imports))
        if locs:
            prod = [x for x in locs if not x[2]]
            ev = [f"{p}:{ln}" for p, ln, _ in (prod or locs)[:3]]
            if prod:
                status[n] = {"status": "imported", "evidence": ev, "reason": f"imported in {len(prod)} place(s)"}
                imported_direct.add(n)
            else:
                status[n] = {"status": "tests_only", "evidence": ev, "reason": "imported only from test code"}
        else:
            status[n] = None   # decided below: transitive of an imported package, or not imported
    reachable_via = {}
    for n in imported_direct:
        for d in nx.descendants(G, n):
            reachable_via.setdefault(d, G.nodes[n].get("label", n))
    for n, s in list(status.items()):
        if s is not None:
            continue
        eco, name = G.nodes[n].get("ecosystem"), G.nodes[n].get("name")
        ref = scan["strings"].get(eco, {}).get(name) if G.nodes[n].get("direct") else None
        if ref:
            status[n] = {"status": "referenced", "evidence": [f"{p}:{ln}" for p, ln, _ in ref[:3]],
                         "reason": f"not imported, but '{name}' is named in application code (loaded by name?)"}
            for d in nx.descendants(G, n):
                reachable_via.setdefault(d, G.nodes[n].get("label", n))
        elif n in reachable_via:
            status[n] = {"status": "transitive", "reason": f"pulled in by imported {reachable_via[n]}"}
        else:
            direct = G.nodes[n].get("direct")
            status[n] = {"status": "not_imported",
                         "reason": "declared but never imported by application code" if direct else
                         "only pulled in by dependencies that the code does not import"}
    exposure = {"network_service": bool(scan["service"] or scan["expose"]),
                "evidence": (scan["service"] + scan["expose"])[:5]}
    summary = collections.Counter(s["status"] for s in status.values())
    return {"per_node": status, "exposure": exposure, "source_files": scan["source_files"], "summary": dict(summary)}
