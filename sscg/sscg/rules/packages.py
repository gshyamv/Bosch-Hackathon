"""Package rules: R01 typosquat, R02 known malicious, R03/R04 install scripts, R09 unpinned dependencies."""
from __future__ import annotations

import base64
import json
import re
from pathlib import PurePosixPath

from rapidfuzz.distance import Levenshtein

from ..discover.pypi import read_requirements
from .common import Ctx, file_ev, line_of, load_json, load_lines, mk, read

POPULAR = {"npm": load_lines("popular_npm.txt"), "pypi": load_lines("popular_pypi.txt")}
LIFECYCLE = ("preinstall", "install", "postinstall", "prepare")
INDICATORS = [
    ("runs shell commands / child processes", r"child_process|\b(exec|execSync|spawn|spawnSync)\(|subprocess\.|os\.system\("),
    ("reads secrets from the environment", r"\b[A-Z0-9_]*(TOKEN|SECRET|PASSWORD|API_KEY|ACCESS_KEY)[A-Z0-9_]*\b"),
    ("hides data with base64", r"Buffer\.from\([^)]*['\"]base64['\"]|\batob\(|base64\s+-d|b64decode\("),
    ("executes dynamic code", r"\beval\(|new Function\("),
    ("network access", r"https?://|\b(curl|wget)\b|require\(['\"](https?|net|dns)['\"]\)|\bfetch\("),
    ("fingerprints the host / user", r"os\.hostname\(|os\.userInfo\(|\bwhoami\b"),
]
B64_LITERAL = re.compile(r"""Buffer\.from\(\s*['"]([A-Za-z0-9+/=]{8,})['"]\s*,\s*['"]base64['"]""")


def _norm(name: str) -> str:
    n = re.sub(r"^(python3?|py|node|js)[-_.]", "", name.lower())
    return re.sub(r"[-_.]", "", n)


def squat_target(name: str, popular: set) -> tuple[str | None, str | None]:
    if name in popular or name.startswith("@"):
        return None, None
    for p in sorted(popular):
        if _norm(name) == _norm(p):
            return p, "identical once separators and 'python-/node-' prefixes are removed"
    for p in sorted(popular):
        d = Levenshtein.distance(name.lower(), p)
        if (d == 1 and len(p) >= 5) or (d == 2 and len(p) >= 8):
            return p, f"{d} character edit{'s' if d > 1 else ''} away"
    return None, None


def _apps(G, n):
    return [p for p in G.predecessors(n) if G.nodes[p]["kind"] == "app"]


def _declared_at(ctx: Ctx, n: str) -> tuple[str | None, dict | None]:
    """file:line where a direct dependency is declared, with the evidence line."""
    G, a = ctx.dg.G, ctx.dg.G.nodes[n]
    for app in _apps(G, n):
        src = G.nodes[app]["source"]
        if a["ecosystem"] == "npm":
            text = read(ctx.repo, src)
            ln = line_of(text, f'"{a["name"]}"')
            return f"{src}:{ln}", file_ev(src, ln, text)
        if ":" in str(a.get("source", "")):
            path, _, ln = a["source"].rpartition(":")
            text = read(ctx.repo, path)
            return a["source"], file_ev(path, int(ln), text)
        return src, file_ev(src, 0, snippet=a["name"])
    return None, None


def typosquat(ctx: Ctx) -> list:
    out = []
    for n, a in ctx.dg.G.nodes(data=True):
        if a["kind"] != "package" or not a.get("direct") or a["ecosystem"] not in POPULAR:
            continue
        target, how = squat_target(a["name"], POPULAR[a["ecosystem"]])
        if target:
            loc, ev = _declared_at(ctx, n)
            out.append(mk("R01_TYPOSQUAT", f"'{a['name']}' looks like the popular package '{target}'", node=n,
                          location=loc, key=(a["ecosystem"], a["name"]),
                          confidence="high" if "identical" in how else "medium",
                          evidence=[ev, {"type": "reference", "source": f"popular_{a['ecosystem']}.txt",
                                         "detail": f"'{a['name']}' is {how} from '{target}'"}]))
    return out


def known_malicious(ctx: Ctx) -> list:
    seeds = load_json("known_malicious.json")["packages"]
    out = []
    for n, a in ctx.dg.G.nodes(data=True):
        if a["kind"] != "package":
            continue
        ev = []
        for s in seeds:
            if s["ecosystem"] == a["ecosystem"] and s["name"] == a["name"].lower() and \
                    (s["versions"] == "*" or a["version"] in s["versions"]):
                ev.append({"type": "reference", "source": "known_malicious.json", "detail": s["reference"]
                           + (f" (impersonates '{s['impersonates']}')" if s.get("impersonates") else "")})
        for adv in a.get("advisories", []):
            if adv["malicious"]:
                ev.append({"type": "advisory", "id": adv["id"], "url": adv["url"], "summary": adv["summary"]})
        if ev:
            loc = _declared_at(ctx, n)[0] if a.get("direct") else a.get("source")
            out.append(mk("R02_KNOWN_MALICIOUS", f"{a['label']} is a documented malicious package", node=n,
                          location=loc, evidence=ev, key=(a["ecosystem"], a["name"]), classification="verified_fact"))
    return out


def _script_files(cmd: str, manifest_dir: str) -> list[str]:
    files = re.findall(r"[\w./\\-]+\.(?:js|mjs|cjs|ts|sh|py)\b", cmd)
    return [str(PurePosixPath(manifest_dir) / f.replace("\\", "/")) if manifest_dir else f.replace("\\", "/")
            for f in files]


def install_scripts(ctx: Ctx) -> list:
    out, G = [], ctx.dg.G
    for n, a in G.nodes(data=True):
        if a["kind"] == "app" and a["ecosystem"] == "npm" and a["source"].endswith("package.json"):
            text = read(ctx.repo, a["source"])
            try:
                scripts = (json.loads(text or "{}").get("scripts") or {})
            except ValueError:
                continue
            parent = str(PurePosixPath(a["source"]).parent)
            mdir = "" if parent == "." else parent
            for hook in LIFECYCLE:
                cmd = scripts.get(hook)
                if not isinstance(cmd, str):
                    continue
                ln = line_of(text, f'"{hook}"')
                out.append(mk("R03_INSTALL_SCRIPT", f"{a['label']} runs a '{hook}' script on every install: {cmd}",
                              location=f"{a['source']}:{ln}", evidence=[file_ev(a["source"], ln, text)],
                              key=(a["source"], hook, cmd), classification="verified_fact"))
                out += _script_content(ctx, a, hook, cmd, mdir)
        elif a["kind"] == "package" and a.get("install_script"):
            out.append(mk("R03_INSTALL_SCRIPT", f"{a['label']} runs an install script (code not inspected)",
                          level="Low", node=n, location=a.get("source"), key=(a["ecosystem"], a["name"]),
                          classification="verified_fact",
                          evidence=[{"type": "fact", "detail": f"lockfile marks {a['label']} with hasInstallScript: true"}]))
    return out


def _script_content(ctx: Ctx, app: dict, hook: str, cmd: str, mdir: str) -> list:
    out = []
    for rel in _script_files(cmd, mdir):
        text = read(ctx.repo, rel)
        if text is None:
            continue
        ev, hits = [], []
        for label, rx in INDICATORS:
            for i, line in enumerate(text.splitlines(), 1):
                if re.search(rx, line) and not line.strip().startswith("//"):
                    hits.append(label)
                    ev.append(dict(file_ev(rel, i, text), indicator=label))
                    break
        for m in B64_LITERAL.finditer(text):
            try:
                decoded = base64.b64decode(m.group(1)).decode("utf-8")
                if decoded.isprintable():
                    ev.append({"type": "fact", "detail": f"base64 string in {rel} decodes to: {decoded}"})
            except (ValueError, UnicodeDecodeError):
                pass
        if hits:
            out.append(mk("R04_INSTALL_SCRIPT_CONTENT",
                          f"'{hook}' script {rel} {', '.join(hits)}",
                          level="Critical" if len(hits) >= 2 else "High", location=f"{rel}:{ev[0]['line']}",
                          evidence=ev, key=(rel,), classification="verified_fact"))
    return out


def unpinned(ctx: Ctx) -> list:
    out, G = [], ctx.dg.G
    for n, a in G.nodes(data=True):
        if a["kind"] != "app":
            continue
        src = a["source"]
        if a["ecosystem"] == "pypi" and src.endswith(".txt"):
            text = read(ctx.repo, src)
            for name, op, ver, ln in read_requirements(ctx.repo / src):
                if op not in ("==", "==="):
                    out.append(mk("R09_UNPINNED_DEPENDENCY",
                                  f"'{name}' has no exact version in {src} ({(op or '') + ver or 'any version'})",
                                  location=f"{src}:{ln}", evidence=[file_ev(src, ln, text)], key=(src, name),
                                  classification="verified_fact"))
        elif a["ecosystem"] == "npm" and src.endswith("package.json"):
            text = read(ctx.repo, src)
            try:
                m = json.loads(text or "{}")
            except ValueError:
                continue
            folder = (ctx.repo / src).parent
            locked = any((folder / f).exists() for f in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock"))
            specs = {k: v for f in ("dependencies", "devDependencies", "optionalDependencies")
                     for k, v in (m.get(f) or {}).items()}
            for name, spec in specs.items():
                if not isinstance(spec, str):
                    continue
                if spec.strip() in ("", "*", "x", "latest") or spec.startswith(("git", "http", "github:")):
                    ln = line_of(text, f'"{name}"')
                    out.append(mk("R09_UNPINNED_DEPENDENCY", f"'{name}' is requested as '{spec}' in {src}",
                                  location=f"{src}:{ln}", evidence=[file_ev(src, ln, text)], key=(src, name),
                                  classification="verified_fact"))
            ranged = [k for k, v in specs.items() if isinstance(v, str) and re.match(r"^[\^~><]|.*\s-\s|.*\|\|", v)]
            if not locked and ranged:
                out.append(mk("R09_UNPINNED_DEPENDENCY",
                              f"{src} has no lockfile: {len(ranged)} dependencies use version ranges",
                              level="Medium", location=src, key=(src, "no-lockfile"), classification="verified_fact",
                              evidence=[{"type": "fact", "detail": f"no package-lock.json / yarn.lock next to {src}; "
                                         f"ranged: {', '.join(ranged[:15])}{' ...' if len(ranged) > 15 else ''}"}]))
    return out
