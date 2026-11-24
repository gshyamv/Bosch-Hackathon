"""Remediate stage, "Recommend safe remediation": deterministic planner + small, verifiable file edits.

1. Edits  - each change is an operation on one file (set a version, remove a dependency, add an npm override,
            restore a lockfile entry, pin an action to a SHA, replace a base image, comment a line ...).
            apply_edit() is a pure text -> text function, so every proposal has an exact unified diff and the
            Validation agent applies exactly what the human approved.
2. Planner- groups findings per component / file (one fix resolves all findings on that package), picks the action
            (upgrade / replace / pin / remove / block / update_base_image / mitigate / escalate_review), the target
            version (registry.safe_version: fewest remaining OSV advisories, smallest change), and states expected
            risk reduction, compatibility impact (semver jump, removal of imported code) and rollback.

Generic for any repository: npm (package.json + lockfile), PyPI (requirements*.txt), Maven (pom.xml),
Dockerfile / Containerfile, GitHub Actions workflows. Anything that cannot be patched safely becomes an
"escalate_review" proposal with concrete reviewer guidance instead of a guessed edit.
"""
from __future__ import annotations

import difflib
import json
import re
from pathlib import Path, PurePosixPath

from . import gitutil, registry
from functools import cmp_to_key

from .versions import compare, sort_versions

NPM_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
VALIDATION_PLAN = ["copy the repository to a sandbox", "apply the approved edits", "regenerate lockfiles",
                   "install / build (install scripts disabled)", "run the project's tests if it has any",
                   "docker build if Docker is running", "rescan with the detection pipeline",
                   "compare SBOM and findings before / after, flag anything new"]
TYPO_RE = re.compile(r"looks like the popular package '([^']+)'")
IMPERSONATES_RE = re.compile(r"impersonates '([^']+)'")


# ------------------------------------------------------------------------------------------------ edits
def _norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _json_dump(data: dict, original: str) -> str:
    m = re.search(r"\n( +)\"", original)
    return json.dumps(data, indent=len(m.group(1)) if m else 2, ensure_ascii=False) + ("\n" if original.endswith("\n") else "")


def _keep_style(old: str, version: str) -> str:
    m = re.match(r"^\s*(\^|~|>=|=)?", old or "")
    return f"{m.group(1) or ''}{version}" if m and m.group(1) in ("^", "~") else version


def _line_index(lines: list[str], match: str) -> int:
    m = match.strip()
    for i, line in enumerate(lines):
        if line.strip() == m:
            return i
    for i, line in enumerate(lines):
        if m and m in line:
            return i
    raise ValueError(f"line not found: {match!r}")


def apply_edit(text: str, e: dict) -> str:
    op = e["op"]
    if op.startswith("npm_"):
        if op == "npm_relock":
            return text
        data = json.loads(text)
        if op == "npm_set":
            hit = False
            for sec in NPM_SECTIONS:
                if e["name"] in data.get(sec, {}):
                    data[sec][e["name"]] = e["version"] if e.get("exact") else _keep_style(data[sec][e["name"]], e["version"])
                    hit = True
            if not hit:
                raise ValueError(f"{e['name']} is not a dependency in {e['file']}")
        elif op == "npm_remove":
            for sec in NPM_SECTIONS:
                data.get(sec, {}).pop(e["name"], None)
        elif op == "npm_add":
            data.setdefault(e.get("section", "dependencies"), {})[e["name"]] = e["version"]
        elif op == "npm_override":
            data.setdefault("overrides", {})[e["name"]] = e["version"]
        elif op == "npm_remove_script":
            data.get("scripts", {}).pop(e["script"], None)
        else:
            raise ValueError(op)
        return _json_dump(data, text)
    if op == "lock_restore":
        data = json.loads(text)
        entry = (data.get("packages") or {}).get(e["key"]) or (data.get("dependencies") or {}).get(e["name"])
        if entry is None:
            raise ValueError(f"lockfile entry {e['key']} not found")
        entry.update(e["fields"])
        return _json_dump(data, text)
    lines = text.splitlines(keepends=True)
    if op == "req_replace":      # same position in the file: old distribution -> new==version
        want, out, done = _norm_py(e["old"]), [], False
        for line in lines:
            m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", line)
            if m and not done and _norm_py(m.group(1)) == want:
                out.append(f"{e['name']}=={e['version']}\n")
                done = True
            else:
                out.append(line)
        if not done:
            raise ValueError(f"{e['old']} not found in {e['file']}")
        return "".join(out)
    if op in ("req_set", "req_remove"):
        want = _norm_py(e["name"])
        out, done = [], False
        for line in lines:
            m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*([<>=!~].*)?$", line.split("#")[0].rstrip("\r\n"))
            if m and _norm_py(m.group(1)) == want:
                done = True
                if op == "req_set":
                    out.append(f"{m.group(1)}{m.group(2) or ''}=={e['version']}\n")
                continue            # req_remove: drop the line
            out.append(line)
        if op == "req_set" and not done:
            if out and not out[-1].endswith("\n"):
                out[-1] += "\n"
            out.append(f"{e['name']}=={e['version']}  # pinned by SSCG: transitive dependency with known advisories\n")
        return "".join(out)
    if op == "pom_set":
        dep = re.compile(r"(<dependency>\s*(?:(?!</dependency>).)*?<groupId>\s*" + re.escape(e["group"]) +
                         r"\s*</groupId>\s*(?:(?!</dependency>).)*?<artifactId>\s*" + re.escape(e["artifact"]) +
                         r"\s*</artifactId>(?:(?!</dependency>).)*?</dependency>)", re.S)
        m = dep.search(text)
        if not m:
            raise ValueError(f"{e['group']}:{e['artifact']} not found in {e['file']}")
        block = m.group(1)
        vm = re.search(r"<version>\s*([^<]+?)\s*</version>", block)
        if not vm:
            raise ValueError("version managed elsewhere (parent / BOM)")
        if vm.group(1).startswith("${"):
            prop = vm.group(1)[2:-1]
            new, n = re.subn(rf"(<{re.escape(prop)}>)[^<]*(</{re.escape(prop)}>)", rf"\g<1>{e['version']}\g<2>", text, 1)
            if not n:
                raise ValueError(f"property {prop} not found")
            return new
        return text[:m.start()] + block.replace(vm.group(0), f"<version>{e['version']}</version>", 1) + text[m.end():]
    if op == "replace_line":
        i = _line_index(lines, e["match"])
        indent = re.match(r"^\s*", lines[i]).group(0)
        lines[i] = indent + e["new"].lstrip() + ("\n" if lines[i].endswith("\n") else "")
        return "".join(lines)
    if op == "comment_line":
        i = _line_index(lines, e["match"])
        indent = re.match(r"^\s*", lines[i]).group(0)
        lines[i] = f"{indent}# {e['note']}\n{indent}# {lines[i].strip()}" + ("\n" if lines[i].endswith("\n") else "")
        return "".join(lines)
    if op == "insert_before":
        i = _line_index(lines, e["match"])
        lines.insert(i, e["line"] + "\n")
        return "".join(lines)
    raise ValueError(f"unknown edit op {op}")


def apply_edits(root: Path, edits: list[dict]) -> dict:
    """Apply edits to files under root. Returns {"changed": [files], "relock": [package.json files]}."""
    changed, relock = [], []
    for e in edits:
        if e["op"] == "npm_relock":
            relock.append(e["file"])
            continue
        p = root / e["file"]
        text = p.read_text(encoding="utf-8")
        new = apply_edit(text, e)
        if new != text:
            p.write_text(new, encoding="utf-8", newline="")
            if e["file"] not in changed:
                changed.append(e["file"])
    return {"changed": changed, "relock": sorted(set(relock))}


def diff_for(root: Path, edits: list[dict]) -> str:
    """Unified diff of the edits against the files in root (lockfile regeneration is noted, not shown)."""
    files, out = {}, []
    for e in edits:
        if e["op"] == "npm_relock":
            continue
        if e["file"] not in files:
            files[e["file"]] = (root / e["file"]).read_text(encoding="utf-8")
        files[e["file"]] = apply_edit(files[e["file"]], e)
    for f, new in files.items():
        old = (root / f).read_text(encoding="utf-8")
        out += difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True), f"a/{f}", f"b/{f}")
    if any(e["op"] == "npm_relock" for e in edits):
        out.append("# + package-lock.json regenerated from the registry during validation (npm --package-lock-only)\n")
    return "".join(out)


# ------------------------------------------------------------------------------------------------ planner
ECO_CMD = {"rubygems": "bundle update {name} --conservative", "cargo": "cargo update -p {name} --precise {to}",
           "go": "go get {name}@v{to}", "nuget": "dotnet add package {name} --version {to}"}


def _file_of(loc: str | None) -> str | None:
    if not loc or loc.startswith("commit"):
        return None
    return re.sub(r":\d+$", "", loc)


def _manifest(dg, comp: dict) -> str | None:
    """Manifest file that declares this package (npm: package.json next to the lockfile)."""
    if not comp or dg is None or comp["id"] not in dg.G:
        return None
    src = _file_of(dg.G.nodes[comp["id"]].get("source"))
    if not src:
        return None
    if comp["ecosystem"] == "npm":
        return str(PurePosixPath(src).parent / "package.json") if PurePosixPath(src).name != "package.json" else src
    return src


def _npm_declared(manifest: Path, name: str) -> str | None:
    """The spec of `name` if package.json declares it directly (any dependency section)."""
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return next((data[s][name] for s in NPM_SECTIONS if name in (data.get(s) or {})), None)


def _npm_bundled(lockfile: Path, name: str) -> list[str]:
    """Parents that BUNDLE a copy of `name` (bundleDependencies): npm overrides cannot change those copies."""
    try:
        data = json.loads(lockfile.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out = []
    for key, meta in (data.get("packages") or {}).items():
        if key.endswith(f"node_modules/{name}") and meta.get("inBundle"):
            parent = key[:-len(f"/node_modules/{name}")].rsplit("node_modules/", 1)[-1]
            if parent and parent not in out:
                out.append(parent)
    return out


def _snippet(f: dict) -> str | None:
    return next((e.get("snippet") for e in f.get("evidence", []) if e.get("type") == "file" and e.get("snippet")), None)


def _bump(old: str | None, new: str | None) -> str:
    if not old or not new:
        return "unknown"
    o, n = [re.findall(r"\d+", x)[:3] + ["0"] * 3 for x in (old, new)]
    if o[0] != n[0]:
        return "major"
    return "minor" if o[1] != n[1] else "patch"


def _lock_entry(repo: Path, target, change: dict | None, lock: str, name: str) -> tuple[str, dict] | None:
    """Last known-good lockfile fields of `name` from the base commit."""
    sha = ((change or {}).get("base") or {}).get("sha")
    if not sha:
        return None
    if target is not None and target.kind == "github":
        base = target.base_dir(sha, repo)
        text = (base / lock).read_text(encoding="utf-8") if base and (base / lock).is_file() else None
    else:
        text = gitutil.git(repo, "show", f"{sha}:{lock}")
    try:
        data = json.loads(text or "")
    except ValueError:
        return None
    for key, meta in (data.get("packages") or {}).items():
        if key.endswith(f"node_modules/{name}"):
            return key, {k: meta[k] for k in ("version", "resolved", "integrity") if k in meta}
    meta = (data.get("dependencies") or {}).get(name)
    return (name, {k: meta[k] for k in ("version", "resolved", "integrity") if k in meta}) if meta else None


class Planner:
    def __init__(self, repo: Path, dg, findings: list, priorities: list, reach: dict, change: dict | None, kb,
                 triage: dict | None = None, target=None):
        self.target = target
        self.repo, self.dg, self.change, self.kb = repo, dg, change, kb
        self.by_id = {f["finding_id"]: f for f in findings}
        self.prio = {p["finding_id"]: p for p in priorities}
        self.reach = (reach or {}).get("per_node", {})
        self.triage = triage or {}

    # -- grouping
    def key(self, f: dict):
        c = f.get("component") or {}
        if c.get("ecosystem") in ("npm", "pypi", "maven", "rubygems", "cargo", "go", "nuget"):
            return ("pkg", c["ecosystem"], c["name"])      # all versions of a package: one coherent fix
        if c.get("ecosystem") == "docker":
            return ("image", _file_of(f.get("location")) or c["id"])
        if f["rule"] in ("R03_INSTALL_SCRIPT", "R04_INSTALL_SCRIPT_CONTENT"):
            return ("app-script", self._script_manifest(f))
        if f["rule"] == "R18_NEW_AUTHOR_SENSITIVE_CHANGE":
            return ("review", f["finding_id"])
        return ("file-rule", f["rule"], _file_of(f.get("location")), f["finding_id"])

    def _script_manifest(self, f: dict) -> str | None:
        loc = _file_of(f.get("location"))
        if loc and loc.endswith("package.json"):
            return loc
        script = loc or ""
        for p in self.repo.rglob("package.json"):
            if "node_modules" in p.parts:
                continue
            try:
                scripts = json.loads(p.read_text(encoding="utf-8")).get("scripts", {})
            except (ValueError, OSError):
                continue
            if any(PurePosixPath(script).name in str(v) for v in scripts.values()):
                return p.relative_to(self.repo).as_posix()
        return None

    def plan(self, levels=("P0", "P1"), max_proposals: int = 20) -> list[dict]:
        groups: dict = {}
        for f in self.by_id.values():
            groups.setdefault(self.key(f), []).append(f)
        rank = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}

        def best(fs):
            ps = [self.prio.get(f["finding_id"], {}) for f in fs]
            return min((rank.get(p.get("priority"), 9), -int(p.get("urgent", False)), -p.get("score", 0)) for p in ps)

        chosen = [(k, fs) for k, fs in groups.items()
                  if any(self.prio.get(f["finding_id"], {}).get("priority") in levels for f in fs)]
        from .agents.pqueue import PriorityQueue
        props = []
        for k, fs in PriorityQueue(chosen, key=lambda kf: best(kf[1])).take(max_proposals):
            p = self.propose(k, sorted(fs, key=lambda f: f["finding_id"]))
            pri = [self.prio.get(f["finding_id"], {}) for f in fs]
            top = min(pri, key=lambda x: (rank.get(x.get("priority"), 9), -x.get("score", 0)))
            p.update(proposal_id=f"P-{len(props) + 1:03d}", finding_ids=[f["finding_id"] for f in fs],
                     priority=top.get("priority"), urgent=any(x.get("urgent") for x in pri),
                     validation_plan=VALIDATION_PLAN if p["edits"] else [],
                     status="proposed" if p["edits"] else "manual", patchable=bool(p["edits"]))
            try:
                p["diff"] = diff_for(self.repo, p["edits"]) if p["edits"] else ""
            except (ValueError, OSError) as e:      # an edit that does not apply cleanly is never proposed blind
                p.update(diff="", notes=p.get("notes", []) + [f"edit could not be prepared: {e}"], edits=[],
                         status="manual", patchable=False, action="escalate_review")
            props.append(p)
        return props

    # -- per group
    def propose(self, k, fs: list) -> dict:
        rules = {f["rule"] for f in fs}
        base = {"edits": [], "notes": [], "files_affected": [], "residual_advisories": [], "component": None,
                "from_version": None, "to_version": None, "compatibility_level": "low"}
        if k[0] == "pkg":
            return {**base, **self._package(k, fs, rules)}
        if k[0] == "image":
            return {**base, **self._image(fs)}
        if k[0] == "app-script":
            return {**base, **self._app_script(k[1], fs)}
        if k[0] == "review":
            return {**base, **self._review(fs)}
        return {**base, **self._file_rule(fs[0])}

    def _package(self, k, fs, rules) -> dict:
        _, eco, name = k
        comps = {f["component"]["id"]: f["component"] for f in fs}          # all installed versions of `name`
        directs = [c for c in comps.values() if c.get("direct")]
        comp = directs[0] if directs else max(comps.values(), key=cmp_to_key(lambda a, b: compare(a["version"], b["version"])))
        version = comp["version"]
        now = sort_versions({c["version"] for c in comps.values()})
        man = _manifest(self.dg, comp)
        direct, transitive = bool(directs), any(not c.get("direct") for c in comps.values())
        r = self.reach.get(comp["id"], {})
        out = {"component": f"{name}@{', '.join(now)}" if len(now) > 1 else comp["label"],
               "from_version": ", ".join(now), "files_affected": [man] if man else []}
        vulns = [f for f in fs if f["category"] == "vulnerability"]
        vuln = vulns[0] if vulns else None
        target = None
        for f in fs:
            m = TYPO_RE.search(f["title"]) or next((IMPERSONATES_RE.search(e.get("detail", "")) for e in f["evidence"]
                                                    if IMPERSONATES_RE.search(e.get("detail", ""))), None)
            if m:
                target = m.group(1)
        malicious = "R02_KNOWN_MALICIOUS" in rules or any(
            self.triage.get(f["finding_id"], {}).get("verdict") == "likely_malicious" for f in fs
            if f["rule"] == "R01_TYPOSQUAT")
        if not man:
            return {**out, "action": "escalate_review", "rationale": f"{comp['label']}: the declaring manifest could not be "
                    "located, so no automatic edit is proposed.", "notes": ["manual change needed"]}

        if eco in ECO_CMD:      # no verified patch writer for these ecosystems: exact guidance, human edit
            fx = [x for f in vulns if (x := (f.get("fixes") or {}).get("upgrade_to_at_least"))]
            to = sort_versions(fx)[-1] if fx else None
            return {**out, "action": "escalate_review", "to_version": to,
                    "rationale": f"{comp['label']} in {man}: " + (f"upgrade to at least {to} (OSV fixed version)"
                                 if to else "no fixed version published, or not a vulnerability; review it") + ".",
                    "notes": [ECO_CMD[eco].format(name=name, to=to)] if to else []}

        # 1. malicious / typosquatted package: remove it, add the package that was probably intended
        if malicious or "R01_TYPOSQUAT" in rules:
            if eco not in ("npm", "pypi"):
                return {**out, "action": "block", "rationale": f"Remove {comp['label']} from {man} (manual for {eco})."}
            to = registry.safe_version(eco, target, None, None).get("version") if target else None
            if eco == "npm":
                edits = [{"file": man, "op": "npm_remove", "name": name}]
                if to:
                    edits.append({"file": man, "op": "npm_add", "name": target, "version": f"^{to}",
                                  "section": "devDependencies" if comp.get("scope") == "dev" else "dependencies"})
            else:   # PyPI: replace the line in place
                edits = [{"file": man, "op": "req_replace", "old": name, "name": target, "version": to}] if to else \
                    [{"file": man, "op": "req_remove", "name": name}]
            if eco == "npm":
                edits.append({"file": man, "op": "npm_relock"})
            imported = r.get("status") in ("imported", "referenced")
            return {**out, "edits": edits, "action": "replace" if to else "remove",
                    "to_version": f"{target}@{to}" if to else None,
                    "rationale": f"{comp['label']} is " + ("a documented malicious package" if "R02_KNOWN_MALICIOUS" in rules
                                                          else "a likely typosquat") +
                                 (f" of '{target}'; replace it with {target}@{to}" if to else "; remove it") + ".",
                    "compatibility_level": "high" if imported else "low",
                    "compatibility_impact": (f"code imports {name} ({', '.join(r.get('evidence', []))}): update it to "
                                             f"use {target or 'an alternative'}" if imported else
                                             f"{name} is not imported by application code"),
                    "rollback": "do NOT roll back to the removed package; revert only if the replacement breaks the build",
                    "expected_risk_reduction": f"removes the malicious / typosquatted package and its install-time "
                                               f"code; resolves {len(fs)} finding(s)"}

        # 2. known vulnerabilities: upgrade (direct) / override or pin (transitive)
        if vuln:
            fixes = [(f.get("fixes") or {}).get("upgrade_to_at_least") for f in vulns]
            fix = sort_versions([x for x in fixes if x])[-1] if any(fixes) else None
            sv = registry.safe_version(eco, name, now[-1], fix)
            to = sv.get("version")
            n_adv = len({e["id"] for f in vulns for e in f["evidence"] if e.get("type") == "advisory"})
            if not to:
                return {**out, "action": "escalate_review", "notes": [sv.get("note", "")],
                        "rationale": f"No safe version of {name} could be determined ({sv.get('note')}): mitigate "
                                     f"in code or replace the library."}
            edits, how = [], ""
            if eco == "npm":
                # npm refuses an override of a DIRECT dependency unless it matches the direct spec (EOVERRIDE), so a
                # package declared in package.json is overridden with "$name": transitive copies follow the direct one
                spec = _npm_declared(self.repo / man, name)
                bundled = _npm_bundled(self.repo / PurePosixPath(man).parent / "package-lock.json", name)
                if bundled:
                    out.setdefault("notes", []).append(
                        f"some copies of {name} are bundled inside {', '.join(bundled[:3])} (bundleDependencies): "
                        f"npm overrides cannot change them; upgrade {bundled[0]} (or the package that pulls it in)")
                if direct:
                    edits.append({"file": man, "op": "npm_set", "name": name, "version": to, "exact": True})
                if transitive:
                    edits.append({"file": man, "op": "npm_override", "name": name,
                                  "version": f"${name}" if spec else to})
                    if spec and not direct:      # the direct copy is not vulnerable: copies move to its version
                        to = re.sub(r"^[\^~>=<\s]+", "", spec)
                        sv = {**sv, "remaining": registry.remaining_advisories(eco, name, [to]).get(to, [])}
                edits.append({"file": man, "op": "npm_relock"})
                how = " and ".join(x for x in ("upgrade" if direct else "",
                                                ("make the transitive copies use the direct dependency's version"
                                                 if spec else "override the transitive copies") if transitive else "")
                                   if x)
            elif eco == "pypi":
                edits = [{"file": man, "op": "req_set", "name": name, "version": to}]
                how = "pin" if direct else "add an explicit pin for the transitive dependency"
            elif eco == "maven":
                if direct:
                    edits = [{"file": man, "op": "pom_set", "group": name.split(":")[0],
                              "artifact": name.split(":")[1], "version": to}]
                    how = "upgrade"
                else:
                    return {**out, "action": "escalate_review", "to_version": to,
                            "rationale": f"{comp['label']} is transitive: add {name}:{to} to <dependencyManagement> "
                                         f"or upgrade the parent that pulls it in."}
            if now and all(v == to for v in now):     # no-op: the "fix" is the version already used
                return {**out, "action": "escalate_review", "to_version": None,
                        "rationale": f"{comp['label']}: no published release fixes its advisories yet "
                                     f"({n_adv} on {to}); replace the package or accept the risk until one exists."}
            bumps = [_bump(v, to) for v in now]
            bump = next((b for b in ("major", "minor", "patch") if b in bumps), "unknown")
            version = ", ".join(now)
            rem = sv.get("remaining") or []
            lock_rules = rules & {"R05_LOCKFILE_UNTRUSTED_SOURCE", "R06_LOCKFILE_INTEGRITY_CHANGED", "R07_LOCKFILE_DRIFT"}
            return {**out, "edits": edits, "action": "upgrade", "to_version": to, "residual_advisories": rem,
                    "rationale": f"{how.capitalize()} {name} {version} -> {to}: fixes the {n_adv} published advisories "
                                 f"on {version}" + (f"; {len(rem)} advisory(ies) remain on {to} (no cleaner release)" if rem else
                                                    "; no known advisories remain on the target") +
                                 (". Regenerating the lockfile from the official registry also undoes the lockfile "
                                  "tampering" if lock_rules else "") + ".",
                    "compatibility_level": {"major": "high", "minor": "medium"}.get(bump, "low"),
                    "compatibility_impact": f"{bump} version change ({version} -> {to})" +
                                            (": breaking API changes are possible, run the tests" if bump == "major" else ""),
                    "rollback": f"restore {name} {version} in {man} (and the lockfile) by reverting the remediation commit",
                    "expected_risk_reduction": f"{n_adv - len(rem)} of {n_adv} advisories fixed; resolves "
                                               f"{len(fs)} finding(s)"}

        # 3. tampered lockfile entry without a CVE: restore the last known-good entry (or regenerate)
        if rules & {"R05_LOCKFILE_UNTRUSTED_SOURCE", "R06_LOCKFILE_INTEGRITY_CHANGED", "R07_LOCKFILE_DRIFT",
                    "R19_SUSPICIOUS_UPDATE"} and eco == "npm":
            lock = str(PurePosixPath(man).parent / "package-lock.json")
            good = _lock_entry(self.repo, self.target, self.change, lock, name)
            if good:
                edits = [{"file": lock, "op": "lock_restore", "key": good[0], "name": name, "fields": good[1]}]
                why = f"restore the base commit's lockfile entry ({good[1].get('resolved', '')})"
            else:
                edits = [{"file": man, "op": "npm_relock"}]
                why = "regenerate the lockfile from the official registry"
            return {**out, "edits": edits, "action": "pin", "to_version": version, "files_affected": [lock],
                    "rationale": f"{comp['label']}: {why}, so the verified tarball is installed again.",
                    "compatibility_impact": "same version, verified source: no code change",
                    "rollback": "none needed (same version)", "expected_risk_reduction": f"resolves {len(fs)} finding(s)"}

        # 4. unpinned dependency: pin to the newest release with the fewest advisories
        if "R09_UNPINNED_DEPENDENCY" in rules and eco == "pypi":
            sv = registry.safe_version(eco, name, None, None)
            if sv.get("version"):
                return {**out, "action": "pin", "to_version": sv["version"],
                        "edits": [{"file": man, "op": "req_set", "name": name, "version": sv["version"]}],
                        "rationale": f"Pin {name}=={sv['version']} so a future (possibly compromised) release is not "
                                     f"installed silently.", "compatibility_impact": "pins the version pip installs today",
                        "rollback": "remove the pin", "expected_risk_reduction": f"resolves {len(fs)} finding(s)"}

        # 5. everything else on a package (unexpected dependency, third-party install script ...): human review
        return {**out, "action": "escalate_review",
                "rationale": f"{comp['label']}: " + "; ".join(sorted({f['type'] for f in fs})) +
                             ". Confirm the dependency is needed and expected; remove it otherwise.",
                "notes": [o["when"] for o in (self.kb.playbook(fs[0]["rule"]).get("remediation_options") or [])][:2]}

    def _image(self, fs) -> dict:
        f = next((x for x in fs if x["rule"] in ("R10_UNTRUSTED_BASE_IMAGE", "R11_MUTABLE_IMAGE_TAG")), fs[0])
        comp, file, snip = f["component"], _file_of(f.get("location")), _snippet(f)
        node = self.dg.G.nodes.get(comp["id"], {}) if self.dg is not None else {}
        repo_name = node.get("repository") or comp["name"].split("/", 1)[-1]
        off = registry.official_image(repo_name, comp.get("version"))
        if not (off and file and snip and snip.upper().startswith("FROM")):
            return {"action": "escalate_review", "component": comp["label"],
                    "rationale": f"Replace {comp['label']} with an official or verified image pinned by digest."}
        rest = snip.split(None, 2)[2] if len(snip.split(None, 2)) > 2 else ""
        new = f"FROM {off['image']}:{off['tag']}@{off['digest']}" if off["digest"] else f"FROM {off['image']}:{off['tag']}"
        return {"action": "update_base_image", "component": comp["label"], "from_version": comp.get("version"),
                "to_version": off["ref"], "files_affected": [file],
                "edits": [{"file": file, "op": "replace_line", "match": snip, "new": f"{new} {rest}".strip()}],
                "rationale": f"Use the official Docker Hub image {off['image']}:{off['tag']}, pinned by digest, instead "
                             f"of {comp['label']} (unverified publisher, mutable tag).",
                "compatibility_level": "medium",
                "compatibility_impact": "the runtime base image changes: check the language runtime version and OS packages",
                "rollback": f"restore 'FROM {comp['label']}' (not recommended)",
                "expected_risk_reduction": f"resolves {len(fs)} finding(s); the image can no longer change silently"}

    def _app_script(self, man, fs) -> dict:
        hook = None
        for f in fs:
            m = re.search(r"'(preinstall|install|postinstall|prepare)'", f["title"])
            if m:
                hook = m.group(1)
        if not (man and hook):
            return {"action": "escalate_review", "rationale": "Review the application's install script manually."}
        return {"action": "block", "component": f"{man} scripts.{hook}", "files_affected": [man],
                "edits": [{"file": man, "op": "npm_remove_script", "script": hook}],
                "rationale": f"Remove the '{hook}' hook from {man}: it runs code that reads secrets on every install "
                             f"(including CI). Review and delete the script file it calls.",
                "compatibility_level": "medium",
                "compatibility_impact": f"anything the '{hook}' step legitimately prepared must now be done explicitly",
                "rollback": f"restore scripts.{hook} in {man} after a security review",
                "expected_risk_reduction": f"stops install-time code execution; resolves {len(fs)} finding(s)"}

    def _review(self, fs) -> dict:
        f = fs[0]
        return {"action": "escalate_review", "rationale": f"{f['title']}. Require a second reviewer for build and "
                "dependency files from this author; the other proposals address the concrete changes.",
                "notes": ["process change, nothing to patch"]}

    def _file_rule(self, f) -> dict:
        rule, file, snip = f["rule"], _file_of(f.get("location")), _snippet(f)
        common = {"files_affected": [file] if file else []}
        if rule == "R12_REMOTE_SCRIPT_EXEC" and file and snip:
            return {**common, "action": "block", "component": file,
                    "edits": [{"file": file, "op": "comment_line", "match": snip,
                               "note": "SSCG: disabled unverified remote script. Download it, verify a pinned checksum "
                                       "or signature, then run it."}],
                    "rationale": f"Disable the download-and-execute step in {file}: its content can change at any time "
                                 f"and is not verified.",
                    "compatibility_level": "medium", "compatibility_impact": "whatever the script set up is no longer done",
                    "rollback": "re-enable only with a checksum check", "expected_risk_reduction": "resolves 1 finding"}
        if rule == "R15_CI_UNPINNED_ACTION" and file and snip:
            m = re.search(r"uses:\s*([\w.-]+/[\w./-]+)@([\w./-]+)", snip)
            sha = registry.action_sha(m.group(1), m.group(2)) if m else None
            if sha:
                return {**common, "action": "pin", "component": f"{m.group(1)}@{m.group(2)}", "to_version": sha,
                        "edits": [{"file": file, "op": "replace_line", "match": snip,
                                   "new": snip.replace(f"@{m.group(2)}", f"@{sha} # {m.group(2)}")}],
                        "rationale": f"Pin {m.group(1)} to commit {sha[:12]} (was the mutable ref '{m.group(2)}').",
                        "compatibility_impact": "same code as today, it just can no longer change",
                        "rollback": f"use @{m.group(2)} again", "expected_risk_reduction": "resolves 1 finding"}
            return {**common, "action": "block", "component": m.group(1) if m else file,
                    "rationale": f"The action {m.group(1) if m else ''} could not be resolved on GitHub (missing or "
                                 f"private): remove this step from {file} or replace it with a trusted action.",
                    "notes": ["removing a workflow step needs a human: later steps may depend on it"]}
        if rule == "R16_CI_EXCESSIVE_PERMISSIONS" and file and snip and "write-all" in snip:
            return {**common, "action": "mitigate", "component": file,
                    "edits": [{"file": file, "op": "replace_line", "match": snip, "new": snip.replace("write-all", "read-all")}],
                    "rationale": f"Reduce the workflow token in {file} from write-all to read-all; grant write "
                                 f"permissions per job only where needed.",
                    "compatibility_level": "medium", "compatibility_impact": "jobs that push, release or comment need an "
                                                                            "explicit per-job permission",
                    "rollback": "restore 'permissions: write-all'", "expected_risk_reduction": "resolves 1 finding"}
        if rule == "R13_CONTAINER_HARDENING" and file and snip and re.match(r"RUN\s+npm\s+install\b", snip):
            lock = (self.repo / PurePosixPath(file).parent / "package-lock.json").exists()
            new = "RUN npm ci --ignore-scripts" if lock else "RUN npm install --ignore-scripts"
            return {**common, "action": "mitigate", "component": file,
                    "edits": [{"file": file, "op": "replace_line", "match": snip, "new": new}],
                    "rationale": f"Install dependencies in {file} with install scripts disabled"
                                 + (" and exactly from the lockfile (npm ci)" if lock else "") + ".",
                    "compatibility_level": "medium", "compatibility_impact": "packages that need a native build step "
                                                                            "must be rebuilt explicitly (npm rebuild <pkg>)",
                    "rollback": f"restore '{snip}'", "expected_risk_reduction": "resolves 1 finding"}
        if rule == "R09_UNPINNED_DEPENDENCY" and file and file.endswith("package.json"):
            return {**common, "action": "pin", "component": file, "edits": [{"file": file, "op": "npm_relock"}],
                    "files_affected": [str(PurePosixPath(file).parent / "package-lock.json")],
                    "rationale": f"Create and commit a lockfile for {file} so every install resolves the same, "
                                 f"verified versions.", "compatibility_impact": "none: records today's resolution",
                    "rollback": "delete the lockfile", "expected_risk_reduction": "resolves 1 finding"}
        guidance = {"R14_CI_PWN_REQUEST": "Do not check out the pull request's code in a pull_request_target workflow; "
                                          "use the pull_request trigger, or split into an unprivileged build and a "
                                          "privileged workflow_run.",
                    "R17_CI_SECRET_EXPOSURE": "Stop passing the secret to downloaded / mutable code (see the related "
                                              "proposals) and rotate the secret: it may already be exposed.",
                    "R13_CONTAINER_HARDENING": "Run the container as a non-root USER and avoid install scripts in the build."}
        return {**common, "action": "escalate_review", "component": file,
                "rationale": guidance.get(rule, f"{f['title']}: review and fix manually."),
                "notes": [o["when"] for o in (self.kb.playbook(rule).get("remediation_options") or [])][:2]}
