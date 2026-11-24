"""Validate stage, "Validate the proposed fix: test before you trust". Generic for any repository.

  1. sandbox   local folders are copied into a container volume; GitHub targets are cloned inside the container
  2. apply     only the human-approved edits (remediation.apply_edits); regenerate npm lockfiles
  3. build     npm ci --ignore-scripts / pip (wheels only) / mvn, on a network that only reaches package registries
  4. test      the project's own tests, with no network
  5. rescan    the detection pipeline on the patched files -> findings + SBOM after the change
  6. compare   resolved / remaining / NEW findings, SBOM component changes, before-vs-after build results

Repository code runs only in containers (sandbox.py). Without Docker: relock + rescan only, verdict at most partial.
"""
from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from . import remediation
from . import sandbox
from .pipeline import build, detect
from .target import as_target

IGNORE_DIRS = {"node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next", "target", ".git"}
COPY_IGNORE = shutil.ignore_patterns("node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next",
                                     "target", ".sscg-venv*", ".pytest_cache", ".tox", "coverage", ".cache")
NPM_FLAGS = ["--ignore-scripts", "--no-audit", "--no-fund", "--fetch-retries=1", "--fetch-retry-mintimeout=2000",
             "--fetch-retry-maxtimeout=5000"]
DEFAULT_TIMEOUT = int(os.getenv("SSCG_VALIDATE_TIMEOUT", "600") or 600)
NPM_NO_TEST = "no test specified"


def _tail(text: str, n: int = 25) -> str:
    from .agents.guard import redact   # same redaction as everything that leaves the tool
    lines = [l for l in (text or "").splitlines() if l.strip()]
    return redact("\n".join(lines[-n:]))[0][-4000:]


def projects(root: Path) -> list[dict]:
    """Buildable projects in the repository (any depth, skipping installed / vendored folders)."""
    out = []
    for p in sorted(root.rglob("*")):
        if any(x in p.parts for x in ("node_modules", ".git", ".venv", "venv", "vendor", "dist", "build", "target")):
            continue
        rel_dir = p.parent
        if p.name == "package.json":
            try:
                scripts = json.loads(p.read_text(encoding="utf-8")).get("scripts", {}) or {}
            except (ValueError, OSError):
                continue
            test = scripts.get("test")
            out.append({"eco": "npm", "dir": rel_dir, "lock": (rel_dir / "package-lock.json").exists(),
                        "test": test if test and NPM_NO_TEST not in test else None})
        elif re.fullmatch(r"requirements[\w.-]*\.txt", p.name) and "dev" not in p.name and "test" not in p.name:
            out.append({"eco": "pypi", "dir": rel_dir, "req": p.name,
                        "pytest": any(rel_dir.glob("test_*.py")) or (rel_dir / "tests").is_dir()})
        elif p.name == "pom.xml":
            out.append({"eco": "maven", "dir": rel_dir})
        elif p.name in ("Dockerfile", "Containerfile"):
            out.append({"eco": "docker", "dir": rel_dir, "file": p.name})
    return out


def _skip(name: str, why: str) -> dict:
    return {"step": name, "cmd": "", "cwd": ".", "status": "skipped", "exit": None, "seconds": 0.0, "log": why}


def safe_to_relock(manifest: Path) -> str | None:
    """Why this package.json must not be resolved on the host (git / file / URL specs), or None.
    npm: aliases are refused too, simply because the allow-list below is strict."""
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
        lock = manifest.parent / "package-lock.json"
        locked = json.loads(lock.read_text(encoding="utf-8")) if lock.exists() else {}
    except (OSError, ValueError) as e:
        return f"unreadable manifest: {e}"
    if data.get("workspaces"):
        return "workspaces need the full repository"

    def specs(x):
        if isinstance(x, dict):
            for v in x.values():
                yield from specs(v)
        else:
            yield x
    for sec in (*remediation.NPM_SECTIONS, "overrides"):
        for s in specs(data.get(sec) or {}):
            if not isinstance(s, str) or not re.fullmatch(r"[\w.^~<>=|*+ $@/-]*", s) or "/" in s.lstrip("$@").split("/", 1)[-1] \
                    or ("/" in s and not s.startswith("$@")):
                return f"non-registry dependency spec {s!r}"
    for m in (locked.get("packages") or locked.get("dependencies") or {}).values():
        r = m.get("resolved") if isinstance(m, dict) else None
        if r and not str(r).startswith(("https://registry.npmjs.org/", "https://registry.yarnpkg.com/")):
            return f"lockfile entry from {str(r)[:60]!r}"
    return None


def host_relock(manifest: Path, label: str) -> dict:
    """No Docker: resolve the lockfile only. npm sees just package.json + lockfile in an empty folder: no .npmrc, no
    scripts, no git, no host environment. Nothing of the repository is installed or executed."""
    name = f"{label}: regenerate lockfile, host, no install ({manifest.parent.name})"
    npm, why = shutil.which("npm"), safe_to_relock(manifest)
    if why or not npm:
        return _skip(name, why or "npm is not installed")
    with tempfile.TemporaryDirectory(prefix="sscg-relock-") as tmp:
        d, t = Path(tmp) / "p", time.perf_counter()
        d.mkdir()
        for f in ("package.json", "package-lock.json"):
            if (manifest.parent / f).exists():
                shutil.copyfile(manifest.parent / f, d / f)
        rc = Path(tmp) / "rc"
        rc.write_text("")
        rc2 = Path(tmp) / "rc2"
        rc2.write_text("")
        env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "PATHEXT", "COMSPEC") if k in os.environ}
        env |= {"HOME": tmp, "USERPROFILE": tmp, "APPDATA": tmp, "LOCALAPPDATA": tmp, "TEMP": tmp, "TMP": tmp,
                "npm_config_userconfig": str(rc), "npm_config_globalconfig": str(rc2), "npm_config_git": "sscg-disabled"}
        try:
            r = subprocess.run([npm, "install", "--package-lock-only", *NPM_FLAGS], cwd=d, env=env, capture_output=True,
                               text=True, encoding="utf-8", errors="replace", timeout=300, stdin=subprocess.DEVNULL)
            ok, log = r.returncode == 0, _tail(r.stdout + r.stderr)
            code = r.returncode
        except subprocess.TimeoutExpired:
            ok, log, code = False, "timeout", None
        if ok:
            shutil.copyfile(d / "package-lock.json", manifest.parent / "package-lock.json")
        return {"step": name, "cmd": "npm install --package-lock-only --ignore-scripts", "cwd": ".",
                "status": "ok" if ok else "failed", "exit": code, "seconds": round(time.perf_counter() - t, 1), "log": log}


def build_and_test(sb, root: Path, label: str, relock: list[str] = ()) -> list[dict]:
    """Relock, install (registry-only network), build and test (no network) every project, inside the sandbox."""
    steps = []

    def step(name, image, cmd, rel, net=False):
        r = sb.run(image, cmd, f"{label}/{rel}", net=net, timeout=DEFAULT_TIMEOUT)
        rec = {"step": f"{label}: {name} ({rel})", "cmd": " ".join(cmd), "cwd": rel, **r, "log": _tail(r["log"])}
        steps.append(rec)
        return rec["status"] == "ok"

    for e in sorted(set(relock)):
        rel = Path(e).parent.as_posix()
        if step("regenerate lockfile", "npm", ["npm", "install", "--package-lock-only", *NPM_FLAGS], rel, True):
            text = sb.read(f"{label}/{rel}/package-lock.json")     # data only: needed by the rescan on the host
            if text:
                (root / rel / "package-lock.json").write_text(text, encoding="utf-8", newline="")
    for pr in projects(root):
        d, rel = pr["dir"], pr["dir"].relative_to(root).as_posix() or "."
        if pr["eco"] == "npm":
            lock = (d / "package-lock.json").exists()
            if step(f"npm {'ci' if lock else 'install'}", "npm", ["npm", "ci" if lock else "install", *NPM_FLAGS], rel, True) \
                    and pr["test"]:
                step("npm test", "npm", ["npm", "test", "--silent"], rel)
        elif pr["eco"] == "pypi":
            py = ".sscg-venv/bin/python"
            if step("create venv", "pypi", ["python", "-m", "venv", ".sscg-venv"], rel) and step(
                    f"pip install -r {pr['req']}", "pypi", [py, "-m", "pip", "install", "--only-binary=:all:", "-q", "-r",
                                                            pr["req"]], rel, True):
                step("pytest" if pr["pytest"] else "compile check", "pypi", [py, "-m", "pytest", "-q"] if pr["pytest"]
                     else [py, "-m", "compileall", "-q", "-x", r"\.sscg-venv", "."], rel)
        elif pr["eco"] == "maven":
            repo = "-Dmaven.repo.local=/work/.m2"
            if step("mvn resolve + compile", "maven", ["mvn", "-B", "-q", repo, "dependency:go-offline", "test-compile"], rel, True):
                step("mvn test", "maven", ["mvn", "-B", "-q", "-o", repo, "test"], rel)
        elif pr["eco"] == "docker":
            steps.append(_skip(f"{label}: docker build ({rel}/{pr['file']})",
                               "not built: RUN steps would get unrestricted network; the image is rescanned statically"))
    return steps


def fkey(f: dict) -> tuple:
    """Stable identity of a finding across two scans (finding IDs are renumbered per scan)."""
    c = f.get("component") or {}
    snip = next((e.get("snippet", "") for e in f.get("evidence", []) if e.get("type") == "file"), "")
    return (f["rule"], c.get("id") or re.sub(r":\d+$", "", f.get("location") or ""), "" if c else snip)


def _components(dg) -> dict:
    out = {}
    for _, a in dg.G.nodes(data=True):
        if a.get("kind") == "package":
            out.setdefault((a["ecosystem"], a["name"]), set()).add(a.get("version") or "")
    return out


def sbom_diff(before, after) -> dict:
    b, a = _components(before), _components(after)
    return {"added": sorted(f"{e}:{n}@{'/'.join(sorted(a[(e, n)]))}" for e, n in a.keys() - b.keys()),
            "removed": sorted(f"{e}:{n}@{'/'.join(sorted(b[(e, n)]))}" for e, n in b.keys() - a.keys()),
            "changed": sorted(f"{e}:{n} {'/'.join(sorted(b[(e, n)]))} -> {'/'.join(sorted(a[(e, n)]))}"
                              for e, n in a.keys() & b.keys() if a[(e, n)] != b[(e, n)])}


def patch_text(orig: Path, sandbox: Path, files: list[str]) -> str:
    out = []
    for f in sorted(set(files)):
        a, b = orig / f, sandbox / f
        old = a.read_text(encoding="utf-8").splitlines(keepends=True) if a.exists() else []
        new = b.read_text(encoding="utf-8").splitlines(keepends=True) if b.exists() else []
        out += difflib.unified_diff(old, new, f"a/{f}", f"b/{f}")
    return "".join(out)


def _sub(target, label: str) -> str:
    sub = getattr(target, "sub", None)
    return f"{label}-full/{sub}" if sub else label


def _load(sb, target, repo: Path, label: str) -> None:
    """GitHub targets are cloned inside the container; local folders are copied in as data."""
    ck = target.checkout_url()
    if not ck:
        sb.put(repo, label, IGNORE_DIRS)
    elif target.sub:
        sb.checkout(*ck, f"{label}-full")
        sb.run("npm", ["ln", "-s", f"/work/{label}-full/{target.sub}", f"/work/{label}"], ".")
    else:
        sb.checkout(*ck, label)


def _only(root: Path, files: list[str], dest: Path) -> Path:
    for f in files:
        (dest / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / f, dest / f)
    dest.mkdir(parents=True, exist_ok=True)
    return dest


def validate(target, before_findings: list, before_dg, proposals: list, base_rev: str | None,
             workdir: Path | None = None, baseline: bool = True, log=print) -> dict:
    """Validate the approved, patchable proposals together (one remediation change set)."""
    target = as_target(target)
    repo = target.head_dir()
    approved = [p for p in proposals if p.get("status") == "approved" and p.get("patchable")]
    if not approved:
        return {"verdict": "not_run", "reason": "no approved proposal with a patch"}
    tmp = Path(workdir or tempfile.mkdtemp(prefix="sscg-validate-"))
    tmp.mkdir(parents=True, exist_ok=True)
    after_dir = tmp / "after"
    shutil.copytree(repo, after_dir, ignore=lambda d, n: COPY_IGNORE(d, n) | {x for x in n if (Path(d) / x).is_symlink()}, dirs_exist_ok=True)
    edits = [e for p in approved for e in p["edits"]]
    applied = remediation.apply_edits(after_dir, edits)
    log(f"applied {len(edits)} edit(s) from {len(approved)} approved proposal(s) to {after_dir}")
    use_docker = sandbox.available()
    steps_before, steps_after = [], []
    if use_docker:
        try:
            with sandbox.Sandbox(trace_dir=Path(workdir) if workdir else tmp) as sb:
                log("sandbox: containers (non-root, no host mounts; registry-only network for installs, none for tests)")
                if baseline:
                    _load(sb, target, repo, "before")
                    log("building the unchanged repository (baseline) ...")
                    steps_before = build_and_test(sb, repo, "before")
                _load(sb, target, repo, "after")
                sb.put(_only(after_dir, applied["changed"], tmp / "edits"), _sub(target, "after"))
                log("building the remediated repository ...")
                steps_after = build_and_test(sb, after_dir, "after", relock=applied["relock"])
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
            use_docker = False
            steps_after.append(_skip("after: sandbox", f"sandbox error: {str(e)[:300]}"))
            log(f"sandbox error, build/test skipped: {e}")
    else:
        log("Docker is not available: lockfile + rescan only, nothing is installed, built or tested on the host")
        steps_after = [host_relock(after_dir / e, "after") for e in sorted(set(applied["relock"]))]
        steps_after.append(_skip("after: build and test", "Docker is not running; repository code never runs on the host"))
    log("rescanning the remediated repository ...")
    dg_after = build(after_dir, None, check_vulns=True)
    fs_after, _ = detect(after_dir, dg_after, base_rev if target.kind == "local" else None)
    before_k = {fkey(f): f for f in before_findings}
    after_k = {fkey(f): f for f in fs_after}
    resolved = [before_k[k]["finding_id"] for k in before_k.keys() - after_k.keys()]
    remaining = [before_k[k]["finding_id"] for k in before_k.keys() & after_k.keys()]
    vuln_before = {(f["component"]["ecosystem"], f["component"]["name"]) for f in before_findings
                   if f["category"] == "vulnerability" and f.get("component")}
    targets = {re.split(r"@", str(p.get("to_version") or ""))[0] for p in approved if p["action"] == "replace"}
    new = []
    for k in after_k.keys() - before_k.keys():
        f = after_k[k]
        c = f.get("component") or {}
        sev = (f.get("severity") or {}).get("label") if f["category"] == "vulnerability" else f["risk"]["level"].upper()
        if f["category"] == "vulnerability" and (c.get("ecosystem"), c.get("name")) in vuln_before:
            kind = "still_vulnerable"        # same package, different version, advisories remain
        elif c.get("name") in targets or any(c.get("name") and c["name"] == str(p.get("component", "")).split("@")[0]
                                             for p in approved):
            kind = "expected"                # e.g. the replacement package is a new direct dependency
        else:
            kind = "introduced"
        new.append({"title": f["title"], "type": f["type"], "level": f["risk"]["level"], "severity": sev,
                    "rule": f["rule"], "kind": kind, "component": c.get("label")})
    changed_files = applied["changed"] + [str(Path(e).parent / "package-lock.json").replace("\\", "/")
                                          for e in applied["relock"]]
    per_prop = {}
    for p in approved:
        got = [f for f in p["finding_ids"] if f in resolved]
        per_prop[p["proposal_id"]] = {"targeted": p["finding_ids"], "resolved": got,
                                      "status": "resolved" if len(got) == len(p["finding_ids"]) else
                                      "partially_resolved" if got else "not_resolved"}
    names = {}
    for p in approved:                      # package names per proposal, to attribute a broken step to a proposal
        for txt in (p.get("component"), p.get("to_version")):
            m = re.match(r"(@?[^@,\s]+)@", str(txt or ""))
            if m and len(m.group(1)) > 2:
                names.setdefault(p["proposal_id"], set()).add(m.group(1))
    trace = {}
    tf = (Path(workdir) if workdir else tmp) / "sandbox_trace.json"
    if tf.is_file():
        trace = json.loads(tf.read_text(encoding="utf-8"))
        ev = tf.with_name("docker_events.log")
        trace["events"] = ev.read_text(encoding="utf-8").splitlines()[-200:] if ev.is_file() else []
    return {"workdir": str(tmp), "docker": use_docker, "sandbox_trace": trace, "applied_files": changed_files,
            "proposal_packages": {k: sorted(v) for k, v in names.items()},
            "steps_before": steps_before, "steps_after": steps_after,
            "findings_before": len(before_findings), "findings_after": len(fs_after),
            "resolved": sorted(resolved), "remaining": sorted(remaining), "new": new,
            "per_proposal": per_prop, "sbom_diff": sbom_diff(before_dg, dg_after) if before_dg is not None else {},
            "patch": patch_text(repo, after_dir, changed_files),
            "after_findings": [{k: v for k, v in f.items() if not k.startswith("_")} for f in fs_after]}


def verdict(res: dict) -> tuple[str, str, list[str]]:
    """(verdict, confidence, reasons) from the before/after comparison."""
    if res.get("verdict") == "not_run":
        return "not_run", "low", [res.get("reason", "")]
    reasons = []
    before = {s["step"].split(": ", 1)[1]: s["status"] for s in res["steps_before"]}
    regress = [s for s in res["steps_after"] if s["status"] in ("failed", "timeout")
               and before.get(s["step"].split(": ", 1)[1]) == "ok"]
    after_fail = [s for s in res["steps_after"] if s["status"] in ("failed", "timeout")]
    ran_ok = [s for s in res["steps_after"] if s["status"] == "ok"]
    tests_ok = [s for s in ran_ok if re.search(r"npm test|pytest|mvn test", s["step"])]
    new_bad = [n for n in res["new"] if n.get("kind", "introduced") == "introduced"
               and str(n.get("severity") or n["level"]).upper() in ("CRITICAL", "HIGH")]
    still = [n for n in res["new"] if n.get("kind") == "still_vulnerable"]
    targeted = [f for v in res["per_proposal"].values() for f in v["targeted"]]
    unresolved = [f for v in res["per_proposal"].values() for f in v["targeted"] if f not in v["resolved"]]
    if regress:
        reasons.append("the fix broke a step that worked before: " + ", ".join(s["step"] for s in regress))
        logs = " ".join(s.get("log", "") for s in regress)
        culprits = [f"{pid} ({', '.join(n for n in pkgs if re.search(rf'(?<![\w-]){re.escape(n)}(?![\w-])', logs))})"
                    for pid, pkgs in (res.get("proposal_packages") or {}).items()
                    if any(re.search(rf"(?<![\w-]){re.escape(n)}(?![\w-])", logs) for n in pkgs)]
        if culprits:
            reasons.append("likely caused by " + ", ".join(culprits[:4]) + ": approve again without "
                           + ("it" if len(culprits) == 1 else "them") + " to keep the other fixes")
    if new_bad:
        reasons.append(f"{len(new_bad)} new Critical/High finding(s) introduced: "
                       + "; ".join(n["title"][:80] for n in new_bad[:3]))
    if still:
        reasons.append(f"{len(still)} package(s) moved to a version that still has advisories: "
                       + ", ".join(n["component"] or n["title"][:40] for n in still[:4]))
    if unresolved:
        reasons.append(f"{len(unresolved)}/{len(targeted)} targeted finding(s) still present: {', '.join(unresolved[:6])}")
    if after_fail and not regress:
        failing = ", ".join(s["step"] for s in after_fail)
        reasons.append(("some steps fail before and after the fix (not caused by it): " if res["steps_before"] else
                        "some steps fail after the fix (baseline skipped: cannot tell whether they failed before): ")
                       + failing)
    improved = res.get("findings_after", 0) < res.get("findings_before", 0) and len(res.get("resolved", [])) > len(new_bad)
    if new_bad and improved:
        reasons.append(f"overall {res['findings_before']} -> {res['findings_after']} findings ({len(res['resolved'])} resolved): "
                       "net improvement; run the next iteration to fix the newly introduced ones")
    if regress or (new_bad and not improved) or len(unresolved) == len(targeted):
        v = "failed"
    elif unresolved or after_fail or new_bad:
        v = "partially_verified"
    else:
        v = "verified"
    conf = "high" if tests_ok and not after_fail else "medium" if ran_ok and not after_fail else "low"
    if not res.get("docker", True):
        if v == "verified":
            v = "partially_verified"
        conf = "low"
        reasons.append("partial: no container sandbox, so nothing was installed, built or tested")
    if not ran_ok:
        reasons.append("nothing could be built in the sandbox: verification relies on the rescan only")
    if v == "verified":
        reasons.insert(0, f"all {len(targeted)} targeted finding(s) resolved, no new Critical/High findings, "
                          f"{len(ran_ok)} build/test step(s) passed")
    return v, conf, reasons
