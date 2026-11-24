"""Day 2 column 4, "Validate the proposed fix: test before you trust". Generic for any repository.

  1. sandbox   copy the repository (with .git, without installed dependencies) to a temporary folder
  2. apply     only the human-approved edits (remediation.apply_edits); regenerate npm lockfiles
  3. build     per detected project: npm ci/install --ignore-scripts, pip install (wheels only) in a venv,
               mvn (if installed), docker build (if the Docker engine is running)
  4. test      the project's own tests when it has them (npm test / pytest / mvn test), else a smoke check
  5. rescan    the Day 1 pipeline on the sandbox -> findings + SBOM after the change
  6. compare   resolved / remaining / NEW findings, SBOM component changes, before-vs-after build results

The unchanged repository is built the same way as a baseline, so a failure that already existed is not blamed on
the fix. Builds run with a scrubbed environment (no API keys, tokens or secrets) and with install scripts
disabled; the application's own tests do run its code, so prefer Docker isolation for untrusted repositories.
"""
from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from . import remediation
from .pipeline import build, detect

COPY_IGNORE = shutil.ignore_patterns("node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next",
                                     "target", ".sscg-venv*", ".pytest_cache", ".tox", "coverage", ".cache")
SECRET_ENV = re.compile(r"(KEY|TOKEN|SECRET|PASSW|CREDENTIAL|AUTH|COOKIE|SESSION)", re.I)
NPM_FLAGS = ["--ignore-scripts", "--no-audit", "--no-fund", "--fetch-retries=1", "--fetch-retry-mintimeout=2000",
             "--fetch-retry-maxtimeout=5000"]
DEFAULT_TIMEOUT = int(os.getenv("SSCG_VALIDATE_TIMEOUT", "600") or 600)
NPM_NO_TEST = "no test specified"


def scrubbed_env() -> dict:
    """Environment for building untrusted code: no API keys / tokens / secrets (our .env keys included)."""
    env = {k: v for k, v in os.environ.items() if not SECRET_ENV.search(k)}
    env.update(CI="true", NO_UPDATE_NOTIFIER="1", npm_config_update_notifier="false", PIP_DISABLE_PIP_VERSION_CHECK="1",
               PYTHONDONTWRITEBYTECODE="1")
    return env


def _tail(text: str, n: int = 25) -> str:
    from .agents.guard import redact   # same redaction as everything that leaves the tool
    lines = [l for l in (text or "").splitlines() if l.strip()]
    return redact("\n".join(lines[-n:]))[0][-4000:]


def run_step(name: str, cmd: list, cwd: Path, root: Path, timeout: int = DEFAULT_TIMEOUT) -> dict:
    exe = shutil.which(cmd[0])
    rec = {"step": name, "cmd": " ".join(cmd), "cwd": cwd.relative_to(root).as_posix() or ".", "status": "skipped",
           "exit": None, "seconds": 0.0, "log": ""}
    if not exe:
        rec["log"] = f"{cmd[0]} is not installed"
        return rec
    t = time.perf_counter()
    try:
        r = subprocess.run([exe, *cmd[1:]], cwd=cwd, env=scrubbed_env(), capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout, stdin=subprocess.DEVNULL)
        rec.update(status="ok" if r.returncode == 0 else "failed", exit=r.returncode,
                   log=_tail((r.stdout or "") + "\n" + (r.stderr or "")))
    except subprocess.TimeoutExpired:
        rec.update(status="timeout", log=f"stopped after {timeout}s")
    rec["seconds"] = round(time.perf_counter() - t, 1)
    return rec


def docker_running() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        r = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"], capture_output=True,
                           text=True, timeout=20)
        return r.returncode == 0 and bool(r.stdout.strip())   # `docker info` exits 0 even when the engine is down
    except (subprocess.TimeoutExpired, OSError):
        return False


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


def build_and_test(root: Path, label: str, relock: list[str] = (), docker: bool = False) -> list[dict]:
    """Build + test every project under root. relock: package.json files whose lockfile must be regenerated."""
    steps = []
    for e in sorted(set(relock)):
        d = root / Path(e).parent
        steps.append(run_step(f"{label}: regenerate lockfile ({Path(e).parent.as_posix() or '.'})",
                              ["npm", "install", "--package-lock-only", *NPM_FLAGS], d, root))
    for pr in projects(root):
        d, rel = pr["dir"], pr["dir"].relative_to(root).as_posix() or "."
        if pr["eco"] == "npm":
            lock = (d / "package-lock.json").exists()
            steps.append(run_step(f"{label}: npm {'ci' if lock else 'install'} ({rel})",
                                  ["npm", "ci" if lock else "install", *NPM_FLAGS], d, root))
            if pr["test"] and steps[-1]["status"] == "ok":
                steps.append(run_step(f"{label}: npm test ({rel})", ["npm", "test", "--silent"], d, root))
        elif pr["eco"] == "pypi":
            venv = d / f".sscg-venv-{label}"
            s = run_step(f"{label}: create venv ({rel})", [sys.executable, "-m", "venv", str(venv)], d, root, 180)
            py = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            if s["status"] == "ok":
                steps.append(run_step(f"{label}: pip install -r {pr['req']} ({rel})",
                                      [str(py), "-m", "pip", "install", "--only-binary=:all:", "-q", "-r", pr["req"]],
                                      d, root))
                if steps[-1]["status"] == "ok":
                    steps.append(run_step(f"{label}: {'pytest' if pr['pytest'] else 'compile check'} ({rel})",
                                          [str(py), "-m", "pytest", "-q"] if pr["pytest"] else
                                          [str(py), "-m", "compileall", "-q", "-x", r"\.sscg-venv", "."], d, root))
            else:
                steps.append(s)
        elif pr["eco"] == "maven":
            steps.append(run_step(f"{label}: mvn test ({rel})", ["mvn", "-B", "-q", "test"], d, root))
        elif pr["eco"] == "docker":
            if docker:
                tag = f"sscg-validate-{label}:{os.getpid()}"
                steps.append(run_step(f"{label}: docker build ({rel}/{pr['file']})",
                                      ["docker", "build", "-q", "-f", pr["file"], "-t", tag, "."], d, root))
                subprocess.run(["docker", "image", "rm", "-f", tag], capture_output=True, timeout=60)  # leave no image
            else:
                steps.append({"step": f"{label}: docker build ({rel}/{pr['file']})", "cmd": "docker build",
                              "cwd": rel, "status": "skipped", "exit": None, "seconds": 0.0,
                              "log": "Docker engine not running: start Docker Desktop to build and rescan the image"})
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


def validate(repo: Path, before_findings: list, before_dg, proposals: list, base_rev: str | None,
             workdir: Path | None = None, baseline: bool = True, log=print) -> dict:
    """Validate the approved, patchable proposals together (one remediation change set)."""
    approved = [p for p in proposals if p.get("status") == "approved" and p.get("patchable")]
    if not approved:
        return {"verdict": "not_run", "reason": "no approved proposal with a patch"}
    tmp = Path(workdir or tempfile.mkdtemp(prefix="sscg-validate-"))
    tmp.mkdir(parents=True, exist_ok=True)
    after_dir = tmp / "after"
    shutil.copytree(repo, after_dir, ignore=COPY_IGNORE, dirs_exist_ok=True)
    edits = [e for p in approved for e in p["edits"]]
    applied = remediation.apply_edits(after_dir, edits)
    log(f"applied {len(edits)} edit(s) from {len(approved)} approved proposal(s) to {after_dir}")
    use_docker = docker_running()
    steps_before = []
    if baseline:
        before_dir = tmp / "before"
        shutil.copytree(repo, before_dir, ignore=COPY_IGNORE, dirs_exist_ok=True)
        log("building the unchanged repository (baseline) ...")
        steps_before = build_and_test(before_dir, "before", docker=use_docker)
    log("building the remediated repository ...")
    steps_after = build_and_test(after_dir, "after", relock=applied["relock"], docker=use_docker)
    log("rescanning the remediated repository with the Day 1 pipeline ...")
    dg_after = build(after_dir, None, check_vulns=True)
    fs_after, _ = detect(after_dir, dg_after, base_rev)
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
    return {"workdir": str(tmp), "docker": use_docker, "applied_files": changed_files,
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
    if regress or new_bad or len(unresolved) == len(targeted):
        v = "failed"
    elif unresolved or after_fail:
        v = "partially_verified"
    else:
        v = "verified"
    conf = "high" if tests_ok and not after_fail else "medium" if ran_ok and not after_fail else "low"
    if not ran_ok:
        reasons.append("nothing could be built in the sandbox: verification relies on the rescan only")
    if v == "verified":
        reasons.insert(0, f"all {len(targeted)} targeted finding(s) resolved, no new Critical/High findings, "
                          f"{len(ran_ok)} build/test step(s) passed")
    return v, conf, reasons
