"""Validate stage, "Validate the proposed fix: test before you trust". Generic for any repository.

  1. copy      the repository (with .git, without installed dependencies) to a temporary folder
  2. apply     only the human-approved edits (remediation.apply_edits); regenerate npm lockfiles
  3. install   npm ci/install --ignore-scripts, pip install (wheels only) in a venv          (kind "install")
  4. build     npm run build (when the project has a build script), Python compile check, mvn test (local Maven,
               or the official Maven image when only Docker is available), docker build      (kinds "build", "compile", "image")
  5. test      the project's own tests: npm test / pytest / mvn test                         (kind "test")
  6. smoke     start each built image (EXPOSEd ports published, memory / CPU / pid limits) and probe it over HTTP
                                                                                              (kind "smoke")
  7. rescan    the detection pipeline on the remediated copy's source (manifests, lockfiles, Dockerfiles,
               workflows) AND the built container image itself (Trivy on a `docker save` archive: OS and language
               packages and their vulnerabilities), before and after
  8. branch    commit exactly the validated files to sscg/remediation-<run> in the copy (hooks disabled) and export
               it as a git bundle: the hand-off is a reviewable branch, never a push or merge
  9. compare   resolved / persisting / new advisories per package across versions, SBOM changes, image vulnerability
               changes, step-by-step before-vs-after results, and per-proposal coverage (what actually ran for each fix)

The unchanged repository is built the same way as a baseline, so a failure that already existed is not blamed on
the fix. Execution boundary: this is a temporary copy, NOT an isolated sandbox. Commands run as local processes
with a scrubbed environment (no API keys, tokens or secrets) and npm install scripts disabled, but the project's
own build scripts and tests do run its code with the user's filesystem and network access. Validate only
repositories you are authorised to run.
"""
from __future__ import annotations

import difflib
import hashlib
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
MAVEN_IMAGE = os.getenv("SSCG_MAVEN_IMAGE", "maven:3.9-eclipse-temurin-17")
TRIVY_IMAGE = os.getenv("SSCG_TRIVY_IMAGE", "aquasec/trivy:0.58.1")
SMOKE_SECONDS = int(os.getenv("SSCG_SMOKE_SECONDS", "40") or 40)
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
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


def run_step(name: str, cmd: list, cwd: Path, root: Path, timeout: int = DEFAULT_TIMEOUT, kind: str = "other") -> dict:
    exe = shutil.which(cmd[0])
    rec = {"step": name, "kind": kind, "cmd": " ".join(cmd), "cwd": cwd.relative_to(root).as_posix() or ".",
           "status": "skipped", "exit": None, "seconds": 0.0, "log": ""}
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


def _docker(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, stdin=subprocess.DEVNULL)


def dockerfile_info(path: Path) -> dict:
    """EXPOSEd TCP ports and the package managers a Dockerfile runs (ignoring commented-out lines)."""
    text = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
    active = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    ports = []
    for line in re.findall(r"(?im)^\s*EXPOSE\s+(.+)$", active):
        ports += [int(m) for m in re.findall(r"\b(\d{1,5})(?:/tcp)?(?![\w/])", line)]
    installs = sorted(eco for eco, pat in (("npm", r"\b(npm\s+(ci|install)|yarn|pnpm)\b"),
                                           ("pypi", r"\bpip3?\s+install\b"), ("maven", r"\bmvn\b"))
                      if re.search(pat, active))
    return {"ports": ports, "installs": installs}


def _http_probe(port: int) -> bool:
    import socket
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as c:
            c.settimeout(3)
            c.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            return bool(c.recv(16))
    except OSError:
        return False


def smoke_run(tag: str, info: dict, name: str, rel: str) -> dict:
    """Start the built image and check that the application comes up (an HTTP reply on an EXPOSEd port)."""
    rec = {"step": name, "kind": "smoke", "cmd": f"docker run -d -P --memory 1g --cpus 1 --pids-limit 256 {tag}",
           "cwd": rel, "status": "failed", "exit": None, "seconds": 0.0, "log": "", "installs": info["installs"]}
    t = time.perf_counter()
    r = _docker("run", "-d", "-P", "--memory", "1g", "--cpus", "1", "--pids-limit", "256", tag)
    if r.returncode != 0:
        rec.update(exit=r.returncode, log=_tail(r.stderr), seconds=round(time.perf_counter() - t, 1))
        return rec
    cid = r.stdout.strip()
    try:
        answered, running, code = None, True, None
        while time.perf_counter() - t < SMOKE_SECONDS:
            st = _docker("inspect", "-f", "{{.State.Running}} {{.State.ExitCode}}", cid).stdout.split()
            running, code = (st[0] == "true", int(st[1])) if len(st) == 2 else (False, None)
            if not running:
                break
            for port in info["ports"]:
                hp = re.findall(r":(\d+)\s*$", _docker("port", cid, f"{port}/tcp").stdout, re.M)
                if hp and _http_probe(int(hp[0])):
                    answered = port
                    break
            if answered or (not info["ports"] and time.perf_counter() - t > 8):
                break
            time.sleep(1)
        logs = _docker("logs", "--tail", "20", cid).stdout + _docker("logs", "--tail", "20", cid).stderr
        secs = round(time.perf_counter() - t, 1)
        if answered:
            rec.update(status="ok", log=f"container started; port {answered} answered an HTTP probe after {secs}s")
        elif running:
            rec.update(status="ok", log=(f"container stayed up for {secs}s; " + (
                f"port(s) {', '.join(map(str, info['ports']))} did not answer an HTTP probe" if info["ports"]
                else "no EXPOSEd port to probe")))
        else:
            rec.update(status="ok" if code == 0 and not info["ports"] else "failed", exit=code,
                       log=f"container exited with code {code} after {secs}s\n" + _tail(logs))
        rec["seconds"] = secs
        return rec
    finally:
        _docker("rm", "-f", cid, timeout=60)


def scan_image(tag: str, label: str, rel: str, workdir: Path) -> dict:
    """Scan the BUILT image (not its Dockerfile): `docker save` + Trivy (official image) on the archive, offline input."""
    out = {"label": label, "dockerfile": rel, "tool": TRIVY_IMAGE, "status": "failed"}
    tar = workdir / f"image-{label}-{abs(hash(rel)) % 100000}.tar"
    t = time.perf_counter()
    try:
        s = _docker("save", "-o", str(tar), tag, timeout=900)
        if s.returncode != 0:
            out["log"] = _tail(s.stderr)
            return out
        r = _docker("run", "--rm", "-v", f"{workdir.resolve()}:/in:ro", "-v", "sscg-trivy-cache:/root/.cache/trivy",
                    TRIVY_IMAGE, "image", "--input", f"/in/{tar.name}", "--format", "json", "--list-all-pkgs",
                    "--scanners", "vuln", "--quiet", "--timeout", "15m", timeout=1800)
        if r.returncode != 0:
            out["log"] = _tail(r.stderr or r.stdout)
            return out
        data = json.loads(r.stdout or "{}")
        pkgs, vulns = [], []
        for res in data.get("Results") or []:
            for pk in res.get("Packages") or []:
                pkgs.append({"name": pk.get("Name"), "version": pk.get("Version"), "type": res.get("Type")})
            for v in res.get("Vulnerabilities") or []:
                vulns.append({"id": v.get("VulnerabilityID"), "package": v.get("PkgName"),
                              "installed": v.get("InstalledVersion"), "fixed": v.get("FixedVersion") or "",
                              "severity": (v.get("Severity") or "UNKNOWN").upper(), "type": res.get("Type")})
        vulns.sort(key=lambda v: SEVERITIES.index(v["severity"]) if v["severity"] in SEVERITIES else 9)
        osinfo = (data.get("Metadata") or {}).get("OS") or {}
        out.update(status="ok", os=f"{osinfo.get('Family', '')} {osinfo.get('Name', '')}".strip(), packages=len(pkgs),
                   by_severity={sv: sum(v["severity"] == sv for v in vulns) for sv in SEVERITIES},
                   vulnerabilities=vulns, package_list=pkgs)
        return out
    except (ValueError, subprocess.TimeoutExpired) as e:
        out["log"] = f"{type(e).__name__}: {str(e)[:300]}"
        return out
    finally:
        out["seconds"] = round(time.perf_counter() - t, 1)
        tar.unlink(missing_ok=True)


def commit_branch(after_dir: Path, files: list[str], run_id: str, proposal_ids: list[str], workdir: Path) -> dict:
    """Commit exactly the validated files to sscg/remediation-<run> in the temporary copy and export a git bundle.
    Repository hooks are disabled (they are code from the scanned repo); nothing is pushed or merged."""
    if not (after_dir / ".git").exists():
        return {"status": "skipped", "note": "the repository is not a git repository: the patch file is the hand-off"}
    hooks = workdir / "no-hooks"
    hooks.mkdir(exist_ok=True)

    def g(*a):
        return subprocess.run(["git", "-C", str(after_dir), "-c", f"core.hooksPath={hooks}", "-c",
                               "user.name=Supply Chain Guardian", "-c", "user.email=sscg@localhost", "-c",
                               "commit.gpgsign=false", *a], capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=300, stdin=subprocess.DEVNULL)
    base = g("rev-parse", "HEAD").stdout.strip()
    branch = f"sscg/remediation-{run_id}"
    present = sorted({f for f in files if (after_dir / f).exists()})
    for step in (("checkout", "-q", "-b", branch), ("add", "--", *present),
                 ("commit", "-q", "--no-verify", "-m", f"Guardian remediation (run {run_id})\n\n"
                  f"Approved proposals: {', '.join(proposal_ids)}\n"
                  "Every change was approved by a human and validated by the Supply Chain Guardian "
                  "(see remediation_report.md).")):
        r = g(*step)
        if r.returncode != 0:
            return {"status": "failed", "branch": branch, "note": f"git {step[0]} failed: {_tail(r.stderr, 5)}"}
    commit = g("rev-parse", "HEAD").stdout.strip()
    bundle = workdir / "remediation.bundle"
    b = g("bundle", "create", str(bundle), f"{base}..{branch}")
    return {"status": "ok", "branch": branch, "base": base, "commit": commit, "files": present,
            "bundle": str(bundle) if b.returncode == 0 and bundle.exists() else None,
            "note": None if b.returncode == 0 else f"bundle not created: {_tail(b.stderr, 3)}"}


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
                        "build": bool(scripts.get("build")),
                        "test": test if test and NPM_NO_TEST not in test else None})
        elif re.fullmatch(r"requirements[\w.-]*\.txt", p.name) and "dev" not in p.name and "test" not in p.name:
            out.append({"eco": "pypi", "dir": rel_dir, "req": p.name,
                        "pytest": any(rel_dir.glob("test_*.py")) or (rel_dir / "tests").is_dir()})
        elif p.name == "pom.xml":
            out.append({"eco": "maven", "dir": rel_dir})
        elif p.name in ("Dockerfile", "Containerfile"):
            out.append({"eco": "docker", "dir": rel_dir, "file": p.name})
    return out


def build_and_test(root: Path, label: str, relock: list[str] = (), docker: bool = False,
                   scans: list | None = None, workdir: Path | None = None) -> list[dict]:
    """Build + test every project under root. relock: package.json files whose lockfile must be regenerated.
    With Docker: every built image is smoke-run and, when `scans` is a list, scanned (results appended to it)."""
    steps = []
    for e in sorted(set(relock)):
        d = root / Path(e).parent
        steps.append(run_step(f"{label}: regenerate lockfile ({Path(e).parent.as_posix() or '.'})",
                              ["npm", "install", "--package-lock-only", *NPM_FLAGS], d, root, kind="relock"))
    for pr in projects(root):
        d, rel = pr["dir"], pr["dir"].relative_to(root).as_posix() or "."
        if pr["eco"] == "npm":
            lock = (d / "package-lock.json").exists()
            steps.append(run_step(f"{label}: npm {'ci' if lock else 'install'} ({rel})",
                                  ["npm", "ci" if lock else "install", *NPM_FLAGS], d, root, kind="install"))
            installed = steps[-1]["status"] == "ok"
            if pr.get("build") and installed:
                steps.append(run_step(f"{label}: npm run build ({rel})", ["npm", "run", "build"], d, root, kind="build"))
            if pr["test"] and installed:
                steps.append(run_step(f"{label}: npm test ({rel})", ["npm", "test", "--silent"], d, root, kind="test"))
        elif pr["eco"] == "pypi":
            venv = d / f".sscg-venv-{label}"
            s = run_step(f"{label}: create venv ({rel})", [sys.executable, "-m", "venv", str(venv)], d, root, 180,
                         kind="setup")
            py = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            if s["status"] == "ok":
                steps.append(run_step(f"{label}: pip install -r {pr['req']} ({rel})",
                                      [str(py), "-m", "pip", "install", "--only-binary=:all:", "-q", "-r", pr["req"]],
                                      d, root, kind="install"))
                if steps[-1]["status"] == "ok":
                    steps.append(run_step(f"{label}: {'pytest' if pr['pytest'] else 'compile check'} ({rel})",
                                          [str(py), "-m", "pytest", "-q"] if pr["pytest"] else
                                          [str(py), "-m", "compileall", "-q", "-x", r"\.sscg-venv", "."], d, root,
                                          kind="test" if pr["pytest"] else "compile"))
            else:
                steps.append(s)
        elif pr["eco"] == "maven":
            kind = "test" if (d / "src" / "test").is_dir() else "build"     # no tests: `mvn test` only compiles
            name = f"{label}: mvn test ({rel})"
            if shutil.which("mvn") or not docker:
                steps.append(run_step(name, ["mvn", "-B", "-q", "test"], d, root, kind=kind))
                if steps[-1]["status"] == "skipped":
                    steps[-1]["log"] = "mvn is not installed and Docker is not running"
            else:          # no local Maven: the official Maven image, project mounted, dependency cache in a volume
                steps.append(run_step(name, ["docker", "run", "--rm", "-v", f"{d.resolve()}:/work", "-w", "/work",
                                             "-v", "sscg-m2:/root/.m2", MAVEN_IMAGE, "mvn", "-B", "-q", "test"],
                                      d, root, timeout=max(DEFAULT_TIMEOUT, 1200), kind=kind))
                steps[-1]["runner"] = f"docker ({MAVEN_IMAGE})"
        elif pr["eco"] == "docker":
            if docker:
                tag = f"sscg-validate-{label}-{os.getpid()}-{abs(hash(rel)) % 100000}:latest"
                info = dockerfile_info(d / pr["file"])
                steps.append(run_step(f"{label}: docker build ({rel}/{pr['file']})",
                                      ["docker", "build", "-q", "-f", pr["file"], "-t", tag, "."], d, root, kind="image"))
                steps[-1]["installs"] = info["installs"]
                if steps[-1]["status"] == "ok":
                    steps.append(smoke_run(tag, info, f"{label}: smoke run ({rel}/{pr['file']})", rel))
                    if scans is not None:
                        scans.append(scan_image(tag, label, rel, workdir or root.parent))
                subprocess.run(["docker", "image", "rm", "-f", tag], capture_output=True, timeout=60)  # leave no image
            else:
                steps.append({"step": f"{label}: docker build ({rel}/{pr['file']})", "kind": "image", "cmd": "docker build",
                              "cwd": rel, "status": "skipped", "exit": None, "seconds": 0.0,
                              "log": "Docker engine not running: start Docker Desktop to build and rescan the image"})
    return steps


def fkey(f: dict) -> tuple:
    """Stable identity of a finding across two scans (finding IDs are renumbered per scan)."""
    c = f.get("component") or {}
    snip = next((e.get("snippet", "") for e in f.get("evidence", []) if e.get("type") == "file"), "")
    return (f["rule"], c.get("id") or re.sub(r":\d+$", "", f.get("location") or ""), "" if c else snip)


def _pkg(f: dict) -> tuple:
    c = f.get("component") or {}
    return c.get("ecosystem"), c.get("name")


def _advisories(f: dict) -> dict:
    """{advisory id: {aliases (id + CVEs), severity}} of a vulnerability finding."""
    return {e["id"]: {"aliases": {e["id"], *(e.get("cves") or [])}, "severity": str(e.get("severity") or "").upper()}
            for e in f.get("evidence", []) if e.get("type") == "advisory"}


def _alias_index(findings: list) -> dict:
    """(ecosystem, name) -> every advisory alias seen on any version of that package."""
    idx = {}
    for f in findings:
        if f["category"] == "vulnerability" and f.get("component"):
            for a in _advisories(f).values():
                idx.setdefault(_pkg(f), set()).update(a["aliases"])
    return idx


COVERAGE_RANK = {"tested": 4, "started": 3, "built": 2, "installed": 1, "rescan_only": 0}
KIND_COVERAGE = {"test": "tested", "smoke": "started", "build": "built", "compile": "built", "image": "built",
                 "install": "installed"}
IMAGE_KINDS = {"image", "smoke"}


def _eco_of(path: str) -> str | None:
    n = Path(path).name
    if n in ("package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock"):
        return "npm"
    if re.fullmatch(r"requirements[\w.-]*\.txt|pyproject\.toml|setup\.(py|cfg)", n):
        return "pypi"
    return "maven" if n == "pom.xml" else None


def coverage(files: list[str], steps_after: list[dict]) -> str:
    """What was actually executed for a proposal's files: tested > started > built > installed > rescan_only.
    A built / started image counts for a manifest in the same folder when the Dockerfile installs that ecosystem's
    dependencies. CI workflow changes cannot be executed locally: not_applicable (verified by the rescan only)."""
    levels = []
    for f in files:
        f = f.replace("\\", "/")
        if f.startswith(".github/"):
            continue
        d = Path(f).parent.as_posix() or "."
        image = re.search(r"(^|/)(Dockerfile|Containerfile)[\w.-]*$", f) is not None
        eco = _eco_of(f)
        got = [KIND_COVERAGE[x["kind"]] for x in steps_after if x["status"] == "ok" and x.get("cwd") == d
               and x.get("kind") in KIND_COVERAGE
               and ((x["kind"] in IMAGE_KINDS) == image or (x["kind"] in IMAGE_KINDS and eco in x.get("installs", [])))]
        levels.append(max(got, key=COVERAGE_RANK.get) if got else "rescan_only")
    return min(levels, key=COVERAGE_RANK.get) if levels else "not_applicable"


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
             workdir: Path | None = None, baseline: bool = True, log=print, run_id: str = "run") -> dict:
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
    steps_before, image_scans = [], []
    if baseline:
        before_dir = tmp / "before"
        shutil.copytree(repo, before_dir, ignore=COPY_IGNORE, dirs_exist_ok=True)
        log("building the unchanged repository (baseline) ...")
        steps_before = build_and_test(before_dir, "before", docker=use_docker, scans=image_scans, workdir=tmp)
    log("building, testing, starting and scanning the remediated repository ...")
    steps_after = build_and_test(after_dir, "after", relock=applied["relock"], docker=use_docker, scans=image_scans,
                                 workdir=tmp)
    changed_files = applied["changed"] + [str(Path(e).parent / "package-lock.json").replace("\\", "/")
                                          for e in applied["relock"]]
    log("rescanning the remediated repository (source, manifests, lockfiles, Dockerfiles, workflows) ...")
    dg_after = build(after_dir, None, check_vulns=True)
    fs_after, _ = detect(after_dir, dg_after, base_rev)
    # the branch is committed only AFTER the rescan: our own commit must not appear in "what changed"
    branch = commit_branch(after_dir, changed_files, run_id, [p["proposal_id"] for p in approved], tmp)
    log(f"controlled branch: {branch.get('branch')} ({branch['status']})")
    osv_down = [n for n in dg_after.notes if "OSV unavailable" in n]
    after_img = [x for x in image_scans if x["label"] == "after"]
    imaged = [x for x in after_img if x["status"] == "ok"]
    scan = {"scope": "source of the remediated copy (manifests, lockfiles, Dockerfiles, CI workflows) with the same "
                     "detection pipeline as the original scan" + (
                         f"; and the built container image(s) {', '.join(x['dockerfile'] + '/Dockerfile' for x in imaged)} "
                         f"with Trivy (OS and language packages)" if imaged else
                         "; the built container image could not be scanned" if after_img else
                         "; no container image was built, so no image was scanned"),
            "vulns_checked": not osv_down, "image_scanned": bool(imaged),
            "notes": [n for n in dg_after.notes if "OSV" in n]}
    before_k = {fkey(f): f for f in before_findings}
    after_k = {fkey(f): f for f in fs_after}
    gone = [before_k[k] for k in before_k.keys() - after_k.keys()]
    remaining = [before_k[k]["finding_id"] for k in before_k.keys() & after_k.keys()]
    # a vulnerability is only resolved if none of its advisories (or their CVE aliases) is still present on ANY
    # version of the same package after the change; an upgrade that keeps the advisory is "persisting"
    alias_after, alias_before = _alias_index(fs_after), _alias_index(before_findings)
    persisting, unverified, resolved = [], [], []
    for f in gone:
        if f["category"] == "vulnerability" and f.get("component"):
            if not scan["vulns_checked"]:
                unverified.append(f["finding_id"])
                continue
            keep = sorted(i for i, a in _advisories(f).items() if a["aliases"] & alias_after.get(_pkg(f), set()))
            if keep:
                persisting.append({"finding_id": f["finding_id"], "component": f["component"]["label"],
                                   "advisories": keep})
                continue
        resolved.append(f["finding_id"])
    remaining += [x["finding_id"] for x in persisting] + unverified
    targets = {re.split(r"@", str(p.get("to_version") or ""))[0] for p in approved if p["action"] == "replace"}
    new = []
    for k in after_k.keys() - before_k.keys():
        f = after_k[k]
        c = f.get("component") or {}
        sev = (f.get("severity") or {}).get("label") if f["category"] == "vulnerability" else f["risk"]["level"].upper()
        new_adv = []
        if f["category"] == "vulnerability" and _pkg(f) in alias_before:
            new_adv = [i for i, a in _advisories(f).items() if not (a["aliases"] & alias_before[_pkg(f)])]
            bad = [i for i in new_adv if _advisories(f)[i]["severity"] in ("CRITICAL", "HIGH")]
            # the package was vulnerable before: only advisories it did NOT have before are new
            kind = "introduced" if bad else "still_vulnerable"
            if bad:
                sev = max((_advisories(f)[i]["severity"] for i in bad), key=["HIGH", "CRITICAL"].index)
        elif c.get("name") in targets or any(c.get("name") and c["name"] == str(p.get("component", "")).split("@")[0]
                                             for p in approved):
            kind = "expected"                # e.g. the replacement package is a new direct dependency
        else:
            kind = "introduced"
        new.append({"title": f["title"], "type": f["type"], "level": f["risk"]["level"], "severity": sev,
                    "rule": f["rule"], "kind": kind, "component": c.get("label"), "new_advisories": new_adv})
    per_prop = {}
    for p in approved:
        got = [f for f in p["finding_ids"] if f in resolved]
        files = list(p.get("files_affected") or []) + [str(Path(e).parent / "package-lock.json").replace("\\", "/")
                                                       for e in applied["relock"] if e in (p.get("files_affected") or [])]
        per_prop[p["proposal_id"]] = {"targeted": p["finding_ids"], "resolved": got,
                                      "persisting": [x for x in persisting if x["finding_id"] in p["finding_ids"]],
                                      "unverified": [f for f in p["finding_ids"] if f in unverified],
                                      "coverage": coverage(files, steps_after),
                                      "status": "resolved" if len(got) == len(p["finding_ids"]) else
                                      "partially_resolved" if got else "not_resolved"}
    names = {}
    for p in approved:                      # package names per proposal, to attribute a broken step to a proposal
        for txt in (p.get("component"), p.get("to_version")):
            m = re.match(r"(@?[^@,\s]+)@", str(txt or ""))
            if m and len(m.group(1)) > 2:
                names.setdefault(p["proposal_id"], set()).add(m.group(1))
    patch = patch_text(repo, after_dir, changed_files)
    levels = ("Critical", "High", "Medium", "Low", "Info")
    risk_levels = {"before": {lv: sum(f["risk"]["level"] == lv for f in before_findings) for lv in levels},
                   "after": {lv: sum(f["risk"]["level"] == lv for f in fs_after) for lv in levels}}
    return {"image_scans": image_scans, "branch": branch, "risk_levels": risk_levels, "proposal_files": {p["proposal_id"]: list(p.get("files_affected") or []) for p in approved},
            "workdir": str(tmp), "docker": use_docker, "applied_files": changed_files, "scan": scan,
            "persisting": persisting, "unverified": unverified,
            "validated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "patch_sha256": hashlib.sha256(patch.encode("utf-8")).hexdigest(), "dg_after": dg_after,
            "proposal_packages": {k: sorted(v) for k, v in names.items()},
            "steps_before": steps_before, "steps_after": steps_after,
            "findings_before": len(before_findings), "findings_after": len(fs_after),
            "resolved": sorted(resolved), "remaining": sorted(remaining), "new": new,
            "per_proposal": per_prop, "sbom_diff": sbom_diff(before_dg, dg_after) if before_dg is not None else {},
            "patch": patch,
            "after_findings": [{k: v for k, v in f.items() if not k.startswith("_")} for f in fs_after]}


def _name(step: dict) -> str:
    return step["step"].split(": ", 1)[1]


def verdict(res: dict) -> tuple[str, str, list[str]]:
    """(verdict, confidence, reasons). "verified" needs: every targeted finding resolved (advisories gone from the
    package on every version), a complete after-scan, no regression or new Critical/High advisory, and every
    approved fix covered by at least a successful install, build or test of the project it changes."""
    if res.get("verdict") == "not_run":
        return "not_run", "low", [res.get("reason", "")]
    reasons = []
    before = {_name(s): s for s in res["steps_before"]}
    after = res["steps_after"]
    failing = [s for s in after if s["status"] in ("failed", "timeout")]
    regress = [s for s in failing if before.get(_name(s), {}).get("status") == "ok"]
    preexisting = [s for s in failing if before.get(_name(s), {}).get("status") in ("failed", "timeout")]
    no_baseline = [s for s in failing if s not in regress and s not in preexisting]
    ran_ok = [s for s in after if s["status"] == "ok" and s.get("kind") not in ("relock", "setup")]
    kinds_ok = {s.get("kind") for s in ran_ok}
    skipped = [s for s in after if s["status"] == "skipped"]
    scan = res.get("scan") or {"vulns_checked": True}
    new_bad = [n for n in res["new"] if n.get("kind", "introduced") == "introduced"
               and str(n.get("severity") or n["level"]).upper() in ("CRITICAL", "HIGH")]
    still = [n for n in res["new"] if n.get("kind") == "still_vulnerable"]
    pp = res["per_proposal"]
    targeted = [f for v in pp.values() for f in v["targeted"]]
    unresolved = [f for v in pp.values() for f in v["targeted"] if f not in v["resolved"]]
    persisting = res.get("persisting") or []
    uncovered = sorted(pid for pid, v in pp.items() if v.get("coverage") == "rescan_only")
    scans = {x["label"]: x for x in res.get("image_scans") or []}
    img_after, img_before = scans.get("after"), scans.get("before")
    img_new_bad = []
    if img_after and img_after.get("status") == "ok":
        seen = {(v["id"], v["package"]) for v in (img_before or {}).get("vulnerabilities", [])} \
            if img_before and img_before.get("status") == "ok" else None
        if seen is not None:
            img_new_bad = [v for v in img_after["vulnerabilities"] if v["severity"] in ("CRITICAL", "HIGH")
                           and (v["id"], v["package"]) not in seen]
    install_only = sorted(pid for pid, v in pp.items() if v.get("coverage") == "installed")

    if regress:
        reasons.append("the fix broke a step that worked before: " + ", ".join(s["step"] for s in regress))
        logs = " ".join(s.get("log", "") for s in regress)
        culprits = [f"{pid} ({', '.join(n for n in pkgs if re.search(rf'(?<![\w-]){re.escape(n)}(?![\w-])', logs))})"
                    for pid, pkgs in (res.get("proposal_packages") or {}).items()
                    if any(re.search(rf"(?<![\w-]){re.escape(n)}(?![\w-])", logs) for n in pkgs)]
        if culprits:
            reasons.append("likely caused by " + ", ".join(culprits[:4]) + ": start a new remediation run and approve "
                           "the other proposals without " + ("it" if len(culprits) == 1 else "them"))
    if img_new_bad:
        reasons.append(f"{len(img_new_bad)} NEW Critical/High vulnerabilities in the built image compared with the "
                       "unchanged image: " + ", ".join(f"{v['id']} ({v['package']})" for v in img_new_bad[:4]))
    if new_bad:
        reasons.append(f"{len(new_bad)} finding(s) with NEW Critical/High advisories after the change: "
                       + "; ".join(n["title"][:80] for n in new_bad[:3]))
    fmt = lambda xs: "; ".join(f"{x['finding_id']} {x['component']} ({', '.join(x['advisories'][:3])})" for x in xs[:4])
    pers_targeted = [x for x in persisting if x["finding_id"] in set(targeted)]
    pers_other = [x for x in persisting if x not in pers_targeted]
    if pers_targeted:
        reasons.append(f"{len(pers_targeted)} targeted vulnerability finding(s) NOT resolved: the same advisories remain "
                       f"on the new version: {fmt(pers_targeted)}")
    if pers_other:
        reasons.append(f"{len(pers_other)} other finding(s), not targeted by an approved fix, moved to a new version that "
                       f"keeps the same advisories (still open): {fmt(pers_other)}")
    if still:
        reasons.append(f"{len(still)} package(s) moved to a version with other (not Critical/High) advisories: "
                       + ", ".join(n["component"] or n["title"][:40] for n in still[:4]))
    if not scan.get("vulns_checked", True):
        reasons.append("the after-scan could not check vulnerabilities (OSV unavailable): vulnerability fixes are "
                       "NOT proven (" + ", ".join(res.get("unverified") or []) + ")")
    other_unresolved = [f for f in unresolved if f not in {x["finding_id"] for x in pers_targeted}
                        and f not in (res.get("unverified") or [])]
    if other_unresolved:
        reasons.append(f"{len(other_unresolved)}/{len(targeted)} targeted finding(s) still present: "
                       f"{', '.join(other_unresolved[:6])}")
    if preexisting:
        reasons.append("failing before and after the fix (not caused by it): " + ", ".join(_name(s) for s in preexisting))
    if no_baseline:
        reasons.append("failing after the fix with no baseline result for the same step (baseline skipped or the step "
                       "did not run before): cannot tell whether the fix caused it: " + ", ".join(_name(s) for s in no_baseline))
    if uncovered:
        reasons.append("not executed, verified by the rescan only: " + ", ".join(
            f"{pid} ({', '.join(f for f in (res.get('proposal_files') or {}).get(pid, []))})" for pid in uncovered)
            + (" (" + "; ".join(f"{_name(s)}: {s.get('log')}" for s in skipped[:3]) + ")" if skipped else ""))
    if install_only:
        reasons.append("dependency installation only (no build or test script for that project): " + ", ".join(install_only))
    if not ran_ok:
        reasons.append("no install, build or test step succeeded: verification relies on the rescan only")
    if img_after and img_after.get("status") == "ok":
        bs = img_after["by_severity"]
        reasons.append(f"built image scanned ({img_after['os'] or 'image'}, {img_after['packages']} packages): "
                       f"{bs['CRITICAL']} critical / {bs['HIGH']} high / {bs['MEDIUM']} medium OS and package "
                       "vulnerabilities" + (" (no baseline image to compare: the unchanged image did not build)"
                                            if not (img_before and img_before.get("status") == "ok") else
                                            f"; {len(img_new_bad)} new Critical/High compared with the unchanged image"))
    elif img_after:
        reasons.append("the built image could not be scanned: " + (img_after.get("log") or "")[:160])

    if regress or new_bad or (targeted and len(unresolved) == len(targeted)):
        v = "failed"
    elif unresolved or failing or uncovered or not ran_ok or not scan.get("vulns_checked", True) or img_new_bad:
        v = "partially_verified"
    else:
        v = "verified"
    applicable = [x for x in pp.values() if x.get("coverage") != "not_applicable"]
    complete = scan.get("vulns_checked", True) and not failing
    if v == "verified":     # high only when tests or a smoke run passed and every fix was at least built
        strong = kinds_ok & {"test", "smoke"}
        conf = "high" if strong and all(x.get("coverage") in ("tested", "started", "built") for x in applicable) \
            else "medium"
    else:                   # confidence in the (negative / partial) verdict itself
        conf = "medium" if ran_ok and complete else "low"
    if v == "verified":
        reasons.insert(0, f"all {len(targeted)} targeted finding(s) resolved (their advisories are gone from every "
                          f"version of the package), no new Critical/High advisories, every approved fix was "
                          f"installed, built, started or tested ({', '.join(sorted(k for k in kinds_ok if k))} passed)")
    return v, conf, reasons
