"""Verdict rules of the validation stage (sscg/validation.py) and the approval fingerprint (sscg/snapshot.py).

Run from the sscg/ folder:  python -m pytest -q tests
"""
from pathlib import Path

from sscg import snapshot, source, validation


def step(label, name, status, kind, cwd=".", log=""):
    return {"step": f"{label}: {name}", "kind": kind, "status": status, "cwd": cwd, "seconds": 1.0, "log": log}


def result(before, after, *, coverage="installed", resolved=True, new=(), persisting=(), vulns_checked=True):
    per = {"P-001": {"targeted": ["F-001"], "resolved": ["F-001"] if resolved else [], "coverage": coverage,
                     "persisting": list(persisting), "unverified": []}}
    return {"steps_before": before, "steps_after": after, "per_proposal": per, "new": list(new),
            "persisting": list(persisting), "unverified": [] if vulns_checked else ["F-001"],
            "scan": {"vulns_checked": vulns_checked}, "proposal_files": {"P-001": ["package.json"]}}


def test_rescan_only_is_not_verified():
    """Every step skipped (no npm / Maven / Docker): the rescan alone must not produce 'verified'."""
    after = [step("after", "npm ci (.)", "skipped", "install", log="npm is not installed")]
    v, conf, reasons = validation.verdict(result([], after, coverage="rescan_only"))
    assert v == "partially_verified" and conf == "low"
    assert any("rescan only" in r for r in reasons)


def test_after_only_failure_is_not_blamed_on_the_baseline():
    """Baseline install OK, the test only ran after the fix and failed: 'cannot tell', never 'failed before too'."""
    before = [step("before", "npm ci (.)", "ok", "install")]
    after = [step("after", "npm ci (.)", "ok", "install"), step("after", "npm test (.)", "failed", "test")]
    v, _, reasons = validation.verdict(result(before, after))
    assert v == "partially_verified"
    assert any("no baseline result for the same step" in r for r in reasons)
    assert not any("not caused by it" in r for r in reasons)


def test_regression_fails():
    before = [step("before", "npm test (.)", "ok", "test")]
    after = [step("after", "npm test (.)", "failed", "test")]
    v, _, reasons = validation.verdict(result(before, after, coverage="tested"))
    assert v == "failed" and any("broke a step that worked before" in r for r in reasons)


def test_osv_outage_cannot_prove_a_fix():
    after = [step("after", "npm ci (.)", "ok", "install"), step("after", "npm test (.)", "ok", "test")]
    v, _, reasons = validation.verdict(result([], after, coverage="tested", vulns_checked=False))
    assert v == "partially_verified"
    assert any("OSV unavailable" in r for r in reasons)


def test_persisting_advisory_is_not_resolved():
    after = [step("after", "npm test (.)", "ok", "test")]
    pers = [{"finding_id": "F-001", "component": "lodash@4.17.21", "advisories": ["GHSA-xxxx"]}]
    v, _, reasons = validation.verdict(result([], after, coverage="tested", resolved=False, persisting=pers))
    assert v == "failed"         # the only targeted finding is not resolved
    assert any("same advisories remain" in r for r in reasons)


def test_verified_needs_execution_and_complete_scan():
    after = [step("after", "npm ci (.)", "ok", "install"), step("after", "npm test (.)", "ok", "test")]
    v, conf, _ = validation.verdict(result([], after, coverage="tested"))
    assert (v, conf) == ("verified", "high")


def test_coverage_levels():
    steps = [step("after", "npm ci (.)", "ok", "install"), step("after", "docker build (./Dockerfile)", "ok", "image"),
             step("after", "mvn test (notifier)", "skipped", "test", cwd="notifier")]
    assert validation.coverage(["package.json"], steps) == "installed"
    assert validation.coverage(["Dockerfile"], steps) == "built"
    assert validation.coverage(["notifier/pom.xml"], steps) == "rescan_only"
    assert validation.coverage([".github/workflows/ci.yml"], steps) == "not_applicable"


def test_fingerprint_detects_a_changed_manifest(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"dependencies": {"a": "1.0.0"}}')
    (tmp_path / "README.md").write_text("docs")
    fp = snapshot.fingerprint(tmp_path)
    assert "package.json" in fp["files"] and "README.md" not in fp["files"]
    assert snapshot.changes(fp, snapshot.fingerprint(tmp_path)) == []
    (tmp_path / "package.json").write_text('{"dependencies": {"a": "2.0.0"}}')
    assert snapshot.changes(fp, snapshot.fingerprint(tmp_path)) == ["changed: package.json"]


def test_repository_links():
    r = source.parse("https://github.com/juice-shop/juice-shop/tree/v17.0.0")
    assert (r.url, r.ref, r.name) == ("https://github.com/juice-shop/juice-shop", "v17.0.0", "juice-shop")
    assert source.parse("github.com/OWASP/NodeGoat.git").url == "https://github.com/OWASP/NodeGoat"
    for bad in ("git@github.com:a/b.git", "http://github.com/a/b", "https://github.com/onlyowner"):
        try:
            source.parse(bad)
            raise AssertionError(bad)
        except source.SourceError:
            pass


def test_dockerfile_info_ignores_comments(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM node:20\n# RUN pip install evil\nRUN npm ci --ignore-scripts\nEXPOSE 3000 8080/tcp 53/udp\n")
    info = validation.dockerfile_info(tmp_path / "Dockerfile")
    assert info == {"ports": [3000, 8080], "installs": ["npm"]}


def test_started_image_covers_its_manifest():
    """A started image that installs npm dependencies is evidence for package.json in the same folder."""
    steps = [step("after", "npm ci (.)", "ok", "install"),
             {**step("after", "smoke run (./Dockerfile)", "ok", "smoke"), "installs": ["npm"]}]
    assert validation.coverage(["package.json"], steps) == "started"
    assert validation.coverage(["Dockerfile"], steps) == "started"
    assert validation.coverage(["worker/requirements.txt"], steps) == "rescan_only"


def test_branch_commits_only_validated_files_without_hooks(tmp_path: Path):
    import subprocess
    repo = tmp_path / "r"
    repo.mkdir()
    run = lambda *a: subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *a],
                                    capture_output=True, text=True, check=True)
    run("init", "-q")
    (repo / "package.json").write_text('{"a": 1}')
    (repo / "notes.txt").write_text("x")
    run("add", ".")
    run("commit", "-q", "-m", "base")
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho hacked > HACKED\n")
    hook.chmod(0o755)
    (repo / "package.json").write_text('{"a": 2}')
    (repo / "notes.txt").write_text("unrelated local edit")
    res = validation.commit_branch(repo, ["package.json"], "t1", ["P-001"], tmp_path)
    assert res["status"] == "ok" and res["branch"] == "sscg/remediation-t1"
    assert res["files"] == ["package.json"] and not (repo / "HACKED").exists()
    shown = subprocess.run(["git", "-C", str(repo), "show", "--name-only", "--format=", "HEAD"],
                           capture_output=True, text=True).stdout.split()
    assert shown == ["package.json"] and res["bundle"] and Path(res["bundle"]).exists()
