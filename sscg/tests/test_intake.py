import httpx
import pytest

from sscg import cache, pipeline
from sscg.intake.github import FetchError, GitHubClient, select, wanted, wanted_source
from sscg.safety import SafetyError, check_rev, jail, parse_github_target
from sscg.target import GitHubTarget, LocalTarget, as_target

SHA, BASE = "a" * 40, "b" * 40
FILES = {"package.json": '{"name":"app","dependencies":{"x":"*"}}',
         "package-lock.json": '{"lockfileVersion":3,"packages":{"":{"dependencies":{"x":"*"}},\n"node_modules/x":'
                              '{"version":"1.0.0","resolved":"https://evil.example/x.tgz"}}}',
         "src/app.js": "require('x')", "test/t.js": "require('x')", "README.md": "hi",
         "..\\..\\evil/package.json": "{}", "node_modules/z/package.json": "{}"}
COMMIT = {"author": {"name": "A", "email": "a@x", "date": "2026-01-01T00:00:00Z"}, "message": "m\n\nbody"}


def handler(req):
    u = str(req.url)
    if u.endswith("/repos/o/r"):
        return httpx.Response(200, json={"default_branch": "main"})
    if u.endswith("/commits/main"):
        return httpx.Response(200, text=SHA)
    if "/compare/" in u:
        return httpx.Response(200, json={"files": [{"status": "added", "filename": "package-lock.json"}]})
    if "author=" in u:
        return httpx.Response(200, json=[])
    for s, par in ((SHA, [{"sha": BASE}]), (BASE, [])):
        if u.endswith(f"/commits/{s}"):
            return httpx.Response(200, json={"sha": s, "commit": COMMIT, "parents": par})
        if f"/git/trees/{s}" in u:
            names = FILES if s == SHA else ["package.json"]
            return httpx.Response(200, json={"tree": [{"path": p, "type": "blob", "size": 9} for p in names]
                                             + [{"path": "link/package.json", "type": "blob", "mode": "120000", "size": 1}]})
        if u.startswith(f"https://raw.githubusercontent.com/o/r/{s}/"):
            return httpx.Response(200, text=FILES[u.split(s + "/")[1]])
    return httpx.Response(404)


@pytest.fixture
def tgt(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "OFFLINE", False)
    return GitHubTarget("https://github.com/o/r", GitHubClient("tok", httpx.MockTransport(handler)), tmp_path)


def test_fetches_manifests_and_source_only(tgt):
    d = tgt.head_dir()
    assert sorted(p.relative_to(d).as_posix() for p in d.rglob("*") if p.is_file()) == \
        ["package-lock.json", "package.json", "src/app.js"]
    assert any("unsafe" in n for n in tgt.notes) and tgt.name == "o__r"


def test_pipeline_permalinks_and_base(tgt):
    dg = pipeline.build(tgt, check_vulns=False)
    fs, ch = pipeline.detect(tgt, dg, "HEAD~1")
    f = next(f for f in fs if f["rule"] == "R05_LOCKFILE_UNTRUSTED_SOURCE")
    assert f["permalink"] == f"https://github.com/o/r/blob/{SHA}/package-lock.json#L2"
    assert f["evidence"][0]["permalink"] == f["permalink"] and f["new_in_change"]
    assert ch.base["sha"] == BASE and ch.first_time_author is True and tgt.resolve("HEAD~2") is None


def test_offline_reuses_fetch(tgt, tmp_path, monkeypatch):
    tgt.head_dir()
    monkeypatch.setattr(cache, "OFFLINE", True)
    t2 = GitHubTarget("https://github.com/o/r", GitHubClient("", httpx.MockTransport(handler)), tmp_path)
    assert t2.sha == SHA and t2.head_dir().is_dir()


def test_host_allowlist_and_rate_limit(monkeypatch):
    monkeypatch.setattr(cache, "OFFLINE", False)
    c = GitHubClient("", httpx.MockTransport(lambda r: httpx.Response(403, headers={"x-ratelimit-remaining": "0"})))
    with pytest.raises(FetchError, match="rate limit"):
        c.api("/x")
    with pytest.raises(FetchError, match="host"):
        c.get("https://evil.example/")


def test_selection():
    assert wanted("a/Gemfile.lock") and wanted(".github/workflows/x.yml") and not wanted("node_modules/a/package.json")
    assert wanted_source("src/a.ts") and not wanted_source("test/a.ts") and not wanted_source("a.min.js")
    assert select([{"path": "a.js", "size": 10**9}])[1] == ["a.js"]


@pytest.mark.parametrize("u", ["https://github.com/o/r@--upload-pack=x", "https://github.com/../r", "https://evil.com/o/r",
                               "https://github.com/o/r/tree/main/../x", "https://github.com/o/r@a..b"])
def test_bad_targets(u):
    with pytest.raises(SafetyError):
        parse_github_target(u)


def test_parse_ok(tmp_path):
    assert parse_github_target("https://github.com/o/r@v1.2") == ("o", "r", "v1.2", None)
    assert parse_github_target("https://github.com/o/r/tree/v1/sub/app") == ("o", "r", "v1", "sub/app")
    assert isinstance(as_target(tmp_path), LocalTarget)
    with pytest.raises(SafetyError):
        check_rev("--output=x")


@pytest.mark.parametrize("p", ["../x", "/x", "a/../../x", "C:/x", "a\\..\\x", "aux.txt", "a//b"])
def test_jail(tmp_path, p):
    with pytest.raises(SafetyError):
        jail(tmp_path, p)
