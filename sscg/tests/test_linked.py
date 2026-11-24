"""A live page linked to its GitHub source repository: one graph, remediation on the source."""
import socket

import httpx
import pytest
from conftest import FIX
from test_intake import SHA, handler

from sscg import cache, pipeline, server
from sscg.__main__ import _link
from sscg.intake.github import GitHubClient
from sscg.safety import SafetyError
from sscg.target import LinkedTarget

PAGE = "https://shop.example/#/search"


@pytest.fixture
def online(monkeypatch):
    monkeypatch.setattr(cache, "OFFLINE", False)
    monkeypatch.setattr("sscg.registry.versions", lambda e, n: ["9.0.0"])
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])
    monkeypatch.setattr("time.sleep", lambda s: None)


def live(status=200):
    def h(req):
        u = str(req.url)
        if status != 200:
            return httpx.Response(status)
        if u == "https://shop.example/":
            return httpx.Response(200, text=(FIX / "live/legacy.html").read_text(encoding="utf-8"))
        if u.endswith("vendor.js"):
            return httpx.Response(200, text=(FIX / "live/js/vendor.js").read_text(encoding="utf-8"))
        return httpx.Response(200, text="/* */")
    return httpx.MockTransport(h)


def linked(tmp_path, status=200):
    return LinkedTarget(PAGE, "https://github.com/o/r", GitHubClient("tok", httpx.MockTransport(handler)), tmp_path,
                        live(status))


def test_linked_graph_and_findings(online, tmp_path):
    t = linked(tmp_path)
    assert (t.kind, t.name, t.sha, t.checkout_url()) == ("github", "o__r", SHA, ("https://github.com/o/r.git", SHA))
    assert t.source == f"https://github.com/o/r@{SHA}" and t.owner == "o"
    dg = pipeline.build(t, check_vulns=False)
    labels = {a["label"] for _, a in dg.G.nodes(data=True) if a["kind"] == "package"}
    assert {"x@1.0.0", "jquery@1.12.4", "lodash@4.17.4"} <= labels
    assert any(a.get("ecosystem") == "live-page" for _, a in dg.G.nodes(data=True))
    fs, _ = pipeline.detect(t, dg, "HEAD~1")
    rules = {f["rule"]: f for f in fs}
    assert rules["R05_LOCKFILE_UNTRUSTED_SOURCE"]["permalink"].startswith(f"https://github.com/o/r/blob/{SHA}/")
    assert rules["R20_MISSING_SRI"]["permalink"] == "https://shop.example/"
    assert not (t.head_dir() / "page.html").exists()          # the source checkout is not touched


def test_live_failure_is_a_note(online, tmp_path):
    dg = pipeline.build(linked(tmp_path, 503), check_vulns=False)
    assert any("not scanned" in n and "503" in n for n in dg.notes)
    assert "x@1.0.0" in {a["label"] for _, a in dg.G.nodes(data=True)}
    assert not any(a.get("ecosystem") == "live-page" for _, a in dg.G.nodes(data=True))


def test_rejects_non_live_target(tmp_path):
    with pytest.raises(SafetyError):
        LinkedTarget("https://github.com/o/r", "https://github.com/o/r", work=tmp_path)


def test_cli_link_skips_without_source():
    class A:
        repo, source, offline = "https://shop.example/", None, True
    _link(A)
    assert A.repo == "https://shop.example/"


def test_server_passes_source(online, monkeypatch):
    from fastapi.testclient import TestClient
    seen = {}
    monkeypatch.setattr(server, "start_job", lambda kind, name, cmd: seen.update(name=name, cmd=cmd) or "job")
    monkeypatch.setattr(server, "job_view", lambda j: {"id": j})
    cl = TestClient(server.app)
    r = cl.post("/api/runs", json={"repo": PAGE, "source": "https://github.com/juice-shop/juice-shop"})
    assert r.status_code == 200 and seen["name"] == "juice-shop__juice-shop"
    assert seen["cmd"][seen["cmd"].index("--source") + 1] == "https://github.com/juice-shop/juice-shop"
    assert cl.post("/api/runs", json={"repo": PAGE, "source": "https://evil.com/x"}).status_code == 400
    assert cl.post("/api/runs", json={"repo": "https://github.com/o/r", "source": "https://github.com/o/r"}).status_code == 400
