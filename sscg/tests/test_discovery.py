import socket

import httpx
import pytest
from conftest import FIX

from sscg import cache, pipeline
from sscg.discover import discover
from sscg.model import DepGraph
from sscg.safety import SafetyError, check_target
from sscg.sbom import read_cyclonedx, write_cyclonedx
from sscg.target import LiveTarget
from sscg.vulns import _ver


@pytest.fixture(scope="module")
def eco():
    dg = DepGraph("eco")
    for d in ("ruby", "rust", "go", "dotnet", "uv"):
        discover(FIX / "eco" / d, dg)
    return dg


@pytest.mark.parametrize("pid,direct", [
    ("pkg:gem/rails@6.0.0", True), ("pkg:gem/rack@2.0.7", False), ("pkg:cargo/time@0.1.45", True),
    ("pkg:cargo/time@0.3.0", False), ("pkg:golang/github.com/gin-gonic/gin@v1.6.0", True),
    ("pkg:nuget/Newtonsoft.Json@12.0.1", True), ("pkg:pypi/flask@2.0.0", True), ("pkg:pypi/werkzeug@2.0.1", False)])
def test_ecosystems(eco, pid, direct):
    assert eco.G.nodes[pid]["direct"] is direct


def test_scopes(eco):
    assert eco.G.nodes["pkg:pypi/pytest@8.0.0"]["scope"] == "dev"
    assert not any("error in" in n for n in eco.notes)
    assert _ver("go", "v1.2.0") == "1.2.0" and _ver("cargo", "1.0") == "1.0"


def test_sbom_roundtrip(eco, tmp_path):
    write_cyclonedx(eco, tmp_path / "b.json")
    dg = DepGraph("eco")
    read_cyclonedx(dg, tmp_path / "b.json")
    pk = lambda g: {n for n, a in g.G.nodes(data=True) if a["kind"] == "package"}  # noqa: E731
    assert pk(dg) == pk(eco)


IPS = {"shop.example": "93.184.216.34", "code.jquery.com": "151.101.2.132", "cdnjs.cloudflare.com": "104.17.24.14",
       "maxcdn.bootstrapcdn.com": "104.18.10.207", "redir.example": "93.184.216.35", "intranet.example": "10.0.0.5",
       "secure.example": "93.184.216.36", "localhost": "127.0.0.1", "cgnat.example": "100.64.0.1"}


@pytest.fixture
def net(monkeypatch):
    monkeypatch.setattr(cache, "OFFLINE", False)
    monkeypatch.setattr("sscg.registry.versions", lambda e, n: ["9.0.0"])
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, *a, **k: [(2, 1, 6, "", (IPS.get(h, h), 0))])

    def handler(req):
        u = str(req.url)
        assert req.method == "GET" and "intranet" not in u
        if u == "https://shop.example/":
            return httpx.Response(200, text=(FIX / "live/legacy.html").read_text(encoding="utf-8"))
        if u.endswith("vendor.js"):
            return httpx.Response(200, text=(FIX / "live/js/vendor.js").read_text(encoding="utf-8"))
        if u.startswith("https://redir"):
            return httpx.Response(302, headers={"location": "http://intranet.example/"})
        if u == "https://secure.example/":
            return httpx.Response(200, text='<script src="http://shop.example/jquery-3.4.1.min.js"></script>')
        return httpx.Response(200, text="/* */")
    return httpx.MockTransport(handler)


def scan(url, net, tmp_path):
    t = LiveTarget(url, tmp_path, net)
    dg = pipeline.build(t, check_vulns=False)
    return dg, pipeline.detect(t, dg, "HEAD~1")[0]


def test_live_page(net, tmp_path):
    dg, fs = scan("https://shop.example/", net, tmp_path)
    assert {a["label"] for _, a in dg.G.nodes(data=True) if a["kind"] == "package"} == \
        {"jquery@1.12.4", "angular@1.5.0", "bootstrap@3.3.7", "lodash@4.17.4"}
    rules = [f["rule"] for f in fs]
    assert rules.count("R20_MISSING_SRI") == 2 and rules.count("R22_OUTDATED_JS_LIBRARY") == 4
    assert all(f["permalink"] == "https://shop.example/" for f in fs if f["location"])


def test_insecure_script(net, tmp_path):
    assert "R21_INSECURE_SCRIPT" in [f["rule"] for f in scan("https://secure.example/", net, tmp_path)[1]]


def test_redirect_to_private_refused(net, tmp_path):
    with pytest.raises(SafetyError, match="non-public"):
        LiveTarget("https://redir.example/", tmp_path, net).head_dir()


@pytest.mark.parametrize("u", ["http://localhost/", "http://127.0.0.1/", "http://10.0.0.5/", "http://169.254.169.254/",
                               "http://[::ffff:127.0.0.1]/", "http://cgnat.example/", "file:///etc/passwd",
                               "http://a:b@shop.example/"])
def test_ssrf(u, net):
    with pytest.raises(SafetyError):
        check_target(u, False)
