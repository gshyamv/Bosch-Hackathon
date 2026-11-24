from conftest import mkrepo

from sscg import cache, ossf_malicious as o, pipeline

PATHS = ["osv/malicious/npm/@evil/pkg/MAL-2024-1.json", "osv/malicious/pypi/Bad_Pkg/MAL-2024-2.json",
         "osv/malicious/npm/evilish/MAL-2024-3.json", "osv/withdrawn/npm/x/MAL-1.json", "README.md"]
REPORTS = {"MAL-2024-1": {"summary": "steals tokens", "affected": [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]},
           "MAL-2024-2": {"summary": "dropper", "affected": [{"versions": ["1.0.0"]}]}}


def test_parse_and_lookup(monkeypatch):
    idx = o.parse_paths(PATHS)
    assert idx["npm"]["@evil/pkg"] == [["@evil/pkg", "MAL-2024-1"]] and "bad-pkg" in idx["pypi"] and "x" not in idx["npm"]
    monkeypatch.setattr(o, "index", lambda: {"commit": "c" * 40, "ecosystems": idx})
    monkeypatch.setattr(cache, "http_json", lambda m, u, b=None: REPORTS.get(u.rsplit("/", 1)[1][:-5]))
    assert o.lookup("npm", "@evil/pkg", "9.9.9")[0]["version_checked"] is True          # every version
    assert o.lookup("pypi", "bad.pkg", "1.0.0")[0]["url"].endswith("/pypi/Bad_Pkg/MAL-2024-2.json")
    assert o.lookup("pypi", "bad-pkg", "2.0.0") == []                                   # other version: not affected
    r = o.lookup("npm", "evilish", "1.0.0")                                              # report not fetched
    assert r and r[0]["version_checked"] is False
    assert o.lookup("npm", "lodash", "4.17.21") == [] and o.lookup("hex", "x", "1") == []


def test_rule_uses_index(tmp_path, monkeypatch):
    idx = o.parse_paths(PATHS)
    monkeypatch.setattr(o, "index", lambda: {"commit": "c" * 40, "ecosystems": idx})
    monkeypatch.setattr(cache, "http_json", lambda m, u, b=None: REPORTS.get(u.rsplit("/", 1)[1][:-5]))
    repo = mkrepo(tmp_path / "r", {"requirements.txt": "bad_pkg==1.0.0\n"})
    dg = pipeline.build(repo, check_vulns=False)
    fs = [f for f in pipeline.detect(repo, dg, None)[0] if f["rule"] == "R02_KNOWN_MALICIOUS"]
    assert fs and any(e.get("id") == "MAL-2024-2" and e.get("source") == "OpenSSF Malicious Packages" for e in fs[0]["evidence"])
