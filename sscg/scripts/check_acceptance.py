"""Scan pinned targets and compare with expected results:  python scripts/check_acceptance.py [--offline]"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sscg import cache, pipeline  # noqa: E402
from sscg.agents.config import load_env  # noqa: E402

# target, {minimum counts}; counts are minimums because OSV keeps adding advisories
CASES = [
    ("../targets/nodejs-goof", {"packages": 900, "vulnerabilities": 130, "anomalies": 15}),
    ("https://github.com/juice-shop/juice-shop@c9f99228d9d56afb5f5ca7925376292f7fa44b13",
     {"packages": 1500, "vulnerabilities": 50, "anomalies": 20, "permalinks": 20}),
    ("https://github.com/OWASP/railsgoat", {"packages": 100, "vulnerabilities": 10}),
]


def main() -> int:
    load_env()
    cache.OFFLINE = "--offline" in sys.argv
    bad = 0
    for tgt, want in CASES:
        try:
            if not tgt.startswith("http"):
                tgt = Path(__file__).resolve().parents[1] / tgt
                if not any(tgt.iterdir()):
                    print(f"SKIP {tgt}: empty folder (see README: getting the sample applications)")
                    continue
            t = pipeline.as_target(tgt)
            dg = pipeline.build(t)
            fs, _ = pipeline.detect(t, dg, None)
        except Exception as e:  # noqa: BLE001
            print(f"FAIL {tgt}: {type(e).__name__}: {e}")
            bad += 1
            continue
        got = {"packages": sum(a["kind"] == "package" for _, a in dg.G.nodes(data=True)),
               "vulnerabilities": sum(f["category"] == "vulnerability" for f in fs),
               "anomalies": sum(f["category"] == "anomaly" for f in fs), "permalinks": sum("permalink" in f for f in fs)}
        ok = all(got[k] >= v for k, v in want.items())
        bad += not ok
        print(f"{'PASS' if ok else 'FAIL'} {t.display}: {got}" + ("" if ok else f" expected at least {want}"))
    return bad


if __name__ == "__main__":
    sys.exit(main())
