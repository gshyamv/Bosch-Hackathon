"""Persisted job logs: out/<project>/logs/*.log + meta, the /api/logs endpoints and the line parser."""
import sys
import time

from fastapi.testclient import TestClient

from sscg import joblog, server

SCRIPT = ("print('=== Guardian agents: demo (run r1) ===');"
          "print('  [Discovery] 12 components');"
          "print('    lodash 4.17.20');"
          "print('  [Bus] Discovery → Vulnerability Intel (handoff): 12 components');"
          "[print('  [Detection] line', i) for i in range(30)];"
          "print('  [Human Approval] PAUSED for human approval: 1 proposal(s)')")


def test_job_log_persisted_and_served(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "OUT", tmp_path)
    monkeypatch.setattr(server, "MAX_LOG_LINES", 10)       # the in-memory view is truncated, the file is not
    (tmp_path / "demo").mkdir()
    job = server.start_job("agent", "demo", [sys.executable, "-c", SCRIPT])
    for _ in range(200):
        if job["status"] != "running":
            break
        time.sleep(0.05)
    assert job["status"] == "ok" and len(job["lines"]) == 10 and job["dropped"] == 25

    logs = list((tmp_path / "demo" / "logs").glob("*.log"))
    assert len(logs) == 1 and logs[0].name.endswith(f"_agent_{job['id']}.log")
    assert len(joblog.read_lines(logs[0])) == 35

    cl = TestClient(server.app)
    rows = cl.get("/api/logs").json()
    assert rows[0]["file"] == logs[0].name and rows[0]["project"] == "demo" and rows[0]["status"] == "ok"
    assert rows[0]["returncode"] == 0 and rows[0]["lines"] == 35

    doc = cl.get(f"/api/logs/demo/{logs[0].name}").json()
    lines = doc["lines"]
    assert len(lines) == 35 and all(x["ts"] for x in lines)
    assert lines[0]["kind"] == "header" and lines[0]["stage"] == "Orchestrator"
    assert lines[1]["tag"] == "Discovery" and lines[1]["transition"]
    assert lines[2]["kind"] == "detail" and lines[2]["stage"] == "Discovery"
    bus = lines[3]
    assert bus["tag"] == "Bus" and bus["kind"] == "handoff" and bus["from"] == "Discovery"
    assert bus["to"] == "Vulnerability Intel" and bus["message"] == "12 components"
    assert lines[-1]["kind"] == "decision" and lines[-1]["stage"] == "Human Approval"

    raw = cl.get(f"/api/logs/demo/{logs[0].name}?download=true")
    assert raw.status_code == 200 and "attachment" in raw.headers["content-disposition"] and "[Discovery]" in raw.text
    for bad in ("..%2f..%2fsecret.log", "x.json", "nope.log"):
        assert cl.get(f"/api/logs/demo/{bad}").status_code == 404, bad
    assert cl.get("/api/logs/..%2fdemo/a.log").status_code in (400, 404)


def test_interrupted_run(tmp_path):
    job = {"id": "abc", "kind": "scan", "project": "p", "started": time.time(), "status": "running"}
    log = joblog.open_log(tmp_path / "p", job)
    log.write("[Discovery] hi")
    log._f.close()
    rows = joblog.list_logs(tmp_path, running=set())
    assert rows[0]["status"] == "interrupted"
    assert joblog.list_logs(tmp_path, running={"abc"})[0]["status"] == "running"
