import json
import threading
from types import SimpleNamespace

from sscg import okf


def test_agents_post_handoffs_on_the_bus(tmp_path, monkeypatch):
    from sscg.agents import bus, runtime
    rt = SimpleNamespace(out=tmp_path, lock=threading.Lock(), log=lambda *a: None)
    monkeypatch.setitem(runtime._RUNTIMES, "r1", rt)

    @runtime.traced("Detection", "deterministic")
    def detection(state):
        return {"findings": [1, 2, 3], "_run": {"anomalies": 2}}

    @runtime.traced("Orchestrator", "deterministic")
    def plan(state):
        return {}

    (tmp_path / "agent_messages.jsonl").write_text('{"old": 1}\n', encoding="utf-8")
    plan({"run_id": "r1"})                       # a new run starts with an empty conversation
    detection({"run_id": "r1"})
    bus.post("r1", "Triage", "OKF Knowledge", "question", "F-001: run okf_search")
    msgs = [json.loads(x) for x in (tmp_path / "agent_messages.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [m["sender"] for m in msgs] == ["Orchestrator", "Detection", "Triage"]
    assert msgs[1]["recipient"] == "Triage" and "3 findings" in msgs[1]["content"] and "anomalies 2" in msgs[1]["content"]
    assert msgs[2]["kind"] == "question"


def test_okf_graph_has_linked_concepts(tmp_path, monkeypatch):
    from sscg import server
    st = okf.Store(tmp_path / "okf")
    monkeypatch.setattr(server.okf, "Store", lambda: st)
    g = server.okf_graph(None, 400)
    ids = {n["id"] for n in g["nodes"]}
    assert g["edges"] and all(e["source"] in ids and e["target"] in ids for e in g["edges"])
    assert "playbook" in g["types"]


def test_iteration_rows_follow_the_loop(tmp_path, monkeypatch):
    from sscg import server
    monkeypatch.setattr(server, "OUT", tmp_path)
    for name, n, after in (("app", 9, 4), ("app__iter1", 4, 1), ("app__iter2", 1, None), ("apple", 7, None)):
        (tmp_path / name / "remediation").mkdir(parents=True)
        (tmp_path / name / "findings.json").write_text(json.dumps({"findings": [{}] * n}), encoding="utf-8")
        if after is not None:
            (tmp_path / name / "remediation" / "post_analysis.json").write_text(
                json.dumps({"after": {"total": after}, "verdict": "verified"}), encoding="utf-8")
    rows = server._iterations("app__iter1")
    assert [(r["iteration"], r["findings"], r["after_fix"]) for r in rows] == [(0, 9, 4), (1, 4, 1), (2, 1, None)]


def test_priority_queue_orders_and_caps():
    from sscg.agents.pqueue import PriorityQueue
    q = PriorityQueue([("b", 5), ("a", 9), ("c", 9), ("d", 1)], key=lambda x: (-x[1],))
    q.push(("e", 7))
    assert [x[0] for x in q.take(3)] == ["a", "c", "e"] and len(q) == 2      # ties keep insertion order
