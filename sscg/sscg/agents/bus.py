"""Agent message bus: the agents hand work to each other with explicit messages.

Every message is appended to out/<repo>/agent_messages.jsonl (served to the dashboard) and printed on the run log.
Kinds: handoff (work passed on), question (an agent asks another for evidence), answer, decision.
"""
from __future__ import annotations

import json

from .runtime import get, now

# node -> who it hands its result to (the graph routes; the message says what was passed and why)
NEXT = {
    "plan": "Discovery", "discovery": "Vulnerability Intel", "vuln_intel": "Detection", "detection": "Triage",
    "gather_evidence": "Triage", "triage_join": "Narrator", "narrate": "Reporter",
    "reporter": "Exploit Intel + Reachability", "exploit_intel": "Prioritizer", "reachability_scan": "Prioritizer",
    "prioritize": "Remediation Planner", "plan_remediation": "Remediation Advisor",
    "advise_remediation": "Human reviewer", "human_approval": "Validation (Docker sandbox)",
    "validate": "Remediation Reporter", "remediation_report": "Human reviewer",
}


def post(run_id: str, sender: str, recipient: str, kind: str, content: str, refs: list | None = None,
         iteration: int = 0) -> None:
    """Never breaks a run."""
    try:
        rt = get(run_id)
        msg = {"at": now(), "run_id": run_id, "iteration": iteration, "sender": sender, "recipient": recipient,
               "kind": kind, "content": content[:600], "refs": (refs or [])[:20]}
        with rt.lock:
            with open(rt.out / "agent_messages.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(msg) + "\n")
        rt.log("Bus", f"{sender} → {recipient} ({kind}): {content[:160]}")
    except Exception:  # noqa: BLE001
        pass


def reset(run_id: str) -> None:
    try:
        (get(run_id).out / "agent_messages.jsonl").unlink(missing_ok=True)
    except Exception:  # noqa: BLE001
        pass


def summary(update: dict, extra: dict) -> str:
    """One readable line of what a node produced."""
    bits = [f"{k} {v}" for k, v in extra.items() if isinstance(v, (int, float, str)) and k not in ("status",)][:6]
    for k in ("findings", "triage_queue", "proposals", "priorities", "clusters", "validations"):
        v = update.get(k)
        if isinstance(v, (list, dict)) and v:
            bits.append(f"{len(v)} {k.replace('_', ' ')}")
    return ", ".join(bits) or "done"
