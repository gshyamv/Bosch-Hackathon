"""Per-run objects that must not live in the LangGraph state.

The state is checkpointed (MemorySaver now, SQLite/Postgres later), so it holds only JSON-safe data. The live
DepGraph, the diff.Change object and the LLM client live here, looked up by the run_id stored in the state.
If a run is resumed in a new process (e.g. approval hours later), rebuild the Runtime from out/<repo>/ files.
"""
from __future__ import annotations

import functools
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .config import AgentSettings
from .kb import KnowledgeBase


@dataclass
class Runtime:
    run_id: str
    repo: Path
    out: Path
    settings: AgentSettings
    kb: KnowledgeBase
    target: object = None         # target.Target (repo = target.head_dir())
    llm: object = None            # llm.LLM or None (rules-only fallback)
    dg: object = None             # model.DepGraph, set by the Discovery agent
    fs: list = field(default_factory=list)   # findings with internal keys, set by the Detection agent
    change: object = None         # diff.Change or None
    labels: set = field(default_factory=set)  # every component label (for the grounding check)
    emitted: dict | None = None   # pipeline.emit() result, set by the Reporter
    llm_disabled: str | None = None   # circuit breaker: set after a fatal LLM error (bad model / key / quota)
    ctx: object = None            # context.Context (notes + OKF) or None
    quiet: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)

    def log(self, agent: str, msg: str) -> None:
        if not self.quiet:
            with self.lock:
                print(f"  [{agent}] {msg}", flush=True)

    def note(self, fn) -> None:
        """Context-store writes must never break a run."""
        if self.ctx is None:
            return
        try:
            with self.lock:
                fn(self.ctx)
        except Exception as e:  # noqa: BLE001
            self.log("Context", f"note not stored: {type(e).__name__}: {str(e)[:120]}")

    def usable_llm(self):
        """The LLM client, or None when there is none or the circuit breaker tripped."""
        return None if self.llm_disabled else self.llm

    def trip(self, agent: str, err) -> None:
        """Fatal error: stop calling the LLM for the rest of this run (instead of failing every call)."""
        with self.lock:
            first = self.llm_disabled is None
            if first:
                self.llm_disabled = str(err)
        if first:
            self.log(agent, f"LLM disabled for the rest of this run: {err}")


_RUNTIMES: dict[str, Runtime] = {}


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def traced(agent: str, kind: str):
    """Node decorator: times the node and appends one audit record to state['agent_runs'].

    A node may return a private '_run' dict (tokens, finding_id, status ...) that is merged into the record.
    """
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(state, *a, **kw):
            started, t = now(), time.perf_counter()
            update = fn(state, *a, **kw) or {}
            extra = update.pop("_run", {})
            rec = {"agent": agent, "kind": kind, "node": fn.__name__, "started": started,
                   "seconds": round(time.perf_counter() - t, 2), "status": "ok", **extra}
            update["agent_runs"] = update.get("agent_runs", []) + [rec]
            if isinstance(state, dict) and state.get("run_id"):
                from . import bus
                if fn.__name__ == "plan":
                    bus.reset(state["run_id"])
                kind_ = "decision" if fn.__name__ in ("triage_one", "human_approval") else "handoff"
                bus.post(state["run_id"], agent, bus.NEXT.get(fn.__name__, "Triage join"), kind_,
                         bus.summary(update, extra), refs=[extra["finding_id"]] if extra.get("finding_id") else [],
                         iteration=int((state.get("options") or {}).get("iteration") or 0))
            return update
        return wrapper
    return deco


def register(rt: Runtime) -> Runtime:
    _RUNTIMES[rt.run_id] = rt
    return rt


def get(run_id: str) -> Runtime:
    try:
        return _RUNTIMES[run_id]
    except KeyError:
        raise RuntimeError(f"no runtime for run {run_id}: resume in the same process, or rebuild it from the "
                           "scan outputs first") from None


def release(run_id: str) -> None:
    rt = _RUNTIMES.pop(run_id, None)
    if rt and rt.ctx:
        rt.ctx.close()
