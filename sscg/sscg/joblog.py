"""Persistent job logs for the dashboard's Logs page.

Every background job (scan / agent / approve) started by the API writes its complete console output to
out/<project>/logs/<YYYYmmdd-HHMMSS>_<kind>_<jobid>.log as the lines arrive (one `<iso time>\t<line>` per line),
plus a small .json meta file (kind, project, command, started, ended, returncode, status, lines). The in-memory job
keeps only the last lines; these files are the full record and survive server restarts.

Log lines are parsed into {ts, tag, stage, kind, message}: agents print `  [Tag] message` (agents/runtime.py log)
and bus handoffs `  [Bus] Sender → Recipient (kind): content` (agents/bus.py).
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

LOG_NAME = re.compile(r"^[\w.-]+\.log$")
_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T[\d:.]+(?:[+-]\d{2}:\d{2}|Z)?$")
_TAG = re.compile(r"^\s*\[([^\]\n]{1,60})\]\s?(.*)$")
_BUS = re.compile(r"^(.+?) → (.+?) \((\w+)\):\s?(.*)$")
_HEADER = re.compile(r"^\s*=== (.+?) ===\s*$")
_SUMMARY = re.compile(r"^\s*([①②③④⑤])\s")
_ERROR = re.compile(r"Traceback \(most recent call last\)|^\s*(error|ERROR|Error)\b|^\s*!\s|\w+Error: |\bException\b")
_DECISION = re.compile(r"PAUSED for human approval|LLM disabled|verdict|Validation: |decisions: ", re.I)
META_KEYS = ("id", "kind", "project", "command", "started", "ended", "returncode", "status")


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


class JobLog:
    """Appends one job's console lines to its log file. Never raises: logging must not break a job."""

    def __init__(self, project_out: Path, job: dict):
        d = project_out / "logs"
        d.mkdir(parents=True, exist_ok=True)
        stem = f"{datetime.fromtimestamp(job['started']).strftime('%Y%m%d-%H%M%S')}_{job['kind']}_{job['id']}"
        self.path, self.meta_path = d / f"{stem}.log", d / f"{stem}.json"
        self.meta = {k: job.get(k) for k in META_KEYS} | {"lines": 0}
        self._f = open(self.path, "a", encoding="utf-8")
        self._save_meta()

    def write(self, line: str) -> None:
        try:
            self._f.write(f"{_now()}\t{line}\n")
            self._f.flush()
            self.meta["lines"] += 1
        except Exception:  # noqa: BLE001
            pass

    def close(self, job: dict) -> None:
        try:
            self._f.close()
        except Exception:  # noqa: BLE001
            pass
        self.meta.update({k: job.get(k) for k in ("ended", "returncode", "status")})
        self._save_meta()

    def _save_meta(self) -> None:
        try:
            tmp = self.meta_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self.meta, indent=1), encoding="utf-8")
            tmp.replace(self.meta_path)
        except Exception:  # noqa: BLE001
            pass


def open_log(project_out: Path, job: dict) -> JobLog | None:
    try:
        return JobLog(project_out, job)
    except Exception:  # noqa: BLE001
        return None


def _meta_for(log: Path) -> dict:
    meta = {}
    try:
        meta = json.loads(log.with_suffix(".json").read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        pass
    if not meta:   # no meta file: recover what the file name says (<stamp>_<kind>_<id>)
        parts = log.stem.split("_")
        meta = {"id": parts[-1] if len(parts) >= 3 else log.stem, "kind": parts[-2] if len(parts) >= 3 else "job",
                "started": log.stat().st_ctime, "ended": log.stat().st_mtime, "status": "unknown"}
    return meta


def list_logs(out: Path, running: set[str]) -> list[dict]:
    """Every persisted job log across projects, newest first. `running` = ids of jobs still alive in this server."""
    rows = []
    if not out.is_dir():
        return rows
    for log in out.glob("*/logs/*.log"):
        if LOG_NAME.match(log.name):
            rows.append(log_row(log, running))
    return sorted(rows, key=lambda r: -(r.get("started") or 0))


def log_row(log: Path, running: set[str]) -> dict:
    m = _meta_for(log)
    status = m.get("status") or "unknown"
    if status == "running" and m.get("id") not in running:
        status = "interrupted"    # the server stopped while it ran
    return {**{k: m.get(k) for k in META_KEYS}, "status": status, "project": log.parent.parent.name,
            "file": log.name, "size": log.stat().st_size, "lines": m.get("lines")}


def read_lines(log: Path) -> list[tuple[str | None, str]]:
    """(timestamp, text) per line; a partly written last line is left out."""
    text = log.read_text(encoding="utf-8", errors="replace")
    if text and not text.endswith("\n"):
        text = text[: text.rfind("\n") + 1]
    rows = []
    for raw in text.splitlines():
        ts, sep, rest = raw.partition("\t")
        rows.append((ts, rest) if sep and _TS.match(ts) else (None, raw))
    return rows


def parse(rows: list[tuple[str | None, str]]) -> list[dict]:
    """Structure the console lines: tag (who printed it), stage (the agent it belongs to), kind and message."""
    out, prev_tag, stage = [], None, None
    for n, (ts, text) in enumerate(rows):
        rec = {"n": n, "ts": ts, "text": text, "tag": None, "stage": None, "kind": "text", "message": text.strip(),
               "transition": False}
        m, h = _TAG.match(text), _HEADER.match(text)
        if h:
            title = h.group(1)
            tag = "Scan" if title.startswith("Guardian scan") else "Orchestrator" if title.startswith("Guardian agents") \
                else "Human Approval" if "resuming" in title else None
            rec.update(kind="header", tag=tag, stage=tag, message=title)
            prev_tag = tag
        elif m:
            tag, msg = m.group(1).strip(), m.group(2)
            rec.update(tag=tag, stage=tag, kind="agent", message=msg)
            if tag == "Bus":
                b = _BUS.match(msg)
                if b:
                    rec.update(stage=b.group(1), kind=b.group(3), message=b.group(4), **{"from": b.group(1), "to": b.group(2)})
            prev_tag = tag
        elif _SUMMARY.match(text):
            rec.update(tag="Scan", stage="Scan", kind="summary")
            prev_tag = "Scan"
        elif text.startswith("    ") and prev_tag and prev_tag != "Bus":
            rec.update(tag=prev_tag, stage=prev_tag, kind="detail")   # continuation of the previous tagged line
        elif not text.strip():
            prev_tag = None
        if _ERROR.search(text):
            rec["kind"] = "error"
        elif rec["kind"] in ("agent", "detail") and _DECISION.search(text):
            rec["kind"] = "decision"
        if rec["stage"] and rec["stage"] != stage and rec["kind"] != "detail":
            rec["transition"], stage = True, rec["stage"]
        out.append(rec)
    return out
