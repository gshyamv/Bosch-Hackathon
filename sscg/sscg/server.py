"""HTTP API for the React dashboard (sscg/web). Start it with:  python -m sscg serve  ->  http://127.0.0.1:8000

The API only reads the files the pipeline writes to out/<repo>/ and starts the same CLI commands the user would type
(`python -m sscg scan|agent|approve`) as background jobs, so the dashboard can never do anything the CLI cannot.
It listens on 127.0.0.1 by default: it can start scans of local folders, so it must not be exposed to a network.
"""
from __future__ import annotations

import itertools
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from functools import lru_cache
from pathlib import Path

import networkx as nx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import okf, safety
from .cache import ROOT
from .export import render_html
from .model import NON_LIBRARY
from .target import LiveTarget

OUT = ROOT / "out"
TARGETS = ROOT.parent / "targets"
WEB = ROOT / "web" / "dist"
NAME = re.compile(r"^[\w.-]+$")
FILE_TYPES = {".json": "application/json", ".html": "text/html; charset=utf-8", ".md": "text/markdown; charset=utf-8",
              ".pdf": "application/pdf", ".patch": "text/x-diff; charset=utf-8", ".mmd": "text/plain; charset=utf-8"}
LLM_CHOICES = ("auto", "claude", "gemini", "groq", "deepseek", "grok", "ollama", "none")
DECISIONS = ("approve", "reject", "accept_risk", "request_changes")
GRAPH_VIEWS = ("levels", "direct", "subtree", "full")
LAYERED_MAX = 300
MAX_LOG_LINES = 4000

app = FastAPI(title="Software Supply Chain Guardian API", version="1.0")


# ------------------------------------------------------------------ helpers
def _read(p: Path):
    return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else None


def project_dir(name: str) -> Path:
    if not NAME.match(name or ""):
        raise HTTPException(400, "invalid project name")
    d = OUT / name
    if not d.is_dir():
        raise HTTPException(404, f"no results for '{name}': scan it first")
    return d


def _mtime(p: Path) -> float | None:
    return p.stat().st_mtime if p.exists() else None


# ------------------------------------------------------------------ background jobs (CLI subprocesses)
JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()


def _pump(job: dict, proc: subprocess.Popen) -> None:
    for line in proc.stdout:   # type: ignore[union-attr]
        job["lines"].append(line.rstrip("\n"))
        if len(job["lines"]) > MAX_LOG_LINES:
            del job["lines"][: len(job["lines"]) - MAX_LOG_LINES]
    job["returncode"] = proc.wait()
    job["status"] = "ok" if job["returncode"] == 0 else "failed"
    job["ended"] = time.time()


def start_job(kind: str, project: str, cmd: list[str]) -> dict:
    with JOBS_LOCK:
        if any(j["project"] == project and j["status"] == "running" for j in JOBS.values()):
            raise HTTPException(409, f"a job is already running for '{project}'")
        env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"}
        proc = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace")
        job = {"id": uuid.uuid4().hex[:12], "kind": kind, "project": project, "status": "running", "returncode": None,
               "started": time.time(), "ended": None, "lines": [],
               "command": " ".join(["python", "-m", "sscg", *cmd[3:]])}
        JOBS[job["id"]] = job
    threading.Thread(target=_pump, args=(job, proc), daemon=True).start()
    return job


def job_view(job: dict, since: int = 0) -> dict:
    return {k: v for k, v in job.items() if k != "lines"} | {"lines": job["lines"][since:], "line_count": len(job["lines"])}


# ------------------------------------------------------------------ meta
@app.get("/api/health")
def health():
    return {"ok": True}


@app.get("/api/meta")
def meta():
    from .agents import config
    config.load_env()
    default = (os.getenv("SSCG_LLM_PROVIDER") or "auto").strip().lower()
    return {"llm_choices": LLM_CHOICES,
            "llm_default": default if default in LLM_CHOICES else "auto",
            "llm_keys": {p: bool(config.api_key(p)) for p in config.PROVIDERS}}   # never the key itself


@app.get("/api/targets")
def targets():
    presets = [{"name": d.name, "path": str(d)} for d in sorted(TARGETS.iterdir()) if d.is_dir()] if TARGETS.is_dir() else []
    projects = []
    if OUT.is_dir():
        for d in sorted(OUT.iterdir()):
            if d.is_dir() and (d / "summary.json").is_file():
                pend = _read(d / "remediation" / "pending.json")
                projects.append({"name": d.name, "scanned_at": _mtime(d / "summary.json"),
                                 "has_findings": (d / "findings.json").is_file(),
                                 "has_agentic": (d / "agentic.json").is_file(),
                                 "remediation": "pending" if pend else ("done" if (d / "remediation" / "remediation.json").is_file() else None),
                                 "repo": (pend or {}).get("repo")})
    return {"presets": presets, "projects": projects}


# ------------------------------------------------------------------ project data
@app.get("/api/projects/{name}")
def project(name: str):
    d = project_dir(name)
    findings = _read(d / "findings.json")
    agentic = _read(d / "agentic.json")
    if agentic:
        agentic.pop("remediation", None)            # the remediation state is served from remediation/ below
        agentic["stale"] = bool(findings and _mtime(d / "agentic.json") < _mtime(d / "findings.json") - 5)
    pending = _read(d / "remediation" / "pending.json")
    files = sorted(p.relative_to(d).as_posix() for p in d.rglob("*")
                   if p.is_file() and p.suffix in FILE_TYPES and ".sscg-state" not in p.parts)
    return {"name": name, "scanned_at": _mtime(d / "summary.json"), "summary": _read(d / "summary.json"),
            "findings": findings, "agentic": agentic, "pending": pending,
            "remediation": None if pending else _read(d / "remediation" / "remediation.json"), "files": files}


@app.get("/api/projects/{name}/sbom")
def sbom(name: str):
    bom = _read(project_dir(name) / "sbom.cdx.json")
    if not bom:
        raise HTTPException(404, "no SBOM")
    return bom


@app.get("/api/projects/{name}/files/{path:path}")
def project_file(name: str, path: str, download: bool = False):
    d = project_dir(name).resolve()
    f = (d / path).resolve()
    if not f.is_relative_to(d) or f.suffix not in FILE_TYPES or ".sscg-state" in f.parts:
        raise HTTPException(404, "not found")
    if not f.is_file() and f.name in ("report.html", "report.pdf") and (d / "report.md").is_file():
        from .report_export import to_html, to_pdf   # results scanned before these formats existed
        text = (d / "report.md").read_text(encoding="utf-8")
        body = to_html(text).encode("utf-8") if f.suffix == ".html" else to_pdf(text)
        return Response(body, media_type=FILE_TYPES[f.suffix], headers=_disposition(name, f, download))
    if not f.is_file():
        raise HTTPException(404, "not found")
    return FileResponse(f, media_type=FILE_TYPES[f.suffix], headers=_disposition(name, f, download))


def _disposition(name: str, f: Path, download: bool) -> dict:
    return {"Content-Disposition": f'attachment; filename="{name}.{f.name}"'} if download else {}


# ------------------------------------------------------------------ dependency graph
@lru_cache(maxsize=8)
def _graph(path: str, mtime: float) -> nx.DiGraph:
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    G = nx.DiGraph()
    for n in d["nodes"]:
        G.add_node(n["id"], **{k: v for k, v in n.items() if k != "id"})
    for e in d["edges"]:
        G.add_edge(e["source"], e["target"], **{k: v for k, v in e.items() if k not in ("source", "target")})
    return G


def load_graph(name: str) -> nx.DiGraph:
    p = project_dir(name) / "graph.json"
    if not p.is_file():
        raise HTTPException(404, "no graph")
    return _graph(str(p), p.stat().st_mtime)


def _library(G, n, libs_only: bool) -> bool:
    a = G.nodes[n]
    return a["kind"] == "package" and (not libs_only or a["ecosystem"] not in NON_LIBRARY)


def _top(G) -> str:
    return next(n for n in G if n.startswith("repo:"))


def _below(G, n) -> int:
    return sum(1 for d in nx.descendants(G, n) if _library(G, d, True))


@app.get("/api/projects/{name}/graph/meta")
def graph_meta(name: str, libs_only: bool = True):
    G = load_graph(name)
    directs = sorted(({"id": n, "label": G.nodes[n]["label"], "transitive": _below(G, n),
                       "depth_below": max(nx.single_source_shortest_path_length(G, n).values())}
                      for n in G if G.nodes[n].get("direct") and _library(G, n, libs_only)),
                     key=lambda x: -x["transitive"])
    depths = [G.nodes[n].get("depth") or 0 for n in G if _library(G, n, True)]
    return {"directs": directs, "max_depth": max(depths or [1]), "nodes": G.number_of_nodes(),
            "edges": G.number_of_edges()}


@app.get("/api/projects/{name}/graph/view", response_class=HTMLResponse)
def graph_view(name: str, mode: str = Query("levels"), levels: int = Query(1, ge=1, le=50), libs_only: bool = True,
               root: str | None = None):
    """One interactive graph view as a standalone HTML page (shown in a sandboxed iframe)."""
    if mode not in GRAPH_VIEWS:
        raise HTTPException(400, "unknown view")
    if mode == "full":
        return HTMLResponse((project_dir(name) / "graph.html").read_text(encoding="utf-8"))
    G = load_graph(name)
    top = _top(G)
    if mode == "subtree":
        if root not in G:
            raise HTTPException(400, "pick a direct dependency")
        dist = nx.single_source_shortest_path_length(G, root)
        pk = {n for n in dist if _library(G, n, libs_only) and dist[n] <= levels}
    else:
        lim = 1 if mode == "direct" else levels
        pk = {n for n in G if _library(G, n, libs_only) and (G.nodes[n].get("depth") or 99) <= lim}
    apps = {p for n in pk for p in G.predecessors(n) if G.nodes[p]["kind"] == "app"}
    H = G.subgraph({top} | apps | pk).copy()
    if mode == "subtree":
        for n in pk:
            H.nodes[n]["_level"] = dist[n] + 2
    if mode == "direct":
        for n in pk:
            H.nodes[n]["label"] = f"{H.nodes[n]['label']}  (+{_below(G, n)})"
    shown = [n for n in H if H.nodes[n]["kind"] == "package"]
    html = render_html(H, mode="dependency", layered=len(shown) <= LAYERED_MAX, small_labels=len(shown) <= 250)
    return HTMLResponse(html, headers={"X-Graph-Nodes": str(len(shown)), "X-Graph-Edges": str(H.number_of_edges()),
                                       "X-Graph-Direct": str(sum(1 for n in shown if H.nodes[n].get("direct"))),
                                       "X-Graph-Layered": str(len(shown) <= LAYERED_MAX).lower()})


@app.get("/api/projects/{name}/why")
def why(name: str, q: str = Query(..., min_length=1, max_length=200)):
    """'Why is this package here?': up to five dependency paths from the repository to each matching package."""
    G = load_graph(name)
    top = _top(G)
    hits = []
    for h, a in G.nodes(data=True):
        if str(a.get("name", "")).lower() != q.strip().lower():
            continue
        paths = [[G.nodes[x]["label"] for x in p[1:]] for p in itertools.islice(nx.shortest_simple_paths(G, top, h), 5)]
        hits.append({"id": h, "label": a["label"], "ecosystem": a.get("ecosystem"), "scope": a.get("scope"),
                     "origin": a.get("resolved") or a.get("source"), "findings": a.get("findings") or [], "paths": paths})
    return {"query": q, "hits": hits}


# ------------------------------------------------------------------ actions: scan / agent / approve
class RunRequest(BaseModel):
    repo: str = Field(..., min_length=1, max_length=1000)
    agentic: bool = False
    llm: str = "auto"
    remediate: bool = False
    osv: bool = True
    offline: bool = False
    resolve_npm: bool = False
    base: str = Field("HEAD~1", max_length=200)
    focus: str = Field("", max_length=200)


@app.post("/api/runs")
def run(req: RunRequest):
    raw = req.repo.strip()
    if re.match(r"^(https?://|github\.com/)", raw):
        try:
            if "github.com/" in raw.split("//")[-1][:11]:
                o, n, _, sub = safety.parse_github_target(raw)
                repo = Path(f"{o}__{n}" + ("__" + re.sub(r"[^\w.-]", "_", sub) if sub else ""))
            else:
                safety.check_target(raw)
                repo = Path(LiveTarget(raw).name)
        except safety.SafetyError as e:
            raise HTTPException(400, str(e)) from None
        arg = raw
    elif raw.startswith("-"):
        raise HTTPException(400, "invalid target")
    else:
        repo = Path(raw).expanduser()
        if not repo.is_absolute():
            repo = (ROOT / repo).resolve()
        if not repo.is_dir():
            raise HTTPException(400, f"folder not found: {repo}")
        arg = str(repo)
    if req.base.strip():
        try:
            safety.check_rev(req.base.strip())
        except safety.SafetyError as e:
            raise HTTPException(400, str(e)) from None
    if req.llm not in LLM_CHOICES:
        raise HTTPException(400, "unknown LLM provider")
    name = repo.name
    if not NAME.match(name):
        raise HTTPException(400, "unsupported folder name")
    cmd = [sys.executable, "-m", "sscg", "agent" if req.agentic else "scan", arg, "--out", str(OUT / name),
           "--top", "0"]
    cmd += ["--base", req.base.strip()] if req.base.strip() else ["--no-diff"]
    cmd += [] if req.osv else ["--no-vulns"]
    cmd += ["--resolve-npm"] if req.resolve_npm else []
    cmd += ["--offline"] if req.offline else []
    cmd += ["--focus", req.focus.strip()] if req.focus.strip() else []
    if req.agentic:
        cmd += ["--llm", req.llm] + (["--remediate", "--decisions", "later"] if req.remediate else [])
    return job_view(start_job("agent" if req.agentic else "scan", name, cmd))


class ApproveRequest(BaseModel):
    decisions: dict[str, str]
    by: str = Field(..., min_length=1, max_length=100)
    reason: str = Field("", max_length=1000)


@app.post("/api/projects/{name}/approve")
def approve(name: str, req: ApproveRequest):
    d = project_dir(name)
    pend = _read(d / "remediation" / "pending.json")
    if not pend:
        raise HTTPException(409, "no run is waiting for approval")
    known = {p["proposal_id"] for p in pend["proposals"]}
    cmd = [sys.executable, "-m", "sscg", "approve", pend["repo"], "--out", str(d), "--run", pend["run_id"],
           "--by", req.by.strip(), "--reason", req.reason.strip() or "decided in the dashboard"]
    for dec in DECISIONS:
        ids = sorted(k for k, v in req.decisions.items() if v == dec and k in known)
        if ids:
            cmd += [f"--{dec.replace('_', '-')}", ",".join(ids)]
    return job_view(start_job("approve", name, cmd))


@app.get("/api/jobs")
def jobs():
    return [job_view(j, len(j["lines"])) for j in sorted(JOBS.values(), key=lambda j: -j["started"])]


@app.get("/api/jobs/{job_id}")
def job(job_id: str, since: int = Query(0, ge=0)):
    j = JOBS.get(job_id)
    if not j:
        raise HTTPException(404, "unknown job")
    return job_view(j, since)


@app.get("/api/jobs/{job_id}/events")
async def job_events(job_id: str, since: int = Query(0, ge=0)):
    """Server-sent events: the job's new console lines as they appear, then one final status."""
    import asyncio
    if job_id not in JOBS:
        raise HTTPException(404, "unknown job")

    async def stream():
        pos = since
        while True:
            v = job_view(JOBS[job_id], pos)
            pos = v["line_count"]
            yield f"data: {json.dumps(v)}\n\n"
            if v["status"] != "running":
                return
            await asyncio.sleep(0.4)
    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


# ------------------------------------------------------------------ OKF context bundle
def _concept(cid: str) -> tuple[dict, str]:
    try:
        return okf.Store().read(cid)
    except KeyError:
        raise HTTPException(404, "unknown concept") from None


@app.get("/api/okf/index")
def okf_index(dir: str = ""):
    st = okf.Store()
    return [st.card(c) for c in st.ids(dir.strip("/") + "/" if dir.strip("/") else "")]


@app.get("/api/okf/search")
def okf_search(q: str = Query(..., max_length=200), type: str | None = None, min_trust: str = "unverified", k: int = Query(10, ge=1, le=50)):
    return okf.Store().search(q, [type] if type else None, min_trust, k)


@app.get("/api/okf/lint")
def okf_lint():
    return {"problems": okf.Store().lint()}


@app.get("/api/okf/neighbors/{cid:path}")
def okf_neighbors(cid: str):
    _concept(cid)
    return okf.Store().neighbors(cid)


class VerifyRequest(BaseModel):
    by: str = Field(..., min_length=1, max_length=100, pattern=r"^[\w .@-]+$")


@app.post("/api/okf/concepts/{cid:path}/verify")
def okf_verify(cid: str, req: VerifyRequest):
    _concept(cid)
    okf.Store().verify(cid, req.by.strip())
    return okf.Store().card(cid)


@app.get("/api/okf/concepts/{cid:path}")
def okf_concept(cid: str):
    meta, body = _concept(cid)
    return {"id": cid, "meta": json.loads(json.dumps(meta, default=str)), "body": body, "trust": okf.trust(meta), "stale": okf.stale(meta)}


@app.get("/api/runs/{run_id}/okf.zip")
def okf_zip(run_id: str):
    if not re.fullmatch(r"[0-9a-f]{12}", run_id):
        raise HTTPException(400, "invalid run id")
    st = okf.Store()
    if not st.ids(f"scans/{run_id}/"):
        raise HTTPException(404, "unknown run")
    return Response(st.export(run_id), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="okf-{run_id}.zip"'})


# ------------------------------------------------------------------ the built React app (npm run build in sscg/web)
if WEB.is_dir():
    app.mount("/assets", StaticFiles(directory=WEB / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        if full_path.startswith("api/"):
            return JSONResponse({"detail": "not found"}, status_code=404)
        f = (WEB / full_path).resolve()
        if full_path and f.is_file() and f.is_relative_to(WEB.resolve()):
            return FileResponse(f)
        return FileResponse(WEB / "index.html")
else:
    @app.get("/", include_in_schema=False)
    def no_ui():
        return HTMLResponse("<h3>Supply Chain Guardian API is running.</h3><p>The web UI is not built yet: run "
                            "<code>npm install &amp;&amp; npm run build</code> in <code>sscg/web</code>, or use "
                            "<code>npm run dev</code> there for development.</p>")


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    import uvicorn
    print(f"Supply Chain Guardian dashboard: http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="warning")
