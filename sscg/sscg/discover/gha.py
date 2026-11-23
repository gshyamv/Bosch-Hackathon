"""CI/CD inspection: GitHub Actions workflows (.github/workflows/*.yml).

Static only: nothing is executed. Recorded per workflow:
  * triggers ("on:") and token permissions
  * every action used (uses: owner/repo[/path]@ref) with its ref and whether it is pinned to a commit SHA
  * container / service images of jobs, and docker:// actions
  * remote files fetched in run steps (curl/wget ...)
"""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import quote

import yaml

from .docker import FETCH_RE, URL_RE, add_artifact, add_image, line_finder

SHA_RE = re.compile(r"[0-9a-f]{40}")


def is_workflow(parts: tuple) -> bool:
    return len(parts) == 3 and parts[:2] == (".github", "workflows") and parts[2].lower().endswith((".yml", ".yaml"))


def _permissions(p) -> str:
    if p is None:
        return "not set (repository default)"
    if isinstance(p, dict):
        return ", ".join(f"{k}: {v}" for k, v in p.items()) or "none"
    return str(p)


def add_action(dg, rid: str, uses: str, source: str, spec: str):
    if uses.startswith("./"):
        return  # local action: code inside this repository
    if uses.startswith("docker://"):
        add_image(dg, rid, uses[len("docker://"):], "ci", source, spec, "workflow")
        return
    path, _, ref = uses.partition("@")
    parts = path.split("/")
    owner, name, sub = parts[0], (parts[1] if len(parts) > 1 else ""), "/".join(parts[2:])
    nid = f"pkg:github/{quote(owner)}/{quote(name)}@{quote(ref, safe='')}" + (f"#{sub}" if sub else "")
    dg.pkg("github-actions", f"{owner}/{name}", ref, nid=nid, label=uses, scope="ci", source=source,
           resolution="workflow", resolved=f"https://github.com/{owner}/{name}",
           owner=owner, action_path=sub, ref=ref, pinned_to_sha=bool(SHA_RE.fullmatch(ref)))
    dg.dep(rid, nid, spec, direct=True, location=source)


def scan(dg, repo: Path, path: Path):
    rel = path.relative_to(repo).as_posix()
    text = path.read_text(encoding="utf-8", errors="replace")
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        dg.notes.append(f"skip {rel}: not a workflow mapping")
        return
    on = data.get("on", data.get(True))  # PyYAML reads the key `on:` as boolean True
    triggers = list(on) if isinstance(on, (dict, list)) else [on] if on else []
    rid = dg.app(rel, "github-actions", str(data.get("name") or path.stem))
    dg.G.nodes[rid].update(triggers=[str(t) for t in triggers], permissions=_permissions(data.get("permissions")))
    find = line_finder(text)

    for jid, job in (data.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        if isinstance(job.get("uses"), str):  # reusable workflow
            add_action(dg, rid, job["uses"], f"{rel}:{find(job['uses'])}", f"job {jid}")
        c = job.get("container")
        img = c.get("image") if isinstance(c, dict) else c
        if isinstance(img, str) and img:
            add_image(dg, rid, img, "ci", f"{rel}:{find(img)}", f"job {jid} container", "workflow")
        for svc, cfg in (job.get("services") or {}).items():
            img = cfg.get("image") if isinstance(cfg, dict) else None
            if isinstance(img, str) and img:
                add_image(dg, rid, img, "ci", f"{rel}:{find(img)}", f"job {jid} service {svc}", "workflow")
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            if isinstance(step.get("uses"), str):
                add_action(dg, rid, step["uses"], f"{rel}:{find(step['uses'])}", f"job {jid}")
            run = step.get("run")
            if isinstance(run, str) and FETCH_RE.search(run):
                for url in URL_RE.findall(run):
                    add_artifact(dg, rid, url, "ci", f"{rel}:{find(url)}", f"job {jid} run download", "workflow")
