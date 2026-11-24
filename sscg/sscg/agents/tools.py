"""Read-only evidence tools the Evidence Gatherer runs for the Triage agent.

Whitelisted by name (schemas.ToolName); the LLM can only *request* them, it never runs code or reaches the network.
None of them installs, executes or modifies anything. Network lookups go through cache.http_json, so --offline
answers from .cache only. Each result is stored with an evidence ID (F-012/T1) that the model must cite.
"""
from __future__ import annotations

from urllib.parse import quote

from .. import cache, gitutil
from ..rules.common import read

CONTEXT_LINES = 4


def _get(url: str):
    """(document, definite): definite=False means offline / unreachable, so a miss is NOT evidence of absence."""
    doc = cache.http_json("GET", url)
    return doc, cache.answered("GET", url)


def _miss(what: str, definite: bool) -> dict:
    if not definite:
        return {"found": None, "note": f"{what}: not checked ("
                + ("offline and not in .cache" if cache.OFFLINE else "service unreachable") + ")"}
    return {"found": False, "note": f"{what}: the registry has no such public package / repository "
                                    "(never published, removed, or private)"}


def _npm(name: str, version: str) -> dict:
    doc, definite = _get(f"https://registry.npmjs.org/{quote(name, safe='@')}")
    if not doc or "versions" not in doc:
        return _miss(f"npm registry lookup of '{name}'", definite)
    t = doc.get("time", {})
    v = doc["versions"].get(version) or {}
    scripts = {k: s for k, s in (v.get("scripts") or {}).items() if k in ("preinstall", "install", "postinstall")}
    repo = doc.get("repository") or {}
    return {"found": True, "source": "registry.npmjs.org",
            "package_created": t.get("created"), "this_version_published": t.get(version),
            "latest": (doc.get("dist-tags") or {}).get("latest"), "version_count": len(doc["versions"]),
            "maintainer_count": len(doc.get("maintainers") or []),
            "this_version_published_by": (v.get("_npmUser") or {}).get("name"),
            "repository": repo.get("url") if isinstance(repo, dict) else repo,
            "description": (doc.get("description") or "")[:200],
            "this_version_install_scripts": scripts or None, "this_version_deprecated": v.get("deprecated"),
            "this_version_in_registry": bool(v)}


def _pypi(name: str, version: str) -> dict:
    doc, definite = _get(f"https://pypi.org/pypi/{quote(name)}/json")
    if not doc or "info" not in doc:
        return _miss(f"PyPI lookup of '{name}'", definite)
    rel = doc.get("releases") or {}
    uploads = sorted(f["upload_time_iso_8601"] for files in rel.values() for f in files if f.get("upload_time_iso_8601"))
    this = rel.get(version) or []
    info = doc["info"]
    return {"found": True, "source": "pypi.org", "first_upload": uploads[0] if uploads else None,
            "this_version_uploaded": this[0].get("upload_time_iso_8601") if this else None,
            "this_version_yanked": any(f.get("yanked") for f in this) if this else None,
            "release_count": len(rel), "latest": info.get("version"), "author": info.get("author"),
            "summary": (info.get("summary") or "")[:200],
            "has_project_urls": bool(info.get("project_urls") or info.get("home_page"))}


def _docker(name: str) -> dict:
    reg, _, repo = name.partition("/")
    if reg != "docker.io":
        return {"found": None, "note": f"registry {reg} is not queried (only Docker Hub is supported)"}
    ns, _, img = repo.partition("/")
    doc, definite = _get(f"https://hub.docker.com/v2/repositories/{quote(ns)}/{quote(img)}/")
    if not doc or "name" not in doc:
        return _miss(f"Docker Hub lookup of '{repo}'", definite)
    return {"found": True, "source": "hub.docker.com", "official_image": ns == "library",
            "pull_count": doc.get("pull_count"), "star_count": doc.get("star_count"),
            "registered": doc.get("date_registered"), "last_updated": doc.get("last_updated"),
            "description": (doc.get("description") or "")[:200]}


def registry_metadata(rt, f: dict, state: dict) -> dict:
    c = f.get("component")
    if not c:
        return {"found": None, "note": "finding has no component"}
    eco, name, ver = c["ecosystem"], c["name"], c.get("version") or ""
    if eco == "npm":
        return _npm(name, ver)
    if eco == "pypi":
        return _pypi(name, ver)
    if eco == "docker":
        return _docker(name)
    return {"found": None, "note": f"registry metadata not implemented for ecosystem '{eco}'"}


def _locations(f: dict) -> list[tuple[str, int]]:
    locs = [(e["path"], e.get("line") or 0) for e in f.get("evidence", []) if e.get("type") == "file"]
    if f.get("location") and ":" in f["location"] and not f["location"].startswith("commit"):
        p, _, ln = f["location"].rpartition(":")
        locs.append((p, int(ln) if ln.isdigit() else 0))
    seen, out = set(), []
    for p, ln in locs:
        if (p, ln) not in seen:
            seen.add((p, ln))
            out.append((p, ln))
    return out[:3]


def repo_file_context(rt, f: dict, state: dict) -> dict:
    """A few lines around each file location of the finding (never whole files; secrets are redacted later)."""
    out = []
    for path, line in _locations(f):
        text = read(rt.repo, path)
        if text is None:
            out.append({"path": path, "note": "file not readable inside the repository"})
            continue
        lines = text.splitlines()
        lo, hi = (max(1, line - CONTEXT_LINES), min(len(lines), line + CONTEXT_LINES)) if line else (1, min(len(lines), 2 * CONTEXT_LINES))
        out.append({"path": path, "lines": f"{lo}-{hi}",
                    "excerpt": "\n".join(f"{i}: {lines[i - 1][:200]}" for i in range(lo, hi + 1))})
    return {"files": out} if out else {"files": [], "note": "no file location on this finding"}


def commit_history(rt, f: dict, state: dict) -> dict:
    ch = state.get("change")
    if not ch:
        return {"found": None, "note": "no base commit was compared (not a git repo root, shallow clone or --no-diff)"}
    h = ch["head"]
    res = {"head_commit": {k: h[k] for k in ("short", "author", "date", "message")},
           "first_time_author": ch["first_time_author"],
           "files_changed_in_change": [f"{x['status']} {x['path']}" for x in ch["files"]][:25],
           "components_added": [a["label"] for a in ch["added"]][:25],
           "components_changed": [f"{x['base']} -> {x['head']} ({', '.join(x['fields'])})" for x in ch["changed"]][:25]}
    emails = gitutil.git(rt.repo, "log", "--format=%ae") or ""
    res["author_commit_count"] = sum(1 for e in emails.splitlines() if e.lower() == h["email"].lower())
    paths = [p for p, _ in _locations(f)]
    if paths:
        log = gitutil.git(rt.repo, "log", "-n", "5", "--format=%h | %an | %ad | %s", "--date=short", "--", paths[0])
        res["recent_history_of_" + paths[0]] = (log or "").splitlines()
    return res


def graph_context(rt, f: dict, state: dict) -> dict:
    c = f.get("component")
    G = rt.dg.G if rt.dg is not None else None
    if not c or G is None or c["id"] not in G:
        return {"found": None, "note": "finding has no component in the dependency graph"}
    n, a = c["id"], G.nodes[c["id"]]
    parents = [G.nodes[p].get("label", p) for p in G.predecessors(n)]
    related = [{"finding_id": x["finding_id"], "rule": x["rule"], "title": x["title"][:120]}
               for x in state.get("findings", []) if x.get("component") and x["component"]["id"] == n
               and x["finding_id"] != f["finding_id"]]
    return {"found": True, "scope": a.get("scope"), "direct": a.get("direct"), "depth": a.get("depth"),
            "required_by": parents[:10], "required_by_count": len(parents),
            "dependencies_count": G.out_degree(n), "new_in_change": f.get("new_in_change"),
            "other_findings_on_this_component": related}


TOOLS = {"registry_metadata": registry_metadata, "repo_file_context": repo_file_context,
         "commit_history": commit_history, "graph_context": graph_context}


def run_tool(name: str, rt, f: dict, state: dict) -> dict:
    fn = TOOLS.get(name)
    if fn is None:
        return {"found": None, "note": f"unknown tool '{name}'"}
    try:
        return fn(rt, f, state)
    except Exception as e:  # a failing tool must never break the run: it becomes "no evidence"
        return {"found": None, "note": f"tool failed: {type(e).__name__}: {str(e)[:200]}"}
