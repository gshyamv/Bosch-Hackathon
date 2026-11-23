"""Container inspection: Dockerfile / Containerfile and docker-compose files.

Static only: nothing is pulled, built or run. Recorded per file:
  * every base image (FROM) with registry, repository, tag and digest
  * the build stage it belongs to (final stage = shipped at runtime, earlier = build only)
  * remote files fetched while building (RUN curl/wget ..., ADD <url>)
  * the USER the final stage runs as
Compose files add the images of their services.
"""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import quote, urlparse

import yaml

# A URL may contain GitHub Actions expressions with spaces, e.g. .../juice-shop/${{ github.ref_name }}/x.yml
URL_RE = re.compile(r"""https?://(?:\$\{\{[^}]*\}\}|[^\s'"`|;&)<>])+""")
FETCH_RE = re.compile(r"\b(curl|wget|Invoke-WebRequest|iwr)\b", re.I)
DOCKER_HUB = {"docker.io", "index.docker.io", "registry-1.docker.io"}


def is_dockerfile(name: str) -> bool:
    n = name.lower()
    return n in ("dockerfile", "containerfile") or n.startswith("dockerfile.") or n.endswith(".dockerfile")


def is_compose(name: str) -> bool:
    return re.fullmatch(r"(docker-)?compose(\.[\w-]+)?\.ya?ml", name.lower()) is not None


def line_finder(text: str):
    """Return find(needle) -> 1-based line number, preferring lines not reported yet."""
    lines, used = text.splitlines(), set()

    def find(needle: str) -> int:
        hits = [i for i, l in enumerate(lines, 1) if needle in l]
        for i in hits:
            if i not in used:
                used.add(i)
                return i
        return hits[0] if hits else 0
    return find


def parse_image(ref: str) -> dict:
    """'node:18' -> docker.io/library/node, tag 18. Handles registry hosts, ports and @sha256 digests."""
    digest = ""
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = ""
    if ":" in ref.rsplit("/", 1)[-1]:
        ref, tag = ref.rsplit(":", 1)
    parts = ref.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry, path = parts[0].lower(), "/".join(parts[1:])
    else:
        registry, path = "docker.io", ref
    if registry in DOCKER_HUB:
        registry = "docker.io"
        if "/" not in path:
            path = "library/" + path
    return {"registry": registry, "repository": path.lower(), "tag": tag, "digest": digest}


def add_image(dg, parent: str, ref: str, scope: str, source: str, spec: str, resolution: str) -> str:
    im = parse_image(ref)
    version = im["digest"] or im["tag"] or "latest"
    nid = (f"pkg:docker/{quote(im['repository'], safe='/')}@{quote(version, safe='')}"
           f"?repository_url={im['registry']}")
    short = im["repository"]
    if im["registry"] == "docker.io" and short.startswith("library/"):
        short = short[len("library/"):]
    elif im["registry"] != "docker.io":
        short = f"{im['registry']}/{short}"
    label = short + (f":{im['tag']}" if im["tag"] else "" if im["digest"] else ":latest") + \
        (f"@{im['digest'][:19]}" if im["digest"] else "")
    dg.pkg("docker", f"{im['registry']}/{im['repository']}", version, nid=nid, label=label,
           scope=scope, source=source, resolution=resolution,
           resolved=f"docker://{im['registry']}/{im['repository']}",
           registry=im["registry"], repository=im["repository"],
           tag=im["tag"] or "latest", tag_implicit=not im["tag"] and not im["digest"],
           digest=im["digest"], pinned_by_digest=bool(im["digest"]),
           official_image=im["registry"] == "docker.io" and im["repository"].startswith("library/"))
    dg.dep(parent, nid, spec, direct=True, location=source)
    return nid


def add_artifact(dg, parent: str, url: str, scope: str, source: str, spec: str, resolution: str) -> str:
    """A file downloaded during a build: its origin is the URL itself."""
    url = url.rstrip(".,")
    u = urlparse(url)
    nid = f"url:{url}"
    dg.pkg("url", url, "", nid=nid, label=f"{u.hostname or ''}{u.path}", scope=scope, source=source,
           resolution=resolution, resolved=url, host=u.hostname or "")
    dg.dep(parent, nid, spec, direct=True, location=source)
    return nid


def _logical_lines(text: str):
    """Join backslash continuations, drop comments. Yields (first line number, instruction)."""
    buf, start = "", None
    for i, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if start is None:
            start = i
        if s.endswith("\\"):
            buf += s[:-1] + " "
            continue
        yield start, buf + s
        buf, start = "", None
    if buf:
        yield start, buf


def scan_dockerfile(dg, repo: Path, path: Path):
    rel = path.relative_to(repo).as_posix()
    text = path.read_text(encoding="utf-8", errors="replace")
    rid = dg.app(rel, "docker", rel)
    args, stages = {}, []

    def expand(s):  # ARG defaults declared before FROM, e.g. FROM node:${NODE_VERSION}
        return re.sub(r"\$\{?(\w+)\}?", lambda m: args.get(m.group(1), m.group(0)), s)

    for line_no, instr in _logical_lines(text):
        kw, _, rest = instr.partition(" ")
        kw, rest = kw.upper(), rest.strip()
        if kw == "ARG":
            k, _, v = rest.partition("=")
            args.setdefault(k.strip(), v.strip().strip("\"'"))
        elif kw == "FROM":
            toks = [t for t in rest.split() if not t.startswith("--")]  # drop --platform=...
            if toks:
                alias = toks[2].lower() if len(toks) >= 3 and toks[1].lower() == "as" else ""
                stages.append({"ref": expand(toks[0]), "alias": alias, "line": line_no,
                               "user": None, "fetches": []})
        elif not stages:
            continue
        elif kw == "USER":
            stages[-1]["user"] = rest
        elif kw == "ADD" or (kw == "RUN" and FETCH_RE.search(rest)):
            stages[-1]["fetches"] += [(u, line_no, kw) for u in URL_RE.findall(rest)]

    aliases = {s["alias"] for s in stages if s["alias"]}
    # The final stage ships, and so does every stage it is built on (FROM base AS production -> base).
    idx_by_alias = {s["alias"]: i for i, s in enumerate(stages) if s["alias"]}
    shipped, chain, j = set(), [], len(stages) - 1
    while j is not None and j >= 0 and j not in shipped:
        shipped.add(j)
        chain.append(j)  # final stage first, then the stage it builds on, ...
        j = idx_by_alias.get(stages[j]["ref"].lower())
    for i, st in enumerate(stages):
        final = i == len(stages) - 1
        scope = "prod" if i in shipped else "build"
        name = f"stage {i + 1}" + (f" '{st['alias']}'" if st["alias"] else "") + \
            (" (final)" if final else " (base of final stage)" if i in shipped else "")
        if st["ref"].lower() not in aliases and st["ref"].lower() != "scratch":
            add_image(dg, rid, st["ref"], scope, f"{rel}:{st['line']}", f"FROM, {name}", "dockerfile")
        for url, ln, kw in st["fetches"]:
            add_artifact(dg, rid, url, scope, f"{rel}:{ln}", f"{kw} download, {name}", "dockerfile")
    # USER is inherited along the stage chain: the last USER set in the final stage or the stages it builds on.
    user = next((stages[k]["user"] for k in chain if stages[k]["user"]), None)
    dg.G.nodes[rid].update(stages=len(stages),
                           runs_as=user or "not set (inherits the base image default)")


def scan_compose(dg, repo: Path, path: Path):
    rel = path.relative_to(repo).as_posix()
    text = path.read_text(encoding="utf-8", errors="replace")
    data = yaml.safe_load(text) or {}
    services = data.get("services") if isinstance(data, dict) else None
    if not isinstance(services, dict):
        return
    rid = dg.app(rel, "docker", rel)
    find = line_finder(text)
    for svc, cfg in services.items():
        if not isinstance(cfg, dict) or cfg.get("build") is not None:
            continue  # built locally: `image:` only names the result; its Dockerfile is scanned separately
        img = cfg.get("image")
        if isinstance(img, str) and img:
            add_image(dg, rid, img, "prod", f"{rel}:{find(img)}", f"service {svc}", "compose")
