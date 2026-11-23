"""Container rules: R10 untrusted image, R11 mutable tag, R12 curl | sh in Dockerfiles, R13 hardening."""
from __future__ import annotations

import re

from ..discover.docker import _logical_lines
from .common import Ctx, file_ev, mk, read

TRUSTED = ("docker.io/library/", "gcr.io/distroless/", "mcr.microsoft.com/", "cgr.dev/chainguard/")
PIPE_TO_SHELL = re.compile(r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z)?sh\b")
NPM_INSTALL = re.compile(r"\bnpm\s+(install|i|ci|update)\b")


def _uses(G, n):
    return [(G.edges[p, n].get("location") or G.nodes[p]["source"]) for p in G.predecessors(n)
            if G.nodes[p]["kind"] == "app"]


def images(ctx: Ctx) -> list:
    out, G = [], ctx.dg.G
    for n, a in G.nodes(data=True):
        if a["kind"] != "package" or a["ecosystem"] != "docker":
            continue
        uses = _uses(G, n)
        evs = []
        for u in uses:
            path, _, ln = u.rpartition(":")
            evs.append(file_ev(path, int(ln), read(ctx.repo, path)) if ln.isdigit() else file_ev(u, 0, snippet=a["label"]))
        full = f"{a['registry']}/{a['repository']}"
        if not full.startswith(TRUSTED):
            out.append(mk("R10_UNTRUSTED_BASE_IMAGE",
                          f"image {a['label']} is not an official / verified-publisher image ({full})",
                          node=n, location=uses[0] if uses else None, key=(full,), evidence=evs))
        if not a.get("pinned_by_digest") and (a.get("tag_implicit") or a.get("tag") == "latest"):
            out.append(mk("R11_MUTABLE_IMAGE_TAG", f"image {a['label']} uses a mutable tag and no digest",
                          node=n, location=uses[0] if uses else None, key=(full, a.get("tag")), evidence=evs,
                          classification="verified_fact"))
    return out


def dockerfiles(ctx: Ctx) -> list:
    out, G = [], ctx.dg.G
    for n, a in G.nodes(data=True):
        if a["kind"] != "app" or a["ecosystem"] != "docker" or "stages" not in a:
            continue  # compose files have no stages
        src, text = a["source"], read(ctx.repo, a["source"])
        for ln, instr in _logical_lines(text or ""):
            kw = instr.split(" ", 1)[0].upper()
            if kw != "RUN":
                continue
            norm = " ".join(instr.split())
            if PIPE_TO_SHELL.search(instr):
                out.append(mk("R12_REMOTE_SCRIPT_EXEC", f"{src} downloads a script and pipes it into a shell",
                              location=f"{src}:{ln}", key=(src, norm), classification="verified_fact",
                              evidence=[file_ev(src, ln, snippet=norm)]))
            if NPM_INSTALL.search(instr) and "--ignore-scripts" not in instr:
                out.append(mk("R13_CONTAINER_HARDENING",
                              f"{src} runs '{NPM_INSTALL.search(instr).group(0)}' with install scripts enabled",
                              location=f"{src}:{ln}", key=(src, norm), classification="verified_fact",
                              evidence=[file_ev(src, ln, snippet=norm)]))
        if str(a.get("runs_as", "")).startswith("not set"):
            out.append(mk("R13_CONTAINER_HARDENING", f"{src} sets no USER: the container runs as the base image's "
                          "default user (usually root)", level="Low", location=src, key=(src, "no-user"),
                          classification="verified_fact",
                          evidence=[{"type": "fact", "detail": f"no USER instruction in the final stage chain of {src}"}]))
    return out
