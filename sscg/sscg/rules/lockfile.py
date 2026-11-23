"""Lockfile and change rules: R05 untrusted source, R06 integrity swap, R07 drift, R08 unexpected dependency,
R19 suspicious update. R06-R08/R19 need the base commit ("what changed")."""
from __future__ import annotations

import json
from urllib.parse import urlparse

from ..graph import TRUSTED_NPM_HOSTS
from .common import Ctx, file_ev, line_of, mk, read

LIBS = ("npm", "pypi", "maven")


def _host(url) -> str:
    return (urlparse(url).hostname or "") if isinstance(url, str) else ""


def untrusted_source(ctx: Ctx) -> list:
    out = []
    for n, a in ctx.dg.G.nodes(data=True):
        url = a.get("resolved")
        if a["kind"] != "package" or a["ecosystem"] != "npm" or not isinstance(url, str) \
                or not url.startswith("http") or _host(url) in TRUSTED_NPM_HOSTS:
            continue
        text = read(ctx.repo, a["source"])
        ln = line_of(text, url)
        out.append(mk("R05_LOCKFILE_UNTRUSTED_SOURCE", f"{a['label']} is downloaded from {_host(url)}, "
                      "not the npm registry", node=n, location=f"{a['source']}:{ln}", key=(a["name"], _host(url)),
                      classification="verified_fact", evidence=[file_ev(a["source"], ln, text)]))
    return out


def _spec(repo, manifest: str, name: str):
    try:
        m = json.loads((repo / manifest).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    for f in ("dependencies", "devDependencies", "optionalDependencies"):
        if name in (m.get(f) or {}):
            return m[f][name]
    return None


def changes(ctx: Ctx) -> list:
    ch = ctx.change
    if not ch:
        return []
    out, G = [], ctx.dg.G
    commit = {"type": "commit", "sha": ch.head["short"], "author": ch.head["author"], "email": ch.head["email"],
              "date": ch.head["date"], "message": ch.head["message"]}
    for c in ch.changed:
        b, h = c["base"], c["head"]
        src = h.get("source", "")
        text = read(ctx.repo, src) if src else None
        ln = line_of(text, h.get("integrity") or h.get("resolved") or f'"{c["name"]}"') if text else 0
        detail = {"type": "change", "file": src, "fields": {f: {"base": b.get(f), "head": h.get(f)} for f in c["fields"]}}
        if "version" not in c["fields"] and "integrity" in c["fields"] and b.get("integrity") and h.get("integrity"):
            out.append(mk("R06_LOCKFILE_INTEGRITY_CHANGED",
                          f"{h['label']}: same version, different content hash (and source) in {src}",
                          node=h["id"], location=f"{src}:{ln}", key=(c["ecosystem"], c["name"], h["version"]),
                          classification="verified_fact", new=True,
                          evidence=[detail, file_ev(src, ln, text), commit]))
        if c["ecosystem"] == "npm" and h.get("direct"):
            manifest = next((G.nodes[p]["source"] for p in G.predecessors(h["id"]) if G.nodes[p]["kind"] == "app"), None)
            if manifest:
                sb, sh = _spec(ch.base_dir, manifest, c["name"]), _spec(ctx.repo, manifest, c["name"])
                if sb is not None and sb == sh:
                    out.append(mk("R07_LOCKFILE_DRIFT",
                                  f"{h['label']}: lockfile entry changed ({', '.join(c['fields'])}) but {manifest} "
                                  f"still asks for '{sh}'", node=h["id"], location=f"{src}:{ln}",
                                  key=(c["ecosystem"], c["name"]), classification="verified_fact", new=True,
                                  evidence=[{"type": "fact", "detail": f"{manifest}: \"{c['name']}\": \"{sh}\" in "
                                             f"both {ch.base['short']} and {ch.head['short']}"}, detail, commit]))
        if "version" in c["fields"]:
            reasons = []
            if not b.get("install_script") and h.get("install_script"):
                reasons.append("the new version adds an install script")
            if _host(b.get("resolved")) and _host(b.get("resolved")) != _host(h.get("resolved")):
                reasons.append(f"download host changed {_host(b.get('resolved'))} -> {_host(h.get('resolved'))}")
            if reasons:
                out.append(mk("R19_SUSPICIOUS_UPDATE", f"{b['label']} -> {h['label']}: {'; '.join(reasons)}",
                              node=h["id"], location=src, key=(c["ecosystem"], c["name"], h["version"]),
                              classification="verified_fact", new=True, evidence=[detail, commit]))
    for a in ch.added:
        if a["ecosystem"] in LIBS and a.get("direct"):
            manifest = next((G.nodes[p]["source"] for p in G.predecessors(a["id"]) if G.nodes[p]["kind"] == "app"), "")
            text = read(ctx.repo, manifest) if manifest else None
            needle = f'"{a["name"]}"' if a["ecosystem"] == "npm" else a["name"]
            ln = line_of(text, needle) if text else 0
            if not ln and text and a["ecosystem"] == "pypi":  # requirement written with other case / separators
                ln = next((i for i, l in enumerate(text.splitlines(), 1)
                           if l.lower().replace("_", "-").startswith(a["name"])), 0)
            out.append(mk("R08_UNEXPECTED_DEPENDENCY",
                          f"new {a.get('scope', 'prod')} dependency {a['label']} added in {manifest or 'a manifest'}",
                          node=a["id"], location=f"{manifest}:{ln}" if manifest else None,
                          key=(a["ecosystem"], a["name"]), classification="verified_fact", new=True,
                          evidence=[file_ev(manifest, ln, text) if manifest else {}, commit]))
    return out
