"""Pillar 2: SBOM in CycloneDX 1.5 JSON. Generate one from the graph, or consume one (ours, Syft, cdxgen ...).

Every graph node becomes a component, every edge an entry in `dependencies`:
  npm / PyPI / Maven -> type "library"      (purl, hashes from lockfile integrity, download URL)
  container image    -> type "container"    (purl pkg:docker/..., sha256 digest if pinned)
  CI action          -> type "application"  (purl pkg:github/owner/repo@ref)
  downloaded file    -> type "file"         (download URL)
  manifest / Dockerfile / workflow -> type "application" (sscg:kind = app)
Facts that CycloneDX has no field for are kept as `sscg:*` properties.
"""
from __future__ import annotations

import base64
import binascii
import datetime
import json
import sys
import uuid
from pathlib import Path

from . import __version__
from .model import DepGraph

CDX_TYPE = {"docker": "container", "github-actions": "application", "url": "file"}
CDX_SCOPE = {"prod": "required", "optional": "optional"}  # dev / test / build / ci -> "excluded"
HASH_ALG = {"sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512"}
HASH_BYTES = {"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}
FACTS = ("ecosystem", "direct", "depth", "dependents", "scope", "source", "resolution", "install_script",
         "registry", "repository", "tag", "tag_implicit", "digest", "pinned_by_digest", "official_image",
         "owner", "action_path", "ref", "pinned_to_sha", "host",
         "triggers", "permissions", "stages", "runs_as")
BOOL_FACTS = {"direct", "install_script", "tag_implicit", "pinned_by_digest", "official_image", "pinned_to_sha"}


# ----------------------------------------------------------------------------- generate
def _hashes(a: dict) -> tuple[list, list]:
    """(valid hashes, malformed integrity tokens). A token whose length doesn't fit its algorithm is not a hash."""
    out, bad = [], []
    for tok in str(a.get("integrity") or "").split():  # SRI, e.g. "sha512-<base64>"
        alg, _, b64 = tok.partition("-")
        try:
            raw = base64.b64decode(b64, validate=True)
        except (binascii.Error, ValueError):
            raw = b""
        if alg in HASH_ALG and len(raw) == HASH_BYTES[alg]:
            out.append({"alg": HASH_ALG[alg], "content": raw.hex()})
        else:
            bad.append(tok)
    d = str(a.get("digest") or "")
    if d.startswith("sha256:") and len(d) == 7 + 64:
        out.append({"alg": "SHA-256", "content": d[7:]})
    return out, bad


def _props(a: dict) -> list:
    out = [{"name": "sscg:kind", "value": a["kind"]}]
    if a["kind"] == "package":
        out += [{"name": "sscg:integrity_malformed", "value": t} for t in _hashes(a)[1]]
    for k in FACTS:
        v = a.get(k)
        if v is None or v == "" or v == []:
            continue
        if isinstance(v, bool):
            v = str(v).lower()
        elif isinstance(v, list):
            v = ", ".join(map(str, v))
        out.append({"name": f"sscg:{k}", "value": str(v)})
    return out


def _component(n: str, a: dict) -> dict:
    if a["kind"] == "app":
        c = {"type": "application", "bom-ref": n, "name": a.get("name") or a["label"]}
        if a.get("version"):
            c["version"] = a["version"]
        c["properties"] = _props(a)
        return c
    c = {"type": CDX_TYPE.get(a["ecosystem"], "library"), "bom-ref": n, "name": a["name"]}
    if a.get("version"):
        c["version"] = a["version"]
    c["scope"] = CDX_SCOPE.get(a.get("scope"), "excluded")
    if n.startswith("pkg:") and a.get("resolution") != "unresolved":
        c["purl"] = n
    if h := _hashes(a)[0]:
        c["hashes"] = h
    if isinstance(a.get("resolved"), str) and a["resolved"]:
        c["externalReferences"] = [{"type": "vcs" if a["ecosystem"] == "github-actions" else "distribution",
                                    "url": a["resolved"]}]
    c["properties"] = _props(a)
    return c


def to_cyclonedx(dg: DepGraph) -> dict:
    G = dg.G
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
            "tools": {"components": [{"type": "application", "name": "sscg", "version": __version__}]},
            "component": {"type": "application", "bom-ref": dg.top, "name": G.nodes[dg.top]["label"]},
        },
        "components": [_component(n, a) for n, a in G.nodes(data=True) if n != dg.top],
        "dependencies": [{"ref": n, "dependsOn": sorted(G.successors(n))} for n in G.nodes],
    }


def write_cyclonedx(dg: DepGraph, path: Path) -> dict:
    bom = to_cyclonedx(dg)
    path.write_text(json.dumps(bom, indent=1), encoding="utf-8")
    return bom


# ----------------------------------------------------------------------------- consume
def _flatten(components):
    for c in components or []:
        yield c
        yield from _flatten(c.get("components"))


def _fact(k: str, v: str):
    return v == "true" if k in BOOL_FACTS else v


def read_cyclonedx(dg: DepGraph, path: Path):
    """Build the graph from a CycloneDX JSON SBOM instead of scanning manifests."""
    try:
        bom = json.loads(path.read_text(encoding="utf-8-sig"))
    except (ValueError, OSError) as e:
        sys.exit(f"cannot read SBOM {path}: {e} (is it CycloneDX JSON? did Syft/Docker fail?)")
    if bom.get("bomFormat") != "CycloneDX":
        sys.exit(f"{path} is not a CycloneDX SBOM (bomFormat={bom.get('bomFormat')!r})")
    G = dg.G
    meta = bom.get("metadata", {}).get("component") or {}
    comps = list(_flatten(bom.get("components")))
    props_of = lambda c: {p["name"]: p.get("value", "") for p in c.get("properties", []) if "name" in p}
    ours = any(props_of(c).get("sscg:kind") == "app" for c in comps)  # written by sscg: keeps app layer

    if ours:
        root = dg.top
    else:  # foreign SBOM: one app node stands for the whole document
        root = dg.app(path.name, "sbom", meta.get("name", "sbom"), meta.get("version", ""))
    ref2id = {meta["bom-ref"]: root} if meta.get("bom-ref") else {}

    for c in comps:
        props = props_of(c)
        ref = c.get("bom-ref") or c.get("purl") or f"{c.get('name')}@{c.get('version', '')}"
        facts = {k[5:]: _fact(k[5:], v) for k, v in props.items()
                 if k.startswith("sscg:") and k[5:] in FACTS and k[5:] not in ("ecosystem", "scope", "source",
                                                                               "resolution", "direct", "depth",
                                                                               "dependents")}
        if props.get("sscg:kind") == "app":
            G.add_node(ref, kind="app", ecosystem=props.get("sscg:ecosystem", "sbom"), name=c.get("name", ""),
                       version=c.get("version", ""), source=props.get("sscg:source", path.name),
                       label=f"{c.get('name')}@{c['version']}" if c.get("version") else c.get("name", ""), **facts)
            ref2id[ref] = ref
            continue
        p = c.get("purl") or ""
        eco = props.get("sscg:ecosystem") or (p[4:].split("/")[0] if p.startswith("pkg:") else "generic")
        nid = ref if "sscg:kind" in props else (p.split("?")[0] if p else ref)
        urls = [r["url"] for r in c.get("externalReferences", []) if r.get("type") in ("distribution", "vcs")]
        scope = props.get("sscg:scope") or {"required": "prod", "optional": "optional",
                                             "excluded": "dev"}.get(c.get("scope"), "prod")
        ref2id[ref] = dg.pkg(eco, c.get("name", "?"), c.get("version", ""), nid=nid, scope=scope,
                             source=props.get("sscg:source", path.name), resolution="sbom",
                             resolved=urls[0] if urls else None, **facts)

    for d in bom.get("dependencies", []):
        src = ref2id.get(d.get("ref"))
        for t in d.get("dependsOn", []):
            if src and t in ref2id:
                child = ref2id[t]
                direct = G.nodes[src]["kind"] in ("repo", "app") and G.nodes[child]["kind"] == "package"
                dg.dep(src, child, direct=direct)
    if not ours and G.out_degree(root) == 0:  # SBOM without dependency info: hang roots under the app
        for nid in set(ref2id.values()) - {root}:
            if G.in_degree(nid) == 0:
                dg.dep(root, nid, direct=True)
