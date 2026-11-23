"""Maven: pom.xml (${props}, dependencyManagement, parent version; deps.dev transitive)."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .depsdev import attach_depsdev


def scan(dg, repo: Path, pom: Path):
    rel = pom.relative_to(repo).as_posix()
    try:
        root = ET.fromstring(pom.read_text(encoding="utf-8"))
    except ET.ParseError:
        dg.notes.append(f"skip {rel}: invalid XML")
        return
    for el in root.iter():  # drop namespaces
        if isinstance(el.tag, str):
            el.tag = el.tag.split("}")[-1]
    props_el = root.find("properties")
    props = {c.tag: (c.text or "").strip() for c in props_el} if props_el is not None else {}
    gid = root.findtext("groupId") or root.findtext("parent/groupId") or ""
    ver = root.findtext("version") or root.findtext("parent/version") or ""
    props.update({"project.version": ver, "project.groupId": gid, "version": ver, "pom.version": ver,
                  "project.parent.version": root.findtext("parent/version") or ""})

    def sub(s):
        s = (s or "").strip()
        for _ in range(5):
            s2 = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), s)
            if s2 == s:
                break
            s = s2
        return s

    managed = {}
    for d in root.findall("dependencyManagement/dependencies/dependency"):
        managed[f"{sub(d.findtext('groupId'))}:{sub(d.findtext('artifactId'))}"] = sub(d.findtext("version"))
    rid = dg.app(rel, "maven", f"{gid}:{root.findtext('artifactId')}", ver)
    parent_ga = f"{root.findtext('parent/groupId')}:{root.findtext('parent/artifactId')}"
    for d in root.findall("dependencies/dependency"):
        g, a = sub(d.findtext("groupId")), sub(d.findtext("artifactId"))
        v = sub(d.findtext("version")) or managed.get(f"{g}:{a}", "")
        scope = {"test": "test", "provided": "build"}.get(d.findtext("scope") or "", "prod")
        name = f"{g}:{a}"
        if g == gid and gid:  # sibling module of the same project
            nid = dg.pkg("maven", name, v or ver, scope=scope, source=rel, resolution="internal-module")
            dg.dep(rid, nid, v, direct=True)
        elif not v or "${" in v:
            nid = dg.pkg("maven", name, "managed-by-parent", scope=scope, source=rel, resolution="unresolved")
            dg.dep(rid, nid, f"version from {parent_ga}", direct=True)
        else:
            attach_depsdev(dg, rid, "maven", "maven", name, v, v, scope, rel, approx=False)
