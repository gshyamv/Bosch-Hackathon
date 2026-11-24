"""OKF bundle: markdown concepts with YAML frontmatter, readable by agents and over REST.

knowledge/ is shipped with the code (agents/knowledge/okf, curated); everything else is a view materialised from
validated notes. Agents never write markdown. Trust tiers: human: > process: > unverified.
"""
from __future__ import annotations

import io
import json
import os
import posixpath
import re
import threading
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .cache import ROOT

BUNDLE = Path(os.getenv("SSCG_OKF_DIR") or ROOT / ".okf")
KNOWLEDGE = Path(__file__).resolve().parent / "agents" / "knowledge" / "okf"
ID_RE = re.compile(r"^[A-Za-z0-9_@+-][\w@.+-]*(/[A-Za-z0-9_@+-][\w@.+-]*)*$")
LINK_RE = re.compile(r"\]\((/?[^)\s#:]+)\.md(?:#[^)]*)?\)")
ACTOR_RE = re.compile(r"^(sscg/[\w.]+|process:[\w.-]+|human:.+)$")
TIERS = {"unverified": 0, "process": 1, "human": 2}
RESERVED = ("index", "log")
_LOCK = threading.RLock()
AGENT, PROC = "sscg/agents", "process:sscg-scan"


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse(text: str) -> tuple[dict, str]:
    m = re.match(r"---\n(.*?)\n---\n?(.*)", text.replace("\r\n", "\n"), re.S)
    return ((yaml.safe_load(m[1]) or {}), m[2].lstrip("\n")) if m else ({}, text)


def dump(meta: dict, body: str) -> str:
    return f"---\n{yaml.safe_dump(meta, sort_keys=False, allow_unicode=True, width=1000)}---\n\n{body.rstrip()}\n"


def trust(meta: dict) -> str:
    by = [str(v.get("by", "")) for v in meta.get("verified") or []]
    return "human" if any(b.startswith("human:") for b in by) else "process" if any(b.startswith("process:") for b in by) else "unverified"


def stale(meta: dict) -> bool:
    s = meta.get("stale_after")
    return bool(s) and datetime.fromisoformat(str(s)) < datetime.now(timezone.utc)


def slug(s: str) -> str:
    return re.sub(r"[^\w@.+-]", "_", s).lstrip(".") or "x"


class Store:
    """Two roots: the writable bundle, and the read-only shipped knowledge/ (bundle copies override it)."""

    def __init__(self, root: Path | None = None, knowledge: Path = KNOWLEDGE):
        self.root, self.kdir = Path(root or BUNDLE), knowledge

    def _path(self, cid: str, root: Path) -> Path:
        if not ID_RE.match(cid) or ".." in cid:
            raise KeyError(cid)
        return root / f"{cid}.md"

    def read(self, cid: str) -> tuple[dict, str]:
        cands = [self._path(cid, self.root)]
        if cid.startswith("knowledge/"):
            cands.append(self._path(cid[10:], self.kdir))
        for p in cands:
            if p.is_file():
                return parse(p.read_text(encoding="utf-8"))
        raise KeyError(cid)

    def ids(self, prefix: str = "") -> list[str]:
        out = {p.relative_to(self.root).with_suffix("").as_posix() for p in self.root.rglob("*.md")}
        out |= {"knowledge/" + p.relative_to(self.kdir).with_suffix("").as_posix() for p in self.kdir.rglob("*.md")}
        return sorted(c for c in out if c.startswith(prefix) and posixpath.basename(c) not in RESERVED)

    def write(self, cid: str, meta: dict, body: str, change: str = "write") -> None:
        with _LOCK:
            p = self._path(cid, self.root)
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(f".{os.getpid()}.tmp")
            tmp.write_text(dump(meta, body), encoding="utf-8", newline="\n")
            os.replace(tmp, p)
            log = self.root / "log.md"
            old = log.read_text(encoding="utf-8").split("\n", 2)[-1] if log.is_file() else ""
            log.write_text(f"# Log\n\n- {now()} {change} /{cid}.md\n" + "\n".join(old.lstrip("\n").splitlines()[:999]) + "\n",
                           encoding="utf-8", newline="\n")

    def index(self) -> None:
        """Regenerate index.md of every folder of the bundle (called once per materialised note)."""
        with _LOCK:
            dirs: dict[str, list] = {}
            for c in self.ids():
                parts = c.split("/")
                for i in range(len(parts)):
                    dirs.setdefault("/".join(parts[:i]), []).append(c)
            for d, cs in dirs.items():
                depth = len(d.split("/")) if d else 0
                rows = sorted({c.split("/")[depth] + ("" if len(c.split("/")) == depth + 1 else "/") for c in cs})
                text = ("---\nokf_version: \"0.2\"\n---\n\n" if not d else "") + f"# {d or 'SSCG context'}\n\n" + "".join(
                    f"- [{r}]({r + 'index.md' if r.endswith('/') else r + '.md'})\n" for r in rows)
                p = self.root / d / "index.md"
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text, encoding="utf-8", newline="\n")

    def card(self, cid: str) -> dict:
        m, _ = self.read(cid)
        return {"id": cid, "type": m.get("type"), "title": m.get("title"), "description": m.get("description"),
                "status": m.get("status"), "trust": trust(m), "stale": stale(m)}

    def search(self, query: str, types=None, min_trust: str = "unverified", k: int = 5, prefix: str = "") -> list[dict]:
        words = set(re.findall(r"[\w.@-]{2,}", query.lower()))
        hits = []
        for cid in self.ids(prefix):
            m, body = self.read(cid)
            if (types and m.get("type") not in types) or TIERS[trust(m)] < TIERS.get(min_trust, 0):
                continue
            head = f"{cid} {m.get('title', '')} {' '.join(map(str, m.get('tags') or []))}".lower()
            low = body.lower()
            s = sum(3 * (w in head) + (w in low) for w in words)
            if s:
                hits.append((-s, cid))
        return [self.card(c) for _, c in sorted(hits)[:k]]

    def links(self, cid: str) -> set[str]:
        _, body = self.read(cid)
        out = set()
        for t in LINK_RE.findall(body):
            c = posixpath.normpath(t[1:] if t.startswith("/") else posixpath.join(posixpath.dirname(cid), t))
            if ID_RE.match(c):
                out.add(c)
        return out

    def neighbors(self, cid: str) -> list[dict]:
        known = set(self.ids())
        near = self.links(cid) | {c for c in known if cid in self.links(c)}
        return [self.card(c) for c in sorted(near & known - {cid})]

    def lint(self) -> list[str]:
        errs, known = [], set(self.ids())
        for cid in sorted(known):
            m, _ = self.read(cid)
            if not m.get("type"):
                errs.append(f"{cid}: no type")
            actors = [m.get("generated") or {}, *(m.get("verified") or [])]
            for a in actors:
                if a and not ACTOR_RE.match(str(a.get("by", ""))):
                    errs.append(f"{cid}: bad actor {a.get('by')!r}")
            for t in [a.get("at") for a in actors if a] + ([m["stale_after"]] if m.get("stale_after") else []):
                try:
                    if datetime.fromisoformat(str(t)).tzinfo is None:
                        raise ValueError
                except ValueError:
                    errs.append(f"{cid}: timestamp without offset {t!r}")
            errs += [f"{cid}: broken link {x}" for x in sorted(self.links(cid) - known)]
        return errs

    def verify(self, cid: str, human: str) -> None:
        m, body = self.read(cid)
        m["verified"] = [*(m.get("verified") or []), {"by": f"human:{human}", "at": now()}]
        m["status"] = "stable"
        self.write(cid, m, body, f"verified by human:{human}")

    def export(self, scan_id: str) -> bytes:
        ids = self.ids(f"scans/{scan_id}/") + self.ids("knowledge/")
        seen = set(ids)
        for c in ids:
            seen |= self.links(c) & set(self.ids("advisories/"))
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("index.md", '---\nokf_version: "0.2"\n---\n\n# SSCG scan ' + scan_id + "\n\n"
                       + "".join(f"- [{c}]({c}.md)\n" for c in sorted(seen)))
            for c in sorted(seen):
                z.writestr(f"{c}.md", dump(*self.read(c)))
        return buf.getvalue()


# ------------------------------------------------------------------ materialiser (deterministic renderers)
def _meta(typ, title, desc, by=PROC, verified=True, **kw) -> dict:
    at = now()
    return {"type": typ, "title": title, "description": desc, "status": kw.pop("status", "draft"),
            "generated": {"by": by, "at": at}, **({"verified": [{"by": PROC, "at": at}]} if verified else {}), **kw}


def _q(text) -> str:
    """Repository- or model-derived text: one line, no markdown links, so it cannot add structure to the bundle."""
    return re.sub(r"\s+", " ", str(text or "")).replace("[", "(").replace("]", ")").replace("`", "'").replace("<", "&lt;")[:1200]


def scan_concept(st: Store, scan: str, target) -> None:
    st.write(f"scans/{scan}/scan", _meta("scan", f"Scan of {_q(target.display)}", "One pipeline run", status="stable",
                                         vv={"target": target.name, "sha": target.sha}), "Scan record.")
    st.index()


def materialize(st: Store, scan: str, kind: str, d: dict) -> None:
    base = f"scans/{scan}"
    if kind == "FactBatch":
        fs = {f["finding_id"]: f for f in d["findings"]}
        for c in d["clusters"]:
            lines, links = [], set()
            for fid in c["finding_ids"]:
                f = fs[fid]
                lines.append(f"- {fid} ({f['rule']}): {_q(f['title'])}")
                pb = f"knowledge/playbooks/{f['rule']}"
                if (st.kdir / f"playbooks/{f['rule']}.md").is_file():
                    links.add(f"[{f['rule']}](/{pb}.md)")
                for e in f["evidence"]:
                    if e.get("type") == "advisory":
                        aid = f"advisories/{slug(e['id'])}"
                        links.add(f"[{e['id']}](/{aid}.md)")
                        fresh = datetime.now(timezone.utc).timestamp() + 86400
                        st_after = datetime.fromtimestamp(fresh, timezone.utc).replace(microsecond=0).isoformat()
                        st.write(aid, _meta("advisory", e["id"], _q(e.get("summary"))[:200], resource=e.get("url"), status="stable",
                                            stale_after=st_after), f"- Severity: {e.get('severity')}\n- Fixed in: "
                                 f"{e.get('fixed_in') or 'no fix published'}\n- CVEs: {', '.join(e.get('cves') or []) or 'none'}\n")
            st.write(f"{base}/clusters/{c['cluster_id']}", _meta(
                "risk-cluster", _q(c["title"]), f"{c['kind']} cluster, {c['exposure']}", tags=[c["kind"], c["exposure"]],
                vv={k: c[k] for k in ("cluster_id", "score", "exposure", "finding_ids")}),
                "## Verified facts\n" + "\n".join(lines) + "\n\n## Related\n" + " · ".join(sorted(links)) + f"\n\n[scan](/{base}/scan.md)\n")
    elif kind == "TriageNote":
        st.write(f"{base}/triage/{d['finding_id']}", _meta(
            "triage", f"{d['finding_id']}: {d['verdict']}", f"confidence {d['confidence']}", by=AGENT, verified=False),
            "## Verified facts\n" + "".join(f"- {x}\n" for x in d["verified_facts"]) + "\n## AI inference (unverified)\n"
            + "".join(f"- {_q(x)}\n" for x in d["inferences"]) + f"\n[scan](/{base}/scan.md)\n")
    elif kind == "PriorityNote":
        return        # kept in SQLite; one concept per finding would only add noise
    elif kind == "RemediationPlan":
        rel = " · ".join(f"[{c}](/{base}/clusters/{c}.md)" for c in d["cluster_ids"])
        st.write(f"{base}/remediations/{d['proposal_id']}", _meta(
            "remediation-plan", f"{d['action']} {_q(d['component'])}", _q(d["rationale"])[:200],
            vv={k: d[k] for k in ("proposal_id", "action", "to_version", "finding_ids")}),
            f"{_q(d['rationale'])}\n\n- Risk reduction: {_q(d['risk_reduction'])}\n- Compatibility: {_q(d['compatibility'])}\n"
            f"- Rollback: {_q(d['rollback'])}\n\n## Related\n{rel}\n")
    elif kind == "ApprovalNote":
        cid = f"{base}/remediations/{d['proposal_id']}"
        st.write(f"{base}/decisions/{d['proposal_id']}", _meta(
            "decision", f"{d['proposal_id']}: {d['decision']}", _q(d["comment"])[:200], status="stable", verified=False)
            | {"verified": [{"by": d["reviewer"], "at": d["decided_at"]}]}, f"[plan](/{cid}.md)\n")
        if d["decision"] == "approve":
            m, body = st.read(cid)
            m["status"] = "stable"
            m["verified"] = [*(m.get("verified") or []), {"by": d["reviewer"], "at": d["decided_at"]}]
            st.write(cid, m, body, "approved")
    elif kind == "ValidationResult":
        steps = "".join(f"- {s['status']}: {_q(s['step'])}\n" for s in d["steps"])
        rel = " · ".join(f"[{p}](/{base}/remediations/{p}.md)" for p in d["proposal_ids"])
        st.write(f"{base}/validations/{d['validation_id']}", _meta(
            "validation-result", f"Validation: {d['verdict']}", f"confidence {d['confidence']}", status="stable"),
            "".join(f"- {_q(r)}\n" for r in d["reasons"]) + f"\n## Steps\n{steps}\n## SBOM diff\n```json\n"
            f"{json.dumps(d['sbom_diff'])[:3000]}\n```\n\n## Related\n{rel}\n")
    st.index()


def pack(st: Store, findings: list[dict], budget: int = 2500) -> list[dict]:
    """Deterministic context pack: the playbooks of these findings plus earlier human decisions, within a budget."""
    out, left = [], budget
    ids = [f"knowledge/playbooks/{r}" for r in sorted({f["rule"] for f in findings})]
    for cid in ids + [c for c in st.ids("scans/") if "/decisions/" in c][-3:]:
        try:
            m, body = st.read(cid)
        except KeyError:
            continue
        text = body[:min(700, left)]
        if not text:
            break
        left -= len(text)
        out.append({"concept": cid, "trust": trust(m), "text": text})
    return out
