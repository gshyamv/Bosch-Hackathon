"""Passive scan of ONE live page (ported from VulnerabilityVision): GET the HTML, then up to 30 <script src> files.

No forms, crawling, login or POST. The SSRF guard runs on every hop, redirects included.
"""
from __future__ import annotations

import hashlib
import re
from functools import lru_cache
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx
import yaml

from .. import cache
from ..safety import SafetyError, check_target

MAX_HTML, MAX_SCRIPT, MAX_SCRIPTS, MAX_REDIRECTS = 5 * 1024 * 1024, 2 * 1024 * 1024, 30, 5
RULES = Path(__file__).resolve().parent.parent / "data" / "live_rules.yaml"


@lru_cache(maxsize=1)
def rules() -> dict:
    r = yaml.safe_load(RULES.read_text(encoding="utf-8"))
    for group in ("cdn_paths", "filenames", "banners"):
        for rule in r[group]:
            rule["rx"] = re.compile(rule["pattern"], re.I | re.S)
    return r


class _Scripts(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts: list[dict] = []
        self.inline = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag != "script":
            return
        if a.get("src"):
            self.scripts.append({"src": a["src"], "integrity": a.get("integrity"), "line": self.getpos()[0]})
        else:
            self.inline += 1


def get(http: httpx.Client, url: str, cap: int) -> tuple[httpx.Response, str, bytes]:
    for _ in range(MAX_REDIRECTS + 1):
        check_target(url)
        with http.stream("GET", url) as r:
            body = b""
            for chunk in r.iter_bytes():
                body += chunk
                if len(body) > cap:
                    body = body[:cap]
                    break
        if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("location"):
            url = urljoin(url, r.headers["location"])
            continue
        return r, url, body
    raise SafetyError("too many redirects")


def detect_libs(url: str, head: str) -> list[dict]:
    out, seen, r = [], set(), rules()
    for group, where in (("cdn_paths", url), ("filenames", url), ("banners", head)):
        for rule in r[group]:
            m = rule["rx"].search(where)
            if not m:
                continue
            gd = m.groupdict()
            name = (rule.get("name") or gd.get("name") or "").lower()
            name, ver = r["npm_names"].get(name, name), gd.get("version")
            if name and ver and (name, ver) not in seen:
                seen.add((name, ver))
                out.append({"name": name, "version": ver, "how": group})
    return out


def fetch_page(url: str, dest: Path, transport=None) -> dict:
    if cache.OFFLINE:
        raise SafetyError("offline: live pages need network access")
    with httpx.Client(timeout=httpx.Timeout(15, read=30), follow_redirects=False, transport=transport,
                      headers={"User-Agent": "sscg-scanner (passive)"}) as http:
        try:
            resp, final, body = get(http, url, MAX_HTML)
        except httpx.HTTPError as e:
            raise SafetyError(f"cannot load {url}: {type(e).__name__}") from e
        if resp.status_code >= 400:
            raise SafetyError(f"page returned HTTP {resp.status_code}")
        html = body.decode(resp.encoding or "utf-8", errors="replace")
        parser = _Scripts()
        parser.feed(html)
        scripts = []
        for s in parser.scripts[:MAX_SCRIPTS]:
            src = urljoin(final, s["src"].strip())
            if not src.startswith(("http://", "https://")):
                continue
            head, err = "", None
            try:
                sr, _, sbody = get(http, src, MAX_SCRIPT)
                head = sbody[:4096].decode("utf-8", errors="replace") if sr.status_code == 200 else ""
            except (SafetyError, httpx.HTTPError) as e:
                err = str(e)[:120]
            scripts.append({"src": src, "sri": bool(s["integrity"]), "line": s["line"], "error": err,
                            "third_party": urlsplit(src).hostname != urlsplit(final).hostname,
                            "insecure": final.startswith("https:") and src.startswith("http:"),
                            "libs": detect_libs(src, head)})
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "page.html").write_text(html, encoding="utf-8", newline="")
    return {"url": url, "final_url": final, "scripts": scripts, "inline": parser.inline,
            "truncated": max(0, len(parser.scripts) - MAX_SCRIPTS), "sha256": hashlib.sha256(body).hexdigest()}


def add_page(dg, page: dict) -> None:
    app = dg.app("page.html", "live-page", page["url"])
    dg.G.nodes[app]["scripts"] = page["scripts"]
    for s in page["scripts"]:
        for lib in s["libs"]:
            n = dg.pkg("npm", lib["name"], lib["version"], source=f"page.html:{s['line']}", script_url=s["src"],
                       detected_by=lib["how"], resolution="page-script")
            dg.dep(app, n, direct=True, location=f"page.html:{s['line']}")
        if s["error"]:
            dg.notes.append(f"script not inspected: {s['src'][:100]}: {s['error']}")
    if page["truncated"]:
        dg.notes.append(f"{page['truncated']} scripts beyond the first {MAX_SCRIPTS} were not inspected")
