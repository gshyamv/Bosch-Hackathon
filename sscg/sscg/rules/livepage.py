"""Live page rules: R20 missing SRI, R21 http script on an https page, R22 outdated / vulnerable JS library."""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from .. import registry
from .common import Ctx, file_ev, mk, read


def page(ctx: Ctx) -> list:
    out, G = [], ctx.dg.G
    pages = [a for _, a in G.nodes(data=True) if a.get("ecosystem") == "live-page"]
    # a live page linked to its source repo keeps page.html in the live fetch folder, not in the scanned repo
    text = read(Path(pages[0]["page_dir"]) if pages[0].get("page_dir") else ctx.repo, "page.html") if pages else None
    if text is None:
        return out
    ev = lambda line: file_ev("page.html", line, text)  # noqa: E731
    for n, a in list(G.nodes(data=True)):
        if a.get("ecosystem") == "live-page":
            for s in a.get("scripts", []):
                kw = {"location": f"page.html:{s['line']}", "evidence": [ev(s["line"])], "key": (s["src"],),
                      "classification": "verified_fact"}
                if s["third_party"] and not s["sri"]:
                    out.append(mk("R20_MISSING_SRI", f"script from {urlsplit(s['src']).hostname} has no integrity hash: "
                                  f"{s['src'][:100]}", **kw))
                if s["insecure"]:
                    out.append(mk("R21_INSECURE_SCRIPT", f"script loaded over http on an https page: {s['src'][:100]}", **kw))
        elif a.get("resolution") == "page-script":
            vs = registry.versions("npm", a["name"])
            advs = [x["id"] for x in a.get("advisories", [])]
            old = bool(vs) and registry.major(vs[-1]) != registry.major(a["version"])
            if not (advs or old):
                continue
            why = ([f"latest is {vs[-1]}"] if old else []) + ([f"{len(advs)} advisories"] if advs else [])
            out.append(mk("R22_OUTDATED_JS_LIBRARY", f"the page loads {a['label']} ({', '.join(why)})", node=n,
                          level="Medium" if advs else "Low", location=a["source"], key=("npm", a["name"]),
                          classification="verified_fact",
                          evidence=[ev(int(a["source"].rpartition(":")[2])),
                                    {"type": "fact", "detail": f"detected by {a['detected_by']} in {a['script_url']}"}]))
    return out
