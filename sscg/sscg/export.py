"""Graph exports: graph.json (machine-readable), graph.html (interactive, offline), graph.mmd (Mermaid).

render_html() draws a (sub)graph with every component coloured AND shaped by its ecosystem (ECOSYSTEMS below), so
npm / PyPI / Maven / Go / Cargo / ... stay distinguishable however many ecosystems a repository mixes:
  fill + shape = ecosystem (node field `eco` = ecosystem id)   big / dark ring = direct, small = transitive
  red border + red halo = published advisories (independent of the ecosystem colour)   diamond = suspicious
The page carries a legend of the ecosystems present (with counts); clicking an entry hides / shows that ecosystem.
mode only changes the repo / manifest colours ("ecosystem" = graph.html, "dependency" = dashboard views).
With layered=True nodes are placed in columns by dependency level: repo | manifests | direct | depth 2 | depth 3 ...
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

import networkx as nx

from .graph import TRUSTED_NPM_HOSTS

# id -> (legend label, colour, shape). Colour follows the ecosystem, never its rank or a filter: code-library
# ecosystems take categorical slots 1-7 of the reference palette in slot order (validated on the light surface,
# adjacent CVD dE >= 9); infrastructure components are neutral inks. Shape is the second channel: any two
# ecosystems sharing a shape differ strongly in colour. Red (advisories), diamond (suspicious) and star (repo) are
# reserved, so no ecosystem uses them. A new ecosystem without an entry falls back to OTHER_COLOR.
ECOSYSTEMS = {
    "npm": ("npm", "#2a78d6", "dot"),
    "pypi": ("PyPI", "#eb6834", "square"),
    "maven": ("Maven", "#1baf7a", "triangle"),
    "go": ("Go", "#eda100", "hexagon"),
    "cargo": ("Cargo", "#e87ba4", "triangleDown"),
    "rubygems": ("RubyGems", "#008300", "dot"),
    "nuget": ("NuGet", "#6250d6", "square"),
    "docker": ("Container images", "#52514e", "square"),
    "github-actions": ("GitHub Actions", "#0b0b0b", "triangle"),
    "url": ("Downloaded files", "#898781", "triangleDown"),
}
ECO_ALIASES = {"gem": "rubygems", "golang": "go", "pip": "pypi", "python": "pypi", "crates": "cargo",
               "image": "docker", "oci": "docker", "actions": "github-actions"}
OTHER_COLOR = "#b4b2a9"
VULN_BORDER = "#d03b3b"   # status "critical"; always paired with the advisory text in the tooltip
VULN_HALO = {"enabled": True, "color": "rgba(208,59,59,0.55)", "size": 14, "x": 0, "y": 0}
INK, INK_2 = "#0b0b0b", "#52514e"
FACT_KEYS = ("registry", "tag", "digest", "pinned_by_digest", "official_image", "ref", "pinned_to_sha", "host")
APP_KEYS = ("triggers", "permissions", "stages", "runs_as")


def eco_key(eco) -> str:
    e = str(eco or "").strip().lower()
    return ECO_ALIASES.get(e, e)


def eco_style(eco) -> dict:
    k = eco_key(eco)
    label, color, shape = ECOSYSTEMS.get(k, (k or "other", OTHER_COLOR, "dot"))
    return {"id": k, "label": label, "color": color, "shape": shape}


def ecosystem_counts(G: nx.DiGraph, nodes=None) -> list[dict]:
    """[{id, label, color, shape, count, vulnerable}] for the package nodes given (default: all), largest first."""
    stats: dict[str, list[int]] = {}
    for n in (G if nodes is None else nodes):
        a = G.nodes[n]
        if a.get("kind") != "package":
            continue
        s = stats.setdefault(eco_key(a.get("ecosystem")), [0, 0])
        s[0] += 1
        s[1] += bool(a.get("vulns"))
    return [{**eco_style(k), "count": c, "vulnerable": v}
            for k, (c, v) in sorted(stats.items(), key=lambda kv: (-kv[1][0], kv[0]))]


def _tint(hex_color: str, t: float = 0.78) -> str:
    """hex_color mixed with white (box fills: dark ink stays readable on every ecosystem colour)."""
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
    return "#" + "".join(f"{round(c + (255 - c) * t):02x}" for c in (r, g, b))


def _safe(s) -> str:
    """Scanned repos are hostile: a lockfile 'version' could contain </script>. Neutralise HTML."""
    return str(s).replace("<", "‹").replace(">", "›").replace("&", "＆")


def _tooltip(a: dict, untrusted: bool) -> str:
    return "\n".join(filter(None, [  # all values already passed through _safe()
        a["label"], f"ecosystem: {a['ecosystem']}  scope: {a.get('scope')}",
        f"{'DIRECT' if a.get('direct') else 'transitive'}  depth: {a.get('depth')}  dependents: {a.get('dependents')}",
        f"resolution: {a.get('resolution')}", f"origin: {a.get('resolved')}" if a.get("resolved") else "",
        f"source: {a.get('source')}", "INSTALL SCRIPT" if a.get("install_script") else "",
        "UNTRUSTED ORIGIN" if untrusted else "",
        *[f"{k}: {a[k]}" for k in FACT_KEYS if a.get(k) not in (None, "")],
        f"{len(a['vulns'])} advisories: {', '.join(a['vulns'][:6])}" if a.get("vulns") else "",
        f"findings: {', '.join(a['findings'])}" if a.get("findings") else ""]))


def render_html(H: nx.DiGraph, mode: str = "ecosystem", layered: bool = False, small_labels: bool = True) -> str:
    """HTML for the graph. small_labels=False hides transitive labels (big views stay readable; hover still works)."""
    from pyvis.network import Network
    # no global font_color: pyvis would override every per-node font with it
    net = Network(height="800px", width="100%", directed=True, cdn_resources="in_line", bgcolor="#fcfcfb")
    boxes = mode == "dependency" and layered and small_labels  # readable tree: name inside a coloured box
    num = {n: i for i, n in enumerate(H.nodes)}  # numeric ids: no repo text in ids
    for n, a in H.nodes(data=True):
        a = {k: (_safe(v) if isinstance(v, str) else v) for k, v in a.items()}
        lvl = a.get("_level", {"repo": 0, "app": 1}.get(a["kind"], (a.get("depth") or 1) + 1))
        extra = {"level": lvl} if layered else {}
        if a["kind"] == "repo":
            net.add_node(num[n], label=a["label"], shape="star", color=INK if mode == "dependency" else "#333333",
                         size=30, **extra)
            continue
        if a["kind"] == "app":
            info = [f"{k}: {_safe(', '.join(map(str, a[k])) if isinstance(a[k], list) else a[k])}"
                    for k in APP_KEYS if a.get(k) not in (None, "", [])]
            dep = mode == "dependency"
            net.add_node(num[n], label=a["label"], shape="box", color=INK_2 if dep else "#2ca02c",
                         font={"color": "#ffffff" if dep else INK}, margin=8,
                         title="\n".join([f"{a['ecosystem']} manifest: {a['source']}"] + info), **extra)
            continue
        untrusted = bool(a.get("resolved")) and (urlparse(a["resolved"]).hostname or "") not in TRUSTED_NPM_HOSTS \
            and a["ecosystem"] == "npm"
        st = eco_style(a["ecosystem"])
        risky = bool(untrusted or a.get("install_script") or a.get("suspicious"))
        shape = "diamond" if risky else st["shape"]
        direct, vuln = bool(a.get("direct")), bool(a.get("vulns"))
        fill = st["color"]
        tip = _tooltip(a, untrusted)
        common = {"eco": st["id"],  # not vis `group`: group defaults would repaint the node
                  "title": tip, "shadow": VULN_HALO if vuln else False, **extra}
        if boxes:
            # name inside a box tinted with the ecosystem colour (dark ink stays >= 4.5:1 on every tint);
            # the full-strength ecosystem colour is the outline, replaced by a thick red one for advisories
            bg = _tint(fill)
            edge = VULN_BORDER if vuln else fill
            color = {"background": bg, "border": edge, "highlight": {"background": bg, "border": INK},
                     "hover": {"background": bg, "border": INK if not vuln else edge}}
            mark = "◆ " if risky else ""
            net.add_node(num[n], label=mark + a["label"], shape="box", color=color, margin=6,
                         borderWidth=4 if vuln else 2, widthConstraint={"maximum": 260},
                         font={"color": INK, "size": 15 if direct else 13}, **common)
            continue
        edge = VULN_BORDER if vuln else (INK if direct else fill)
        color = {"background": fill, "border": edge, "highlight": {"background": fill, "border": INK},
                 "hover": {"background": fill, "border": edge if vuln else INK}}
        label = a["label"] if (direct or small_labels) else " "
        size = (14 if direct else 7) if layered else (20 if direct else 10)
        net.add_node(num[n], label=label, color=color, size=size, shape=shape,
                     borderWidth=4 if vuln else (2 if direct else 1), **common)
    for u, v, e in H.edges(data=True):
        net.add_edge(num[u], num[v], title=_safe(e.get("spec", "")), color="#c3c2b7", arrows="to")
    if layered:
        net.set_options(json.dumps({
            "layout": {"hierarchical": {"enabled": True, "direction": "LR", "sortMethod": "directed",
                                        "levelSeparation": 320 if boxes else 220,
                                        "nodeSpacing": 42 if boxes else 18, "treeSpacing": 60}},
            "physics": {"enabled": False},
            "edges": {"smooth": {"type": "cubicBezier", "forceDirection": "horizontal", "roundness": 0.4},
                      "width": 0.6},
            "interaction": {"hover": True, "navigationButtons": True}}))
    else:
        net.set_options('{"physics":{"solver":"forceAtlas2Based","stabilization":{"iterations":250}},'
                        '"interaction":{"hover":true,"navigationButtons":true}}')
    html = net.generate_html(notebook=False)
    i = html.rfind("</body>")
    return html[:i] + _legend(ecosystem_counts(H)) + html[i:] if i >= 0 else html + _legend(ecosystem_counts(H))


LEGEND_MARK = "sscg-eco-legend"
_LEGEND_JS = r"""
(function () {
  var E = __DATA__, box = document.getElementById("sscg-eco-list"), off = {};
  var m = /(?:^|[#&])eco=([^&]*)/.exec(location.hash || "");
  if (m) { var want = decodeURIComponent(m[1]).split(","); E.forEach(function (e) { off[e.id] = want.indexOf(e.id) < 0; }); }
  var NS = "http://www.w3.org/2000/svg";
  function glyph(shape, color) {
    var s = document.createElementNS(NS, "svg"); s.setAttribute("width", "12"); s.setAttribute("height", "12");
    s.setAttribute("viewBox", "0 0 12 12"); s.setAttribute("aria-hidden", "true");
    var pts = {square: null, triangle: "6,1 11,11 1,11", triangleDown: "1,1 11,1 6,11",
               hexagon: "3,1 9,1 11.5,6 9,11 3,11 0.5,6", diamond: "6,0.5 11.5,6 6,11.5 0.5,6"}[shape];
    var el;
    if (shape === "square") { el = document.createElementNS(NS, "rect"); el.setAttribute("x", "1.5"); el.setAttribute("y", "1.5");
      el.setAttribute("width", "9"); el.setAttribute("height", "9"); el.setAttribute("rx", "1"); }
    else if (pts) { el = document.createElementNS(NS, "polygon"); el.setAttribute("points", pts); }
    else { el = document.createElementNS(NS, "circle"); el.setAttribute("cx", "6"); el.setAttribute("cy", "6"); el.setAttribute("r", "5"); }
    el.setAttribute("fill", color); s.appendChild(el); return s;
  }
  function apply() {
    if (typeof nodes === "undefined" || !nodes) return;
    var upd = [];
    nodes.forEach(function (n) { if (n.eco) { var h = !!off[n.eco]; if (!!n.hidden !== h) upd.push({id: n.id, hidden: h}); } });
    if (upd.length) nodes.update(upd);
  }
  E.forEach(function (e) {
    var b = document.createElement("button"); b.type = "button"; b.className = "sscg-eco";
    b.title = e.vulnerable ? e.vulnerable + " with advisories" : "";
    b.appendChild(glyph(e.shape, e.color));
    var t = document.createElement("span"); t.className = "sscg-eco-name"; t.textContent = e.label; b.appendChild(t);
    var c = document.createElement("span"); c.className = "sscg-eco-n"; c.textContent = e.count + (e.vulnerable ? "  (" + e.vulnerable + " vuln)" : "");
    b.appendChild(c);
    function paint() { b.setAttribute("aria-pressed", off[e.id] ? "false" : "true"); b.style.opacity = off[e.id] ? "0.4" : "1"; }
    b.onclick = function () { off[e.id] = !off[e.id]; paint(); apply(); };
    paint(); box.appendChild(b);
  });
  if (!E.length) document.getElementById("sscg-eco-legend").style.display = "none";
  apply();
})();
"""


def _legend(entries: list[dict]) -> str:
    """Overlay listing the ecosystems on the page (glyph, name, count); click toggles an ecosystem's nodes."""
    data = json.dumps(entries).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return f"""
<style>
#{LEGEND_MARK}{{position:fixed;top:10px;left:10px;z-index:5;max-width:280px;max-height:calc(100vh - 20px);overflow:auto;
 background:rgba(252,252,251,.95);border:1px solid #e1e0d9;border-radius:8px;padding:8px 10px;
 font:12px/1.35 system-ui,-apple-system,"Segoe UI",sans-serif;color:{INK};box-shadow:0 1px 3px rgba(0,0,0,.08)}}
#{LEGEND_MARK} .h{{font-weight:600;margin-bottom:4px}} #{LEGEND_MARK} .h span{{font-weight:400;color:{INK_2}}}
#{LEGEND_MARK} .sscg-eco{{display:flex;align-items:center;gap:6px;width:100%;border:0;background:none;padding:2px 2px;
 font:inherit;color:inherit;cursor:pointer;text-align:left;border-radius:4px}}
#{LEGEND_MARK} .sscg-eco:hover{{background:#f0efec}} #{LEGEND_MARK} .sscg-eco svg{{flex:none}}
#{LEGEND_MARK} .sscg-eco-name{{flex:1}} #{LEGEND_MARK} .sscg-eco-n{{color:{INK_2};font-variant-numeric:tabular-nums}}
#{LEGEND_MARK} .k{{margin-top:6px;padding-top:6px;border-top:1px solid #e1e0d9;color:{INK_2}}}
#{LEGEND_MARK} .ring{{display:inline-block;width:9px;height:9px;border-radius:50%;border:2.5px solid {VULN_BORDER};
 box-shadow:0 0 4px rgba(208,59,59,.6);vertical-align:-1px;margin-right:3px}}
</style>
<div id="{LEGEND_MARK}" role="group" aria-label="Ecosystems">
 <div class="h">Ecosystems <span>· click to hide / show</span></div>
 <div id="sscg-eco-list"></div>
 <div class="k"><span class="ring"></span>red ring = advisories · ◆ suspicious<br>large / dark outline = direct · small = transitive</div>
</div>
<script type="text/javascript">{_LEGEND_JS.replace("__DATA__", data)}</script>
"""


def export_html(H: nx.DiGraph, path: Path):
    path.write_text(render_html(H), encoding="utf-8")


def export_mermaid(H: nx.DiGraph, path: Path, max_nodes: int = 80) -> bool:
    if H.number_of_nodes() > max_nodes:
        return False
    ids = {n: f"n{i}" for i, n in enumerate(H.nodes)}
    lines = ["graph LR"]
    for n, a in H.nodes(data=True):
        label = _safe(a["label"]).replace('"', "'")
        lines.append(f'  {ids[n]}["{label}"]' + (":::vuln" if a.get("vulns") else ""))
    lines += [f"  {ids[u]} --> {ids[v]}" for u, v in H.edges]
    lines.append("  classDef vuln fill:#f8d7da,stroke:#d62728")
    path.write_text("\n".join(lines), encoding="utf-8")
    return True


def export_json(G: nx.DiGraph, path: Path):
    path.write_text(json.dumps({
        "nodes": [{"id": n, **a} for n, a in G.nodes(data=True)],
        "edges": [{"source": u, "target": v, **e} for u, v, e in G.edges(data=True)],
    }, indent=1, default=str), encoding="utf-8")
