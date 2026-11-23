"""report.md -> report.html (standalone, offline) and report.pdf (reportlab, pure Python, no system libraries).

The Markdown from report.py is the single source; both formats are rendered from it so they never disagree.
Report text includes strings taken from the scanned (possibly hostile) repository, so everything is escaped:
markdown-it runs with raw HTML disabled, and the PDF path escapes all text before building reportlab markup.
"""
from __future__ import annotations

import html
import io
import re
from pathlib import Path

from markdown_it import MarkdownIt

LEVEL_COLOR = {"🟥": "#d03b3b", "🟧": "#e07b1f", "🟨": "#c9a000", "🟦": "#2a78d6", "⬜": "#9a9890"}


def _md() -> MarkdownIt:
    return MarkdownIt("commonmark", {"html": False}).enable("table")


def _title(md: str) -> str:
    m = re.search(r"^# (.+)$", md, re.M)
    return m.group(1).strip() if m else "Guardian evidence report"


# ------------------------------------------------------------------------------------------------ HTML
CSS = """
:root{--bg:#fcfcfb;--fg:#1b1b19;--muted:#5f5e58;--line:#dedcd4;--head:#f1f0ec;--zebra:#f7f6f3;
--code:#f1f0ec;--link:#1f5fbf;--accent:#2a78d6}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#161615;--fg:#ecebe6;--muted:#a3a19a;
--line:#3a3935;--head:#22221f;--zebra:#1c1c1a;--code:#2a2a27;--link:#7fb0f5;--accent:#6aa6ef}}
:root[data-theme="dark"]{--bg:#161615;--fg:#ecebe6;--muted:#a3a19a;--line:#3a3935;--head:#22221f;--zebra:#1c1c1a;
--code:#2a2a27;--link:#7fb0f5;--accent:#6aa6ef}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif}
main{max-width:1180px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:1.9rem;line-height:1.2;margin:0 0 .4rem}
h2{font-size:1.35rem;margin:2.2rem 0 .8rem;padding-bottom:.3rem;border-bottom:2px solid var(--accent)}
h3{font-size:1.05rem;margin:1.8rem 0 .5rem}
p,li{max-width:110ch}
em{color:var(--muted)}
a{color:var(--link);overflow-wrap:anywhere}
code{font:.86em/1.4 ui-monospace,SFMono-Regular,Consolas,"DejaVu Sans Mono",monospace;background:var(--code);
padding:.1em .35em;border-radius:4px;overflow-wrap:anywhere}
pre{background:var(--code);padding:12px;border-radius:6px;overflow-x:auto}
pre code{padding:0;background:none}
table{display:block;overflow-x:auto;border-collapse:collapse;margin:.8rem 0 1.2rem;font-size:13px;max-width:100%}
th,td{border:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}
th{background:var(--head);font-weight:600}
tbody tr:nth-child(even){background:var(--zebra)}
ul{padding-left:1.4rem}
li{margin:.15rem 0}
footer{margin-top:3rem;color:var(--muted);font-size:12px}
@media print{:root{--bg:#fff;--fg:#000;--zebra:#f6f6f6}main{max-width:none;padding:0}
table{display:table;font-size:10px}h2,h3{break-after:avoid}tr{break-inside:avoid}a{color:inherit}}
"""


def to_html(md: str, title: str | None = None) -> str:
    """Standalone HTML page (inline CSS, no external resources, light/dark aware, prints cleanly)."""
    title = html.escape(title or _title(md))
    body = _md().render(md)
    return (f'<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f'<meta name="generator" content="sscg report_export">\n<title>{title}</title>\n'
            f'<style>{CSS}</style>\n</head>\n<body>\n<main>\n{body}'
            f'<footer>Generated from report.md by sscg. All findings with full evidence are in findings.json.</footer>\n'
            f'</main>\n</body>\n</html>\n')


# ------------------------------------------------------------------------------------------------ PDF
_FONT_SETS = [  # (regular, bold, italic, bold-italic, mono): first set whose files all exist wins
    [r"C:\Windows\Fonts\arial.ttf", r"C:\Windows\Fonts\arialbd.ttf", r"C:\Windows\Fonts\ariali.ttf",
     r"C:\Windows\Fonts\arialbi.ttf", r"C:\Windows\Fonts\consola.ttf"],
    ["/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
     "/usr/share/fonts/truetype/dejavu/DejaVuSans-Oblique.ttf",
     "/usr/share/fonts/truetype/dejavu/DejaVuSans-BoldOblique.ttf",
     "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"],
    ["/System/Library/Fonts/Supplemental/Arial.ttf", "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
     "/System/Library/Fonts/Supplemental/Arial Italic.ttf",
     "/System/Library/Fonts/Supplemental/Arial Bold Italic.ttf",
     "/System/Library/Fonts/Supplemental/Courier New.ttf"],
]
_fonts: tuple[str, str, bool] | None = None   # (body family, mono font, unicode-capable)


def _register_fonts() -> tuple[str, str, bool]:
    global _fonts
    if _fonts:
        return _fonts
    from reportlab.lib.fonts import addMapping
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    for files in _FONT_SETS:
        if all(Path(f).exists() for f in files):
            try:
                for name, f in zip(["RptSans", "RptSans-B", "RptSans-I", "RptSans-BI", "RptMono"], files):
                    pdfmetrics.registerFont(TTFont(name, f))
                for b, i, name in [(0, 0, "RptSans"), (1, 0, "RptSans-B"), (0, 1, "RptSans-I"), (1, 1, "RptSans-BI")]:
                    addMapping("RptSans", b, i, name)
                _fonts = ("RptSans", "RptMono", True)
                return _fonts
            except Exception:  # unreadable font file: try the next set
                continue
    _fonts = ("Helvetica", "Courier", False)  # built-in fonts: Latin-1 only, symbols are transliterated
    return _fonts


_ASCII = {"→": "->", "≥": ">=", "≤": "<=", "✔": "(ok)", "…": "...", "·": "-", "🆕": "NEW", "■": "#",
          "“": '"', "”": '"', "‘": "'", "’": "'", "–": "-", "—": "-", "‹": "<", "›": ">"}


def _plain(s: str, unicode_ok: bool) -> str:
    """Text the chosen font can draw: the text fonts have no ✔; the built-in fallback fonts are cp1252 only."""
    if unicode_ok:
        return s.replace("✔", "")
    s = "".join(_ASCII.get(ch, ch) for ch in s)
    return s.encode("cp1252", "replace").decode("cp1252")


def _esc(s: str, unicode_ok: bool) -> str:
    return html.escape(_plain(s, unicode_ok), quote=False)


_ICON_KEYS = [*LEVEL_COLOR, "🆕"]


def _text(s: str, unicode_ok: bool) -> str:
    """Escape text; level emoji become a coloured square (PDF fonts have no colour emoji), 🆕 a bold NEW.
    Icons travel through \\x01n\\x02 placeholders so the cp1252 fallback cannot turn them into '?'."""
    for k, emo in enumerate(_ICON_KEYS):
        s = s.replace(emo, f"\x01{k}\x02")
    s = _esc(s, unicode_ok)
    mark = "■" if unicode_ok else "#"

    def icon(m):
        k = int(m.group(1))
        if k == len(LEVEL_COLOR):
            return '<font color="#2a78d6"><b>NEW</b></font>'
        return f'<font color="{LEVEL_COLOR[_ICON_KEYS[k]]}">{mark}</font>'
    return re.sub("\x01(\\d+)\x02", icon, s)


def _inline(tok, mono: str, uni: bool) -> tuple[str, str]:
    """markdown-it inline token -> (reportlab paragraph markup, plain text for width estimates)."""
    out, plain, links = [], [], []
    for c in tok.children or []:
        t = c.type
        if t == "text":
            out.append(_text(c.content, uni))
            plain.append(c.content)
        elif t == "code_inline":
            out.append(f'<font face="{mono}" color="#7a2e1f">{_esc(c.content, uni)}</font>')
            plain.append(c.content)
        elif t in ("strong_open", "strong_close"):
            out.append("<b>" if t.endswith("open") else "</b>")
        elif t in ("em_open", "em_close"):
            out.append("<i>" if t.endswith("open") else "</i>")
        elif t == "link_open":
            href = str(c.attrGet("href") or "")
            ok = href.startswith(("https://", "http://"))
            links.append(ok)
            if ok:
                out.append(f'<a href="{html.escape(href, quote=True)}" color="#1f5fbf">')
        elif t == "link_close":
            if links and links.pop():
                out.append("</a>")
        elif t == "softbreak":
            out.append(" ")
        elif t == "hardbreak":
            out.append("<br/>")
        else:  # html_inline etc. (disabled, but never pass anything through unescaped)
            out.append(_esc(c.content or "", uni))
            plain.append(c.content or "")
    return "".join(out), "".join(plain)


def to_pdf(md: str, title: str | None = None) -> bytes:
    """A4 PDF of the report: headings, paragraphs, nested bullet lists and wrapping tables that split across pages."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (HRFlowable, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table,
                                    TableStyle)

    sans, mono, uni = _register_fonts()
    title = title or _title(md)
    bold = "RptSans-B" if uni else "Helvetica-Bold"
    ink, muted, line, head = colors.HexColor("#1b1b19"), colors.HexColor("#5f5e58"), \
        colors.HexColor("#d9d7cf"), colors.HexColor("#f1f0ec")
    S = {
        "h1": ParagraphStyle("h1", fontName=bold, fontSize=18, leading=22, spaceAfter=6, textColor=ink),
        "h2": ParagraphStyle("h2", fontName=bold, fontSize=13.5, leading=17, spaceBefore=14, spaceAfter=6,
                             textColor=ink, keepWithNext=1),
        "h3": ParagraphStyle("h3", fontName=bold, fontSize=10.5, leading=13.5, spaceBefore=10, spaceAfter=3,
                             textColor=ink, keepWithNext=1),
        "p": ParagraphStyle("p", fontName=sans, fontSize=9, leading=12.5, spaceAfter=5, textColor=ink,
                            alignment=TA_LEFT),
        "cell": ParagraphStyle("cell", fontName=sans, fontSize=7.4, leading=9.2, textColor=ink),
        "th": ParagraphStyle("th", fontName=bold, fontSize=7.4, leading=9.2, textColor=ink),
        "pre": ParagraphStyle("pre", fontName=mono, fontSize=7.5, leading=9.5, backColor=head, borderPadding=4),
    }
    page_w, page_h = A4
    margin = 15 * mm
    avail = page_w - 2 * margin

    def li_style(depth: int) -> ParagraphStyle:
        return ParagraphStyle(f"li{depth}", parent=S["p"], leftIndent=10 + depth * 12, bulletIndent=depth * 12,
                              bulletFontName=sans, spaceAfter=2)

    story: list = []
    toks = _md().parse(md)
    depth, item_first, i = 0, False, 0
    while i < len(toks):
        t = toks[i]
        if t.type == "heading_open":
            markup, _ = _inline(toks[i + 1], mono, uni)
            story.append(Paragraph(markup, S.get(t.tag, S["h3"])))
            if t.tag == "h1":
                story.append(HRFlowable(width="100%", thickness=1.2, color=colors.HexColor("#2a78d6"),
                                        spaceAfter=6))
            i += 3
            continue
        if t.type in ("bullet_list_open", "ordered_list_open"):
            depth += 1
        elif t.type in ("bullet_list_close", "ordered_list_close"):
            depth -= 1
            if depth == 0:
                story.append(Spacer(1, 4))
        elif t.type == "list_item_open":
            item_first = True
        elif t.type == "inline":  # paragraph text (headings and table cells are consumed elsewhere)
            markup, _ = _inline(t, mono, uni)
            if depth:
                style = li_style(depth - 1)
                bullet = ("•" if depth == 1 else "–" if uni else "-") if item_first else None
                story.append(Paragraph(markup, style, bulletText=bullet))
                item_first = False
            else:
                story.append(Paragraph(markup, S["p"]))
        elif t.type in ("fence", "code_block"):
            story.append(Preformatted(_plain(t.content, uni), S["pre"]))
        elif t.type == "hr":
            story.append(HRFlowable(width="100%", thickness=0.6, color=line, spaceBefore=4, spaceAfter=4))
        elif t.type == "table_open":
            rows, header, j = [], False, i + 1
            while toks[j].type != "table_close":
                if toks[j].type == "tr_open":
                    rows.append([])
                elif toks[j].type in ("th_open", "td_open"):
                    markup, plain = _inline(toks[j + 1], mono, uni)
                    rows[-1].append((markup, plain, toks[j].type == "th_open"))
                    j += 2
                j += 1
            i = j + 1
            header = bool(rows) and rows[0][0][2]
            if header and not any(p.strip() for _, p, _ in rows[0]):  # "| | |" key/value tables: no header row
                rows, header = rows[1:], False
            story.append(_table(rows, header, avail, S, line, head, Paragraph, Table, TableStyle, colors))
            story.append(Spacer(1, 6))
            continue
        i += 1

    def on_page(canvas, doc):
        canvas.saveState()
        canvas.setFont(sans, 7.5)
        canvas.setFillColor(muted)
        canvas.drawString(margin, 9 * mm, _plain(title, uni)[:120])
        canvas.drawRightString(page_w - margin, 9 * mm, f"page {doc.page}")
        canvas.restoreState()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=margin, rightMargin=margin, topMargin=margin,
                            bottomMargin=16 * mm, title=title, author="sscg", subject="Supply-chain evidence report")
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()


def _table(rows, header, avail, S, line, head, Paragraph, Table, TableStyle, colors):
    ncol = max(len(r) for r in rows)
    rows = [r + [("", "", False)] * (ncol - len(r)) for r in rows]
    # column widths in proportion to content length (capped so one long column cannot starve the others)
    weight = [max(min(len(r[c][1]), 70) for r in rows) + 4 for c in range(ncol)]
    floor = avail * 0.05
    widths = [max(floor, avail * w / sum(weight)) for w in weight]
    widths = [w * avail / sum(widths) for w in widths]
    data = [[Paragraph(m, S["th"] if (header and ri == 0) else S["cell"]) for m, _, _ in r]
            for ri, r in enumerate(rows)]
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    style = [("GRID", (0, 0), (-1, -1), 0.4, line), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
             ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
             ("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1), [colors.white, colors.HexColor("#f7f6f3")])]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), head))
    t.setStyle(TableStyle(style))
    return t


def write_all(md: str, out: Path) -> list[str]:
    """Write report.html and report.pdf next to report.md. Returns the file names written; a PDF failure
    (e.g. reportlab missing) is reported but never breaks the scan."""
    written = []
    (out / "report.html").write_text(to_html(md), encoding="utf-8")
    written.append("report.html")
    try:
        (out / "report.pdf").write_bytes(to_pdf(md))
        written.append("report.pdf")
    except Exception as e:  # noqa: BLE001
        print(f"  note: report.pdf not written ({type(e).__name__}: {e})")
    return written
