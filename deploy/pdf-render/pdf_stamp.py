"""Signatures drawn onto a PDF that is already made (`POST /pdf/stamp`), for Word templates.

A Word template's signature spots carry an invisible marker, `[[sig:<key>]]` (white, 1 pt), written by
docx_edit.prepare. Stamping finds each marker in the PDF's text, and draws the signature for that key
just above where the marker sits (the signature line the builder left stays under it). Keys: `A1`..
`An` the applicants in order, `A*` all applicants side by side, `B` the builder's signatory, `W1`..
witnesses. A signer whose key has no spot in the document, and every signer when `recordPage` is
on, also go on a "Signatures" page added at the end (image, name, how and when), so a signature is
never lost because the template had no place for it.

The PDF is not made again: the signer signs exactly the file they were shown, and stamping takes
milliseconds where converting a long agreement takes seconds.

Request: `{"file": <PDF URL>, "stamps": [{"key", "image" (data:image/png|jpeg URL), "name", "lines"
[...], "widthMm" (default 32)}], "recordPage": bool}`. Answer: the PDF; header `X-Stamp-Result` is JSON
`{"placed": [keys], "onRecordPage": [keys]}`.
"""

import base64
import html
import io
import json
import re

from pypdf import PdfReader, PdfWriter

MARKER = re.compile(r"\[\[sig:([A-Za-z0-9*]{1,4})\]\]")
DATA_IMAGE = re.compile(r"^data:image/(png|jpe?g);base64,[A-Za-z0-9+/=\s]+$")
PT_PER_MM = 72 / 25.4
MARGIN_PT = 28.0  # signatures stay this far inside the page's right edge
GAP_PT = 6.0
MIN_MM = 18.0


class BadStamp(Exception):
    """A request stamping cannot do: a 400."""


def find_spots(reader):
    """{key: [(page index, x, y)]}: where each marker starts, in PDF points from the page's
    bottom left (the text's baseline)."""
    spots = {}
    for pi, page in enumerate(reader.pages):
        chunks = []

        def visit(text, cm, tm, font, size):
            if not text:
                return
            # the text space origin in user space: tm then cm
            x = tm[4] * cm[0] + tm[5] * cm[2] + cm[4]
            y = tm[4] * cm[1] + tm[5] * cm[3] + cm[5]
            chunks.append((text, x, y))

        page.extract_text(visitor_text=visit)
        joined, owner = "", []
        for ci, (text, _, _) in enumerate(chunks):
            joined += text
            owner.extend([ci] * len(text))
        for m in MARKER.finditer(joined):
            text, x, y = chunks[owner[m.start()]]
            spots.setdefault(m.group(1), []).append((pi, x, y))
    return spots


def _overlay_html(width_pt, height_pt, items):
    """One page of the given size with images at absolute places (points from the bottom left)."""
    boxes = []
    for x, y, w_pt, img in items:
        boxes.append(f'<img src="{img}" style="position:absolute;left:{x:.2f}pt;bottom:{y:.2f}pt;width:{w_pt:.2f}pt">')
    return (f"<html><head><style>@page{{size:{width_pt:.2f}pt {height_pt:.2f}pt;margin:0}}"
            f"body{{margin:0;position:relative;width:{width_pt:.2f}pt;height:{height_pt:.2f}pt}}</style></head>"
            f"<body>{''.join(boxes)}</body></html>")


def _record_html(rows):
    cells = []
    for r in rows:
        lines = "".join(f"<div class='l'>{html.escape(str(x))}</div>" for x in r.get("lines") or [])
        img = f"<img src='{r['image']}'>" if r.get("image") else ""
        cells.append(f"<tr><td class='i'>{img}</td><td><div class='n'>{html.escape(str(r.get('name') or r['key']))}</div>{lines}</td></tr>")
    return ("<html><head><style>@page{size:A4;margin:20mm}body{font-family:'Noto Sans',sans-serif;font-size:9.5pt;color:#111}"
            "h1{font-size:12pt;margin:0 0 6mm}table{width:100%;border-collapse:collapse}td{border-bottom:1px solid #ccc;"
            "padding:3mm 2mm;vertical-align:top}td.i{width:55mm}td.i img{max-width:50mm;max-height:22mm}.n{font-weight:bold}"
            ".l{color:#444;font-size:8.5pt}</style></head><body><h1>Signatures</h1><table>"
            + "".join(cells) + "</table></body></html>")


def _check_image(src):
    if not isinstance(src, str) or not DATA_IMAGE.match(src) or len(src) > 7_000_000:
        raise BadStamp("an image must be a data:image/png or data:image/jpeg URL under 5 MiB")
    return src


def stamp(pdf_bytes, stamps, record_page=False, render_html=None):
    """The PDF with the signatures drawn (bytes) and what was placed where."""
    if render_html is None:
        from weasyprint import HTML

        def render_html(markup):
            return HTML(string=markup).write_pdf()

    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
    except Exception as e:
        raise BadStamp(f"not a PDF: {type(e).__name__}") from None
    if not isinstance(stamps, list) or not stamps:
        raise BadStamp("stamps: at least one signature")
    for s in stamps:
        if not isinstance(s, dict) or not MARKER.fullmatch(f"[[sig:{s.get('key', '')}]]"):
            raise BadStamp("every stamp needs a key such as A1, A*, B or W1")
        _check_image(s.get("image"))
    spots = find_spots(reader)
    per_page, placed, unplaced = {}, [], []
    applicants = sorted((s for s in stamps if re.fullmatch(r"A[0-9]+", s["key"])), key=lambda s: int(s["key"][1:]))

    def put(pi, x, y, row):
        """A row of signatures starting at the marker, inside the page's right margin: narrowed to
        fit (down to MIN_MM each), then moved left if it still does not."""
        right = float(reader.pages[pi].mediabox.width) - MARGIN_PT
        widths = [float(s.get("widthMm") or 32) * PT_PER_MM for s in row]
        room = right - x - GAP_PT * (len(row) - 1)
        if sum(widths) > room:
            scale = max(room, MIN_MM * PT_PER_MM * len(row)) / sum(widths)
            widths = [w * scale for w in widths]
        total = sum(widths) + GAP_PT * (len(row) - 1)
        cx = max(MARGIN_PT, min(x, right - total))
        for s, w in zip(row, widths):
            per_page.setdefault(pi, []).append((cx, y + 1.5, w, s["image"]))
            cx += w + GAP_PT

    for s in stamps:
        where = spots.get(s["key"], [])
        for pi, x, y in where:
            put(pi, x, y, [s])
        (placed if where else unplaced).append(s["key"])
    # A*: every applicant, side by side, at each A* spot
    for pi, x, y in spots.get("A*", []):
        if applicants:
            put(pi, x, y, applicants)
        if applicants:
            placed.append("A*")
            unplaced = [k for k in unplaced if not re.fullmatch(r"A[0-9]+", k)]
    writer = PdfWriter(clone_from=reader)
    for pi, items in per_page.items():
        page = writer.pages[pi]
        box = page.mediabox
        overlay = PdfReader(io.BytesIO(render_html(_overlay_html(float(box.width), float(box.height), items)))).pages[0]
        page.merge_page(overlay)
    record = [s for s in stamps if s["key"] in unplaced or record_page]
    if record:
        for p in PdfReader(io.BytesIO(render_html(_record_html(record)))).pages:
            writer.add_page(p)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue(), {"placed": sorted(set(placed)), "onRecordPage": [s["key"] for s in record]}


def handle(body, policy):
    try:
        req = json.loads(body)
    except ValueError:
        raise BadStamp("body: not JSON") from None
    if not isinstance(req, dict) or not isinstance(req.get("file"), str) or not req["file"]:
        raise BadStamp("body: `file` (the PDF URL) is required")
    from docx_render import _read_file

    return stamp(_read_file(req["file"], policy), req.get("stamps"), bool(req.get("recordPage")))
