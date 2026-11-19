"""A rendered HTML template (a cost sheet, a booking form) as an editable Word file: `POST /docx/from-html`.

Not pixel-identical to the PDF: Word has no flexbox, no `border-spacing`, no running elements. The aim is a
file staff can edit, with the same words, tables, colours, logo and page setup. How:

1. normalise (`prepare`): the `<style>` rules are applied to every element as inline styles (cssselect2, the
   same selector engine WeasyPrint uses, specificity then order), so LibreOffice, whose own CSS support is
   partial, only sees what it understands: `background` becomes `background-color`, `text-transform` is applied
   to the text, an image is fetched through the same `Policy` as the PDF render (files URLs only) and embedded
   at the size its `max-width`/`max-height` give, a flex row becomes a one-row table (a wrapping one, rows of as
   many as fit), a row of `inline-block` boxes becomes a table row, `position: fixed|absolute` boxes (watermarks)
   are left out, and the `position: running()` header and footer are taken out of the page body;
2. LibreOffice imports the HTML (`HTML (StarWriter)`) and saves it as .docx (`docx_render.Converter`);
3. python-docx sets the page (size, orientation, margins from `@page`) and builds the header and footer from the
   running elements, with "Page X of Y" as real Word fields when the template prints it.

Everything fetched goes through `Policy.fetch`; the HTML is never given a URL to open on its own.
"""

import io
import logging
import re
import subprocess
import os
import shutil
import signal
import tempfile
import urllib.parse

LOG = logging.getLogger("pdf-render.docx_html")

BASE_URL = "https://pdf-render.invalid/"
MAX_IMAGE_BYTES = 5 * 1024 * 1024

DROP = {
    "position", "top", "left", "right", "bottom", "z-index", "box-shadow", "border-radius", "gap", "row-gap", "column-gap",
    "flex", "flex-grow", "flex-shrink", "flex-basis", "flex-direction", "flex-wrap", "align-items", "align-content",
    "justify-content", "align-self", "box-sizing", "overflow", "overflow-x", "overflow-y", "opacity", "table-layout",
    "page-break-inside", "break-inside", "orphans", "widows", "border-spacing", "max-width", "max-height", "min-width",
    "min-height", "text-overflow", "float", "clear", "cursor", "transform", "word-break", "hyphens", "outline",
    "column-count", "column-gap", "column-width", "columns", "column-rule", "-webkit-print-color-adjust", "print-color-adjust", "text-transform", "font-display",
}
COLOR = re.compile(r"#[0-9a-fA-F]{3,8}\b|rgba?\([^)]*\)|\b(?:white|black|red|green|blue|gray|grey|silver|yellow|orange|navy|teal|maroon|purple|transparent)\b")
LEN = re.compile(r"^(-?[0-9.]+)\s*(mm|cm|in|pt|px|em|%)?$")
PX_PER = {"px": 1.0, "mm": 96 / 25.4, "cm": 96 / 2.54, "in": 96.0, "pt": 96 / 72}
MM_PER = {"mm": 1.0, "cm": 10.0, "in": 25.4, "pt": 25.4 / 72, "px": 25.4 / 96}


# the browser's own margins (px) of block elements that have some, top and bottom; others are 0
UA_MARGIN = {"div": (0, 0), "p": (12, 12), "h1": (21, 21), "h2": (20, 20), "h3": (19, 19), "h4": (21, 21), "h5": (22, 22),
             "h6": (25, 25), "ul": (12, 12), "ol": (12, 12), "li": (0, 0), "blockquote": (12, 12), "pre": (12, 12)}


def _px(value):
    m = LEN.match((value or "").strip())
    if not m or m.group(2) in ("%", "em"):
        return None
    return float(m.group(1)) * PX_PER[m.group(2) or "px"]


def _mm(value):
    m = LEN.match((value or "").strip())
    if not m or m.group(2) in ("%", "em"):
        return None
    return float(m.group(1)) * MM_PER[m.group(2) or "px"]


def _decls(text):
    """`a:b; c:d` as an ordered dict (later wins)."""
    import tinycss2

    out = {}
    for d in tinycss2.parse_declaration_list(text or "", skip_comments=True, skip_whitespace=True):
        if d.type == "declaration":
            out[d.lower_name] = (tinycss2.serialize(d.value).strip(), d.important)
    return out


def _page_rule(css):
    """What `@page` says: size (mm), landscape, margins (mm), the running elements named by the margin boxes and
    whether it prints "Page x of y"."""
    page = {"w": 210.0, "h": 297.0, "margin": [18.0, 18.0, 18.0, 18.0], "boxes": {}, "numbers": False}
    for m in re.finditer(r"@page\s*[a-zA-Z:]*\s*\{", css):
        depth, i = 1, m.end()
        while i < len(css) and depth:
            depth += {"{": 1, "}": -1}.get(css[i], 0)
            i += 1
        body = css[m.end():i - 1]
        head = re.sub(r"@[a-z-]+\s*\{[^{}]*\}", "", body)
        d = _decls(head)
        size = d.get("size", ("", False))[0].lower()
        if size:
            toks = size.split()
            sizes = {"a4": (210.0, 297.0), "a3": (297.0, 420.0), "a5": (148.0, 210.0), "letter": (215.9, 279.4), "legal": (215.9, 355.6)}
            for t in toks:
                if t in sizes:
                    page["w"], page["h"] = sizes[t]
            if "landscape" in toks:
                page["w"], page["h"] = max(page["w"], page["h"]), min(page["w"], page["h"])
            dims = [_mm(t) for t in toks]
            if len(dims) == 2 and all(dims):
                page["w"], page["h"] = dims
        mg = d.get("margin", ("", False))[0].split()
        vals = [_mm(v) for v in mg]
        if vals and all(v is not None for v in vals):
            page["margin"] = _four(vals)
        for side, key in (("top", "margin-top"), ("right", "margin-right"), ("bottom", "margin-bottom"), ("left", "margin-left")):
            if key in d and _mm(d[key][0]) is not None:
                page["margin"]["trbl".index(side[0])] = _mm(d[key][0])
        for box in re.finditer(r"@([a-z-]+)\s*\{([^{}]*)\}", body):
            name, content = box.group(1), box.group(2)
            el = re.search(r"content\s*:\s*element\(\s*([A-Za-z0-9_-]+)\s*\)", content)
            if el:
                page["boxes"][name] = el.group(1)
            elif "counter(page)" in content:
                page["numbers"] = True
    return page


def _fetch(url, policy):
    return policy.fetch(urllib.parse.urljoin(BASE_URL, url))["string"]


def _image(src, policy):
    """The image's bytes (data URL or a files URL through the policy), None when it cannot be read."""
    import base64

    try:
        m = re.match(r"^data:[^;,]*;base64,(.+)$", src, re.S)
        raw = base64.b64decode(m.group(1)) if m else _fetch(src, policy)
    except Exception as e:  # a missing logo must not fail the document
        LOG.warning("image left out (%s): %s", type(e).__name__, str(e)[:120])
        return None
    return raw if len(raw) <= MAX_IMAGE_BYTES else None


def _size_image(raw, style):
    """(width_px, height_px) the image takes: its CSS width/height, else its natural size cut to max-width/max-height."""
    from PIL import Image

    try:
        with Image.open(io.BytesIO(raw)) as im:
            w, h = im.size
    except Exception:
        return None
    cw, ch = _px(style.get("width", ("", 0))[0]), _px(style.get("height", ("", 0))[0])
    if cw and not ch:
        return cw, cw * h / w
    if ch and not cw:
        return ch * w / h, ch
    if cw and ch:
        return cw, ch
    mw, mh = _px(style.get("max-width", ("", 0))[0]), _px(style.get("max-height", ("", 0))[0])
    k = 1.0
    if mw:
        k = min(k, mw / w)
    if mh:
        k = min(k, mh / h)
    return max(1.0, w * k), max(1.0, h * k)


def _ctype(raw):
    if raw[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if raw[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if raw[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    return None


def _transform(el, how):
    f = {"uppercase": str.upper, "lowercase": str.lower, "capitalize": str.title}.get(how)
    if not f:
        return
    for node in el.iter():
        if not isinstance(node.tag, str):
            continue
        if node.text and node is not el:
            node.text = f(node.text)
    # own text and every tail inside the element
    if el.text:
        el.text = f(el.text)
    for node in el.iter():
        if node is not el and node.tail and node.getparent() is not None:
            node.tail = f(node.tail)


class Prepared:
    def __init__(self, html, page, header, footer, pads=(), marks=()):
        self.html, self.page, self.header, self.footer = html, page, header, footer
        # paragraphs given a rule or a shading after the conversion (LibreOffice turns a div's border and
        # background into a box around its characters): index -> {"bottom": (pt, hex), "top": ..., "box": ..., "fill": hex}
        self.marks = list(marks)
        # per table, in document order: the cell padding (top, right, bottom, left) in twips, or None
        self.pads = list(pads)


def prepare(html, policy):
    """The normalised HTML plus the page setup and the running header/footer (see the module doc)."""
    import cssselect2
    import tinycss2
    from lxml import etree
    from lxml import html as lh

    root = lh.document_fromstring(html)
    css = "\n".join(s.text_content() for s in root.iter("style"))
    page = _page_rule(css)
    matcher = cssselect2.Matcher()
    order = 0
    sheet = tinycss2.parse_stylesheet(css, skip_comments=True, skip_whitespace=True)
    for rule in sheet:
        if rule.type != "qualified-rule":
            continue
        try:
            selectors = cssselect2.compile_selector_list(tinycss2.serialize(rule.prelude))
        except Exception:
            continue
        decls = _decls(tinycss2.serialize(rule.content))
        for sel in selectors:
            if sel.pseudo_element:
                continue
            order += 1
            matcher.add_selector(sel, (sel.specificity, order, decls))
    wrapper = cssselect2.ElementWrapper.from_html_root(root)

    styles = {}  # element -> {prop: (value, important)}
    for el in root.iter():
        if not isinstance(el.tag, str):
            continue
    for w in [wrapper] + list(wrapper.iter_subtree())[1:]:
        el = w.etree_element
        if not isinstance(el.tag, str):
            continue
        merged = {}
        hits = sorted((payload for *_x, payload in matcher.match(w)), key=lambda p: (p[0], p[1]))
        for _spec, _order, decls in hits:
            for k, (v, imp) in decls.items():
                if imp or k not in merged or not merged[k][1]:
                    merged[k] = (v, imp)
        for k, (v, imp) in _decls(el.get("style", "")).items():
            if imp or k not in merged or not merged[k][1]:
                merged[k] = (v, imp)
        styles[el] = merged

    # running elements (the page header and footer) leave the body
    running = {}
    for el, st in list(styles.items()):
        pos = st.get("position", ("", 0))[0]
        m = re.match(r"running\(\s*([A-Za-z0-9_-]+)\s*\)", pos)
        if m:
            running[m.group(1)] = el
    header = footer = None
    for box, name in page["boxes"].items():
        el = running.get(name)
        if el is None:
            continue
        if box.startswith("top") and header is None:
            header = el
        elif box.startswith("bottom") and footer is None:
            footer = el
    if header is None and "hdr" in running:
        header = running["hdr"]
    if footer is None and "ftr" in running:
        footer = running["ftr"]
    header_parts = _running_parts(header, styles, policy) if header is not None else None
    footer_parts = _running_parts(footer, styles, policy) if footer is not None else None
    for el in running.values():
        if el.getparent() is not None:
            el.getparent().remove(el)

    body = root.find("body")
    _convert_layout(body, styles, page, policy)
    _table_spacers(body, styles)
    _inherit_fonts(body, styles, root)
    pads = [_table_padding(t, styles) for t in body.iter("table")]
    marks = []
    _write(body, styles, policy, "", marks)

    for tag in ("style", "link", "script"):
        for el in list(root.iter(tag)):
            el.getparent().remove(el)
    head = root.find("head")
    if head is None:
        head = etree.SubElement(root, "head")
        root.insert(0, head)
    for m in head.findall("meta"):
        head.remove(m)
    etree.SubElement(head, "meta", charset="utf-8")
    out = lh.tostring(root, encoding="unicode", doctype="<!DOCTYPE html>")
    return Prepared(out, page, header_parts, footer_parts, pads, marks)


def _border(value):
    """`1px solid #111` as (pt, hex), None for none/0."""
    if not value or value.strip() in ("0", "none") or "none" in value or "hidden" in value:
        return None
    w = _px(next((t for t in value.split() if LEN.match(t)), "1px")) or 1.0
    if w <= 0:
        return None
    m = COLOR.search(value)
    color = m.group(0) if m else "#000"
    if color.startswith("rgb"):
        n = [int(float(x)) for x in re.findall(r"[0-9.]+", color)[:3]]
        color = "#%02x%02x%02x" % tuple(n)
    if len(color) == 4:
        color = "#" + "".join(c * 2 for c in color[1:])
    return (max(0.25, w * 0.75), color.lstrip("#").upper()[:6])


def _mark_of(st):
    """What a block's border and background ask of the paragraph (see Prepared.marks), or None."""
    mark = {}
    for side in ("top", "bottom", "left", "right"):
        b = _border(st.get(f"border-{side}", ("", 0))[0])
        if b:
            mark[side] = b
    allb = _border(st.get("border", ("", 0))[0])
    if allb:
        for side in ("top", "bottom", "left", "right"):
            mark.setdefault(side, allb)
    bg = st.get("background-color", ("", 0))[0] or st.get("background", ("", 0))[0]
    m = COLOR.search(bg or "")
    if m and m.group(0) != "transparent" and "gradient" not in bg:
        c = m.group(0)
        if c.startswith("rgb"):
            n = [int(float(x)) for x in re.findall(r"[0-9.]+", c)[:3]]
            c = "#%02x%02x%02x" % tuple(n)
        if len(c) == 4:
            c = "#" + "".join(x * 2 for x in c[1:])
        mark["fill"] = c.lstrip("#").upper()[:6]
    return mark or None


def _four(parts):
    """CSS's one to four values as (top, right, bottom, left)."""
    n = len(parts)
    if n == 1:
        return parts * 4
    if n == 2:
        return parts * 2
    if n == 3:
        return parts + [parts[1]]
    return (parts + [0.0] * 4)[:4]


def _box(st, prop):
    """(top, right, bottom, left) in px of `margin` or `padding` (shorthand, then the longhands)."""
    vals = [None] * 4
    parts = [_px(v) if v != "auto" else 0.0 for v in st.get(prop, ("", 0))[0].split()]
    if parts and all(v is not None for v in parts):
        vals = _four(parts)
    for i, side in enumerate(("top", "right", "bottom", "left")):
        v = _px(st.get(f"{prop}-{side}", ("", 0))[0])
        if v is not None:
            vals[i] = v
    return [v or 0.0 for v in vals]


def _table_padding(table, styles):
    """The padding most of the table's cells have, in twips, with half of a `border-spacing` row gap added above
    and below (Word has no row gap): LibreOffice reads cell padding only from the table, and a cell that
    names its own padding loses the table's, so the padding is put back on the table by `finish`."""
    counts = {}
    for td in table.iter("td", "th"):
        pad = tuple(_box(styles.get(td, {}), "padding"))
        counts[pad] = counts.get(pad, 0) + 1
    if not counts:
        return None
    top, right, bottom, left = max(counts, key=counts.get)
    spacing = styles.get(table, {}).get("border-spacing", ("", 0))[0].split()
    gap = (_px(spacing[-1]) or 0.0) / 2 if spacing and styles.get(table, {}).get("border-collapse", ("", 0))[0] != "collapse" else 0.0
    tw = lambda px: int(round((px + 0) * 15))
    return [tw(top + gap), tw(right), tw(bottom + gap), tw(left)]


def _inherit_fonts(body, styles, root):
    """A heading has LibreOffice's own heading font unless its style names one: give it the page's (body's) font."""
    for el in body.iter("h1", "h2", "h3", "h4", "h5", "h6"):
        st = styles.setdefault(el, {})
        if "font-family" in st:
            continue
        node = el.getparent()
        while node is not None:
            ff = styles.get(node, {}).get("font-family")
            if ff:
                st["font-family"] = ff
                break
            node = node.getparent()


def _table_spacers(body, styles):
    """A table's `margin-top`/`margin-bottom` as an empty paragraph with that space (LibreOffice drops it)."""
    from lxml import html as lh

    for table in list(body.iter("table")):
        mt, _r, mb, _l = _box(styles.get(table, {}), "margin")
        for px, before in ((mt, True), (mb, False)):
            if px < 10 or table.getparent() is None:
                continue
            sp = lh.Element("p")
            sp.text = "\u00a0"
            styles[sp] = {"margin-top": (f"{max(0.0, px - 9.5):.0f}px", False), "margin-bottom": ("0px", False), "margin-left": ("0px", False),
                          "margin-right": ("0px", False), "font-size": ("1pt", False), "line-height": ("1pt", False)}
            parent = table.getparent()
            if before:
                parent.insert(parent.index(table), sp)
            else:
                sp.tail = table.tail
                table.tail = None
                parent.insert(parent.index(table) + 1, sp)


def _running_parts(el, styles, policy):
    """A running header/footer as a list of paragraphs python-docx can place: {images [(bytes, w_px, h_px)], text, right,
    bold, size (pt), color, fill, rule}: each top-level table (a logo row) or block of the element becomes one."""
    paras = []

    def one(node):
        st = styles.get(node, {})
        images = []
        for im in node.iter("img"):
            raw = _image(im.get("src", ""), policy)
            if raw and _ctype(raw):
                sz = _size_image(raw, styles.get(im, {}))
                if sz:
                    images.append((raw, sz[0], sz[1]))
        right = ""
        for td in node.iter("td"):
            if styles.get(td, {}).get("text-align", ("", 0))[0] == "right":
                right = " ".join(td.text_content().split())
        text = " ".join(node.text_content().split())
        if right and text.endswith(right):
            text = text[: -len(right)].strip()
        fs = _px(st.get("font-size", ("", 0))[0])
        mark = _mark_of(st) if node.tag != "table" else None
        color = COLOR.search(st.get("color", ("", 0))[0] or "")
        if images or text or right:
            paras.append({"images": images, "text": text, "right": right, "bold": "bold" in st.get("font-weight", ("", 0))[0],
                          "size": fs * 0.75 if fs else None, "color": color.group(0) if color else None, "mark": mark})

    kids = [c for c in el if isinstance(c.tag, str)]
    if not kids:
        one(el)
    for c in kids:
        one(c)
    return paras


def _display(st):
    return (st.get("display", ("", 0))[0] or "").strip().lower()


def _is_text_ws(s):
    return s is None or not s.strip()


def _convert_layout(body, styles, page, policy):
    """Flex rows and rows of inline-blocks become tables; fixed/absolute boxes are dropped."""
    from lxml import etree
    from lxml import html as lh

    content_mm = page["w"] - page["margin"][1] - page["margin"][3]

    def build_table(children, gap_mm, widths_mm, ncols, justify_right_last=False):
        table = lh.Element("table")
        st = {"width": ("100%", False), "border-collapse": ("collapse", False)}
        styles[table] = st
        rows = [children[i:i + ncols] for i in range(0, len(children), ncols)] or [[]]
        for row in rows:
            tr = etree.SubElement(table, "tr")
            styles[tr] = {}
            for idx, child in enumerate(row):
                td = etree.SubElement(tr, "td")
                tst = {"vertical-align": ("top", False)}
                w = widths_mm.get(child)
                if w:
                    tst["width"] = (f"{min(100.0, w / content_mm * 100):.1f}%", False)
                elif ncols > 1:
                    tst["width"] = (f"{max(5.0, (content_mm - (gap_mm or 0) * (ncols - 1)) / ncols / content_mm * 100):.1f}%", False)
                if justify_right_last and idx == len(row) - 1 and idx > 0:
                    tst["text-align"] = ("right", False)
                styles[td] = tst
                td.append(child)
                if gap_mm and idx < len(row) - 1:
                    gap = etree.SubElement(tr, "td")
                    styles[gap] = {"width": (f"{gap_mm / content_mm * 100:.1f}%", False)}
                    gap.text = ""
        return table

    def child_elements(el):
        return [c for c in el if isinstance(c.tag, str)]

    def walk(el):
        for child in list(el):
            if not isinstance(child.tag, str):
                continue
            st = styles.get(child, {})
            if st.get("position", ("", 0))[0] in ("fixed", "absolute"):
                tail = child.tail
                parent = child.getparent()
                prev = child.getprevious()
                parent.remove(child)
                if tail:
                    if prev is not None:
                        prev.tail = (prev.tail or "") + tail
                    else:
                        parent.text = (parent.text or "") + tail
                continue
            walk(child)
            st = styles.get(child, {})
            kids = child_elements(child)
            disp = _display(st)
            ncol = st.get("column-count", ("", 0))[0]
            if ncol.isdigit() and int(ncol) > 1 and len(kids) > 1 and child.tag not in ("table", "tr", "td"):
                n = int(ncol)
                per = -(-len(kids) // n)
                gap = _mm(st.get("column-gap", ("", 0))[0]) or 0
                for k in kids:
                    child.remove(k)
                    k.tail = None
                chunks = []
                for i in range(n):
                    holder = lh.Element("div")
                    styles[holder] = {}
                    for k in kids[i * per:(i + 1) * per]:
                        holder.append(k)
                    chunks.append(holder)
                chunks = [c for c in chunks if len(c)]
                child.text = None
                child.append(build_table(chunks, gap, {}, len(chunks), False))
                st["display"] = ("block", False)
                continue
            if disp == "flex" and child.tag not in ("table", "tr", "td"):
                gap = _mm(st.get("gap", ("", 0))[0] or st.get("column-gap", ("", 0))[0] or "")
                wrap = st.get("flex-wrap", ("", 0))[0] == "wrap"
                widths = {k: _mm(styles.get(k, {}).get("width", ("", 0))[0]) for k in kids}
                if len(kids) <= 1 and not (child.text or "").strip():
                    st["display"] = ("block", False)
                    continue
                ncols = len(kids)
                if wrap and any(widths.values()):
                    w = max(v for v in widths.values() if v)
                    ncols = max(1, int((content_mm + (gap or 0)) // (w + (gap or 0))))
                right = st.get("justify-content", ("", 0))[0] == "space-between" and len(kids) == 2
                for k in kids:
                    child.remove(k)
                    k.tail = None
                    if styles.get(k, {}).get("display", ("", 0))[0] in ("inline-block", "flex"):
                        styles[k]["display"] = ("block", False)
                for t in list(child.itertext()):
                    pass
                child.text = None
                table = build_table(kids, gap or 0, {k: v for k, v in widths.items() if v}, ncols, right)
                child.append(table)
                st["display"] = ("block", False)
            elif kids and all(styles.get(k, {}).get("display", ("", 0))[0] == "inline-block" for k in kids) and all(_is_text_ws(k.tail) for k in kids) and _is_text_ws(child.text) and len(kids) > 1:
                widths = {}
                for k in kids:
                    wv = styles.get(k, {}).get("width", ("", 0))[0]
                    widths[k] = wv
                for k in kids:
                    child.remove(k)
                    k.tail = None
                    styles[k]["display"] = ("block", False)
                table = lh.Element("table")
                styles[table] = {"width": ("100%", False), "border-collapse": ("collapse", False)}
                tr = etree.SubElement(table, "tr")
                styles[tr] = {}
                # the row's own border and padding (a key/value line with a rule under it) go on its cells
                carried = {k2: v2 for k2, v2 in st.items() if k2.startswith("border-bottom") or k2.startswith("border-top") or k2 == "border" or k2.startswith("padding")}
                for k2 in carried:
                    st.pop(k2, None)
                for k in kids:
                    td = etree.SubElement(tr, "td")
                    tst = {"vertical-align": ("top", False), **carried}
                    if widths.get(k):
                        tst["width"] = (widths[k], False)
                    styles[td] = tst
                    td.append(k)
                child.append(table)

    walk(body)


def _write(el, styles, policy, inherited_transform, marks):
    """The merged styles as the `style` attribute (and table/cell attributes), images embedded, text-transform applied."""
    import base64

    st = styles.get(el, {})
    transform = st.get("text-transform", (inherited_transform, 0))[0] or inherited_transform
    if isinstance(el.tag, str):
        out = {}
        for k, (v, _imp) in st.items():
            if k in DROP and k not in ("max-width", "max-height"):
                continue
            if k in ("max-width", "max-height"):
                continue
            if k == "background":
                m = COLOR.search(v)
                if m and "gradient" not in v and m.group(0) != "transparent":
                    out["background-color"] = m.group(0)
                continue
            if k == "display" and v in ("flex", "inline-flex", "grid", "inline-grid"):
                continue
            if k in ("padding", "margin") and "auto" in v:
                continue
            if k.startswith("padding"):
                continue
            if k == "margin" or k.startswith("margin-"):
                continue
            out[k] = v
        # LibreOffice's CSS parser stops at a value it cannot read and drops the rest of the style: no `.5` without a
        # leading zero, no em letter spacing
        if "letter-spacing" in out:
            ls = out.pop("letter-spacing")
            m = re.match(r"^(-?[0-9.]+)em$", ls.strip())
            if m:
                fs_pt = (_px(out.get("font-size", "")) or _px(st.get("font-size", ("", 0))[0]) or 13.0) * 0.75
                ls = f"{float(m.group(1)) * fs_pt:.2f}pt"
            if _px(ls) is not None:
                out["letter-spacing"] = ls
        out = {k: re.sub(r"(?<![0-9.])\.([0-9])", r"0.\1", v) for k, v in out.items()}
        if el.tag in UA_MARGIN and el.tag != "li":
            mark = _mark_of(st)
            for k in [k for k in out if k.startswith("border")] + (["background-color"] if "background-color" in out else []):
                out.pop(k, None)
            if mark:
                marks.append(mark)
                el.text = f"%%M{len(marks) - 1}%%" + (el.text or "")
        elif el.tag not in ("td", "th", "table", "tr", "img", "li"):
            for k in [k for k in out if k.startswith("border")]:
                out.pop(k, None)
        if el.tag not in ("td", "th", "table", "tr", "img") and "background-color" in out:
            pt, _pr, pb, _pl = _box(st, "padding")
            fs = _px(out.get("font-size", "")) or (_px(st.get("font-size", ("", 0))[0]) or 13.0)
            if pt + pb >= 2:
                out["line-height"] = f"{fs * 1.2 + pt + pb:.0f}px"
        if el.tag in UA_MARGIN:
            # LibreOffice gives every paragraph 7pt after unless told: say each side, from the template, else the browser default
            has = {side: (st.get("margin", ("", 0))[0] != "" or f"margin-{side}" in st) for side in ("top", "bottom")}
            top, right, bottom, left = _box(st, "margin")
            dtop, dbottom = UA_MARGIN[el.tag]
            top = top if has["top"] else dtop
            bottom = bottom if has["bottom"] else dbottom
            out["margin-top"], out["margin-bottom"] = f"{top:.0f}px", f"{bottom:.0f}px"
            if left:
                out["margin-left"] = f"{left:.0f}px"
            if right:
                out["margin-right"] = f"{right:.0f}px"
        # a size cap is not a size: the image gets its real one
        if el.tag == "img":
            raw = _image(el.get("src", ""), policy)
            ct = _ctype(raw) if raw else None
            if not raw or not ct:
                el.getparent().remove(el) if el.getparent() is not None else None
                return
            sz = _size_image(raw, st)
            el.set("src", f"data:{ct};base64," + base64.b64encode(raw).decode())
            if sz:
                el.set("width", str(int(round(sz[0]))))
                el.set("height", str(int(round(sz[1]))))
            out.pop("width", None)
            out.pop("height", None)
        if el.tag in ("td", "th"):
            if "background-color" in out:
                el.set("bgcolor", out["background-color"])
            w = out.get("width")
            if w:
                px = _px(w)
                el.set("width", w if w.endswith("%") else (str(int(px)) if px else w))
            va = out.get("vertical-align")
            if va in ("top", "middle", "bottom"):
                el.set("valign", va)
            if out.get("text-align") in ("left", "right", "center"):
                el.set("align", out["text-align"])
        if el.tag == "tr" and "background-color" in out:
            el.set("bgcolor", out["background-color"])
        if el.tag == "table":
            if out.get("width"):
                el.set("width", out["width"])
            collapse = out.get("border-collapse") == "collapse"
            spacing = st.get("border-spacing", ("", 0))[0].split()
            el.set("cellspacing", "0" if collapse else str(int(round(_px(spacing[-1]) or 0)) if spacing else 0))
            el.set("border", "0")
            el.set("cellpadding", "0")
        if out:
            el.set("style", ";".join(f"{k}:{v}" for k, v in out.items()))
        elif "style" in el.attrib:
            del el.attrib["style"]
        for att in ("class", "id"):
            el.attrib.pop(att, None)
        # `margin-right` between inline boxes (the meta line of a cost sheet): spaces, as Word has no such margin
        if el.tag in ("span", "b", "i", "strong", "em", "a") and styles.get(el):
            mr = _mm(styles[el].get("margin-right", ("", 0))[0] or "")
            if mr and mr >= 1:
                el.tail = ("\u00a0" * max(1, int(round(mr / 1.4)))) + (el.tail or "")
    for child in list(el):
        _write(child, styles, policy, transform, marks)
    if isinstance(el.tag, str):
        _transform_own(el, transform)


def _transform_own(el, how):
    f = {"uppercase": str.upper, "lowercase": str.lower, "capitalize": str.title}.get(how)
    if not f:
        return
    if el.text:
        el.text = f(el.text)
    for child in el:
        if child.tail:
            child.tail = f(child.tail)


# ------------------------------------------------------------------------------------------------------------
# python-docx pass

def _field(paragraph, code):
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    run = paragraph.add_run()
    for kind, text in (("begin", None), (None, code), ("separate", None), (None, "1"), ("end", None)):
        if kind:
            fc = OxmlElement("w:fldChar")
            fc.set(qn("w:fldCharType"), kind)
            run._r.append(fc)
        elif text == code:
            it = OxmlElement("w:instrText")
            it.set(qn("xml:space"), "preserve")
            it.text = f" {code} "
            run._r.append(it)
        else:
            t = OxmlElement("w:t")
            t.text = text
            run._r.append(t)
    return run


def finish(docx_bytes, prepared):
    """The page setup, header and footer on the converted file."""
    from docx import Document
    from docx.enum.section import WD_ORIENT
    from docx.enum.text import WD_TAB_ALIGNMENT
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Mm, Pt, RGBColor

    doc = Document(io.BytesIO(docx_bytes))
    page = prepared.page
    for s in doc.sections:
        s.page_width, s.page_height = Mm(page["w"]), Mm(page["h"])
        s.orientation = WD_ORIENT.LANDSCAPE if page["w"] > page["h"] else WD_ORIENT.PORTRAIT
        top, right, bottom, left = page["margin"]
        s.top_margin, s.right_margin, s.bottom_margin, s.left_margin = Mm(top), Mm(right), Mm(bottom), Mm(left)
        s.header_distance = Mm(min(9.0, max(4.0, top / 3)))
        s.footer_distance = Mm(min(9.0, max(4.0, bottom / 3)))
        text_w = Mm(page["w"] - left - right)

        def fill_part(part, paras, with_numbers):
            part.is_linked_to_previous = False
            first = True
            for spec in paras or []:
                p = part.paragraphs[0] if first else part.add_paragraph()
                first = False
                for raw, w, hh in spec["images"][:3]:
                    p.add_run().add_picture(io.BytesIO(raw), width=Pt(w * 0.75), height=Pt(hh * 0.75))
                if spec["text"] and not spec["images"]:
                    r = p.add_run(spec["text"])
                    r.bold = spec["bold"] or None
                    r.font.size = Pt(spec["size"] or 9)
                    _tint(r, spec["color"])
                elif spec["text"]:
                    p.add_run(" ")
                    r = p.add_run(spec["text"])
                    r.font.size = Pt(spec["size"] or 8)
                    _tint(r, spec["color"])
                if spec["right"]:
                    p.paragraph_format.tab_stops.add_tab_stop(text_w, WD_TAB_ALIGNMENT.RIGHT)
                    r = p.add_run("\t" + spec["right"])
                    r.font.size = Pt(spec["size"] or 7.5)
                    _tint(r, spec["color"])
                if spec["mark"]:
                    _style_paragraph(p._p, spec["mark"])
            if with_numbers:
                p = part.paragraphs[-1] if paras else part.paragraphs[0]
                if paras and (paras[-1]["text"] or paras[-1]["images"]) and paras[-1]["right"]:
                    p = part.add_paragraph()
                p.paragraph_format.tab_stops.add_tab_stop(text_w, WD_TAB_ALIGNMENT.RIGHT)
                r = p.add_run("\tPage ")
                r.font.size = Pt(8)
                _field(p, "PAGE").font.size = Pt(8)
                r = p.add_run(" of ")
                r.font.size = Pt(8)
                _field(p, "NUMPAGES").font.size = Pt(8)

        if prepared.header:
            fill_part(s.header, prepared.header, False)
        if prepared.footer or page["numbers"]:
            fill_part(s.footer, prepared.footer, page["numbers"])
    _apply_table_padding(doc, prepared.pads)
    _apply_marks(doc, prepared.marks)
    out = io.BytesIO()
    doc.save(out)
    return out.getvalue()


MARK = re.compile(r"%%M(\d+)%%")
# what may follow `pBdr` and `shd` in a paragraph's properties (the schema is ordered; Word refuses a misplaced one)
_AFTER_SHD = ("tabs", "suppressAutoHyphens", "kinsoku", "wordWrap", "overflowPunct", "topLinePunct", "autoSpaceDE", "autoSpaceDN",
              "bidi", "adjustRightInd", "snapToGrid", "spacing", "ind", "contextualSpacing", "mirrorIndents", "suppressOverlap",
              "jc", "textDirection", "textAlignment", "textboxTightWrap", "outlineLvl", "divId", "cnfStyle", "rPr", "sectPr", "pPrChange")


def _tint(run, color):
    from docx.shared import RGBColor

    if color and color.startswith("#") and len(color) in (4, 7):
        h = color.lstrip("#")
        h = "".join(c * 2 for c in h) if len(h) == 3 else h
        run.font.color.rgb = RGBColor.from_string(h.upper())


def _style_paragraph(para, mark):
    """`mark`'s borders and fill on the paragraph element (in schema order)."""
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    ppr = para.find(qn("w:pPr"))
    if ppr is None:
        ppr = OxmlElement("w:pPr")
        para.insert(0, ppr)

    def put(el):
        for child in ppr:
            if child.tag.split("}")[1] in _AFTER_SHD:
                child.addprevious(el)
                return
        ppr.append(el)

    for old in ("w:pBdr", "w:shd"):
        e = ppr.find(qn(old))
        if e is not None:
            ppr.remove(e)
    sides = [side for side in ("top", "left", "bottom", "right") if side in mark]
    if sides:
        bdr = OxmlElement("w:pBdr")
        for side in sides:
            pt, color = mark[side]
            e = OxmlElement(f"w:{side}")
            e.set(qn("w:val"), "single")
            e.set(qn("w:sz"), str(max(2, int(round(pt * 8)))))
            e.set(qn("w:space"), "1")
            e.set(qn("w:color"), color)
            bdr.append(e)
        put(bdr)
    if "fill" in mark:
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), mark["fill"])
        put(shd)


def _take_marker(para):
    """The mark index named by the `%%M<n>%%` token in the paragraph's text (which LibreOffice may have split over
    runs), with the token removed; None when there is none."""
    from docx.oxml.ns import qn

    ts = [t for t in para.iter(qn("w:t")) if t.text]
    full = "".join(t.text for t in ts)
    m = MARK.search(full)
    if not m:
        return None
    start, end = m.span()
    pos = 0
    for t in ts:
        a, b = pos, pos + len(t.text)
        lo, hi = max(a, start) - a, min(b, end) - a
        if lo < hi:
            t.text = t.text[:lo] + t.text[hi:]
        pos = b
    return int(m.group(1))


def _apply_marks(doc, marks):
    """The rules and shading the HTML blocks asked for, on the paragraphs carrying their marker (the marker is removed)."""
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    for para in list(doc.element.body.iter(qn("w:p"))):
        hit = _take_marker(para)
        if hit is None or hit >= len(marks):
            continue
        _style_paragraph(para, marks[hit])
        # LibreOffice also drew them around the characters: take that off
        for r in para.iter(qn("w:rPr")):
            for tag in ("w:shd", "w:bdr"):
                e = r.find(qn(tag))
                if e is not None:
                    r.remove(e)


def _apply_table_padding(doc, pads):
    """Each table's cell margins from the HTML table in the same place (tables are 1:1 in document order)."""
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    tbls = list(doc.element.body.iter(qn("w:tbl")))
    if len(tbls) != len(pads):
        LOG.info("table count differs (%d in the file, %d in the HTML): cell padding left as converted", len(tbls), len(pads))
        return
    for tbl, pad in zip(tbls, pads):
        if not pad:
            continue
        pr = tbl.find(qn("w:tblPr"))
        old = pr.find(qn("w:tblCellMar"))
        if old is not None:
            pr.remove(old)
        mar = OxmlElement("w:tblCellMar")
        for side, v in zip(("top", "left", "bottom", "right"), (pad[0], pad[3], pad[2], pad[1])):
            e = OxmlElement(f"w:{side}")
            e.set(qn("w:w"), str(v))
            e.set(qn("w:type"), "dxa")
            mar.append(e)
        pr.append(mar)
        # a cell LibreOffice gave its own margin (the padding it read as default) follows the table
        for tc in tbl.iter(qn("w:tc")):
            pr_tc = tc.find(qn("w:tcPr"))
            if pr_tc is not None and pr_tc.find(qn("w:tcMar")) is not None:
                pr_tc.remove(pr_tc.find(qn("w:tcMar")))


def to_docx(html, policy, converter):
    """The HTML (UTF-8 text) as .docx bytes."""
    prepared = prepare(html, policy)
    raw = converter.convert(prepared.html.encode("utf-8"), "html", "docx:MS Word 2007 XML", infilter="HTML (StarWriter)")
    return finish(raw, prepared)
