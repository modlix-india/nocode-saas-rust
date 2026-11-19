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
    "-webkit-print-color-adjust", "print-color-adjust", "text-transform", "font-display",
}
COLOR = re.compile(r"#[0-9a-fA-F]{3,8}\b|rgba?\([^)]*\)|\b(?:white|black|red|green|blue|gray|grey|silver|yellow|orange|navy|teal|maroon|purple|transparent)\b")
LEN = re.compile(r"^(-?[0-9.]+)\s*(mm|cm|in|pt|px|em|%)?$")
PX_PER = {"px": 1.0, "mm": 96 / 25.4, "cm": 96 / 2.54, "in": 96.0, "pt": 96 / 72}
MM_PER = {"mm": 1.0, "cm": 10.0, "in": 25.4, "pt": 25.4 / 72, "px": 25.4 / 96}


def _px(value):
    m = LEN.match((value or "").strip())
    if not m or m.group(2) in (None, "%", "em"):
        return None
    return float(m.group(1)) * PX_PER[m.group(2)]


def _mm(value):
    m = LEN.match((value or "").strip())
    if not m or m.group(2) in (None, "%", "em"):
        return None
    return float(m.group(1)) * MM_PER[m.group(2)]


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
            page["margin"] = {1: vals * 4, 2: vals * 2, 3: vals + [vals[1]], 4: vals}[len(vals)][:4]
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
    def __init__(self, html, page, header, footer):
        self.html, self.page, self.header, self.footer = html, page, header, footer


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
    _write(body, styles, policy, "")

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
    return Prepared(out, page, header_parts, footer_parts)


def _running_parts(el, styles, policy):
    """A running header/footer as {text lines, images (bytes, w_px, h_px), right text}: what python-docx can place."""
    lines, images = [], []
    for node in el.iter():
        if not isinstance(node.tag, str):
            continue
        if node.tag == "img":
            raw = _image(node.get("src", ""), policy)
            if raw and _ctype(raw):
                sz = _size_image(raw, styles.get(node, {}))
                if sz:
                    images.append((raw, sz[0], sz[1]))
    right = ""
    for td in el.iter("td"):
        if "text-align" in styles.get(td, {}) and styles[td]["text-align"][0] == "right":
            right = " ".join(td.text_content().split())
    text = " ".join(el.text_content().split())
    if right and text.endswith(right):
        text = text[: -len(right)].strip()
    if text:
        lines.append(text)
    rule = any("border-bottom" in styles.get(n, {}) for n in el.iter() if isinstance(n.tag, str))
    return {"lines": lines, "images": images, "right": right, "rule": rule}


def _display(st):
    return (st.get("display", ("", 0))[0] or "").strip().lower()


def _is_text_ws(s):
    return s is None or not s.strip()


def _convert_layout(body, styles, page, policy):
    """Flex rows and rows of inline-blocks become tables; fixed/absolute boxes are dropped."""
    from lxml import html as lh

    content_mm = page["w"] - page["margin"][1] - page["margin"][3]

    def build_table(children, gap_mm, widths_mm, ncols, justify_right_last=False):
        table = lh.Element("table")
        st = {"width": ("100%", False), "border-collapse": ("collapse", False)}
        styles[table] = st
        rows = [children[i:i + ncols] for i in range(0, len(children), ncols)] or [[]]
        for row in rows:
            tr = lh.SubElement(table, "tr")
            styles[tr] = {}
            for idx, child in enumerate(row):
                td = lh.SubElement(tr, "td")
                tst = {"vertical-align": ("top", False)}
                w = widths_mm.get(child)
                if w:
                    tst["width"] = (f"{w:.1f}mm", False)
                elif len(row) > 1:
                    tst["width"] = (f"{100.0 / ncols:.1f}%", False)
                if justify_right_last and idx == len(row) - 1 and idx > 0:
                    tst["text-align"] = ("right", False)
                styles[td] = tst
                td.append(child)
                if gap_mm and idx < len(row) - 1:
                    gap = lh.SubElement(tr, "td")
                    styles[gap] = {"width": (f"{gap_mm:.1f}mm", False)}
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
                tr = lh.SubElement(table, "tr")
                styles[tr] = {}
                for k in kids:
                    td = lh.SubElement(tr, "td")
                    tst = {"vertical-align": ("top", False)}
                    if widths.get(k):
                        tst["width"] = (widths[k], False)
                    styles[td] = tst
                    td.append(k)
                child.append(table)

    walk(body)


def _write(el, styles, policy, inherited_transform):
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
            out[k] = v
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
                el.set("width", w.replace("mm", "mm"))
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
            pad = None
            for td in el.iter("td", "th"):
                p = styles.get(td, {}).get("padding", ("", 0))[0].split()
                if p:
                    pad = p
                    break
            if pad:
                v = _px(pad[0]) if len(pad) in (1, 2) else _px(pad[0])
                if v is not None:
                    el.set("cellpadding", str(int(round(v))))
        if "font-size" in out and out["font-size"].endswith("pt") is False:
            pass
        if out:
            el.set("style", ";".join(f"{k}:{v}" for k, v in out.items()))
        elif "style" in el.attrib:
            del el.attrib["style"]
        for att in ("class", "id"):
            el.attrib.pop(att, None)
    for child in list(el):
        _write(child, styles, policy, transform)
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
        for part, spec in ((s.header, prepared.header), (s.footer, None)):
            pass
        if prepared.header:
            h = s.header
            h.is_linked_to_previous = False
            p = h.paragraphs[0]
            for raw, w, hh in prepared.header["images"][:2]:
                p.add_run().add_picture(io.BytesIO(raw), width=Pt(w * 0.75), height=Pt(hh * 0.75))
            if prepared.header["lines"]:
                r = p.add_run((" " if prepared.header["images"] else "") + prepared.header["lines"][0])
                r.font.size = Pt(8)
            if prepared.header["right"]:
                p.paragraph_format.tab_stops.add_tab_stop(text_w, WD_TAB_ALIGNMENT.RIGHT)
                r = p.add_run("\t" + prepared.header["right"])
                r.font.size = Pt(8)
                r.font.color.rgb = RGBColor(0xAA, 0, 0)
            if prepared.header["rule"]:
                ppr = p._p.get_or_add_pPr()
                bdr = OxmlElement("w:pBdr")
                b = OxmlElement("w:bottom")
                for k, v in (("val", "single"), ("sz", "6"), ("space", "1"), ("color", "111111")):
                    b.set(qn(f"w:{k}"), v)
                bdr.append(b)
                ppr.append(bdr)
        if prepared.footer or page["numbers"]:
            f = s.footer
            f.is_linked_to_previous = False
            p = f.paragraphs[0]
            if prepared.footer and prepared.footer["lines"]:
                r = p.add_run(prepared.footer["lines"][0])
                r.font.size = Pt(7.5)
                r.font.color.rgb = RGBColor(0x77, 0x77, 0x77)
            if page["numbers"]:
                p.paragraph_format.tab_stops.add_tab_stop(text_w, WD_TAB_ALIGNMENT.RIGHT)
                r = p.add_run("\tPage ")
                r.font.size = Pt(8)
                _field(p, "PAGE").font.size = Pt(8)
                r = p.add_run(" of ")
                r.font.size = Pt(8)
                _field(p, "NUMPAGES").font.size = Pt(8)
    out = io.BytesIO()
    doc.save(out)
    return out.getvalue()


def to_docx(html, policy, converter):
    """The HTML (UTF-8 text) as .docx bytes."""
    prepared = prepare(html, policy)
    raw = converter.convert(prepared.html.encode("utf-8"), "html", "docx:MS Word 2007 XML", infilter="HTML (StarWriter)")
    return finish(raw, prepared)
