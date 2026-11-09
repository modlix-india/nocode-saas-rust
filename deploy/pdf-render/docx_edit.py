"""Word templates, before they are filled: find a builder's blanks (`/docx/inspect`) and write field
tags in their place (`/docx/prepare`).

Both work on the same view of the file: tracked changes accepted (deletions dropped, insertions
kept). A paragraph is addressed by its part (`document`, `header1`, `footer2`, ...) and its index in
that part's paragraphs (document order, table cells included); a place in it by character offsets
into its text, which is the text of its runs (`w:t`), a tab counting as one character (`\\t`) and a
line break as one (`\\n`). `inspect` reports blanks in those terms and `prepare` takes them back, so
a mapping made from one inspect applies to the same file.

A blank is 2+ underscores, 3+ dashes, 4+ dots or 2+ ellipses. Highlighted text with no blank in it
is a reviewer's mark, reported as a hint, not a blank. A Word comment over a blank is reported with
it: builders write there what the blank is for ("Please fetch the 1st Applicant's Name in bold").

Prepare actions per blank:
- `TAG`: `{{ <expr>|<filters> }}` in place of the blank, in a run of its own that copies the
  blank's formatting (font, size, underline), optionally bold or in capitals;
- `REMOVE`: the blank, or a wider span (`removeStart`/`removeEnd`, e.g. its label), goes; a
  paragraph left empty goes too; `removeParagraph` takes the blank's whole paragraph out;
- `SIGN`: the blank line stays, and an invisible marker `[[sig:<key>]]` (white, 1 pt) is written
  just before it, for `/pdf/stamp` to find in the PDF;
- `KEEP`: the line stays, to fill by hand.
`conditions` shape the document around the blanks, each by its `kind`:
- `IF` (the default): paragraphs `fromPara`..`toPara` wrapped in `{%p if <test> %}` ... `{%p endif %}`
  (e.g. the second applicant's block, shown only when there is one);
- `FOR`: paragraphs `fromPara`..`toPara` repeated per item of `list` as `var`
  (`{%p for var in list %}` ... `{%p endfor %}`): one block per applicant, its fields `var.name` ...;
- `ROWS`: rows `fromRow`..`toRow` of table `table` (its index in the part, as inspect lists them) become
  one row repeated per item of `list` as `var` (`{%tr for %}`), formatted as row `fromRow`, its cells
  given by `cells` (a tag `{expr, filters, bold}` per column, or null for an empty cell): a payment
  schedule from the plan, the header and total rows kept;
- `CELL`: the cell `row`, `col` of table `table` filled with a tag (`expr`, `filters`, `bold`): an empty
  total cell, for example.
A tag's `expr` is a field path, or simple arithmetic over paths and numbers (`pl.row.amount - pl.row.taxAmount`);
`prefix` / `suffix` add a little plain text around it (`%` after a percent in a table cell).
Inspect lists the tables (`tables`: part, index and each row's cell texts) for ROWS and CELL. Options: `stripHighlights`, `stripComments`,
`acceptTracked` (all on by default; acceptTracked is always applied to the result).
"""

import copy
import hashlib
import io
import re
import subprocess
import zipfile

from lxml import etree

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
NS = {"w": W}
XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"
BLANK = re.compile(r"_{2,}|-{3,}|\.{4,}|…{2,}")
TAG = re.compile(r"\{\{.*?\}\}|\{%.*?%\}")
SIGNER_KEY = re.compile(r"^(A[1-9][0-9]?|A\*|B[1-9]?|W[1-9])$")
FIELD_EXPR = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*|\[[0-9]+\])*$")
_TERM = r"(?:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*|\[[0-9]+\])*|[0-9]+(?:\.[0-9]+)?)"
ARITH_EXPR = re.compile(r"^" + _TERM + r"(?:\s*[-+*/]\s*" + _TERM + r")+$")
LOOP_VAR = re.compile(r"^[a-z][a-z0-9_]{0,15}$")
RESERVED_VARS = {"al", "data", "input", "pay", "case", "loop", "true", "false", "none", "for", "in", "if", "not", "and", "or"}
MAX_TABLE_ROWS = 80
FILTERS = {"upper", "title", "inr", "inr0", "words", "num_words", "date_dmy", "date_long", "date_words", "age", "pct"}
PART_RE = re.compile(r"^word/(document|header[0-9]+|footer[0-9]+)\.xml$")
MAX_TEXT = 300


def q(tag):
    return f"{{{W}}}{tag}"


class BadRequest(Exception):
    """A request prepare cannot apply (unknown paragraph, blank text changed, bad field): a 400."""


# ── the text model ──────────────────────────────────────────────────────────────────────────


def _parts(z):
    return [n for n in z.namelist() if PART_RE.match(n)]


def _part_name(path):
    return PART_RE.match(path).group(1)


def accept_tracked(root):
    """Tracked changes accepted: deletions (and their runs) dropped, insertions unwrapped,
    formatting-change records dropped. Answers whether there were any."""
    changed = False
    for tag in ("del", "moveFrom"):
        for el in list(root.iter(q(tag))):
            el.getparent().remove(el)
            changed = True
    for tag in ("ins", "moveTo"):
        for el in list(root.iter(q(tag))):
            parent = el.getparent()
            i = parent.index(el)
            for child in list(el):
                parent.insert(i, child)
                i += 1
            parent.remove(el)
            changed = True
    for tag in ("rPrChange", "pPrChange", "sectPrChange", "tblPrChange", "trPrChange", "tcPrChange"):
        for el in list(root.iter(q(tag))):
            el.getparent().remove(el)
            changed = True
    return changed


def _own_paragraph(el, p):
    """Whether `el`'s nearest paragraph is `p` (text boxes nest paragraphs inside paragraphs)."""
    cur = el.getparent()
    while cur is not None:
        if cur.tag == q("p"):
            return cur is p
        cur = cur.getparent()
    return False


def segments(p):
    """The paragraph's text, piece by piece: [(element, run, start, end, kind)] where kind is
    `t` (editable text), `tab` or `br`; plus comment marks [(id, offset, 'start'|'end')]."""
    segs, marks, pos = [], [], 0
    for el in p.iter(q("t"), q("tab"), q("br"), q("cr"), q("commentRangeStart"), q("commentRangeEnd")):
        if not _own_paragraph(el, p):
            continue
        tag = etree.QName(el).localname
        if tag in ("commentRangeStart", "commentRangeEnd"):
            marks.append((el.get(q("id")), pos, "start" if tag == "commentRangeStart" else "end"))
            continue
        run = el.getparent()
        if run.tag != q("r"):
            continue  # a w:tab inside w:tabs (paragraph properties) is not text
        if tag == "t":
            n = len(el.text or "")
            segs.append((el, run, pos, pos + n, "t"))
            pos += n
        else:
            segs.append((el, run, pos, pos + 1, "tab" if tag == "tab" else "br"))
            pos += 1
    return segs, marks


def para_text(segs):
    return "".join((s[0].text or "") if s[4] == "t" else ("\t" if s[4] == "tab" else "\n") for s in segs)


def _highlight(run):
    h = run.find("w:rPr/w:highlight", NS)
    v = h.get(q("val")) if h is not None else None
    return None if v in (None, "none") else v


def _where(p):
    for a in p.iterancestors():
        n = etree.QName(a).localname
        if n == "tc":
            return "table"
        if n == "txbxContent":
            return "textbox"
    return "body"


def _fonts(z):
    used = set()
    for name in z.namelist():
        if name.startswith("word/") and name.endswith(".xml"):
            for m in re.finditer(rb'w:(?:ascii|hAnsi)="([^"]+)"', z.read(name)):
                used.add(m.group(1).decode())
    used.discard("")
    used = {f for f in used if not f.startswith("+")}  # theme references (+mn-lt), not fonts
    try:
        out = subprocess.run(["fc-list", ":", "family"], capture_output=True, text=True, timeout=10).stdout
        have = {f.strip().lower() for line in out.splitlines() for f in line.split(",")}
        out = subprocess.run(["fc-match", "-s", "--format=%{family}\\n", ":"], capture_output=True, text=True, timeout=10)
        missing = []
        for f in sorted(used):
            if f.lower() in have:
                continue
            got = subprocess.run(["fc-match", "--format=%{family}", f], capture_output=True, text=True, timeout=10).stdout
            missing.append({"font": f, "shownAs": got.split(",")[0]})
    except (OSError, subprocess.SubprocessError):
        missing = None
    return sorted(used), missing


# ── inspect ─────────────────────────────────────────────────────────────────────────────────


def _comments(z):
    if "word/comments.xml" not in z.namelist():
        return {}
    root = etree.fromstring(z.read("word/comments.xml"))
    out = {}
    for c in root.iter(q("comment")):
        text = " ".join("".join(t.text or "" for t in p.iter(q("t"))) for p in c.iter(q("p"))).strip()
        out[c.get(q("id"))] = {"text": re.sub(r"\s+", " ", text), "author": c.get(q("author"))}
    return out


def inspect(docx_bytes):
    try:
        z = zipfile.ZipFile(io.BytesIO(docx_bytes))
    except zipfile.BadZipFile:
        raise BadRequest("not a Word file") from None
    if "word/document.xml" not in z.namelist():
        raise BadRequest("not a Word file: no word/document.xml")
    comments = _comments(z)
    blanks, hints, tags = [], [], []
    tracked = False
    ranges = {}  # comment id -> [(part, para, offset) start, end]
    per_para = []  # (part, index, text, segs) for comment matching
    paragraphs = 0
    tables = []
    for path in _parts(z):
        part = _part_name(path)
        root = etree.fromstring(z.read(path))
        tracked = accept_tracked(root) or tracked
        for ti, tbl in enumerate(root.iter(q("tbl"))):
            rows = tbl.findall("w:tr", NS)
            tables.append({"part": part, "table": ti, "rowCount": len(rows), "rows": [
                [_cell_text(c)[:80] for c in r.findall("w:tc", NS)] for r in rows[:MAX_TABLE_ROWS]]})
        for i, p in enumerate(root.iter(q("p"))):
            paragraphs += 1
            segs, marks = segments(p)
            for cid, off, kind in marks:
                ranges.setdefault(cid, [None, None])[0 if kind == "start" else 1] = (part, i, off)
            text = para_text(segs)
            if not text.strip():
                continue
            per_para.append((part, i))
            hl = [None] * len(text)
            for el, run, s, e, kind in segs:
                v = _highlight(run)
                for k in range(s, e):
                    hl[k] = v
            taken = [(m.start(), m.end()) for m in TAG.finditer(text)]
            for m in TAG.finditer(text):
                tags.append({"part": part, "para": i, "start": m.start(), "end": m.end(), "text": m.group(0)})
            spans = [(m.start(), m.end()) for m in BLANK.finditer(text) if not any(a <= m.start() < b for a, b in taken)]
            for s, e in spans:
                blanks.append({
                    "id": f"{part}:{i}:{s}",
                    "part": part, "para": i, "start": s, "end": e, "text": text[s:e],
                    "where": _where(p),
                    "before": text[max(0, s - 80):s], "after": text[e:e + 60],
                    "sentence": text[:MAX_TEXT],
                    "highlight": next((h for h in hl[s:e] if h), None),
                    "comment": None,
                })
            # a highlighted stretch with a blank in it is that blank's; one without is a reviewer's hint
            k = 0
            while k < len(text):
                if not hl[k]:
                    k += 1
                    continue
                j = k
                while j < len(text) and hl[j]:
                    j += 1
                if text[k:j].strip() and not any(a < j and b > k for a, b in spans):
                    hints.append({"part": part, "para": i, "start": k, "end": j, "text": text[k:j][:MAX_TEXT], "highlight": hl[k]})
                k = j
    # a comment belongs to every blank its range overlaps
    for cid, (start, end) in ranges.items():
        if not start or not end or cid not in comments:
            continue
        for b in blanks:
            a = (b["part"], b["para"], b["start"])
            z_ = (b["part"], b["para"], b["end"])
            if b["part"] == start[0] == end[0] and a < end and z_ > start:
                b["comment"] = comments[cid]["text"]
    used, missing = _fonts(z)
    return {
        "sha256": hashlib.sha256(docx_bytes).hexdigest(),
        "paragraphs": paragraphs,
        "blanks": blanks,
        "hints": hints,
        "tags": tags,
        "comments": len(comments),
        "trackedChanges": tracked,
        "fonts": {"used": used, "missing": missing},
        "embeddedFonts": any(n.startswith("word/fonts/") for n in z.namelist()),
        "tables": tables[:40],
    }


def _cell_text(cell):
    """A table cell's text: its own paragraphs (not a nested table's), joined by a space."""
    return " ".join(para_text(segments(p)[0]) for p in cell.findall("w:p", NS)).strip()


# ── prepare ─────────────────────────────────────────────────────────────────────────────────


def _content_children(run):
    return [c for c in run if c.tag != q("rPr")]


def split_run(run, el, k):
    """Splits `run` before character `k` of its text element `el`: `run` keeps what comes before,
    the new run (a copy with the same properties, placed right after it) gets the rest."""
    right = copy.deepcopy(run)
    kids, rkids = _content_children(run), _content_children(right)
    idx = kids.index(el)
    for c in kids[idx + 1:]:
        run.remove(c)
    for c in rkids[:idx]:
        right.remove(c)
    text = el.text or ""
    el.text = text[:k]
    rkids[idx].text = text[k:]
    for t in (el, rkids[idx]):
        t.set(XML_SPACE, "preserve")
    if not el.text:
        run.remove(el)
    run.addnext(right)
    return right


def split_before(run, el):
    """Splits `run` before its content element `el` (text, tab, break): answers the new run that
    starts with `el`, placed right after `run`."""
    right = copy.deepcopy(run)
    kids, rkids = _content_children(run), _content_children(right)
    idx = kids.index(el)
    for c in kids[idx:]:
        run.remove(c)
    for c in rkids[:idx]:
        right.remove(c)
    run.addnext(right)
    return right


def _split_at(p, offset):
    """Makes `offset` fall on a run boundary; answers the run that starts there (or None at the end)."""
    for el, run, s, e, kind in segments(p)[0]:
        if s <= offset < e:
            if offset == s:
                return run if _content_children(run)[0] is el else split_before(run, el)
            return split_run(run, el, offset - s)  # inside a text: a tab or break is one character
    return None


def isolate(p, start, end):
    """The span [start, end) as one run of its own (the properties of the run it starts in):
    answers that run, its text set to the span's text."""
    _split_at(p, end)
    first = _split_at(p, start)
    segs, _ = segments(p)
    text = para_text(segs)[start:end]
    runs = []
    for el, run, s, e, kind in segs:
        if s >= start and e <= end and run not in runs:
            runs.append(run)
    for el, run, s, e, kind in segs:
        if start <= s < end and run is not first:
            el.getparent().remove(el) if kind != "t" else setattr(el, "text", "")
    for c in _content_children(first):
        first.remove(c)
    t = etree.SubElement(first, q("t"))
    t.text = text
    t.set(XML_SPACE, "preserve")
    return first


def _rpr(run):
    rpr = run.find("w:rPr", NS)
    if rpr is None:
        rpr = etree.Element(q("rPr"))
        run.insert(0, rpr)
    return rpr


def _set_prop(rpr, tag, attrs=None):
    for old in rpr.findall(f"w:{tag}", NS):
        rpr.remove(old)
    el = etree.SubElement(rpr, q(tag))
    for k, v in (attrs or {}).items():
        el.set(q(k), v)
    return el


def _drop_highlight(run):
    rpr = run.find("w:rPr", NS)
    if rpr is not None:
        for h in rpr.findall("w:highlight", NS):
            rpr.remove(h)


def field_tag(f):
    expr = (f.get("expr") or "").strip()
    if ARITH_EXPR.match(expr):
        expr = "(" + re.sub(r"\s+", " ", expr) + ")"
    elif not FIELD_EXPR.match(expr):
        raise BadRequest(f"field {expr!r}: a field is a path such as al.unit.number, or arithmetic over paths and numbers")
    filters = list(f.get("filters") or [])
    if f.get("caps"):
        filters.append("upper")
    for flt in filters:
        if flt not in FILTERS:
            raise BadRequest(f"filter {flt!r} is not one of {sorted(FILTERS)}")
    fix = {}
    for k in ("prefix", "suffix"):
        v = str(f.get(k) or "")
        if len(v) > 12 or "{" in v or "}" in v:
            raise BadRequest(f"{k} {v!r}: up to 12 characters of plain text, such as % or Rs.")
        fix[k] = v
    return fix["prefix"] + "{{ " + "|".join([expr] + filters) + " }}" + fix["suffix"]


def sign_marker_run(like, key):
    """A run with the invisible marker, formatted as `like` but white and 1 pt."""
    run = copy.deepcopy(like)
    for c in _content_children(run):
        run.remove(c)
    rpr = _rpr(run)
    for tag in ("highlight", "u", "b", "i", "strike", "vanish"):
        for old in rpr.findall(f"w:{tag}", NS):
            rpr.remove(old)
    _set_prop(rpr, "color", {"val": "FFFFFF"})
    _set_prop(rpr, "sz", {"val": "2"})
    _set_prop(rpr, "szCs", {"val": "2"})
    t = etree.SubElement(run, q("t"))
    t.text = f"[[sig:{key}]]"
    return run


def _strip_comments(root):
    for tag in ("commentRangeStart", "commentRangeEnd"):
        for el in list(root.iter(q(tag))):
            el.getparent().remove(el)
    for ref in list(root.iter(q("commentReference"))):
        run = ref.getparent()
        if run.tag == q("r") and not [c for c in _content_children(run) if c is not ref]:
            run.getparent().remove(run)
        else:
            run.remove(ref)


def _jinja_paragraph(like, text):
    p = etree.Element(q("p"))
    ppr = like.find("w:pPr", NS)
    if ppr is not None:
        p.append(copy.deepcopy(ppr))
    r = etree.SubElement(p, q("r"))
    t = etree.SubElement(r, q("t"))
    t.text = text
    return p


def _loop_of(c):
    lst, var = str(c.get("list", "")).strip(), str(c.get("var", "")).strip()
    if not FIELD_EXPR.match(lst):
        raise BadRequest(f"list {lst!r}: a path to a list, such as al.plan or al.applicants")
    if not LOOP_VAR.match(var) or var in RESERVED_VARS:
        raise BadRequest(f"var {var!r}: a short lower-case name for each item, such as pl or a (not al, data, input, pay, loop)")
    return lst, var


def _run_like(rpr, text, bold=False):
    r = etree.Element(q("r"))
    if rpr is not None:
        r.append(copy.deepcopy(rpr))
    if bold:
        _set_prop(_rpr(r), "b")
    t = etree.SubElement(r, q("t"))
    t.text = text
    t.set(XML_SPACE, "preserve")
    return r


def _fill_cell(tc, text, bold=False):
    """The cell holds one paragraph with `text` (or nothing), formatted as its first run and paragraph were."""
    ps = tc.findall("w:p", NS)
    if not ps:
        ps = [etree.SubElement(tc, q("p"))]
    first_run = next((r for p in ps for r in p.findall("w:r", NS)), None)
    rpr = first_run.find("w:rPr", NS) if first_run is not None else None
    if rpr is None:  # an empty cell: the paragraph mark's formatting
        ppr_rpr = ps[0].find("w:pPr/w:rPr", NS)
        rpr = copy.deepcopy(ppr_rpr) if ppr_rpr is not None else None
        if rpr is not None:
            rpr.tag = q("rPr")
    rpr = copy.deepcopy(rpr) if rpr is not None else None
    for p in ps[1:]:
        tc.remove(p)
    p = ps[0]
    for ch in list(p):
        if ch.tag != q("pPr"):
            p.remove(ch)
    if text:
        p.append(_run_like(rpr, text, bold))


def _tag_row(like, text):
    """A copy of the row `like` whose cells are empty but the first, which holds a `{%tr ... %}` tag."""
    tr = copy.deepcopy(like)
    for k, tc in enumerate(tr.findall("w:tc", NS)):
        _fill_cell(tc, text if k == 0 else "")
    return tr


def prepare(docx_bytes, fields, conditions=(), options=None):
    """The Word file with the mapping applied (bytes), and what was done."""
    opts = {"stripHighlights": True, "stripComments": True, **(options or {})}
    try:
        zin = zipfile.ZipFile(io.BytesIO(docx_bytes))
    except zipfile.BadZipFile:
        raise BadRequest("not a Word file") from None
    by_part = {}
    for f in fields or []:
        by_part.setdefault(str(f.get("part", "document")), []).append(f)
    conds = {}
    for c in conditions or []:
        conds.setdefault(str(c.get("part", "document")), []).append(c)
    known = {_part_name(n) for n in _parts(zin)}
    for part in set(by_part) | set(conds):
        if part not in known:
            raise BadRequest(f"part {part!r} is not in the file")
    done = {"tagged": 0, "removed": 0, "signSpots": [], "kept": 0, "conditions": 0, "paragraphsRemoved": 0,
            "repeats": 0, "tableRows": 0, "cells": 0}
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            data = zin.read(info.filename)
            if PART_RE.match(info.filename):
                data = _prepare_part(data, _part_name(info.filename), by_part.get(_part_name(info.filename), []),
                                     conds.get(_part_name(info.filename), []), opts, done)
            zout.writestr(info, data)
    return out.getvalue(), done


def _prepare_part(data, part, fields, conditions, opts, done):
    root = etree.fromstring(data)
    accept_tracked(root)
    paras = list(root.iter(q("p")))
    tables = list(root.iter(q("tbl")))
    table_rows = [t.findall("w:tr", NS) for t in tables]  # as inspect numbered them, before any change
    if opts.get("stripComments"):
        _strip_comments(root)

    def row_of(c, key):
        ti, ri = c.get("table"), c.get(key)
        if not isinstance(ti, int) or not 0 <= ti < len(tables):
            raise BadRequest(f"{part}: table {ti!r} does not exist")
        if not isinstance(ri, int) or not 0 <= ri < len(table_rows[ti]):
            raise BadRequest(f"{part}: table {ti} has no row {ri!r}")
        return table_rows[ti][ri]

    def para(i):
        if not isinstance(i, int) or not 0 <= i < len(paras):
            raise BadRequest(f"{part}: paragraph {i!r} does not exist")
        return paras[i]

    by_para = {}
    for f in fields:
        by_para.setdefault(f.get("para"), []).append(f)
    emptied = []
    for i, items in by_para.items():
        p = para(i)
        text = para_text(segments(p)[0])
        # right to left, so earlier offsets stay where they are
        for f in sorted(items, key=lambda f: -int(f.get("start", 0))):
            s, e = int(f.get("start", -1)), int(f.get("end", -1))
            if not (0 <= s < e <= len(text)):
                raise BadRequest(f"{part}:{i}: span {s}-{e} is outside the paragraph")
            if f.get("text") is not None and text[s:e] != f["text"]:
                raise BadRequest(f"{part}:{i}: the text at {s}-{e} is {text[s:e]!r}, not {f['text']!r} (another version of the file?)")
            action = (f.get("action") or "TAG").upper()
            if action == "TAG":
                run = isolate(p, s, e)
                run.find("w:t", NS).text = field_tag(f)
                _drop_highlight(run)
                if f.get("bold"):
                    _set_prop(_rpr(run), "b")
                done["tagged"] += 1
            elif action == "REMOVE" and f.get("removeParagraph"):
                emptied.append(p)  # the whole paragraph goes (its other blanks with it)
                done["removed"] += 1
            elif action == "REMOVE":
                rs, re_ = int(f.get("removeStart", s)), int(f.get("removeEnd", e))
                if not (0 <= rs <= s and e <= re_ <= len(text)):
                    raise BadRequest(f"{part}:{i}: removeStart/removeEnd must contain the blank")
                run = isolate(p, rs, re_)
                p.remove(run) if run.getparent() is p else run.getparent().remove(run)
                done["removed"] += 1
            elif action == "SIGN":
                key = str(f.get("signer", ""))
                if not SIGNER_KEY.match(key):
                    raise BadRequest(f"signer {key!r}: A1..A99 (an applicant), A* (all applicants), B (the builder), W1.. (a witness)")
                run = isolate(p, s, e)
                _drop_highlight(run)
                run.addprevious(sign_marker_run(run, key))
                done["signSpots"].append(key)
            elif action == "KEEP":
                _drop_highlight(isolate(p, s, e))
                done["kept"] += 1
            else:
                raise BadRequest(f"action {action!r}: TAG, REMOVE, SIGN or KEEP")
        if not para_text(segments(p)[0]).strip() and text.strip() and p not in emptied:
            emptied.append(p)
    # tables first (single cells, then repeated rows), then paragraph ranges (by element, so removals cannot
    # shift them), then empties go
    kinds = [(str(c.get("kind") or "IF").upper(), c) for c in conditions]
    for kind, c in kinds:
        if kind not in ("IF", "FOR", "ROWS", "CELL"):
            raise BadRequest(f"condition kind {kind!r}: IF, FOR, ROWS or CELL")
    for kind, c in kinds:
        if kind == "CELL":
            cells = row_of(c, "row").findall("w:tc", NS)
            col = c.get("col")
            if not isinstance(col, int) or not 0 <= col < len(cells):
                raise BadRequest(f"{part}: table {c.get('table')} row {c.get('row')} has no column {col!r}")
            _fill_cell(cells[col], field_tag(c), bool(c.get("bold")))
            done["cells"] += 1
    for kind, c in kinds:
        if kind != "ROWS":
            continue
        lst, var = _loop_of(c)
        first, last = row_of(c, "fromRow"), row_of(c, "toRow" if "toRow" in c else "fromRow")
        rows = table_rows[c["table"]]
        a, z = rows.index(first), rows.index(last)
        if z < a:
            raise BadRequest(f"{part}: table {c['table']}: toRow comes before fromRow")
        specs = c.get("cells") or []
        tcs = first.findall("w:tc", NS)
        if len(specs) > len(tcs):
            raise BadRequest(f"{part}: table {c['table']} row {a} has {len(tcs)} columns, cells gives {len(specs)}")
        for k, tc in enumerate(tcs):
            spec = specs[k] if k < len(specs) else None
            _fill_cell(tc, field_tag(spec) if spec and spec.get("expr") else "", bool(spec and spec.get("bold")))
        for r in rows[a + 1:z + 1]:
            if r.getparent() is not None:
                r.getparent().remove(r)
        first.addprevious(_tag_row(first, "{%tr for " + var + " in " + lst + " %}"))
        first.addnext(_tag_row(first, "{%tr endfor %}"))
        done["tableRows"] += 1
    for kind, c in kinds:
        if kind not in ("IF", "FOR"):
            continue
        if kind == "IF":
            test = str(c.get("test", "")).strip()
            if not test or "%" in test or "{" in test:
                raise BadRequest("a condition needs a test such as al.applicants|length > 1")
            open_, close = "{%p if " + test + " %}", "{%p endif %}"
            done["conditions"] += 1
        else:
            lst, var = _loop_of(c)
            open_, close = "{%p for " + var + " in " + lst + " %}", "{%p endfor %}"
            done["repeats"] += 1
        first, last = para(c.get("fromPara")), para(c.get("toPara", c.get("fromPara")))
        first.addprevious(_jinja_paragraph(first, open_))
        last.addnext(_jinja_paragraph(last, close))
    for p in emptied:
        parent = p.getparent()
        if parent is None:
            continue
        if parent.tag == q("tc") and len(parent.findall("w:p", NS)) == 1:
            for r in list(p):  # a table cell needs one paragraph: keep it, empty
                if r.tag != q("pPr"):
                    p.remove(r)
        else:
            parent.remove(p)
        done["paragraphsRemoved"] += 1
    if opts.get("stripHighlights"):
        for h in list(root.iter(q("highlight"))):
            h.getparent().remove(h)
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)
