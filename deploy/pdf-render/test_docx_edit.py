"""Tests for finding blanks, writing tags (docx_edit.py), formats (docx_filters.py) and stamping
signatures (pdf_stamp.py). Run in the image: python -m unittest test_docx_edit"""

import base64
import io
import json
import unittest
import urllib.error
import urllib.request
import zipfile

from pypdf import PdfReader

import app
import docx_edit
import docx_render
import pdf_stamp
from test_app import PNG, serve

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
FONT = '<w:rFonts w:ascii="Bookman Old Style" w:hAnsi="Bookman Old Style"/><w:sz w:val="22"/>'


def run(text, hl=None, extra=""):
    h = f'<w:highlight w:val="{hl}"/>' if hl else ""
    return f'<w:r><w:rPr>{FONT}{h}{extra}</w:rPr><w:t xml:space="preserve">{text}</w:t></w:r>'


def para(*runs):
    return "<w:p>" + "".join(runs) + "</w:p>"


def make_docx(body, comments=None):
    """A minimal Word file from raw paragraphs (and comments {id: text})."""
    ct = ('<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
          + ('<Override PartName="/word/comments.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml"/>' if comments else "")
          + "</Types>")
    rels = ('<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
    drels = ('<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
             + ('<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/comments" Target="comments.xml"/>' if comments else "")
             + "</Relationships>")
    doc = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="{W}"><w:body>{body}<w:sectPr/></w:body></w:document>'
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", rels)
        z.writestr("word/_rels/document.xml.rels", drels)
        z.writestr("word/document.xml", doc)
        if comments:
            cs = "".join(f'<w:comment w:id="{i}" w:author="Legal"><w:p><w:r><w:t>{t}</w:t></w:r></w:p></w:comment>' for i, t in comments.items())
            z.writestr("word/comments.xml", f'<?xml version="1.0" encoding="UTF-8"?><w:comments xmlns:w="{W}">{cs}</w:comments>')
    return out.getvalue()


def doc_xml(b):
    with zipfile.ZipFile(io.BytesIO(b)) as z:
        return z.read("word/document.xml").decode()


def text_of(b):
    from lxml import etree

    root = etree.fromstring(doc_xml(b).encode())
    return [docx_edit.para_text(docx_edit.segments(p)[0]) for p in root.iter(f"{{{W}}}p")]


LETTER = make_docx(
    para(run("Mr./Mrs./Ms. ________", hl="yellow")) +
    para(run("allotted a "), run("___", hl="yellow"), run(" BHK flat bearing No. "), run("___"), run(" admeasuring")) +
    para(run("(Address)", hl="yellow")) +
    para(run("Aged about "), '<w:commentRangeStart w:id="7"/>', run("----"), '<w:commentRangeEnd w:id="7"/>', run(" years,")) +
    para(run("Old "), '<w:del w:id="1" w:author="x"><w:r><w:delText>gone ____ </w:delText></w:r></w:del>',
         '<w:ins w:id="2" w:author="x">' + run("new ____") + "</w:ins>") +
    para(run("Already {{ al.caseNumber }} here")) +
    para(run("S/o/ D/o/ W/o. Mr./Mrs. -----------,")) +
    para(run("Signature ______________")),
    comments={"7": "Please fetch the 1st Applicant's age in bold."},
)


class InspectTest(unittest.TestCase):
    def setUp(self):
        self.r = docx_edit.inspect(LETTER)
        self.by = {(b["para"], b["text"], b["start"]): b for b in self.r["blanks"]}

    def test_blanks_with_their_words(self):
        texts = [(b["para"], b["text"]) for b in self.r["blanks"]]
        self.assertEqual(texts, [(0, "________"), (1, "___"), (1, "___"), (3, "----"), (4, "____"), (6, "-----------"), (7, "______________")])
        b = self.r["blanks"][1]
        self.assertEqual((b["before"], b["after"][:4], b["highlight"]), ("allotted a ", " BHK", "yellow"))
        self.assertEqual(self.r["blanks"][2]["before"].endswith("bearing No. "), True)

    def test_a_comment_belongs_to_its_blank(self):
        self.assertEqual(self.r["blanks"][3]["comment"], "Please fetch the 1st Applicant's age in bold.")
        self.assertIsNone(self.r["blanks"][0]["comment"])
        self.assertEqual(self.r["comments"], 1)

    def test_tracked_changes_are_accepted(self):
        self.assertTrue(self.r["trackedChanges"])
        self.assertEqual(self.r["blanks"][4]["sentence"], "Old new ____", "the deleted text is gone, the inserted text is in")

    def test_highlights_without_a_blank_are_hints_and_tags_are_listed(self):
        self.assertEqual([h["text"] for h in self.r["hints"]], ["(Address)"])
        self.assertEqual([t["text"] for t in self.r["tags"]], ["{{ al.caseNumber }}"])
        self.assertIn("Bookman Old Style", self.r["fonts"]["used"])
        self.assertEqual(len(self.r["sha256"]), 64)


def field(b, **kw):
    return {"part": "document", "para": b["para"], "start": b["start"], "end": b["end"], "text": b["text"], **kw}


class PrepareTest(unittest.TestCase):
    def setUp(self):
        self.blanks = docx_edit.inspect(LETTER)["blanks"]

    def prepared(self, fields, conditions=(), options=None):
        return docx_edit.prepare(LETTER, fields, conditions, options)

    def test_tags_keep_the_font_and_bold_only_the_value(self):
        b = self.blanks
        out, done = self.prepared([field(b[0], expr="al.primary.name", bold=True), field(b[1], expr="al.unit.configuration"),
                                   field(b[2], expr="al.unit.number", caps=True), field(b[3], expr="al.primary.age")])
        self.assertEqual(done["tagged"], 4)
        t = text_of(out)
        self.assertEqual(t[0], "Mr./Mrs./Ms. {{ al.primary.name }}")
        self.assertEqual(t[1], "allotted a {{ al.unit.configuration }} BHK flat bearing No. {{ al.unit.number|upper }} admeasuring")
        x = doc_xml(out)
        # the label run is not bold; the value run is, with the label's font and size
        self.assertRegex(x, r'<w:r><w:rPr><w:rFonts w:ascii="Bookman Old Style"[^>]*/><w:sz w:val="22"/></w:rPr><w:t xml:space="preserve">Mr\./Mrs\./Ms\. </w:t></w:r>')
        self.assertRegex(x, r'Bookman Old Style[^<]*/><w:sz w:val="22"/><w:b/></w:rPr><w:t xml:space="preserve">\{\{ al\.primary\.name \}\}')
        self.assertNotIn("highlight", x, "highlights stripped")
        self.assertNotIn("commentRange", x, "comments stripped")

    def test_a_blank_next_to_tabs_in_the_same_run(self):
        doc = make_docx('<w:p><w:r><w:rPr>' + FONT + '</w:rPr><w:t xml:space="preserve">No. _____</w:t><w:tab/><w:tab/>'
                        '<w:t xml:space="preserve">Date:______</w:t></w:r></w:p>')
        b = docx_edit.inspect(doc)["blanks"]
        out, _ = docx_edit.prepare(doc, [field(b[0], expr="al.caseNumber"), field(b[1], expr="al.letterDate", filters=["date_dmy"])])
        self.assertEqual(text_of(out), ["No. {{ al.caseNumber }}\t\tDate:{{ al.letterDate|date_dmy }}"])

    def test_remove_with_its_label_drops_the_emptied_paragraph(self):
        b = self.blanks[5]
        out, done = self.prepared([field(b, action="REMOVE", removeStart=0, removeEnd=len(b["sentence"]))])
        self.assertEqual((done["removed"], done["paragraphsRemoved"]), (1, 1))
        self.assertNotIn("S/o", "".join(text_of(out)))

    def test_remove_a_whole_paragraph(self):
        b = self.blanks[4]
        out, done = self.prepared([field(b, action="REMOVE", removeParagraph=True)])
        self.assertEqual((done["removed"], done["paragraphsRemoved"]), (1, 1))
        self.assertNotIn("Old new", "".join(text_of(out)))
        self.assertEqual(len(text_of(out)), len(text_of(LETTER)) - 1)

    def test_a_sign_spot_keeps_the_line_and_adds_an_invisible_marker(self):
        out, done = self.prepared([field(self.blanks[6], action="SIGN", signer="A*")])
        self.assertEqual(done["signSpots"], ["A*"])
        self.assertEqual(text_of(out)[-1], "Signature [[sig:A*]]______________")
        self.assertRegex(doc_xml(out), r'<w:color w:val="FFFFFF"/><w:sz w:val="2"/><w:szCs w:val="2"/></w:rPr><w:t>\[\[sig:A\*\]\]')

    def test_conditions_wrap_paragraphs(self):
        out, done = self.prepared([], [{"part": "document", "fromPara": 3, "toPara": 4, "test": "al.applicants|length > 1"}])
        t = text_of(out)
        i = t.index("{%p if al.applicants|length > 1 %}")
        self.assertEqual(t[i + 3], "{%p endif %}")

    def test_refusals(self):
        b = self.blanks[0]
        for f, why in [
            (field(b, expr="al.x", text="___"), "not '___'"),
            (field(b, expr="al.x.__class__()"), "a field is a path"),
            (field(b, expr="al.x", filters=["attr"]), "filter"),
            (field(b, action="SIGN", signer="Z9"), "signer"),
            ({**field(b, expr="al.x"), "para": 99}, "does not exist"),
            ({**field(b, expr="al.x"), "part": "header7"}, "not in the file"),
        ]:
            with self.subTest(why=why), self.assertRaises(docx_edit.BadRequest) as e:
                self.prepared([f])
            self.assertIn(why, str(e.exception))

    def test_the_prepared_file_fills(self):
        b = self.blanks
        out, _ = self.prepared([field(b[0], expr="al.primary.name", caps=True), field(b[1], expr="al.price", filters=["inr0"]),
                                field(b[2], expr="al.price", filters=["words"]), field(b[3], expr="al.parking", filters=["num_words"])])
        filled = text_of(docx_render.fill(out, {"al": {"primary": {"name": "Rohit Sharma"}, "price": 14280000, "parking": 1}}, app.Policy()))
        self.assertEqual(filled[0], "Mr./Mrs./Ms. ROHIT SHARMA")
        self.assertEqual(filled[1], "allotted a 1,42,80,000 BHK flat bearing No. One Crore Forty Two Lakh Eighty Thousand admeasuring")
        self.assertEqual(filled[3], "Aged about 1 (One) years,")


def cell(text):
    return f"<w:tc><w:tcPr/>{para(run(text)) if text else '<w:p/>'}</w:tc>"


def row(*texts):
    return "<w:tr>" + "".join(cell(t) for t in texts) + "</w:tr>"


SCHEDULE = make_docx(
    para(run("Allottee: ______")) +
    para(run("Address: ______")) +
    para(run("SCHEDULE G")) +
    "<w:tbl><w:tblGrid>" + '<w:gridCol w:w="1800"/>' * 5 + "</w:tblGrid>" + row("Payment Schedule", "% of Billing", "Payment Schedule (in INR)", "GST", "Total")
    + row("Booking Amount:", "5%", "", "", "") + row("On foundations", "15%", "", "", "") + row("On roof slab", "80%", "", "", "")
    + row("Total Sale Value", "100%", "", "", "") + "</w:tbl>")
PLAN = {"al": {"applicants": [{"name": "Asha Rao", "address": "Pune"}, {"name": "Ravi Rao", "address": "Mumbai"}],
               "plan": [{"row": {"label": "Booking amount", "percent": 10, "amount": 1051575, "taxAmount": 56575}},
                        {"row": {"label": "On agreement", "percent": 90, "amount": 9464175, "taxAmount": 509175}}],
               "totals": {"basic": {"amount": "94,25,000"}}}}


class TablesAndRepeatsTest(unittest.TestCase):
    def test_inspect_lists_tables(self):
        t = docx_edit.inspect(SCHEDULE)["tables"]
        self.assertEqual((t[0]["part"], t[0]["table"], t[0]["rowCount"]), ("document", 0, 5))
        self.assertEqual(t[0]["rows"][1], ["Booking Amount:", "5%", "", "", ""])

    def test_rows_from_a_list_cells_and_a_block_per_applicant(self):
        ins = docx_edit.inspect(SCHEDULE)
        b = ins["blanks"]
        fields = [{**{k: b[0][k] for k in ("part", "para", "start", "end", "text")}, "action": "TAG", "expr": "a.name"},
                  {**{k: b[1][k] for k in ("part", "para", "start", "end", "text")}, "action": "TAG", "expr": "a.address"}]
        conds = [{"kind": "FOR", "part": "document", "fromPara": 0, "toPara": 1, "list": "al.applicants", "var": "a"},
                 {"kind": "ROWS", "part": "document", "table": 0, "fromRow": 1, "toRow": 3, "list": "al.plan", "var": "pl",
                  "cells": [{"expr": "pl.row.label"}, {"expr": "pl.row.percent", "filters": ["pct"], "suffix": "%"},
                            {"expr": "pl.row.amount - pl.row.taxAmount", "filters": ["inr0"]},
                            {"expr": "pl.row.taxAmount", "filters": ["inr0"]}, {"expr": "pl.row.amount", "filters": ["inr0"], "bold": True}]},
                 {"kind": "CELL", "part": "document", "table": 0, "row": 4, "col": 2, "expr": "al.totals.basic.amount"}]
        out, done = docx_edit.prepare(SCHEDULE, fields, conds)
        self.assertEqual((done["repeats"], done["tableRows"], done["cells"], done["tagged"]), (1, 1, 1, 2))
        filled = [t for t in text_of(docx_render.fill(out, PLAN, app.Policy())) if t.strip()]
        self.assertEqual(filled[:4], ["Allottee: Asha Rao", "Address: Pune", "Allottee: Ravi Rao", "Address: Mumbai"])
        i = filled.index("Payment Schedule")
        self.assertEqual(filled[i + 5:i + 10], ["Booking amount", "10%", "9,95,000", "56,575", "10,51,575"])
        self.assertEqual(filled[i + 10:i + 15], ["On agreement", "90%", "89,55,000", "5,09,175", "94,64,175"])
        self.assertEqual(filled[i + 15:], ["Total Sale Value", "100%", "94,25,000"])
        self.assertNotIn("On foundations", filled, "the typed stage rows are replaced by the plan")

    def test_refusals(self):
        for c, why in [
            ({"kind": "ROWS", "table": 5, "fromRow": 1, "list": "al.plan", "var": "pl"}, "table 5 does not exist"),
            ({"kind": "ROWS", "table": 0, "fromRow": 9, "list": "al.plan", "var": "pl"}, "has no row 9"),
            ({"kind": "ROWS", "table": 0, "fromRow": 1, "list": "al.plan", "var": "al"}, "var 'al'"),
            ({"kind": "FOR", "fromPara": 0, "list": "al.plan()", "var": "pl"}, "list"),
            ({"kind": "CELL", "table": 0, "row": 1, "col": 9, "expr": "al.x"}, "no column 9"),
            ({"kind": "CELL", "table": 0, "row": 1, "col": 1, "expr": "al.x.__class__ - 1()"}, "a field is a path"),
            ({"kind": "WHILE"}, "kind 'WHILE'"),
            ({"kind": "CELL", "table": 0, "row": 1, "col": 1, "expr": "al.x", "suffix": "{{evil}}"}, "suffix"),
        ]:
            with self.subTest(why=why), self.assertRaises(docx_edit.BadRequest) as e:
                docx_edit.prepare(SCHEDULE, [], [{"part": "document", **c}])
            self.assertIn(why, str(e.exception))


class FiltersTest(unittest.TestCase):
    def test_formats(self):
        import docx_filters as f

        self.assertEqual((f.inr(14280000), f.inr0("1428000"), f.inr("x")), ("1,42,80,000.00", "14,28,000", "x"))
        self.assertEqual(f.words(123456789.5), "Twelve Crore Thirty Four Lakh Fifty Six Thousand Seven Hundred Eighty Nine and Fifty Paise")
        self.assertEqual((f.num_words(1), f.num_words(2.5)), ("1 (One)", 2.5))
        import datetime
        self.assertEqual((f.age("1980-11-10", datetime.date(2026, 11, 9)), f.age("09/11/1980", datetime.date(2026, 11, 9)), f.age("?")), (45, 46, "?"))
        self.assertEqual((f.pct(10), f.pct("12.50"), f.pct(100 / 3), f.pct("x")), ("10", "12.5", "33.33", "x"))
        self.assertEqual(f.date_words("2026-11-09"), "9th Day of November, Two Thousand Twenty-Six")
        self.assertEqual((f.date_dmy("2026-11-09T10:00:00"), f.date_long("9/11/2026"), f.date_dmy("soon")), ("09-11-2026", "9 November 2026", "soon"))


SIG = "data:image/png;base64," + base64.b64encode(PNG).decode()


class StampTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        doc = make_docx(para(run("Allottee: ______________")) + para(run("Builder: ______________")))
        blanks = docx_edit.inspect(doc)["blanks"]
        prepared, _ = docx_edit.prepare(doc, [field(blanks[0], action="SIGN", signer="A1"), field(blanks[1], action="SIGN", signer="B")])
        cls.pdf = docx_render.Converter(concurrent=1, timeout=120).to_pdf(docx_render.fill(prepared, {}, app.Policy()))

    def test_markers_are_found(self):
        spots = pdf_stamp.find_spots(PdfReader(io.BytesIO(self.pdf)))
        self.assertEqual(sorted(spots), ["A1", "B"])
        (pa, xa, ya), (pb, xb, yb) = spots["A1"][0], spots["B"][0]
        self.assertEqual((pa, pb), (0, 0))
        self.assertGreater(ya, yb, "the builder's line is below the allottee's")
        self.assertTrue(50 < xa < 400, xa)

    def test_signatures_are_drawn_where_the_markers_are(self):
        out, result = pdf_stamp.stamp(self.pdf, [{"key": "A1", "image": SIG, "name": "Rohit Sharma"}])
        self.assertEqual(result, {"placed": ["A1"], "onRecordPage": []})
        r = PdfReader(io.BytesIO(out))
        self.assertEqual(len(r.pages), 1)
        self.assertEqual(len(r.pages[0].images), 1)
        self.assertIn("[[sig:A1]]", r.pages[0].extract_text(), "the original page is kept as it was")

    def test_a_row_of_applicants_stays_inside_the_page(self):
        doc = make_docx('<w:p><w:pPr><w:jc w:val="right"/></w:pPr>' + run("Signature ______________") + "</w:p>")
        b = docx_edit.inspect(doc)["blanks"]
        prepared, _ = docx_edit.prepare(doc, [field(b[0], action="SIGN", signer="A*")])
        pdf = docx_render.Converter(concurrent=1, timeout=120).to_pdf(docx_render.fill(prepared, {}, app.Policy()))
        seen = []
        orig = pdf_stamp._overlay_html
        pdf_stamp._overlay_html = lambda w, h, items: seen.append((w, items)) or orig(w, h, items)
        try:
            pdf_stamp.stamp(pdf, [{"key": f"A{i}", "image": SIG} for i in (1, 2, 3)])
        finally:
            pdf_stamp._overlay_html = orig
        (width, items), = seen
        self.assertEqual(len(items), 3)
        self.assertLessEqual(max(x + w for x, y, w, _ in items), width - pdf_stamp.MARGIN_PT + 0.01)
        self.assertGreaterEqual(min(w for _, _, w, _ in items), pdf_stamp.MIN_MM * pdf_stamp.PT_PER_MM - 0.01)

    def test_a_signer_without_a_spot_goes_on_the_record_page(self):
        out, result = pdf_stamp.stamp(self.pdf, [{"key": "A2", "image": SIG, "name": "Priya Sharma", "lines": ["Signed in the app"]}])
        self.assertEqual(result, {"placed": [], "onRecordPage": ["A2"]})
        r = PdfReader(io.BytesIO(out))
        self.assertEqual(len(r.pages), 2)
        self.assertIn("Priya Sharma", r.pages[1].extract_text())

    def test_a_typed_signature_is_drawn_as_text(self):
        out, result = pdf_stamp.stamp(self.pdf, [{"key": "A1", "text": "Rohit Sharma"}])
        self.assertEqual(result["placed"], ["A1"])
        self.assertIn("Rohit Sharma", PdfReader(io.BytesIO(out)).pages[0].extract_text())

    def test_refusals(self):
        for stamps in ([], [{"key": "A1", "image": "https://x/y.png"}], [{"key": "ZZZZZ", "image": SIG}], [{"key": "A1"}]):
            with self.subTest(stamps=stamps), self.assertRaises(pdf_stamp.BadStamp):
                pdf_stamp.stamp(self.pdf, stamps)
        with self.assertRaises(pdf_stamp.BadStamp):
            pdf_stamp.stamp(b"not a pdf", [{"key": "A1", "image": SIG}])


class EndpointsTest(unittest.TestCase):
    def test_inspect_prepare_and_stamp_over_http(self):
        handler = type("H", (app.Handler,), {"policy": app.Policy(), "max_body": 20_000_000,
                                             "converter": docx_render.Converter(concurrent=1, timeout=120)})
        srv, base = serve(handler)
        url = lambda b, mime: f"data:{mime};base64," + base64.b64encode(b).decode()
        post = lambda path, body: urllib.request.urlopen(urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST"), timeout=120)
        try:
            doc = url(LETTER, "application/octet-stream")
            r = json.loads(post("/docx/inspect", {"file": doc}).read())
            self.assertEqual(len(r["blanks"]), 7)
            resp = post("/docx/prepare", {"file": doc, "fields": [field(r["blanks"][6], action="SIGN", signer="A1")]})
            self.assertEqual(json.loads(resp.headers["X-Result"])["signSpots"], ["A1"])
            prepared = resp.read()
            pdf = post("/docx/render", {"file": url(prepared, "application/octet-stream"), "data": {}}).read()
            resp = post("/pdf/stamp", {"file": url(pdf, "application/pdf"), "stamps": [{"key": "A1", "image": SIG}]})
            self.assertEqual(json.loads(resp.headers["X-Result"])["placed"], ["A1"])
            self.assertTrue(resp.read().startswith(b"%PDF"))
            bad = [("/docx/prepare", {"file": doc, "fields": [field(r["blanks"][0], expr="x y")]}),
                   ("/docx/inspect", {"file": url(b"zip? no", "application/octet-stream")}),
                   ("/pdf/stamp", {"file": url(pdf, "application/pdf"), "stamps": []}),
                   ("/docx/inspect", {})]
            for path, body in bad:
                with self.subTest(path=path), self.assertRaises(urllib.error.HTTPError) as e:
                    post(path, body)
                self.assertEqual(e.exception.code, 400)
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
