"""Tests for HTML to Word (docx_html.py, `POST /docx/from-html`) and the Word template fill (`POST /docx/fill`).
Run in the image: python -m unittest test_docx_html"""

import base64
import io
import json
import unittest
import urllib.error
import urllib.request
import zipfile

import app
import docx_html
import docx_render
from test_app import PNG, serve
from test_docx import data_url, make_docx

PAGE = """<html><head><style>
@page{size:A4;margin:20mm 15mm 18mm 15mm;
  @top-left{content:element(hdr)}
  @bottom-right{content:"Page " counter(page) " of " counter(pages)}}
#hdr{position:running(hdr)}
body{font-family:Helvetica;font-size:10pt}
h1{font-size:15pt;letter-spacing:.04em;margin:0 0 3mm}
.band{background:#efefef;padding:2mm 4mm;text-align:center;font-weight:bold;text-transform:uppercase}
.sec{border-bottom:1px solid #111;margin:6mm 0 2mm}
table.d{width:100%;border-collapse:collapse}
table.d td{border:1px solid #bbb;padding:2mm 3mm;background:#f4f4f4}
.cols{display:flex;gap:9mm}
.col{flex:1}
.two{column-count:2}
.wm{position:fixed;top:60mm;opacity:.1}
</style></head><body>
<div id="hdr"><table><tr><td><img src="__IMG__"/></td><td style="text-align:right">Right note</td></tr></table></div>
<div class="wm">DRAFT WATERMARK</div>
<h1>Agreement</h1>
<div class="band">cost sheet</div>
<div class="sec">Unit</div>
<table class="d"><tr><td>Unit number</td><td>301</td></tr><tr><td>Floor</td><td>3</td></tr></table>
<div class="cols"><div class="col">Left column</div><div class="col">Right column</div></div>
<div class="two"><p>one</p><p>two</p><p>three</p></div>
</body></html>""".replace("__IMG__", "data:image/png;base64," + base64.b64encode(PNG).decode())


def doc_xml(raw):
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        return z.read("word/document.xml").decode()


def part_xml(raw, name):
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        return "".join(z.read(n).decode() for n in z.namelist() if n.startswith(f"word/{name}"))


class PrepareTest(unittest.TestCase):
    def setUp(self):
        self.p = docx_html.prepare(PAGE, app.Policy())

    def test_the_page_comes_from_at_page(self):
        self.assertEqual((self.p.page["w"], self.p.page["h"]), (210.0, 297.0))
        self.assertEqual([round(m) for m in self.p.page["margin"]], [20, 15, 18, 15])
        self.assertTrue(self.p.page["numbers"])
        self.assertEqual(self.p.page["boxes"].get("top-left"), "hdr")

    def test_landscape_and_other_sizes(self):
        page = docx_html._page_rule("@page{size:A4 landscape;margin:12mm}")
        self.assertEqual((page["w"], page["h"]), (297.0, 210.0))
        self.assertEqual(page["margin"], [12.0] * 4)
        self.assertEqual(docx_html._page_rule("@page{size:Letter}")["w"], 215.9)

    def test_the_running_header_leaves_the_body_and_keeps_its_logo_and_text(self):
        self.assertNotIn("Right note", self.p.html)
        paras = self.p.header
        self.assertEqual(len(paras), 1)
        self.assertEqual(len(paras[0]["images"]), 1)
        self.assertEqual(paras[0]["right"], "Right note")

    def test_a_fixed_box_is_left_out(self):
        self.assertNotIn("WATERMARK", self.p.html)

    def test_css_is_inlined_and_librecoffice_safe(self):
        h = self.p.html
        self.assertNotIn("<style", h)
        self.assertNotIn("display:flex", h)
        self.assertNotIn("column-count", h)
        self.assertIn("COST SHEET", h, "text-transform is applied to the text")
        # a number without a leading zero, or an em letter spacing, would stop LibreOffice reading the rest of the style
        self.assertNotRegex(h, r"[:\s]\.\d")
        self.assertNotIn("em;", h.replace("em;margin", "X"))

    def test_flex_and_columns_become_tables(self):
        self.assertGreaterEqual(self.p.html.count("<table"), 3)
        self.assertIn("Left column", self.p.html)
        self.assertEqual(len(self.p.pads), self.p.html.count("<table"))

    def test_a_block_border_and_background_become_marks(self):
        kinds = [sorted(m) for m in self.p.marks]
        self.assertIn(["bottom"], kinds)
        self.assertIn(["fill"], kinds)
        self.assertIn("%%M", self.p.html)

    def test_cell_padding_goes_on_the_table(self):
        # 2mm / 3mm: 7.56px / 11.34px, in twips
        self.assertIn([113, 170, 113, 170], self.p.pads)

    def test_an_unreadable_image_is_left_out_not_fatal(self):
        h = docx_html.prepare('<html><body><p>x</p><img src="https://evil.example/x.png"/></body></html>', app.Policy()).html
        self.assertNotIn("<img", h)

    def test_the_policy_is_asked_for_files_urls_only(self):
        class Spy(app.Policy):
            def __init__(self):
                super().__init__()
                self.asked = []

            def fetch(self, url):
                self.asked.append(url)
                raise app.Refused("no")

        spy = Spy()
        docx_html.prepare('<html><body><img src="/api/files/static/file/C/logo.png"/></body></html>', spy)
        self.assertEqual(spy.asked, [app.BASE_URL + "api/files/static/file/C/logo.png"])


class ConvertTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conv = docx_render.Converter(concurrent=1, timeout=120)
        cls.raw = docx_html.to_docx(PAGE, app.Policy(), cls.conv)

    def test_it_is_a_word_file_with_the_words(self):
        self.assertTrue(self.raw.startswith(b"PK"))
        body = doc_xml(self.raw)
        for word in ("Agreement", "COST SHEET", "Unit number", "Left column", "Right column"):
            self.assertIn(word, body)
        self.assertNotIn("%%M", body, "the markers are taken out")
        self.assertNotIn("WATERMARK", body)

    def test_the_page_is_set_and_the_header_footer_are_real_parts(self):
        body = doc_xml(self.raw)
        self.assertIn('w:w="11906"', body)  # A4 width in twips
        self.assertIn("w:pgMar", body)
        self.assertIn("Right note", part_xml(self.raw, "header"))
        footer = part_xml(self.raw, "footer")
        self.assertIn("PAGE", footer)
        self.assertIn("NUMPAGES", footer)

    def test_rules_and_shading_are_on_paragraphs(self):
        body = doc_xml(self.raw)
        self.assertIn("<w:pBdr>", body)
        self.assertIn('w:fill="EFEFEF"', body)

    def test_the_file_opens_again_and_converts_to_a_pdf(self):
        from docx import Document

        Document(io.BytesIO(self.raw))
        self.assertTrue(self.conv.to_pdf(self.raw).startswith(b"%PDF"))


class FillTest(unittest.TestCase):
    def test_the_endpoints(self):
        handler = type("H", (app.Handler,), {"policy": app.Policy(), "max_body": 10_000_000,
                                             "converter": docx_render.Converter(concurrent=1, timeout=120)})
        srv, base = serve(handler)
        try:
            ok = json.dumps({"file": data_url(make_docx("Hello {{ who }}")), "data": {"who": "Ann"}}).encode()
            r = urllib.request.urlopen(urllib.request.Request(base + "/docx/fill", data=ok, method="POST"), timeout=60)
            self.assertEqual(r.headers.get_content_type(), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
            self.assertIn("Hello Ann", doc_xml(r.read()))
            for body in (b"not json", json.dumps({"data": {}}).encode(), json.dumps({"file": "file:///etc/passwd"}).encode(),
                         json.dumps({"file": data_url(make_docx("{{ ''.__class__ }}"))}).encode()):
                with self.subTest(body=body[:40]), self.assertRaises(urllib.error.HTTPError) as e:
                    urllib.request.urlopen(urllib.request.Request(base + "/docx/fill", data=body, method="POST"), timeout=60)
                self.assertEqual(e.exception.code, 400)
            html = PAGE.encode()
            r = urllib.request.urlopen(urllib.request.Request(base + "/docx/from-html", data=html, method="POST"), timeout=120)
            self.assertTrue(r.read().startswith(b"PK"))
            with self.assertRaises(urllib.error.HTTPError) as e:
                urllib.request.urlopen(urllib.request.Request(base + "/docx/from-html", data=b"  ", method="POST"), timeout=30)
            self.assertEqual(e.exception.code, 400)
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
