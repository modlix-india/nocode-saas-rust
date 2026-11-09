"""Tests for Word templates (docx_render.py). Run in the image: python -m unittest test_docx"""

import base64
import io
import json
import os
import stat
import tempfile
import unittest
import urllib.error
import urllib.request
import zipfile

import app
import docx_render
from test_app import PNG, serve


def make_docx(*paragraphs):
    from docx import Document

    d = Document()
    for p in paragraphs:
        d.add_paragraph(p)
    out = io.BytesIO()
    d.save(out)
    return out.getvalue()


def body_xml(docx_bytes):
    with zipfile.ZipFile(io.BytesIO(docx_bytes)) as z:
        return z.read("word/document.xml").decode()


def data_url(raw, mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document"):
    return f"data:{mime};base64," + base64.b64encode(raw).decode()


SIG = "data:image/png;base64," + base64.b64encode(PNG).decode()


class FillTest(unittest.TestCase):
    def test_fields_missing_fields_and_images(self):
        src = make_docx("Name: {{ al.primary.name }}", "Missing: [{{ al.nope.deeper.still }}]",
                        "Signed: {{ image(sig, 20) }}", "Unsigned: [{{ image(none_here) }}]")
        out = body_xml(docx_render.fill(src, {"al": {"primary": {"name": "Ann Rao"}}, "sig": SIG}, app.Policy()))
        self.assertIn("Name: Ann Rao", out)
        self.assertIn("Missing: []", out, "a missing field renders as nothing at any depth")
        self.assertIn("<w:drawing", out, "the signature is an inline picture")
        self.assertIn("Unsigned: []", out)

    def test_values_are_text_not_markup(self):
        out = body_xml(docx_render.fill(make_docx("{{ v }}"), {"v": "<w:p>A & B</w:p>"}, app.Policy()))
        self.assertIn("&lt;w:p&gt;A &amp; B&lt;/w:p&gt;", out)

    def test_the_sandbox_refuses_python(self):
        for tag in ("{{ ''.__class__.__mro__ }}", "{{ image.__globals__ }}"):
            with self.subTest(tag=tag), self.assertRaises(docx_render.BadTemplate):
                docx_render.fill(make_docx(tag), {}, app.Policy())

    def test_not_a_word_file(self):
        with self.assertRaises(docx_render.BadTemplate):
            docx_render.fill(b"not a zip", {}, app.Policy())

    def test_an_image_url_goes_through_the_policy(self):
        with self.assertRaises(app.Refused):
            docx_render.fill(make_docx("{{ image('file:///etc/passwd') }}"), {}, app.Policy())


class FilesTest(unittest.TestCase):
    def test_relative_files_urls_are_read_from_the_files_service(self):
        from test_app import FakeFiles

        srv, base = serve(FakeFiles)
        try:
            p = app.Policy(files_url=base)
            before = len(FakeFiles.seen)
            for url in ("/api/files/static/file/SYSTEM/x.png", "api/files/static/file/SYSTEM/x.png"):
                self.assertEqual(docx_render._fetch(url, p), PNG, url)
            self.assertEqual(len(FakeFiles.seen) - before, 2)
            self.assertIn("/api/files/internal/static/file?filePath=SYSTEM%2Fx.png", FakeFiles.seen[-1])
        finally:
            srv.shutdown()


class ConvertTest(unittest.TestCase):
    def test_a_filled_template_becomes_a_pdf(self):
        conv = docx_render.Converter(concurrent=1, timeout=120)
        body = json.dumps({"file": data_url(make_docx("Hello {{ who }}")), "data": {"who": "Ann"}}).encode()
        self.assertTrue(docx_render.render(body, app.Policy(), conv).startswith(b"%PDF"))

    def test_a_conversion_that_hangs_is_killed(self):
        d = tempfile.mkdtemp()
        fake = os.path.join(d, "soffice")
        with open(fake, "w") as f:
            f.write("#!/bin/sh\nsleep 30\n")
        os.chmod(fake, os.stat(fake).st_mode | stat.S_IEXEC)
        conv = docx_render.Converter(concurrent=1, timeout=1, soffice=fake)
        with self.assertRaises(docx_render.Busy):
            conv.to_pdf(make_docx("x"))
        # its profile slot came back, so the next conversion is not stuck behind it
        self.assertEqual(conv.profiles.qsize(), 1)

    def test_the_http_endpoint(self):
        handler = type("H", (app.Handler,), {"policy": app.Policy(), "max_body": 10_000_000,
                                             "converter": docx_render.Converter(concurrent=1, timeout=120)})
        srv, base = serve(handler)
        try:
            ok = json.dumps({"file": data_url(make_docx("{{ a }}")), "data": {"a": 1}}).encode()
            r = urllib.request.urlopen(urllib.request.Request(base + "/docx/render", data=ok, method="POST"), timeout=120)
            self.assertEqual(r.headers.get_content_type(), "application/pdf")
            self.assertTrue(r.read().startswith(b"%PDF"))
            bad = [b"not json", json.dumps({"data": {}}).encode(), json.dumps({"file": "file:///etc/passwd"}).encode(),
                   json.dumps({"file": data_url(b"zip? no")}).encode(),
                   json.dumps({"file": data_url(make_docx("{{ ''.__class__ }}"))}).encode()]
            for body in bad:
                with self.subTest(body=body[:40]), self.assertRaises(urllib.error.HTTPError) as e:
                    urllib.request.urlopen(urllib.request.Request(base + "/docx/render", data=body, method="POST"), timeout=60)
                self.assertEqual(e.exception.code, 400)
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
