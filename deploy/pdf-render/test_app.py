"""Tests for pdf-render: the URL policy (no WeasyPrint needed) and, where WeasyPrint is
installed (the image), real renders. Run: `python -m unittest -v test_app`."""

import http.server
import subprocess
import threading
import unittest
import urllib.request

import app

try:
    import weasyprint  # noqa: F401

    HAVE_WEASYPRINT = True
except Exception:  # noqa: BLE001
    HAVE_WEASYPRINT = False

PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
    "1f15c4890000000d49444154789c63f8cfc0f01f0005000201a5c3b1d30000000049454e44ae426082"
)


class FakeFiles(http.server.BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        FakeFiles.seen.append(self.path)
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
            return
        if "missing" in self.path:
            self.send_response(404)
            self.end_headers()
            return
        body = b"x" * 100 if "big" in self.path else PNG
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(handler):
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s, f"http://127.0.0.1:{s.server_address[1]}"


class PolicyTest(unittest.TestCase):
    def setUp(self):
        self.p = app.Policy(files_url="http://files-serve:8103/", allowed_hosts=["cdn.example.com"])

    def test_files_urls_go_to_the_internal_route_whatever_the_host(self):
        self.assertEqual(
            self.p.target("https://antera.dev.modlix.com/api/files/static/file/SYSTEM/logos/a%20b.png?width=10"),
            "http://files-serve:8103/api/files/internal/static/file?filePath=SYSTEM%2Flogos%2Fa+b.png&width=10",
        )
        self.assertEqual(
            self.p.target(app.BASE_URL + "api/files/secured/file/ACME/docs/x.png"),
            "http://files-serve:8103/api/files/internal/secured/file?filePath=ACME%2Fdocs%2Fx.png",
        )

    def test_everything_else_is_refused(self):
        for url in [
            "file:///etc/passwd",
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:8080/api/security/internal/x",
            "http://fonts.googleapis.com/css?family=Inter",  # font host, but not https
            "https://fonts.googleapis.com.evil.io/css",
            "http://cdn.example.com/a.png",  # allowed host, but not https
            "https://cdn.example.com:8443/a.png",  # allowed host, other port
            "https://cdn.example.com.evil.io/a.png",
            "ftp://cdn.example.com/a.png",
            "https://x/api/files/internal/static/file?filePath=a",  # only the public shapes map
        ]:
            with self.subTest(url=url), self.assertRaises(app.Refused):
                self.p.target(url)

    def test_allowed_hosts_and_data_urls(self):
        self.assertEqual(self.p.target("https://CDN.example.com/a.png"), "https://CDN.example.com/a.png")
        self.assertIsNone(self.p.target("data:image/png;base64,AAAA"))

    def test_web_font_hosts_are_allowed_by_default(self):
        for url in ["https://fonts.googleapis.com/css2?family=Poppins:wght@400;600",
                    "https://fonts.gstatic.com/s/poppins/v22/pxiEyp8kv8JHgFVrJJfecg.woff2"]:
            self.assertEqual(self.p.target(url), url)
        with self.assertRaises(app.Refused):
            app.Policy(font_hosts=[""]).target("https://fonts.googleapis.com/css2?family=Poppins")

    def test_no_files_url_refuses_files_too(self):
        with self.assertRaises(app.Refused):
            app.Policy().target("https://a/api/files/static/file/SYSTEM/x.png")


class FetchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base = serve(FakeFiles)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_fetch_reads_from_files_with_caps(self):
        p = app.Policy(files_url=self.base, max_bytes=len(PNG) + 10)
        got = p.fetch("https://h/api/files/static/file/SYSTEM/x.png")
        self.assertEqual((got["string"], got["mime_type"]), (PNG, "image/png"))
        self.assertIn("/api/files/internal/static/file?filePath=SYSTEM%2Fx.png", FakeFiles.seen[-1])
        with self.assertRaises(app.Refused):
            p.fetch("https://h/api/files/static/file/SYSTEM/big.png")
        with self.assertRaises(app.Refused):
            p.fetch("https://h/api/files/static/file/SYSTEM/missing.png")

    def test_web_fonts_are_fetched_once(self):
        calls = []

        class Resp:
            headers = __import__("email.message").message.Message()

            def __init__(self):
                self.headers = __import__("email.message").message.Message()
                self.headers["Content-Type"] = "font/woff2"

            def read(self, n):
                return b"FONT"

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        real = app._OPENER.open
        app._OPENER.open = lambda req, timeout: calls.append(req.full_url) or Resp()
        try:
            p = app.Policy(font_cache_bytes=6)
            url = "https://fonts.gstatic.com/s/poppins/a.woff2"
            for _ in range(3):
                got = p.fetch(url)
                self.assertEqual((got["string"], got["mime_type"]), (b"FONT", "font/woff2"))
            self.assertEqual(calls, [url])
            p.fetch("https://fonts.gstatic.com/s/poppins/b.woff2")  # over budget: a.woff2 goes
            p.fetch(url)
            self.assertEqual(len(calls), 3)
        finally:
            app._OPENER.open = real

    def test_redirects_are_not_followed(self):
        req = urllib.request.Request(self.base + "/redirect")
        with self.assertRaises(app.Refused):
            app._OPENER.open(req, timeout=5)


@unittest.skipUnless(HAVE_WEASYPRINT, "WeasyPrint is not installed (run in the image)")
class RenderTest(unittest.TestCase):
    def test_css_page_size_margins_and_styles_apply(self):
        from weasyprint import HTML

        html = """<html><head><style>@page { size: A5; margin: 10mm }
            td { border: 1px solid #333; background: #e8f1fb; color: #1a5fa8 }</style></head>
            <body><table><tr><td>Total Basic Cost</td><td>&#8377; 3,12,99,300</td></tr></table></body></html>"""
        doc = HTML(string=html, base_url=app.BASE_URL, url_fetcher=app.Policy().fetch).render()
        page = doc.pages[0]
        self.assertAlmostEqual(page.width, 148 / 25.4 * 96, delta=1)  # A5 in CSS px
        box = page._page_box
        self.assertAlmostEqual(box.margin_left, 10 / 25.4 * 96, delta=1)

        def walk(b):
            yield b
            for c in getattr(b, "children", []):
                yield from walk(c)

        cells = [b for b in walk(box) if type(b).__name__ == "TableCellBox"]
        self.assertEqual(len(cells), 2)
        bg = cells[0].style["background_color"]
        self.assertEqual([round(c * 255) for c in bg[:3]], [0xE8, 0xF1, 0xFB], "the <style> block applies")
        self.assertEqual(cells[0].style["border_left_width"], 1)
        pdf = app.render(html, app.Policy())
        self.assertTrue(pdf.startswith(b"%PDF"))

    def test_an_inline_running_element_with_a_table(self):
        # cxapp's cost sheet: WeasyPrint alone fails with "'TextBox' object has no attribute 'is_header'".
        html = """<style>@page { @top-center { content: element(abc) } }</style>
            <commonElement style="position:running(abc)">
              <table><tr><td>header</td></tr></table>
            </commonElement><p>body</p>"""
        self.assertTrue(app.render(html, app.Policy()).startswith(b"%PDF"))
        span = '<style>@page{@top-center{content:element(h)}}</style><span style="position:running(h)"><table><tr><td>a</td></tr></table></span>x'
        self.assertTrue(app.render(span, app.Policy()).startswith(b"%PDF"))

    def test_a_font_with_the_rupee_sign_is_installed(self):
        out = subprocess.run(["fc-list", ":charset=20b9", "family"], capture_output=True, text=True).stdout
        self.assertTrue(out.strip(), "no installed font has U+20B9")

    def test_refused_and_files_images(self):
        srv, base = serve(FakeFiles)
        try:
            p = app.Policy(files_url=base)
            html = '<img src="/api/files/static/file/SYSTEM/logo.png"><img src="file:///etc/passwd"><img src="http://169.254.169.254/x">'
            before = len(FakeFiles.seen)
            self.assertTrue(app.render(html, p).startswith(b"%PDF"))
            self.assertEqual(len(FakeFiles.seen) - before, 1, "only the files URL was fetched")
        finally:
            srv.shutdown()

    def test_the_http_endpoint(self):
        handler = type("H", (app.Handler,), {"policy": app.Policy(), "max_body": 1000})
        srv, base = serve(handler)
        try:
            r = urllib.request.urlopen(urllib.request.Request(base + "/render", data=b"<p>Hello</p>", method="POST"), timeout=30)
            self.assertEqual(r.headers.get_content_type(), "application/pdf")
            self.assertTrue(r.read().startswith(b"%PDF"))
            for body, code in [(b"   ", 400), (b"x" * 2000, 413)]:
                with self.subTest(code=code), self.assertRaises(urllib.error.HTTPError) as e:
                    urllib.request.urlopen(urllib.request.Request(base + "/render", data=body, method="POST"), timeout=30)
                self.assertEqual(e.exception.code, code)
            self.assertEqual(urllib.request.urlopen(base + "/healthz", timeout=5).read(), b"ok")
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
