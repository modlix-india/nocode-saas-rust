"""pdf-render: HTML to PDF with WeasyPrint, for core's TemplateToPdf and the template PDF preview.

An internal service (no host port, reached only by core-exec and core-editor on the compose
network). It never fetches what a template names on its own:

- `data:` URLs are read in place;
- a URL whose path is a files URL (`/api/files/static/file/<path>` or
  `/api/files/secured/file/<path>`, on any host, relative or absolute) is read from the files
  service's internal route (`FILES_URL` + `/api/files/internal/<static|secured>/file?filePath=`),
  as Java's FileServerStreamFactory did for secured files; the host in the template is ignored;
- web fonts: `https` URLs on the hosts in `FONT_HOSTS` (default `fonts.googleapis.com` and
  `fonts.gstatic.com`) are fetched as is, with no redirects, so a template can name any Google
  font (`<link href="https://fonts.googleapis.com/css2?family=...">`); answers are kept in memory
  (`FONT_CACHE_BYTES`, 64 MiB) so a font is downloaded once, not on every render;
- an `https` URL on a host listed in `ALLOWED_HOSTS` (exact names, empty by default) is fetched
  as is, with no redirects;
- anything else (`file:`, other hosts, IP addresses, metadata endpoints) is refused, and
  WeasyPrint leaves that resource out.

Every fetch has a timeout and a size cap. Endpoints: `POST /render` (the HTML as the body,
UTF-8) answers `application/pdf`; `POST /docx/render` (JSON `{file, data}`: a Word template filled
and converted by LibreOffice, see docx_render.py) answers `application/pdf`; `POST /docx/inspect`
(JSON `{file}`) answers the blanks of a Word file, `POST /docx/prepare` (JSON `{file, fields,
conditions, options}`) the Word file with field tags in place of its blanks, `POST /pdf/stamp`
(JSON `{file, stamps}`) the PDF with signatures drawn at its markers (docx_edit.py, pdf_stamp.py;
what was done comes back as JSON in the `X-Result` header); `GET /healthz` answers `ok`.

Environment: `PORT` (8120), `FILES_URL` (empty: files URLs are refused too), `ALLOWED_HOSTS`,
`FONT_HOSTS` (fonts.googleapis.com,fonts.gstatic.com; empty turns web fonts off), `FONT_CACHE_BYTES`,
`MAX_BODY_BYTES` (50 MiB), `FETCH_TIMEOUT_SECONDS` (10), `FETCH_MAX_BYTES` (20 MiB),
`MAX_CONCURRENT` (2), `DOCX_CONCURRENT` (2), `DOCX_TIMEOUT_SECONDS` (90), `LOG_LEVEL` (INFO).
"""

import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = logging.getLogger("pdf-render")

DEFAULT_FONT_HOSTS = "fonts.googleapis.com,fonts.gstatic.com"
DOCX_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
FILES_PATH = re.compile(r"^/api/files/(static|secured)/file/(.+)$")
# Relative URLs in a template resolve against this, so `/api/files/...` matches FILES_PATH.
BASE_URL = "https://pdf-render.invalid/"


class Refused(Exception):
    """A URL the policy does not allow."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Refused(f"redirect to {newurl} refused")


_OPENER = urllib.request.build_opener(_NoRedirect)


class Policy:
    def __init__(self, files_url="", allowed_hosts=(), timeout=10.0, max_bytes=20 * 1024 * 1024,
                 font_hosts=DEFAULT_FONT_HOSTS.split(","), font_cache_bytes=64 * 1024 * 1024):
        self.files_url = files_url.rstrip("/")
        self.allowed_hosts = {h.strip().lower() for h in allowed_hosts if h.strip()}
        self.font_hosts = {h.strip().lower() for h in font_hosts if h.strip()}
        self.timeout = timeout
        self.max_bytes = max_bytes
        # Web font answers (CSS and font files) by URL: they do not change, and fetching them on
        # every render would make each PDF wait on Google. Oldest out first past the byte budget.
        self.font_cache = {}
        self.font_cache_bytes = font_cache_bytes
        self._font_cache_size = 0
        self._font_lock = threading.Lock()

    @classmethod
    def from_env(cls):
        return cls(
            files_url=os.environ.get("FILES_URL", ""),
            allowed_hosts=os.environ.get("ALLOWED_HOSTS", "").split(","),
            timeout=float(os.environ.get("FETCH_TIMEOUT_SECONDS", "10")),
            max_bytes=int(os.environ.get("FETCH_MAX_BYTES", str(20 * 1024 * 1024))),
            font_hosts=os.environ.get("FONT_HOSTS", DEFAULT_FONT_HOSTS).split(","),
            font_cache_bytes=int(os.environ.get("FONT_CACHE_BYTES", str(64 * 1024 * 1024))),
        )

    def target(self, url):
        """The URL actually fetched for `url`, or `None` for a `data:` URL; `Refused` otherwise."""
        if url.startswith("data:"):
            return None
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https"):
            raise Refused(f"scheme {u.scheme or '(none)'} refused")
        m = FILES_PATH.match(u.path)
        if m:
            if not self.files_url:
                raise Refused("files URL refused: FILES_URL is not set")
            kind, rest = m.group(1), urllib.parse.unquote(m.group(2))
            query = urllib.parse.urlencode([("filePath", rest)] + urllib.parse.parse_qsl(u.query))
            return f"{self.files_url}/api/files/internal/{kind}/file?{query}"
        host = (u.hostname or "").lower()
        if u.scheme == "https" and host in (self.allowed_hosts | self.font_hosts) and u.port in (None, 443):
            return url
        raise Refused(f"host {host or '(none)'} refused")

    def fetch(self, url):
        """WeasyPrint's `url_fetcher`."""
        target = self.target(url)
        if target is None:
            from weasyprint.urls import default_url_fetcher

            return default_url_fetcher(url)
        font = urllib.parse.urlsplit(target).hostname in self.font_hosts
        if font:
            with self._font_lock:
                hit = self.font_cache.get(target)
            if hit:
                return dict(hit)
        req = urllib.request.Request(target, headers={"User-Agent": "modlix-pdf-render"})
        try:
            with _OPENER.open(req, timeout=self.timeout) as resp:
                body = resp.read(self.max_bytes + 1)
                if len(body) > self.max_bytes:
                    raise Refused(f"{url}: larger than {self.max_bytes} bytes")
                mime = resp.headers.get_content_type()
                charset = resp.headers.get_content_charset()
        except urllib.error.HTTPError as e:
            raise Refused(f"{url}: HTTP {e.code}") from None
        result = {"string": body, "mime_type": mime, "redirected_url": url}
        if charset:
            result["encoding"] = charset
        if font:
            self._remember_font(target, result)
        return result

    def _remember_font(self, url, result):
        size = len(result["string"])
        if size > self.font_cache_bytes:
            return
        with self._font_lock:
            if url in self.font_cache:
                return
            while self.font_cache and self._font_cache_size + size > self.font_cache_bytes:
                old = self.font_cache.pop(next(iter(self.font_cache)))
                self._font_cache_size -= len(old["string"])
            self.font_cache[url] = dict(result)
            self._font_cache_size += size


_PATCHED = False


def _blockify_running_elements():
    """Lay a running element (`position: running(x)`, openhtmltopdf's page headers) out as a
    block, as openhtmltopdf did and as WeasyPrint already does for absolute and floated boxes.
    WeasyPrint keeps an inline one inline and then fails on a table inside it (`'TextBox' object
    has no attribute 'is_header'`): cxapp's cost sheet wraps its header table in a custom
    (inline) `<commonElement style="position:running(abc)">`."""
    global _PATCHED
    if _PATCHED:
        return
    from weasyprint.css import computed_values as cv

    original = cv.COMPUTER_FUNCTIONS["display"]

    def display(style, name, value):
        position = style.specified["position"]
        if isinstance(position, tuple) and position and position[0] == "running()" and value and value[0] == "inline":
            return ("block", "table") if value == ("inline-table",) else ("block", "flow")
        return original(style, name, value)

    cv.COMPUTER_FUNCTIONS["display"] = display
    _PATCHED = True


def render(html, policy):
    from weasyprint import HTML

    _blockify_running_elements()
    return HTML(string=html, base_url=BASE_URL, url_fetcher=policy.fetch).write_pdf()


class Handler(BaseHTTPRequestHandler):
    server_version = "pdf-render"
    policy = Policy()
    max_body = 50 * 1024 * 1024
    slots = threading.BoundedSemaphore(2)
    converter = None
    sealer = None  # pdf_seal.Sealer when PDF_SEAL_P12 is set

    def log_message(self, fmt, *args):
        LOG.debug("%s %s", self.address_string(), fmt % args)

    def _send(self, code, body, ctype="text/plain; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/healthz", "/readyz"):
            return self._send(200, b"ok")
        self._send(404, b"not found")

    def do_POST(self):
        if self.path not in ("/render", "/docx/render", "/docx/inspect", "/docx/prepare", "/pdf/stamp", "/pdf/seal"):
            return self._send(404, b"not found")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._send(411, b"Content-Length required")
        if length > self.max_body:
            return self._send(413, b"body too large")
        if self.path == "/docx/render":
            return self._docx(self.rfile.read(length))
        if self.path == "/pdf/seal":
            return self._seal(self.rfile.read(length))
        if self.path in ("/docx/inspect", "/docx/prepare", "/pdf/stamp"):
            return self._edit(self.path, self.rfile.read(length))
        html = self.rfile.read(length).decode("utf-8", errors="replace")
        if not html.strip():
            return self._send(400, b"empty body")
        started = time.monotonic()
        with self.slots:
            try:
                pdf = render(html, self.policy)
            except Exception as e:  # a broken document must not take the service down
                LOG.exception("render failed")
                return self._send(500, f"render failed: {type(e).__name__}".encode())
        LOG.info("rendered %d bytes of HTML into %d bytes of PDF in %.0f ms", length, len(pdf), (time.monotonic() - started) * 1000)
        self._send(200, pdf, "application/pdf")

    def _send_with(self, body, ctype, result):
        """A file answered with what was done, as JSON in `X-Result`."""
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Result", json.dumps(result, separators=(",", ":")))
        self.end_headers()
        self.wfile.write(body)

    def _edit(self, path, body):
        """`/docx/inspect` (JSON), `/docx/prepare` (the prepared .docx) and `/pdf/stamp` (the
        stamped PDF): see docx_edit.py and pdf_stamp.py."""
        import docx_edit
        import docx_render
        import pdf_stamp

        try:
            req = json.loads(body)
            if not isinstance(req, dict) or not isinstance(req.get("file"), str) or not req["file"]:
                raise docx_edit.BadRequest("body: `file` is required")
            if path == "/pdf/stamp":
                with self.slots:
                    pdf, result = pdf_stamp.stamp(docx_render._read_file(req["file"], self.policy), req.get("stamps"),
                                                  bool(req.get("recordPage")), render_html=lambda m: render(m, self.policy))
                return self._send_with(pdf, "application/pdf", result)
            src = docx_render._read_file(req["file"], self.policy)
            if path == "/docx/inspect":
                return self._send(200, json.dumps(docx_edit.inspect(src)).encode(), "application/json")
            out, done = docx_edit.prepare(src, req.get("fields"), req.get("conditions"), req.get("options"))
            # the prepared file must fill: a bad tag is the caller's to fix now, not at the first document
            docx_render.fill(out, {}, self.policy)
            self._send_with(out, DOCX_TYPE, done)
        except ValueError:
            self._send(400, b"body: not JSON")
        except (docx_edit.BadRequest, docx_render.BadTemplate, pdf_stamp.BadStamp, Refused) as e:
            self._send(400, f"{path}: {e}".encode())
        except Exception as e:
            LOG.exception("%s failed", path)
            self._send(500, f"{path} failed: {type(e).__name__}".encode())

    def _seal(self, body):
        """`/pdf/seal`: the PDF in the body sealed with the platform's certificate (pdf_seal.py), what was
        done in `X-Result`. 501 when this environment has no certificate: the caller keeps the PDF as it is."""
        if self.sealer is None:
            return self._send(501, b"seal: no certificate on this environment (PDF_SEAL_P12)")
        import pdf_seal

        try:
            with self.slots:
                pdf, result = self.sealer.seal(body)
        except pdf_seal.BadPdf as e:
            return self._send(400, f"seal: {e}".encode())
        except Exception as e:
            LOG.exception("seal failed")
            return self._send(500, f"seal failed: {type(e).__name__}".encode())
        self._send_with(pdf, "application/pdf", result)

    def _docx(self, body):
        """Word templates have their own converters (docx_render.Converter), so a long agreement
        never holds up the HTML renders (receipts, cost sheets)."""
        import docx_render

        if self.converter is None:
            Handler.converter = docx_render.Converter.from_env()
        try:
            pdf = docx_render.render(body, self.policy, self.converter)
        except (docx_render.BadTemplate, Refused) as e:
            return self._send(400, f"docx: {e}".encode())
        except docx_render.Busy as e:
            return self._send(504, f"docx: {e}".encode())
        except Exception as e:
            LOG.exception("docx render failed")
            return self._send(500, f"docx render failed: {type(e).__name__}".encode())
        self._send(200, pdf, "application/pdf")


def main():
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    # WeasyPrint reports each refused or missing resource as a warning; keep them visible.
    logging.getLogger("weasyprint").setLevel(logging.WARNING)
    Handler.policy = Policy.from_env()
    Handler.max_body = int(os.environ.get("MAX_BODY_BYTES", str(50 * 1024 * 1024)))
    Handler.slots = threading.BoundedSemaphore(int(os.environ.get("MAX_CONCURRENT", "2")))
    import docx_render

    Handler.converter = docx_render.Converter.from_env()
    if os.environ.get("PDF_SEAL_P12", "").strip():  # only then is pdf_seal (and pyHanko) loaded at start
        import pdf_seal

        Handler.sealer = pdf_seal.Sealer.from_env()  # None: no seal on this environment (/pdf/seal answers 501)
    port = int(os.environ.get("PORT", "8120"))
    LOG.info("listening on %d (files: %s, allowed hosts: %s)", port, Handler.policy.files_url or "none", sorted(Handler.policy.allowed_hosts) or "none")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
