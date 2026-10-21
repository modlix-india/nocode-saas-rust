"""pdf-render: HTML to PDF with WeasyPrint, for core's TemplateToPdf and the template PDF preview.

An internal service (no host port, reached only by core-exec and core-editor on the compose
network). It never fetches what a template names on its own:

- `data:` URLs are read in place;
- a URL whose path is a files URL (`/api/files/static/file/<path>` or
  `/api/files/secured/file/<path>`, on any host, relative or absolute) is read from the files
  service's internal route (`FILES_URL` + `/api/files/internal/<static|secured>/file?filePath=`),
  as Java's FileServerStreamFactory did for secured files; the host in the template is ignored;
- an `https` URL on a host listed in `ALLOWED_HOSTS` (exact names, empty by default) is fetched
  as is, with no redirects;
- anything else (`file:`, other hosts, IP addresses, metadata endpoints) is refused, and
  WeasyPrint leaves that resource out.

Every fetch has a timeout and a size cap. Endpoints: `POST /render` (the HTML as the body,
UTF-8) answers `application/pdf`; `GET /healthz` answers `ok`.

Environment: `PORT` (8120), `FILES_URL` (empty: files URLs are refused too), `ALLOWED_HOSTS`,
`MAX_BODY_BYTES` (50 MiB), `FETCH_TIMEOUT_SECONDS` (10), `FETCH_MAX_BYTES` (20 MiB),
`MAX_CONCURRENT` (2), `LOG_LEVEL` (INFO).
"""

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
    def __init__(self, files_url="", allowed_hosts=(), timeout=10.0, max_bytes=20 * 1024 * 1024):
        self.files_url = files_url.rstrip("/")
        self.allowed_hosts = {h.strip().lower() for h in allowed_hosts if h.strip()}
        self.timeout = timeout
        self.max_bytes = max_bytes

    @classmethod
    def from_env(cls):
        return cls(
            files_url=os.environ.get("FILES_URL", ""),
            allowed_hosts=os.environ.get("ALLOWED_HOSTS", "").split(","),
            timeout=float(os.environ.get("FETCH_TIMEOUT_SECONDS", "10")),
            max_bytes=int(os.environ.get("FETCH_MAX_BYTES", str(20 * 1024 * 1024))),
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
        if u.scheme == "https" and host in self.allowed_hosts and u.port in (None, 443):
            return url
        raise Refused(f"host {host or '(none)'} refused")

    def fetch(self, url):
        """WeasyPrint's `url_fetcher`."""
        target = self.target(url)
        if target is None:
            from weasyprint.urls import default_url_fetcher

            return default_url_fetcher(url)
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
        return result


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
        if self.path != "/render":
            return self._send(404, b"not found")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._send(411, b"Content-Length required")
        if length > self.max_body:
            return self._send(413, b"body too large")
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


def main():
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    # WeasyPrint reports each refused or missing resource as a warning; keep them visible.
    logging.getLogger("weasyprint").setLevel(logging.WARNING)
    Handler.policy = Policy.from_env()
    Handler.max_body = int(os.environ.get("MAX_BODY_BYTES", str(50 * 1024 * 1024)))
    Handler.slots = threading.BoundedSemaphore(int(os.environ.get("MAX_CONCURRENT", "2")))
    port = int(os.environ.get("PORT", "8120"))
    LOG.info("listening on %d (files: %s, allowed hosts: %s)", port, Handler.policy.files_url or "none", sorted(Handler.policy.allowed_hosts) or "none")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
