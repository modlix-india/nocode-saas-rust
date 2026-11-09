"""Word templates: a .docx with Jinja tags, filled with the data and converted to PDF by LibreOffice.

`POST /docx/render` with JSON `{"file": "<files URL of the .docx>", "data": {...}}` answers
`application/pdf`. The file is read through the same `Policy` as HTML templates (files URLs only;
`data:` URLs are accepted too, for tests and previews of a file not yet saved).

Filling (docxtpl, Jinja in a sandbox):
- tags are `{{ al.unit.number }}`, `{%p if ... %}`, `{%tr for ... %}` (docxtpl's paragraph and
  table-row forms); a missing field renders as nothing, at any depth, as FreeMarker's `!` does;
- `{{ image(src, 30) }}` puts an image 30 mm wide where the tag is: `src` is a `data:image/png` or
  `data:image/jpeg` URL (a drawn signature) or a files URL; an empty `src` renders as nothing;
- the sandbox refuses attribute tricks (`''.__class__`), so a tenant's file cannot reach Python.

Converting: `soffice --headless --convert-to pdf`, at most `DOCX_CONCURRENT` (2) at a time, each with
its own LibreOffice profile, killed after `DOCX_TIMEOUT_SECONDS` (90). Fonts the file names but the
image lacks fall back by fontconfig (see fonts.conf: Bookman Old Style to URW Bookman, Calibri to
Carlito, Cambria to Caladea); fonts embedded in the .docx are used as they are.
"""

import base64
import io
import logging
import os
import queue
import re
import shutil
import signal
import subprocess
import tempfile
import time

LOG = logging.getLogger("pdf-render.docx")

DATA_IMAGE = re.compile(r"^data:image/(png|jpe?g);base64,(.+)$", re.S)
MAX_IMAGE_BYTES = 5 * 1024 * 1024


class BadTemplate(Exception):
    """The file is not a Word template we can fill (bad zip, bad tag, refused tag): a 400."""


class Busy(Exception):
    """Conversion did not finish in time: a 504."""


def _read_file(url, policy):
    if url.startswith("data:"):
        m = re.match(r"^data:[^;,]*;base64,(.+)$", url, re.S)
        if not m:
            raise BadTemplate("file: only base64 data URLs are read")
        return base64.b64decode(m.group(1))
    return policy.fetch(url)["string"]


def _image_bytes(src, policy):
    m = DATA_IMAGE.match(src)
    if m:
        raw = base64.b64decode(m.group(2))
    else:
        raw = policy.fetch(src)["string"]
    if len(raw) > MAX_IMAGE_BYTES:
        raise BadTemplate("image larger than 5 MiB")
    return raw


def _sandbox_class():
    from jinja2.exceptions import SecurityError
    from jinja2.sandbox import SandboxedEnvironment

    class Sandbox(SandboxedEnvironment):
        """The sandbox, refusing out loud: with lenient missing fields, Jinja's own sandbox would
        render an unsafe attribute (`''.__class__`) as nothing; here it fails the render."""

        def unsafe_undefined(self, obj, attribute):
            raise SecurityError(f"{attribute!r} is not allowed in a template")

    return Sandbox


def fill(docx_bytes, data, policy):
    """The .docx with its tags filled (bytes)."""
    from docx.shared import Mm
    from docxtpl import DocxTemplate, InlineImage
    from jinja2 import ChainableUndefined, TemplateError

    _Sandbox = _sandbox_class()

    try:
        tpl = DocxTemplate(io.BytesIO(docx_bytes))
        tpl.init_docx()
    except Exception as e:
        raise BadTemplate(f"not a Word file: {type(e).__name__}") from None

    def image(src, width_mm=30, height_mm=None):
        if not src or not isinstance(src, str):
            return ""
        raw = _image_bytes(src, policy)
        return InlineImage(tpl, io.BytesIO(raw), width=Mm(float(width_mm)),
                           height=Mm(float(height_mm)) if height_mm else None)

    env = _Sandbox(autoescape=True, undefined=ChainableUndefined)
    env.globals["image"] = image
    try:
        tpl.render(data or {}, env)
    except TemplateError as e:
        raise BadTemplate(f"template: {e}") from None
    out = io.BytesIO()
    tpl.save(out)
    return out.getvalue()


class Converter:
    """LibreOffice, a few at a time, each with its own profile directory."""

    def __init__(self, concurrent=2, timeout=90.0, soffice="soffice"):
        self.timeout = timeout
        self.soffice = soffice
        self.profiles = queue.Queue()
        root = tempfile.mkdtemp(prefix="lo-profiles-")
        for i in range(max(1, concurrent)):
            self.profiles.put(os.path.join(root, str(i)))

    @classmethod
    def from_env(cls):
        return cls(concurrent=int(os.environ.get("DOCX_CONCURRENT", "2")),
                   timeout=float(os.environ.get("DOCX_TIMEOUT_SECONDS", "90")))

    def to_pdf(self, docx_bytes):
        try:
            profile = self.profiles.get(timeout=self.timeout)
        except queue.Empty:
            raise Busy("no converter free") from None
        work = tempfile.mkdtemp(prefix="docx-")
        try:
            src = os.path.join(work, "doc.docx")
            with open(src, "wb") as f:
                f.write(docx_bytes)
            cmd = [self.soffice, f"-env:UserInstallation=file://{profile}", "--headless", "--norestore",
                   "--nologo", "--nolockcheck", "--convert-to", "pdf", "--outdir", work, src]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env={**os.environ, "HOME": work}, start_new_session=True)
            try:
                _, err = proc.communicate(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.communicate()
                raise Busy(f"conversion took longer than {self.timeout:.0f} s") from None
            pdf_path = os.path.join(work, "doc.pdf")
            if proc.returncode != 0 or not os.path.exists(pdf_path):
                raise BadTemplate(f"conversion failed: {err.decode(errors='replace')[-200:]}")
            with open(pdf_path, "rb") as f:
                return f.read()
        finally:
            shutil.rmtree(work, ignore_errors=True)
            self.profiles.put(profile)


def render(body, policy, converter):
    """`POST /docx/render`: the request's JSON body as a PDF."""
    import json

    try:
        req = json.loads(body)
    except ValueError:
        raise BadTemplate("body: not JSON") from None
    if not isinstance(req, dict) or not isinstance(req.get("file"), str) or not req["file"]:
        raise BadTemplate("body: `file` (the .docx URL) is required")
    data = req.get("data") or {}
    if not isinstance(data, dict):
        raise BadTemplate("body: `data` must be an object")
    started = time.monotonic()
    filled = fill(_read_file(req["file"], policy), data, policy)
    t_fill = time.monotonic()
    pdf = converter.to_pdf(filled)
    LOG.info("docx filled in %.0f ms, converted in %.0f ms (%d bytes of PDF)",
             (t_fill - started) * 1000, (time.monotonic() - t_fill) * 1000, len(pdf))
    return pdf
