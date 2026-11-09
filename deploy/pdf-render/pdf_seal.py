"""pdf_seal: seal a finished PDF with the platform's document signing certificate (PAdES), plus a trusted
timestamp (RFC 3161) when a timestamp server is set.

The seal proves the file has not changed since the platform made it: any later edit shows as a broken
signature in a PDF reader, without asking the platform. It says nothing about who signed the form (that is
the form's own signature record and trail); it is the platform's seal over the finished file.

Optional. Configured only by the environment of this internal service, so the certificate never reaches a
database, a page or the core units:

    PDF_SEAL_P12            path of the PKCS#12 file (.p12 / .pfx): the certificate, its chain and its key
    PDF_SEAL_PASSWORD       its password (or PDF_SEAL_PASSWORD_FILE: a file holding it)
    PDF_SEAL_TSA_URL        optional: an RFC 3161 timestamp server (usually the CA's); without it the seal
                            carries the signing time of this machine only
    PDF_SEAL_REASON         optional: the reason shown in the reader (default below)
    PDF_SEAL_LOCATION       optional: the location shown in the reader

Without PDF_SEAL_P12, `Sealer.from_env()` is None and `/pdf/seal` answers 501, which the core reads as
"no seal on this environment": the PDF is stored as it is.
"""
from __future__ import annotations

import io
import logging
import os

LOG = logging.getLogger("pdf-render.seal")

DEFAULT_REASON = "Sealed by the platform: any change to this file after it was made breaks this seal."
FIELD = "PlatformSeal"


class BadPdf(Exception):
    """The body is not a PDF this service can seal."""


class Sealer:
    def __init__(self, signer, tsa_url: str = "", reason: str = DEFAULT_REASON, location: str = ""):
        self.signer = signer
        self.tsa_url = tsa_url
        self.reason = reason
        self.location = location
        cert = signer.signing_cert
        self.subject = cert.subject.human_friendly if cert is not None else ""

    @classmethod
    def from_env(cls) -> "Sealer | None":
        path = os.environ.get("PDF_SEAL_P12", "").strip()
        if not path:
            return None
        password = os.environ.get("PDF_SEAL_PASSWORD", "")
        pw_file = os.environ.get("PDF_SEAL_PASSWORD_FILE", "").strip()
        if pw_file:
            with open(pw_file, "rb") as f:
                password = f.read().decode("utf-8").strip()
        from pyhanko.sign import signers

        signer = signers.SimpleSigner.load_pkcs12(path, passphrase=password.encode("utf-8") if password else None)
        if signer is None:
            raise RuntimeError(f"PDF_SEAL_P12 {path}: the certificate or its key could not be read (wrong password?)")
        s = cls(signer, os.environ.get("PDF_SEAL_TSA_URL", "").strip(),
                os.environ.get("PDF_SEAL_REASON", "").strip() or DEFAULT_REASON, os.environ.get("PDF_SEAL_LOCATION", "").strip())
        LOG.info("seal: certificate %s, timestamp server %s", s.subject, s.tsa_url or "none")
        return s

    def seal(self, pdf: bytes) -> tuple[bytes, dict]:
        """The sealed PDF and what was done: {sealed, signer, timestamped}."""
        if not pdf.startswith(b"%PDF"):
            raise BadPdf("the body is not a PDF")
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        from pyhanko.sign import fields, signers, timestamps

        try:
            writer = IncrementalPdfFileWriter(io.BytesIO(pdf), strict=False)
        except Exception as e:  # a PDF pyHanko cannot read is the caller's to keep unsealed
            raise BadPdf(f"the PDF cannot be read: {type(e).__name__}") from e
        meta = signers.PdfSignatureMetadata(
            field_name=FIELD, reason=self.reason, location=self.location or None,
            subfilter=fields.SigSeedSubFilter.PADES, md_algorithm="sha256")
        stamper = timestamps.HTTPTimeStamper(self.tsa_url) if self.tsa_url else None
        out = signers.sign_pdf(writer, meta, signer=self.signer, timestamper=stamper)
        return out.getvalue(), {"sealed": True, "signer": self.subject, "timestamped": bool(stamper)}
