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

A client's own certificate (per app, in the client's Settings; the core keeps it encrypted and sends it only for
one seal): `/pdf/seal` with a JSON body {pdf, p12, password} (base64 for the files) seals with it instead.
`/seal/inspect` reads an uploaded .p12 (subject, issuer, validity, fingerprint; refuses one that cannot sign or
has expired); `/seal/issue` makes a client a certificate signed by the platform's private CA
(PDF_SEAL_CA_P12, PDF_SEAL_CA_PASSWORD or _FILE; 501 without it).
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

    def with_p12(self, p12: bytes, password: str) -> "Sealer":
        """The same seal settings (timestamp server, reason, location) with a client's own certificate."""
        from pyhanko.sign import signers

        try:
            signer = signers.SimpleSigner.load_pkcs12_data(p12, other_certs=[], passphrase=password.encode("utf-8") if password else None)
        except Exception as e:
            raise BadCertificate(f"the certificate cannot be read: {type(e).__name__}") from e
        if signer is None or signer.signing_cert is None:
            raise BadCertificate("the certificate or its key cannot be read (wrong password?)")
        return Sealer(signer, self.tsa_url, self.reason, self.location)

    @classmethod
    def defaults_from_env(cls) -> "Sealer":
        """A sealer without a platform certificate, for sealing with a client's own (with_p12)."""
        s = cls.__new__(cls)
        s.signer, s.subject = None, ""
        s.tsa_url = os.environ.get("PDF_SEAL_TSA_URL", "").strip()
        s.reason = os.environ.get("PDF_SEAL_REASON", "").strip() or DEFAULT_REASON
        s.location = os.environ.get("PDF_SEAL_LOCATION", "").strip()
        return s


class BadCertificate(Exception):
    """A .p12 that cannot be read, has no key, cannot sign or has expired."""


def _secret(var: str) -> str:
    value = os.environ.get(var, "")
    path = os.environ.get(var + "_FILE", "").strip()
    if path:
        with open(path, "rb") as f:
            value = f.read().decode("utf-8").strip()
    return value


def inspect(p12: bytes, password: str) -> dict:
    """What a .p12 holds, for the core to show and to refuse a certificate that cannot seal: subject, issuer,
    validity, the SHA-256 fingerprint of the certificate, and whether it can sign now. Nothing secret."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import pkcs12

    try:
        key, cert, _chain = pkcs12.load_key_and_certificates(p12, password.encode("utf-8") if password else None)
    except Exception as e:
        raise BadCertificate("the file is not a .p12 / .pfx, or the password is wrong") from e
    if cert is None or key is None:
        raise BadCertificate("the file has no certificate with its private key")
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        can_sign = bool(ku.digital_signature or ku.content_commitment)
    except x509.ExtensionNotFound:
        can_sign = True
    now = datetime.datetime.now(datetime.timezone.utc)
    info = {
        "subject": cert.subject.rfc4514_string(),
        "commonName": next((a.value for a in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)), ""),
        "organization": next((a.value for a in cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)), ""),
        "issuer": cert.issuer.rfc4514_string(),
        "notBefore": cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%S"),
        "notAfter": cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%S"),
        "fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "selfSigned": cert.issuer == cert.subject,
        "canSign": can_sign,
        "expired": now > cert.not_valid_after_utc,
        "notYetValid": now < cert.not_valid_before_utc,
    }
    if not can_sign:
        raise BadCertificate("this certificate is not allowed to sign (key usage)")
    if info["expired"]:
        raise BadCertificate(f"this certificate expired on {info['notAfter']} (UTC)")
    return info


class Issuer:
    """The platform's private document-seal CA (PDF_SEAL_CA_P12 + PDF_SEAL_CA_PASSWORD or _FILE): it issues a
    client's own seal certificate, named after the client. Readers do not trust this CA unless told to, so such
    a seal protects the file but shows "validity unknown"; a certificate bought from a trusted CA (uploaded)
    shows the reader's green tick. Without PDF_SEAL_CA_P12 there is no Issuer and /seal/issue answers 501."""

    def __init__(self, ca_key, ca_cert):
        self.ca_key, self.ca_cert = ca_key, ca_cert

    @classmethod
    def from_p12(cls, data: bytes, password: str) -> "Issuer":
        from cryptography.hazmat.primitives.serialization import pkcs12

        try:
            key, cert, _ = pkcs12.load_key_and_certificates(data, password.encode("utf-8") if password else None)
        except Exception as e:
            raise BadCertificate("the platform CA cannot be read") from e
        if key is None or cert is None:
            raise BadCertificate("the platform CA has no certificate with its key")
        return cls(key, cert)

    @classmethod
    def from_env(cls) -> "Issuer | None":
        path = os.environ.get("PDF_SEAL_CA_P12", "").strip()
        if not path:
            return None
        from cryptography.hazmat.primitives.serialization import pkcs12

        password = _secret("PDF_SEAL_CA_PASSWORD")
        with open(path, "rb") as f:
            key, cert, _ = pkcs12.load_key_and_certificates(f.read(), password.encode("utf-8") if password else None)
        if key is None or cert is None:
            raise RuntimeError(f"PDF_SEAL_CA_P12 {path}: no certificate with its key")
        LOG.info("seal: issuing CA %s", cert.subject.rfc4514_string())
        return cls(key, cert)

    def issue(self, common_name: str, organization: str, days: int = 730) -> tuple[bytes, str, dict]:
        """A new key and certificate for one client, signed by the CA, as a .p12 under a new random password:
        (p12, password, inspect() of it)."""
        import datetime
        import secrets

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import pkcs12
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

        common_name = (common_name or "").strip()[:64]
        organization = (organization or "").strip()[:64]
        if not common_name:
            raise BadCertificate("a name for the certificate is required")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
        if organization:
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name(attrs)).issuer_name(self.ca_cert.subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=days))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=False,
                                             data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                             crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]), critical=False)
                .sign(self.ca_key, hashes.SHA256()))
        password = secrets.token_urlsafe(24)
        p12 = pkcs12.serialize_key_and_certificates(common_name.encode("utf-8"), key, cert, [self.ca_cert],
                                                    serialization.BestAvailableEncryption(password.encode("utf-8")))
        return p12, password, inspect(p12, password)
