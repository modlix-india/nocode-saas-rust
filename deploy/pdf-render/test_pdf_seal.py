"""pdf_seal: a PDF sealed with a throwaway self-signed certificate is intact and covers the whole file; one
changed byte breaks it; no certificate means no sealer.

    python -m unittest test_pdf_seal
"""
import datetime
import io
import os
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

import pdf_seal


def _p12(path, password):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Document Seal")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))
    with open(path, "wb") as f:
        f.write(pkcs12.serialize_key_and_certificates(b"seal", key, cert, None, serialization.BestAvailableEncryption(password)))
    return cert


def _pdf():
    from pypdf import PdfWriter

    w = PdfWriter()
    w.add_blank_page(width=595, height=842)
    out = io.BytesIO()
    w.write(out)
    return out.getvalue()


class SealTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.p12 = os.path.join(self.dir.name, "seal.p12")
        self.cert = _p12(self.p12, b"pw")
        self.env = {k: os.environ.pop(k) for k in list(os.environ) if k.startswith("PDF_SEAL_")}

    def tearDown(self):
        for k in [k for k in os.environ if k.startswith("PDF_SEAL_")]:
            del os.environ[k]
        os.environ.update(self.env)
        self.dir.cleanup()

    def test_no_certificate_no_sealer(self):
        self.assertIsNone(pdf_seal.Sealer.from_env())

    def test_sealed_intact_and_tamper_breaks_it(self):
        from pyhanko.keys import load_cert_from_pemder  # noqa: F401  (pyHanko present)
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.sign.validation import validate_pdf_signature
        from pyhanko_certvalidator import ValidationContext
        from asn1crypto import x509 as asn1_x509

        os.environ.update(PDF_SEAL_P12=self.p12, PDF_SEAL_PASSWORD="pw")
        s = pdf_seal.Sealer.from_env()
        self.assertIn("Test Document Seal", s.subject)
        out, res = s.seal(_pdf())
        self.assertEqual(res, {"sealed": True, "signer": s.subject, "timestamped": False})
        root = asn1_x509.Certificate.load(self.cert.public_bytes(serialization.Encoding.DER))
        vc = ValidationContext(trust_roots=[root])
        st = validate_pdf_signature(PdfFileReader(io.BytesIO(out)).embedded_signatures[0], vc)
        self.assertTrue(st.intact and st.valid)
        i = out.find(b"/MediaBox")
        bad = out[:i] + b"/MediaBoy" + out[i + 9:]
        st2 = validate_pdf_signature(PdfFileReader(io.BytesIO(bad), strict=False).embedded_signatures[0], vc)
        self.assertFalse(st2.intact)

    def test_not_a_pdf(self):
        os.environ.update(PDF_SEAL_P12=self.p12, PDF_SEAL_PASSWORD="pw")
        with self.assertRaises(pdf_seal.BadPdf):
            pdf_seal.Sealer.from_env().seal(b"hello")


if __name__ == "__main__":
    unittest.main()
