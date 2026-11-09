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


class ClientCertificateTest(unittest.TestCase):
    """A client's own certificate: issued by the platform's private CA, or uploaded (inspect), then used to seal."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.ca = os.path.join(self.dir.name, "ca.p12")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Seal CA")])
        now = datetime.datetime.now(datetime.timezone.utc)
        self.ca_cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
                        .not_valid_after(now + datetime.timedelta(days=3650))
                        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                        .sign(key, hashes.SHA256()))
        with open(self.ca, "wb") as f:
            f.write(pkcs12.serialize_key_and_certificates(b"ca", key, self.ca_cert, None, serialization.BestAvailableEncryption(b"capw")))
        self.env = {k: os.environ.pop(k) for k in list(os.environ) if k.startswith("PDF_SEAL_")}

    def tearDown(self):
        for k in [k for k in os.environ if k.startswith("PDF_SEAL_")]:
            del os.environ[k]
        os.environ.update(self.env)
        self.dir.cleanup()

    def test_no_ca_no_issuer(self):
        self.assertIsNone(pdf_seal.Issuer.from_env())

    def test_issue_inspect_and_seal_with_it(self):
        from asn1crypto import x509 as asn1_x509
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.sign.validation import validate_pdf_signature
        from pyhanko_certvalidator import ValidationContext

        os.environ.update(PDF_SEAL_CA_P12=self.ca, PDF_SEAL_CA_PASSWORD="capw")
        p12, password, info = pdf_seal.Issuer.from_env().issue("Fincity Homes Document Seal", "Fincity Homes")
        self.assertEqual((info["commonName"], info["organization"]), ("Fincity Homes Document Seal", "Fincity Homes"))
        self.assertIn("Test Seal CA", info["issuer"])
        self.assertTrue(info["canSign"] and not info["expired"] and not info["selfSigned"])
        self.assertEqual(pdf_seal.inspect(p12, password)["fingerprint"], info["fingerprint"])
        with self.assertRaises(pdf_seal.BadCertificate):
            pdf_seal.inspect(p12, "wrong")
        out, res = pdf_seal.Sealer.defaults_from_env().with_p12(p12, password).seal(_pdf())
        self.assertIn("Fincity Homes Document Seal", res["signer"])
        root = asn1_x509.Certificate.load(self.ca_cert.public_bytes(serialization.Encoding.DER))
        st = validate_pdf_signature(PdfFileReader(io.BytesIO(out)).embedded_signatures[0], ValidationContext(trust_roots=[root]))
        self.assertTrue(st.intact and st.valid and st.trusted, "chains to the platform CA")

    def test_expired_or_keyless_is_refused(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Old")])
        now = datetime.datetime.now(datetime.timezone.utc)
        old = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=30))
               .not_valid_after(now - datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
        p12 = pkcs12.serialize_key_and_certificates(b"o", key, old, None, serialization.BestAvailableEncryption(b"pw"))
        with self.assertRaisesRegex(pdf_seal.BadCertificate, "expired"):
            pdf_seal.inspect(p12, "pw")
        certonly = pkcs12.serialize_key_and_certificates(b"o", None, old, None, serialization.BestAvailableEncryption(b"pw"))
        with self.assertRaises(pdf_seal.BadCertificate):
            pdf_seal.inspect(certonly, "pw")


if __name__ == "__main__":
    unittest.main()
