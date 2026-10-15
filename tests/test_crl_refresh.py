"""Offline tests for CRL signature, freshness, revocation, and fail-closed refreshing."""
import datetime as dt
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

spec = importlib.util.spec_from_file_location(
    "crl_update", Path(__file__).resolve().parents[1] / "scripts" / "update-crl.py")
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)
UTC = dt.timezone.utc


class CRLTests(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime.now(UTC)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Operational CA")])
        self.issuer = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                       .public_key(self.key.public_key()).serial_number(1)
                       .not_valid_before(self.now - dt.timedelta(days=2))
                       .not_valid_after(self.now + dt.timedelta(days=30))
                       .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                       .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False,
                                      key_agreement=False, key_cert_sign=True, crl_sign=True,
                                      encipher_only=False, decipher_only=False), critical=True)
                       .sign(self.key, hashes.SHA256()))
        self.pem = self.issuer.public_bytes(serialization.Encoding.PEM)

    def build_crl(self, stale=False, revoked=False, key=None):
        builder = (x509.CertificateRevocationListBuilder().issuer_name(self.issuer.subject)
                   .last_update(self.now - dt.timedelta(days=4 if stale else 1))
                   .next_update(self.now - dt.timedelta(days=1) if stale else self.now + dt.timedelta(days=5)))
        if revoked:
            entry = (x509.RevokedCertificateBuilder().serial_number(42)
                     .revocation_date(self.now - dt.timedelta(days=2)).build())
            builder = builder.add_revoked_certificate(entry)
        return builder.sign(key or self.key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    def test_fresh_and_revoked_entry(self):
        crl = updater.verify_crl(self.build_crl(revoked=True), self.pem, self.now)
        self.assertIsNotNone(crl.get_revoked_certificate_by_serial_number(42))
        self.assertIsNone(crl.get_revoked_certificate_by_serial_number(43))

    def test_expired_crl_rejected(self):
        with self.assertRaisesRegex(ValueError, "expired"):
            updater.verify_crl(self.build_crl(stale=True), self.pem, self.now)

    def test_wrong_signature_rejected(self):
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with self.assertRaisesRegex(ValueError, "signature"):
            updater.verify_crl(self.build_crl(key=other), self.pem, self.now)

    def test_unapproved_url_rejected_without_replacing_file(self):
        with tempfile.TemporaryDirectory() as td:
            issuer = Path(td) / "issuer.pem"
            crl = Path(td) / "crl"
            issuer.write_bytes(self.pem)
            crl.write_bytes(b"existing")
            with self.assertRaisesRegex(ValueError, "approved"):
                updater.refresh("http://example.com/crl", issuer, crl)
            self.assertEqual(crl.read_bytes(), b"existing")


if __name__ == "__main__":
    unittest.main()
