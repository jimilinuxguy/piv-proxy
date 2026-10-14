"""Offline issuer-agnostic CRL validation tests."""
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

spec = importlib.util.spec_from_file_location("piv_server", Path(__file__).resolve().parents[1] / "app" / "server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


class MultiIssuerTests(unittest.TestCase):
    def test_selects_matching_issuer_crl_and_rejects_revocation(self):
        now = dt.datetime.now(dt.timezone.utc)
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            issuer_pems = []
            leafs = []
            for label, revoked in (("Agency A", False), ("Agency B", True)):
                key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])
                issuer = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                          .public_key(key.public_key()).serial_number(x509.random_serial_number())
                          .not_valid_before(now - dt.timedelta(days=1))
                          .not_valid_after(now + dt.timedelta(days=10))
                          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                              key_encipherment=False, data_encipherment=False, key_agreement=False,
                              key_cert_sign=True, crl_sign=True, encipher_only=False,
                              decipher_only=False), critical=True)
                          .sign(key, hashes.SHA256()))
                issuer_pems.append(issuer.public_bytes(serialization.Encoding.PEM))
                leaf = (x509.CertificateBuilder().subject_name(x509.Name([
                            x509.NameAttribute(NameOID.COMMON_NAME, "Test User")]))
                        .issuer_name(name).public_key(key.public_key()).serial_number(1234)
                        .not_valid_before(now - dt.timedelta(days=1))
                        .not_valid_after(now + dt.timedelta(days=10))
                        .sign(key, hashes.SHA256()))
                leafs.append(leaf)
                builder = (x509.CertificateRevocationListBuilder().issuer_name(name)
                           .last_update(now - dt.timedelta(hours=1))
                           .next_update(now + dt.timedelta(days=1)))
                if revoked:
                    builder = builder.add_revoked_certificate(
                        x509.RevokedCertificateBuilder().serial_number(1234)
                        .revocation_date(now - dt.timedelta(hours=2)).build())
                (directory / (label.replace(" ", "-") + ".crl")).write_bytes(
                    builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
            bundle = directory / "issuers.pem"
            bundle.write_bytes(b"".join(issuer_pems))
            with patch.object(server, "ISSUER_PATH", bundle), patch.object(server, "CRL_DIRECTORY", directory):
                server.check_revocation(leafs[0], now)
                with self.assertRaisesRegex(ValueError, "revoked"):
                    server.check_revocation(leafs[1], now)


if __name__ == "__main__":
    unittest.main()
