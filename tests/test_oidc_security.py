"""OIDC negative-path and key rollover regression tests."""
import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from app import oidc
from demo.server import verify

class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.first = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.second = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.path = self.root / "private.pem"
        self.previous = self.root / "previous"
        self.previous.mkdir()
        self.env = patch.dict(os.environ, {"OIDC_ISSUER":"https://localhost:8443",
            "OIDC_SIGNING_KEY_PATH":str(self.path), "OIDC_PREVIOUS_PUBLIC_KEYS_DIR":str(self.previous)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.write_key(self.first)
    def write_key(self, key):
        self.path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    def claims(self, **changes):
        import time
        values = {"iss":"https://localhost:8443","aud":"piv-demo","sub":"person:123",
                  "nonce":"expected","iat":int(time.time()),"exp":int(time.time())+300}
        values.update(changes)
        return values
    def test_signed_token_verification(self):
        token = oidc.jwt(self.claims())
        self.assertEqual(verify(token, oidc.jwks(), "expected")["sub"], "person:123")
    def test_reject_invalid_identity_claims(self):
        for changes in ({"iss":"https://attacker.invalid"}, {"aud":"other"},
                        {"nonce":"wrong"}, {"exp":0}, {"iat":9999999999}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                verify(oidc.jwt(self.claims(**changes)), oidc.jwks(), "expected")
    def test_reject_unsigned_and_modified_tokens(self):
        token = oidc.jwt(self.claims())
        head, body, signature = token.split(".")
        with self.assertRaises(Exception):
            verify(head+"."+body+"."+signature[:-2]+"xx", oidc.jwks(), "expected")
        payload = self.claims(sub="attacker")
        forged_body = oidc.b64(json.dumps(payload).encode())
        with self.assertRaises(Exception):
            verify(head+"."+forged_body+"."+signature, oidc.jwks(), "expected")
        unsigned_head = oidc.b64(b'{"alg":"none","kid":"none"}')
        with self.assertRaises(ValueError):
            verify(unsigned_head+"."+body+".", oidc.jwks(), "expected")
    def test_key_rollover_overlap(self):
        old_token = oidc.jwt(self.claims())
        old_pub = self.first.public_key().public_bytes(serialization.Encoding.PEM,
                                                         serialization.PublicFormat.SubjectPublicKeyInfo)
        (self.previous/"old.pem").write_bytes(old_pub)
        self.write_key(self.second)
        jwks = oidc.jwks()
        self.assertEqual(len(jwks["keys"]), 2)
        self.assertEqual(verify(old_token, jwks, "expected")["sub"], "person:123")
        self.assertEqual(verify(oidc.jwt(self.claims()), jwks, "expected")["sub"], "person:123")
        (self.previous/"old.pem").unlink()
        with self.assertRaises(ValueError):
            verify(old_token, oidc.jwks(), "expected")

if __name__ == "__main__":
    unittest.main()
