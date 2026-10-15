"""Additional OIDC integration contract regression tests."""
import hashlib
import json
import os
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import rsa
from app import oidc

class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            "example": {"redirect_uris":["https://app.example.test/callback"],
                        "post_logout_redirect_uris":["https://app.example.test/"],
                        "scopes":["openid", "profile"],
                        "token_endpoint_auth_method":"client_secret_post",
                        "client_secret":"long-random-test-secret"}
        }
        self.env = patch.dict(os.environ, {
            "OIDC_ENABLED":"true", "OIDC_ISSUER":"https://identity.example.test",
            "OIDC_CLIENTS_JSON":json.dumps(self.config),
            "PIV_MTLS_ORIGIN":"https://smartcard.example.test",
            "PIV_SUBJECT_MAP_JSON":json.dumps({"a"*64:"person:123"})})
        self.env.start()
        self.keypatch = patch.object(oidc, "signing_key", return_value=rsa.generate_private_key(public_exponent=65537, key_size=2048))
        self.keypatch.start()
    def tearDown(self):
        self.keypatch.stop()
        self.env.stop()
    def test_stable_subject_mapping(self):
        self.assertEqual(oidc.persistent_subject("a"*64), "person:123")
        self.assertEqual(oidc.persistent_subject("b"*64), "sha256:"+"b"*64)
    def test_confidential_client_secret(self):
        cfg = oidc.decode_clients()["example"]
        self.assertTrue(oidc.client_auth(cfg, {"client_secret":["long-random-test-secret"]}))
        self.assertFalse(oidc.client_auth(cfg, {"client_secret":["incorrect"]}))
        self.assertFalse(oidc.client_auth(cfg, {}))
    def test_discovery_and_origins(self):
        discovery = oidc.discovery()
        self.assertEqual(discovery["issuer"], "https://identity.example.test")
        self.assertEqual(discovery["end_session_endpoint"], "https://identity.example.test/oidc/logout")
        self.assertEqual(oidc.login_origin(), "https://smartcard.example.test")
    def test_scope_restriction(self):
        verifier = "A"*43
        params = {"client_id":["example"],"redirect_uri":["https://app.example.test/callback"],
                  "state":["state"],"nonce":["nonce"],"code_challenge":[oidc.b64(hashlib.sha256(verifier.encode()).digest())],
                  "code_challenge_method":["S256"],"response_type":["code"],"scope":["openid email"]}
        with self.assertRaises(ValueError):
            oidc.check_authorize(params)
        params["scope"] = ["openid profile"]
        self.assertEqual(oidc.check_authorize(params)["scope"], "openid profile")

if __name__ == "__main__":
    unittest.main()
