"""OIDC PKCE, client allowlist, one-time code, RS256 signature tests."""
import base64
import hashlib
import json
import os
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from app import oidc

VERIFIER = "A" * 43
CHALLENGE = oidc.b64(hashlib.sha256(VERIFIER.encode()).digest())
CLIENTS = {"demo-client": ["https://remote.example/callback"]}

class Store:
    def __init__(self):
        self.data = {}
    def setex(self, key, ttl, value):
        self.data[key] = value
    def get(self, key):
        return self.data.get(key)
    def getdel(self, key):
        return self.data.pop(key, None)
    def ttl(self, key):
        return 500 if key in self.data else -2

class OIDCTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"OIDC_ENABLED":"true", "OIDC_ISSUER":"https://localhost:8443",
            "OIDC_CLIENTS_JSON":json.dumps(CLIENTS)})
        self.env.start()
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.keypatch = patch.object(oidc, "signing_key", return_value=self.key)
        self.keypatch.start()
        self.store = Store()
        self.params = {"client_id":["demo-client"], "redirect_uri":["https://remote.example/callback"],
                       "state":["random-state"], "nonce":["random-nonce"], "code_challenge":[CHALLENGE],
                       "code_challenge_method":["S256"], "response_type":["code"], "scope":["openid"]}
    def tearDown(self):
        self.keypatch.stop()
        self.env.stop()
    def test_unregistered_redirect_rejected(self):
        self.params["redirect_uri"] = ["https://evil.example/callback"]
        with self.assertRaises(ValueError):
            oidc.create_request(self.store, self.params)
    def test_pkce_exchange_and_replay(self):
        request_id = oidc.create_request(self.store, self.params)
        self.store.setex("session:"+"a"*64, 900, json.dumps({"subject_id":"sha256:abc","identity":"Example User"}))
        redirect = oidc.authorize_from_session(self.store, request_id, "a"*64)
        from urllib.parse import urlsplit, parse_qs
        code = parse_qs(urlsplit(redirect).query)["code"][0]
        form = {"grant_type":["authorization_code"], "code":[code], "client_id":["demo-client"],
                "redirect_uri":["https://remote.example/callback"], "code_verifier":[VERIFIER]}
        with self.assertRaises(ValueError):
            oidc.authorize_from_session(self.store, request_id, "a"*64)
        bad = dict(form, code_verifier=["B"*43])
        with self.assertRaises(ValueError):
            oidc.exchange_code(self.store, bad)
        result = oidc.exchange_code(self.store, form)
        self.assertIn("id_token", result)
        with self.assertRaises(ValueError):
            oidc.exchange_code(self.store, form)
    def test_signed_id_token(self):
        token = oidc.jwt({"iss":oidc.issuer(), "sub":"sha256:abc"})
        header, body, signature = token.split(".")
        signing_input = (header+"."+body).encode()
        sig = base64.urlsafe_b64decode(signature+"="*(-len(signature)%4))
        self.key.public_key().verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())

if __name__ == "__main__":
    unittest.main()
