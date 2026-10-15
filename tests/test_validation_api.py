"""Session validation API tests."""
import importlib.util
import os
import json
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("piv_api_server", Path(__file__).resolve().parents[1] / "app" / "server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)

TOKEN = "a" * 64

class FakeStore:
    def __init__(self, identity=None, ttl=500):
        self.identity = json.dumps(server.session_claims(identity, 'b' * 64)) if identity is not None else None
        self.remaining = ttl
    def get(self, key):
        return self.identity
    def ttl(self, key):
        return self.remaining

class ValidationAPITests(unittest.TestCase):
    def validate(self, key="test-secret", token=TOKEN, identity="Example User", ttl=500):
        headers = {"Authorization": "Bearer " + key, "Cookie": "piv_proxy_session=" + token}
        with patch.dict(os.environ, {"PIV_VALIDATION_API_KEY": "test-secret"}), patch.object(server, "STORE", FakeStore(identity, ttl)):
            return server.validate_api(headers)

    def test_success(self):
        self.assertEqual(self.validate(), (200, {"authenticated": True, "identity": "Example User", "subject_id": "sha256:" + "b" * 64, "certificate_sha256": "b" * 64, "auth_method": "piv", "expires_in": 500}))

    def test_bad_api_key(self):
        self.assertEqual(self.validate(key="wrong")[0], 403)

    def test_missing_api_key_configuration(self):
        with patch.dict(os.environ, {"PIV_VALIDATION_API_KEY": ""}):
            self.assertEqual(server.validate_api({"Authorization": "Bearer ", "Cookie": "piv_proxy_session=" + TOKEN})[0], 403)

    def test_expired_or_missing_session(self):
        self.assertEqual(self.validate(identity=None)[0], 401)
        self.assertEqual(self.validate(ttl=-2)[0], 401)

    def test_legacy_session_requires_reauthentication(self):
        with patch.dict(os.environ, {"PIV_VALIDATION_API_KEY": "test-secret"}), patch.object(server, "STORE", FakeStore("Example User")):
            server.STORE.identity = "Example User"
            status, result = server.validate_api({"Authorization": "Bearer test-secret", "Cookie": "piv_proxy_session=" + TOKEN})
            self.assertEqual(status, 401)
            self.assertEqual(result["error"], "reauthentication_required")

    def test_invalid_token(self):
        self.assertEqual(self.validate(token="bad")[0], 401)

if __name__ == "__main__":
    unittest.main()
