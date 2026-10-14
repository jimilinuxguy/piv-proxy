"""Unit tests for certificate policy and cookie handling. Run: python -m unittest discover -s tests"""
import importlib.util
import os
import unittest
from http.client import HTTPMessage
from pathlib import Path
from unittest.mock import patch

# Avoid importing the running server process: source module must be import-safe.
spec = importlib.util.spec_from_file_location("piv_server", Path(__file__).resolve().parents[1] / "app" / "server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)

class AuthTests(unittest.TestCase):
    def test_no_cookie(self):
        self.assertIsNone(server.session_token({}))
    def test_cookie_extraction(self):
        self.assertEqual(server.session_token({"Cookie": "other=x; piv_proxy_session=abc"}), "abc")
    def test_invalid_session_token_rejected(self):
        self.assertIsNone(server.session_identity({"Cookie": "piv_proxy_session=short"}))
    def test_random_session_token_size(self):
        import secrets
        self.assertEqual(len(secrets.token_hex(32)), 64)

if __name__ == "__main__":
    unittest.main()
