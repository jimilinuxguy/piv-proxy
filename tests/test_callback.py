"""Post-auth callback validation tests."""
import importlib.util
import os
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("piv_callback_server", Path(__file__).resolve().parents[1] / "app" / "server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)

class CallbackTests(unittest.TestCase):
    def test_default(self):
        self.assertEqual(server.callback_url("/login"), "https://localhost:8443/app/")

    def test_relative(self):
        self.assertEqual(server.callback_url("/login?return_to=%2Fapp%2Fdashboard"), "https://localhost:8443/app/dashboard")

    def test_allowlisted_origin(self):
        with patch.dict(os.environ, {"PIV_CALLBACK_ALLOWED_ORIGINS": "https://localhost:8443,https://localhost:3000"}):
            self.assertEqual(server.callback_url("/login?return_to=https%3A%2F%2Flocalhost%3A3000%2Fdashboard"), "https://localhost:3000/dashboard")

    def test_rejected_callbacks(self):
        for url in [
            "https://evil.example/", "http://localhost:3000/", "//evil.example/",
            "https://localhost:8443@evil.example/", "https://localhost:8443/#fragment",
            "/\\evil.example/", "javascript:alert(1)",
        ]:
            from urllib.parse import quote
            with self.subTest(url=url), self.assertRaises(ValueError):
                server.callback_url("/login?return_to=" + quote(url, safe=""))

if __name__ == "__main__":
    unittest.main()
