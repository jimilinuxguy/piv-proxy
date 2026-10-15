"""Standalone OIDC relying-party demo; never trusts proxy identity headers."""
import base64
import hashlib
import html
import json
import os
import secrets
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request, urlopen
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ISSUER = os.getenv("OIDC_ISSUER", "https://localhost:8443").rstrip("/")
BACKCHANNEL = os.getenv("OIDC_BACKCHANNEL", "http://app:8000").rstrip("/")
CLIENT = os.getenv("OIDC_DEMO_CLIENT_ID", "piv-demo")
CALLBACK = os.getenv("OIDC_DEMO_CALLBACK", "https://localhost:8445/callback")
PENDING, SESSIONS = {}, {}

def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

def verify(token, jwks, nonce):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed token")
    header, claims = json.loads(decode(parts[0])), json.loads(decode(parts[1]))
    if header.get("alg") != "RS256":
        raise ValueError("Unsupported signing algorithm")
    keys = [k for k in jwks["keys"] if k.get("kid") == header.get("kid") and k.get("kty") == "RSA" and k.get("alg") == "RS256"]
    if len(keys) != 1:
        raise ValueError("Unknown key")
    key = keys[0]
    pub = rsa.RSAPublicNumbers(int.from_bytes(decode(key["e"]), "big"), int.from_bytes(decode(key["n"]), "big")).public_key()
    pub.verify(decode(parts[2]), (parts[0] + "." + parts[1]).encode(), padding.PKCS1v15(), hashes.SHA256())
    now = int(time.time())
    if (claims.get("iss") != ISSUER or claims.get("aud") != CLIENT or claims.get("nonce") != nonce
        or not isinstance(claims.get("sub"), str) or not isinstance(claims.get("exp"), int)
        or claims["exp"] <= now or not isinstance(claims.get("iat"), int) or claims["iat"] > now + 30):
        raise ValueError("Invalid identity claims")
    return claims

def request_json(path, data=None):
    req = Request(BACKCHANNEL + path, data=urlencode(data).encode() if data is not None else None,
                  headers={"Content-Type":"application/x-www-form-urlencoded"} if data is not None else {})
    with urlopen(req, timeout=5) as response:
        return json.load(response)

def cookie_token(headers):
    jar = cookies.SimpleCookie()
    jar.load(headers.get("Cookie", ""))
    return jar["demo_oidc"].value if "demo_oidc" in jar else None

class Handler(BaseHTTPRequestHandler):
    def respond(self, status, body="", location=None, cookie=None):
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        if location:
            self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        now = time.time()
        for table in (PENDING, SESSIONS):
            for key, item in list(table.items()):
                if item["expires"] <= now:
                    table.pop(key, None)
        path = urlsplit(self.path).path
        if path == "/login":
            state, nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(48)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            PENDING[state] = {"nonce":nonce, "verifier":verifier, "expires":now+300}
            query = {"response_type":"code", "scope":"openid profile", "client_id":CLIENT, "redirect_uri":CALLBACK,
                     "state":state, "nonce":nonce, "code_challenge":challenge, "code_challenge_method":"S256"}
            return self.respond(303, location=ISSUER + "/authorize?" + urlencode(query))
        if path == "/callback":
            query = parse_qs(urlsplit(self.path).query)
            states, codes = query.get("state", []), query.get("code", [])
            if len(states) != 1 or len(codes) != 1:
                return self.respond(400, "Invalid callback")
            pending = PENDING.pop(states[0], None)
            if not pending or pending["expires"] <= now:
                return self.respond(400, "Expired login attempt")
            try:
                tokens = request_json("/token", {"grant_type":"authorization_code", "client_id":CLIENT,
                    "redirect_uri":CALLBACK, "code":codes[0], "code_verifier":pending["verifier"]})
                claims = verify(tokens["id_token"], request_json("/jwks.json"), pending["nonce"])
            except Exception:
                return self.respond(401, "OIDC token verification failed")
            sid = secrets.token_urlsafe(32)
            SESSIONS[sid] = {"claims":claims, "expires":min(now+900, claims["exp"])}
            return self.respond(303, location="/", cookie="demo_oidc="+sid+"; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=900")
        if path == "/":
            token = cookie_token(self.headers)
            record = SESSIONS.get(token)
            if not record:
                return self.respond(200, '<h2>OIDC demo application</h2><p>Independent OpenID Connect client</p><a href="/login">Sign in with CAC/PIV</a>')
            claims = record["claims"]
            return self.respond(200, "<h2>OIDC demo application</h2><p>Signed in: "+html.escape(str(claims.get("name","")))+"</p><p>Verified subject: "+html.escape(claims["sub"])+'</p><form method="POST" action="/logout"><button>Sign out</button></form>')
        return self.respond(404, "Not found")

    def do_POST(self):
        if self.path != "/logout":
            return self.respond(404, "Not found")
        SESSIONS.pop(cookie_token(self.headers), None)
        return self.respond(303, location="/", cookie="demo_oidc=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")

if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8001), Handler).serve_forever()
