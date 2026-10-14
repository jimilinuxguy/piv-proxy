"""Local-only NASA PIV mTLS session gateway. Not production authorization."""
import datetime
import html
import os
import secrets
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote
import redis
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID, NameOID

SESSION_TTL = 900
COOKIE_NAME = "piv_proxy_session"
STORE = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379/0"), decode_responses=True)

def validate_piv(encoded):
    cert = x509.load_pem_x509_certificate(unquote(encoded).encode("ascii"))
    now = datetime.datetime.now(datetime.timezone.utc)
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        raise ValueError("Certificate expired or not yet valid")
    eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
        raise ValueError("Certificate does not permit TLS client authentication")
    nasa_issuer = os.getenv("NASA_ISSUER", "NASA Operational CA")
    if not any(a.value == nasa_issuer for a in cert.issuer):
        raise ValueError("Certificate issuer is not NASA Operational CA")
    required = {x.strip() for x in os.getenv("REQUIRED_POLICY_OIDS", "").split(",") if x.strip()}
    if required:
        policies = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
        actual = {p.policy_identifier.dotted_string for p in policies}
        if not actual.intersection(required):
            raise ValueError("Missing approved PIV certificate policy")
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    subject = cn[0].value if cn else cert.subject.rfc4514_string()
    return subject, cert.fingerprint(hashes.SHA256()).hex()

def session_token(headers):
    jar = cookies.SimpleCookie()
    try:
        jar.load(headers.get("Cookie", ""))
    except cookies.CookieError:
        return None
    morsel = jar.get(COOKIE_NAME)
    return morsel.value if morsel else None

def session_identity(headers):
    token = session_token(headers)
    if not token or len(token) != 64:
        return None
    return STORE.get("session:" + token)

class Handler(BaseHTTPRequestHandler):
    def respond(self, status, body="", content_type="text/plain; charset=utf-8", headers=None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/healthz":
            return self.respond(200, "ok")
        if self.path == "/session":
            try:
                identity = session_identity(self.headers)
            except redis.RedisError:
                return self.respond(503, "Session store unavailable")
            if not identity:
                return self.respond(401, "PIV login required")
            return self.respond(200, "ok", headers={"X-Authenticated-User": identity})
        if self.path == "/login":
            if self.headers.get("X-PIV-Verified") != "SUCCESS":
                return self.respond(403, "PIV rejected: NGINX did not verify certificate")
            encoded = self.headers.get("X-PIV-Cert", "")
            if not encoded:
                return self.respond(403, "PIV rejected: missing client certificate")
            try:
                identity, fingerprint = validate_piv(encoded)
                token = secrets.token_hex(32)
                # A new random session is issued only after NGINX verified client mTLS.
                STORE.setex("session:" + token, SESSION_TTL, identity)
            except (ValueError, x509.ExtensionNotFound, redis.RedisError) as exc:
                return self.respond(403, "PIV rejected: " + str(exc))
            cookie = f"{COOKIE_NAME}={token}; Path=/; Max-Age={SESSION_TTL}; Secure; HttpOnly; SameSite=Lax"
            return self.respond(303, "", headers={"Set-Cookie": cookie, "Location": "https://localhost:8443/app/"})
        return self.respond(404, "Not found")

    def do_POST(self):
        if self.path != "/logout":
            return self.respond(404, "Not found")
        token = session_token(self.headers)
        try:
            if token:
                STORE.delete("session:" + token)
        except redis.RedisError:
            return self.respond(503, "Session store unavailable")
        cookie = f"{COOKIE_NAME}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax"
        return self.respond(303, "", headers={"Set-Cookie": cookie, "Location": "https://localhost:8443/"})

if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
