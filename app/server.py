"""Local-only configurable PIV mTLS session gateway. Not production authorization."""
import datetime
import html
import json
import hmac
import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent))
import oidc
import os
import secrets
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit, parse_qs, quote
import redis
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID, NameOID

SESSION_TTL = 900
COOKIE_NAME = "piv_proxy_session"
STRICT = os.getenv("PIV_STRICT", "false").lower() == "true"
CRL_PATH = Path(os.getenv("PIV_CRL_PATH", "/app/pki/nasa-leaf.crl"))
ISSUER_PATH = Path(os.getenv("PIV_ISSUER_PATH", "/app/pki/nasa-operational.pem"))
CRL_DIRECTORY = Path(os.getenv("PIV_CRL_DIRECTORY", "/app/pki/crls"))
STORE = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379/0"), decode_responses=True)


def load_pem_certificates(data):
    import re
    return [x509.load_pem_x509_certificate(m.group(0)) for m in re.finditer(
        rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.S)]

def check_revocation(cert, now):
    """Fail closed unless a current, correctly signed issuer CRL covers the certificate."""
    try:
        issuers = load_pem_certificates(ISSUER_PATH.read_bytes())
        paths = (sorted(p for p in CRL_DIRECTORY.iterdir() if p.is_file() and
                        p.suffix.lower() in (".crl", ".der"))
                 if CRL_DIRECTORY.is_dir() else [CRL_PATH])
        crls = []
        for path in paths:
            data = path.read_bytes()
            crls.append(x509.load_pem_x509_crl(data) if b"-----BEGIN X509 CRL-----" in data
                        else x509.load_der_x509_crl(data))
    except (OSError, ValueError) as exc:
        raise ValueError("Revocation data unavailable or invalid") from exc
    candidates = [issuer for issuer in issuers if issuer.subject == cert.issuer]
    if not candidates:
        raise ValueError("Certificate issuer is not in the configured issuer bundle")
    for crl in crls:
        if crl.issuer != cert.issuer:
            continue
        if crl.next_update_utc is None or not (crl.last_update_utc <= now < crl.next_update_utc):
            continue
        try:
            crl.extensions.get_extension_for_class(x509.DeltaCRLIndicator)
            continue
        except x509.ExtensionNotFound:
            pass
        try:
            idp = crl.extensions.get_extension_for_class(x509.IssuingDistributionPoint).value
            if (idp.indirect_crl or idp.only_some_reasons or
                    idp.only_contains_attribute_certs or idp.only_contains_ca_certs):
                continue
        except x509.ExtensionNotFound:
            pass
        for issuer in candidates:
            try:
                usage = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
                if not usage.crl_sign:
                    continue
                issuer_ski = issuer.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
                cert_aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
                if cert_aki.key_identifier and cert_aki.key_identifier != issuer_ski.digest:
                    continue
                crl_aki = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
                if crl_aki.key_identifier and crl_aki.key_identifier != issuer_ski.digest:
                    continue
            except x509.ExtensionNotFound:
                pass
            if not crl.is_signature_valid(issuer.public_key()):
                continue
            if crl.get_revoked_certificate_by_serial_number(cert.serial_number):
                raise ValueError("PIV certificate is revoked")
            return
    raise ValueError("No current, valid issuer CRL for PIV certificate")

def validate_piv(encoded):
    cert = x509.load_pem_x509_certificate(unquote(encoded).encode("ascii"))
    now = datetime.datetime.now(datetime.timezone.utc)
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        raise ValueError("Certificate expired or not yet valid")
    eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
        raise ValueError("Certificate does not permit TLS client authentication")
    try:
        issuers = load_pem_certificates(ISSUER_PATH.read_bytes())
    except (OSError, ValueError) as exc:
        raise ValueError("Configured issuer bundle unavailable") from exc
    if not any(issuer.subject == cert.issuer for issuer in issuers):
        raise ValueError("Certificate issuer is not in the configured issuer bundle")
    required = {x.strip() for x in os.getenv("REQUIRED_POLICY_OIDS", "").split(",") if x.strip()}
    if STRICT and not required:
        raise ValueError("Strict mode requires approved PIV policy OIDs")
    if required:
        policies = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
        actual = {p.policy_identifier.dotted_string for p in policies}
        if not actual.intersection(required):
            raise ValueError("Missing approved PIV certificate policy")
    if STRICT:
        check_revocation(cert, now)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    subject = cn[0].value if cn else cert.subject.rfc4514_string()
    return subject, cert.fingerprint(hashes.SHA256()).hex()

DEFAULT_RETURN_URL = os.getenv("PIV_DEFAULT_RETURN_URL", "https://localhost:8443/app/")

def callback_url(request_path):
    """Only redirect to relative paths or explicitly approved HTTPS origins."""
    query = parse_qs(urlsplit(request_path).query, keep_blank_values=True)
    values = query.get("return_to", [])
    if not values:
        return DEFAULT_RETURN_URL
    if len(values) != 1:
        raise ValueError("Invalid callback URL")
    target = values[0]
    if not target or any(ord(c) < 32 or ord(c) == 127 for c in target) or chr(92) in target:
        raise ValueError("Invalid callback URL")
    parsed = urlsplit(target)
    if parsed.fragment or parsed.username or parsed.password:
        raise ValueError("Invalid callback URL")
    if target.startswith("/") and not target.startswith("//"):
        return os.getenv("PIV_PUBLIC_ORIGIN", "https://localhost:8443").rstrip("/") + target
    if parsed.scheme != "https" or not parsed.hostname or not parsed.netloc:
        raise ValueError("Callback must be HTTPS and explicitly allowed")
    allowed = {x.strip().rstrip("/") for x in
               os.getenv("PIV_CALLBACK_ALLOWED_ORIGINS", os.getenv("PIV_PUBLIC_ORIGIN", "https://localhost:8443")).split(",")
               if x.strip()}
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if origin not in allowed:
        raise ValueError("Callback origin not allowed")
    return target

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
    record = STORE.get("session:" + token)
    if not record:
        return None
    try:
        claims = json.loads(record)
    except (ValueError, TypeError):
        # Legacy sessions contain only the display name.
        return record
    if not isinstance(claims, dict):
        return None
    return claims.get("identity") if isinstance(claims.get("identity"), str) else None

def session_claims(identity, fingerprint):
    """Bind a session to the validated leaf certificate, not just its CN."""
    return {"identity": identity, "subject_id": oidc.persistent_subject(fingerprint),
            "certificate_sha256": fingerprint, "auth_method": "piv"}

def validate_api(headers):
    """Internal, shared-secret authenticated session introspection."""
    expected = os.getenv("PIV_VALIDATION_API_KEY", "")
    authorization = headers.get("Authorization", "")
    if not expected or not hmac.compare_digest(authorization, "Bearer " + expected):
        return 403, {"authenticated": False, "error": "forbidden"}
    token = session_token(headers)
    if not token or len(token) != 64 or any(c not in "0123456789abcdef" for c in token):
        return 401, {"authenticated": False}
    record = STORE.get("session:" + token)
    if not record:
        return 401, {"authenticated": False}
    try:
        claims = json.loads(record)
    except (ValueError, TypeError):
        # Do not assert a stable identifier for sessions issued by old code.
        return 401, {"authenticated": False, "error": "reauthentication_required"}
    if (not isinstance(claims, dict) or
            not isinstance(claims.get("identity"), str) or
            not isinstance(claims.get("certificate_sha256"), str) or
            len(claims["certificate_sha256"]) != 64 or
            any(c not in "0123456789abcdef" for c in claims["certificate_sha256"]) or
            claims.get("subject_id") != oidc.persistent_subject(claims["certificate_sha256"]) or
            claims.get("auth_method") != "piv"):
        return 401, {"authenticated": False}
    ttl = STORE.ttl("session:" + token)
    if ttl <= 0:
        return 401, {"authenticated": False}
    return 200, {"authenticated": True, **claims, "expires_in": ttl}

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
        route = urlsplit(self.path).path
        if route in ("/.well-known/openid-configuration", "/jwks.json"):
            try:
                if os.getenv("OIDC_ENABLED", "false").lower() != "true":
                    return self.respond(404, "Not found")
                payload = oidc.discovery() if route.startswith("/.well-known") else oidc.jwks()
                return self.respond(200, json.dumps(payload), "application/json")
            except (ValueError, OSError):
                return self.respond(503, "OIDC configuration unavailable")
        if route == "/authorize":
            try:
                request_id = oidc.create_request(STORE, parse_qs(urlsplit(self.path).query, keep_blank_values=True))
            except (ValueError, redis.RedisError, OSError) as exc:
                return self.respond(400, "Authorization request rejected")
            return self.respond(303, "", headers={"Location": oidc.login_origin() + "/login?oidc_request=" + quote(request_id)})
        if route == "/oidc/complete":
            try:
                request_id = parse_qs(urlsplit(self.path).query).get("id", [""])[0]
                destination = oidc.authorize_from_session(STORE, request_id, session_token(self.headers))
            except (ValueError, redis.RedisError, TypeError):
                return self.respond(401, "Authorization expired; restart CAC/PIV login")
            return self.respond(303, "", headers={"Location": destination})
        if route == "/oidc/logout":
            query = parse_qs(urlsplit(self.path).query)
            redirect = query.get("post_logout_redirect_uri", [""])[0]
            client_id = query.get("client_id", [""])[0]
            clients = oidc.decode_clients()
            allowed = clients.get(client_id, {}).get("post_logout_redirect_uris", [])
            if redirect and (redirect not in allowed or len(query.get("post_logout_redirect_uri", [])) != 1):
                return self.respond(400, "Unregistered post-logout redirect")
            if redirect and not client_id:
                return self.respond(400, "Client ID required")
            token = session_token(self.headers)
            if token:
                STORE.delete("session:" + token)
            cookie = f"{COOKIE_NAME}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax"
            return self.respond(303, "", headers={"Set-Cookie": cookie, "Location": redirect or oidc.issuer() + "/signed-out"})
        if route == "/userinfo":
            try:
                claims = oidc.userinfo(STORE, self.headers.get("Authorization", "")) if os.getenv("OIDC_ENABLED", "false").lower() == "true" else None
            except redis.RedisError:
                return self.respond(503, "Session store unavailable")
            return self.respond(200, json.dumps(claims), "application/json") if claims else self.respond(401, '{"error":"invalid_token"}', "application/json")
        if self.path == "/healthz":
            return self.respond(200, "ok")
        if self.path == "/api/v1/session/validate":
            try:
                status, result = validate_api(self.headers)
            except redis.RedisError:
                status, result = 503, {"authenticated": False, "error": "session_store_unavailable"}
            return self.respond(status, json.dumps(result), "application/json; charset=utf-8")
        if self.path == "/session":
            try:
                identity = session_identity(self.headers)
            except redis.RedisError:
                return self.respond(503, "Session store unavailable")
            if not identity:
                return self.respond(401, "PIV login required")
            return self.respond(200, "ok", headers={"X-Authenticated-User": identity})
        if urlsplit(self.path).path == "/login":
            if self.headers.get("X-PIV-Verified") != "SUCCESS":
                return self.respond(403, "PIV rejected: NGINX did not verify certificate")
            encoded = self.headers.get("X-PIV-Cert", "")
            if not encoded:
                return self.respond(403, "PIV rejected: missing client certificate")
            try:
                oidc_requests = parse_qs(urlsplit(self.path).query).get("oidc_request", [])
                if oidc_requests:
                    if len(oidc_requests) != 1 or not STORE.exists("oidc-request:" + oidc_requests[0]):
                        raise ValueError("OIDC authorization request expired")
                    destination = oidc.issuer() + "/oidc/complete?id=" + quote(oidc_requests[0])
                else:
                    destination = callback_url(self.path)
                identity, fingerprint = validate_piv(encoded)
                token = secrets.token_hex(32)
                # A new random session is issued only after NGINX verified client mTLS.
                STORE.setex("session:" + token, SESSION_TTL, json.dumps(session_claims(identity, fingerprint)))
            except (ValueError, x509.ExtensionNotFound, redis.RedisError) as exc:
                return self.respond(403, "PIV rejected: " + str(exc))
            cookie = f"{COOKIE_NAME}={token}; Path=/; Max-Age={SESSION_TTL}; Secure; HttpOnly; SameSite=Lax"
            return self.respond(303, "", headers={"Set-Cookie": cookie, "Location": destination})
        return self.respond(404, "Not found")

    def do_POST(self):
        if self.path == "/token":
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 8192 or self.headers.get("Content-Type", "").split(";")[0].strip() != "application/x-www-form-urlencoded":
                    return self.respond(400, '{"error":"invalid_request"}', "application/json")
                form = parse_qs(self.rfile.read(size).decode("utf-8"), keep_blank_values=True)
                payload = oidc.exchange_code(STORE, form)
                return self.respond(200, json.dumps(payload), "application/json")
            except (ValueError, UnicodeError, OSError):
                return self.respond(400, '{"error":"invalid_grant"}', "application/json")
            except redis.RedisError:
                return self.respond(503, '{"error":"temporarily_unavailable"}', "application/json")
        if self.path != "/logout":
            return self.respond(404, "Not found")
        token = session_token(self.headers)
        try:
            if token:
                STORE.delete("session:" + token)
        except redis.RedisError:
            return self.respond(503, "Session store unavailable")
        cookie = f"{COOKIE_NAME}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax"
        return self.respond(303, "", headers={"Set-Cookie": cookie, "Location": oidc.issuer() + "/signed-out"})

if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
