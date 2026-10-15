"""Local demonstration OIDC authorization-code + PKCE bridge. Not production IdP."""
import base64
import datetime
import hashlib
import json
import os
import secrets
import time
from urllib.parse import urlencode, urlsplit
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def decode_clients():
    """Allow legacy redirect arrays or structured, explicitly registered clients."""
    clients = json.loads(os.getenv("OIDC_CLIENTS_JSON", "{}"))
    if not isinstance(clients, dict):
        raise ValueError("Invalid OIDC client configuration")
    normalized = {}
    for client_id, config in clients.items():
        if isinstance(config, list):
            config = {"redirect_uris": config, "scopes": ["openid", "profile"], "token_endpoint_auth_method": "none"}
        if not isinstance(config, dict) or not isinstance(config.get("redirect_uris"), list):
            raise ValueError("Invalid OIDC client configuration")
        method = config.get("token_endpoint_auth_method", "none")
        if method not in ("none", "client_secret_post"):
            raise ValueError("Unsupported client authentication method")
        if method == "client_secret_post" and not config.get("client_secret"):
            raise ValueError("Confidential client requires a secret")
        normalized[client_id] = config
    return normalized

def login_origin():
    return os.getenv("PIV_MTLS_ORIGIN", "https://localhost:8444").rstrip("/")

def persistent_subject(fingerprint):
    """Optional administrator-provisioned certificate-to-person mapping.
    Unmapped certificates retain per-certificate subject IDs; never infer identity from CN.
    """
    mapping = json.loads(os.getenv("PIV_SUBJECT_MAP_JSON", "{}"))
    if not isinstance(mapping, dict):
        raise ValueError("Invalid subject mapping")
    value = mapping.get(fingerprint)
    if value is None:
        return "sha256:" + fingerprint
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError("Invalid mapped subject")
    return value

def client_auth(config, form):
    method = config.get("token_endpoint_auth_method", "none")
    secret = form.get("client_secret", [])
    if method == "none":
        return not secret
    return len(secret) == 1 and secrets.compare_digest(secret[0], config["client_secret"])


def issuer():
    value = os.getenv("OIDC_ISSUER", "").rstrip("/")
    if not value or urlsplit(value).scheme != "https" or not urlsplit(value).netloc or urlsplit(value).path not in ("", "/"):
        raise ValueError("OIDC_ISSUER must be a public HTTPS origin")
    return value

def signing_key():
    path = os.getenv("OIDC_SIGNING_KEY_PATH", "")
    if not path:
        raise ValueError("OIDC signing key not configured")
    key = serialization.load_pem_private_key(open(path, "rb").read(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise ValueError("OIDC requires RSA signing key of at least 2048 bits")
    return key

def jwks():
    pub = signing_key().public_key().public_numbers()
    size = (pub.n.bit_length() + 7) // 8
    return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "piv-oidc-1",
                      "n": b64(pub.n.to_bytes(size, "big")),
                      "e": b64(pub.e.to_bytes((pub.e.bit_length()+7)//8, "big"))}]}

def jwt(payload):
    head = b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "piv-oidc-1"}, separators=(",", ":")).encode())
    body = b64(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = (head + "." + body).encode("ascii")
    sig = signing_key().sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return head + "." + body + "." + b64(sig)

def discovery():
    base = issuer()
    return {"issuer": base, "authorization_endpoint": base + "/authorize",
            "token_endpoint": base + "/token", "jwks_uri": base + "/jwks.json",
            "userinfo_endpoint": base + "/userinfo",
            "response_types_supported": ["code"], "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["public"], "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile"], "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
            "end_session_endpoint": base + "/oidc/logout",
            "code_challenge_methods_supported": ["S256"]}

def check_authorize(params):
    if os.getenv("OIDC_ENABLED", "false").lower() != "true":
        raise ValueError("OIDC disabled")
    issuer()
    signing_key()
    clients = decode_clients()
    cid = params.get("client_id", [""])[0]
    redirect = params.get("redirect_uri", [""])[0]
    if len(params.get("client_id", [])) != 1 or len(params.get("redirect_uri", [])) != 1:
        raise ValueError("Invalid client parameters")
    if (urlsplit(redirect).scheme != "https" or not urlsplit(redirect).netloc or
            urlsplit(redirect).fragment or cid not in clients or redirect not in clients[cid]["redirect_uris"]):
        raise ValueError("Unregistered client or redirect URI")
    for name in ("state", "nonce", "code_challenge", "code_challenge_method", "response_type", "scope"):
        if len(params.get(name, [])) != 1:
            raise ValueError("Missing or duplicate " + name)
    scopes = params["scope"][0].split()
    if not set(scopes).issubset(set(clients[cid].get("scopes", ["openid", "profile"]))):
        raise ValueError("Scope not allowed")
    challenge = params["code_challenge"][0]
    if (params["response_type"][0] != "code" or "openid" not in params["scope"][0].split()
            or params["code_challenge_method"][0] != "S256" or len(challenge) != 43
            or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in challenge)
            or not params["state"][0] or not params["nonce"][0]):
        raise ValueError("Invalid OIDC authorization parameters")
    return {name: params[name][0] for name in ("client_id", "redirect_uri", "state", "nonce", "code_challenge", "scope")}

def create_request(store, params):
    data = check_authorize(params)
    request_id = secrets.token_urlsafe(32)
    store.setex("oidc-request:" + request_id, 300, json.dumps(data))
    return request_id

def authorize_from_session(store, request_id, cookie_token):
    if not request_id or not cookie_token or len(cookie_token) != 64:
        raise ValueError("Invalid authorization request or session")
    raw = store.get("oidc-request:" + request_id)
    if not raw:
        raise ValueError("Authorization request expired")
    data = json.loads(raw)
    check_authorize({**{k:[v] for k,v in data.items()},
                     "code_challenge_method":["S256"], "response_type":["code"]})
    session_raw = store.get("session:" + cookie_token)
    if not session_raw:
        raise ValueError("Session expired")
    claims = json.loads(session_raw)
    if not isinstance(claims, dict) or not claims.get("subject_id") or not claims.get("identity"):
        raise ValueError("PIV reauthentication required")
    if store.ttl("session:" + cookie_token) <= 0:
        raise ValueError("Session expired")
    # GETDEL prevents authorization request replay.
    if not store.getdel("oidc-request:" + request_id):
        raise ValueError("Authorization request already used")
    code = secrets.token_urlsafe(32)
    store.setex("oidc-code:" + code, 60, json.dumps({"request": data, "claims": claims, "auth_time": int(time.time())}))
    return data["redirect_uri"] + ("&" if "?" in data["redirect_uri"] else "?") + urlencode({"code":code, "state":data["state"]})

def exchange_code(store, form):
    if os.getenv("OIDC_ENABLED", "false").lower() != "true":
        raise ValueError("OIDC disabled")
    for name in ("grant_type", "code", "client_id", "redirect_uri", "code_verifier"):
        if len(form.get(name, [])) != 1:
            raise ValueError("Missing or duplicate " + name)
    clients = decode_clients()
    config = clients.get(form["client_id"][0])
    if not config or not client_auth(config, form):
        raise ValueError("Client authentication failed")
    if form["grant_type"][0] != "authorization_code":
        raise ValueError("Unsupported grant")
    code = form["code"][0]
    if len(code) > 256:
        raise ValueError("Invalid code")
    raw = store.getdel("oidc-code:" + code)
    if not raw:
        raise ValueError("Invalid or expired code")
    data = json.loads(raw)
    req = data["request"]
    if form["client_id"][0] != req["client_id"] or form["redirect_uri"][0] != req["redirect_uri"]:
        raise ValueError("Client mismatch")
    verifier = form["code_verifier"][0]
    if not (43 <= len(verifier) <= 128) or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~" for c in verifier):
        raise ValueError("Invalid PKCE verifier")
    if not secrets.compare_digest(b64(hashlib.sha256(verifier.encode()).digest()), req["code_challenge"]):
        raise ValueError("PKCE mismatch")
    now = int(time.time())
    claims = data["claims"]
    subject = claims["subject_id"]
    scopes = req.get("scope", "openid").split()
    token_claims = {"iss":issuer(), "sub":subject, "aud":req["client_id"],
                 "iat":now, "exp":now+300, "auth_time":data["auth_time"],
                 "nonce":req["nonce"], "amr":["piv"]}
    if "profile" in scopes:
        token_claims["name"] = claims["identity"]
        token_claims["preferred_username"] = claims["identity"]
    token = jwt(token_claims)
    access = secrets.token_urlsafe(32)
    user_claims = {"sub": subject}
    if "profile" in scopes:
        user_claims.update({"name": claims["identity"], "preferred_username": claims["identity"]})
    store.setex("oidc-access:" + access, 300, json.dumps(user_claims))
    return {"access_token":access, "token_type":"Bearer", "expires_in":300, "id_token":token}

def userinfo(store, authorization):
    if not authorization.startswith("Bearer "):
        return None
    token = authorization[7:]
    if not token or len(token) > 256:
        return None
    raw = store.get("oidc-access:" + token)
    return json.loads(raw) if raw else None
