# PIV Proxy — local CAC/PIV mTLS gateway

**Local development demonstration only; not production authorization.** PIV Proxy is a configurable, loopback-only HTTPS gateway that authenticates a browser-presented smart-card client certificate using NGINX mTLS, verifies certificate policy and issuer-specific revocation status in Python, and issues a short-lived Redis-backed session.

The gateway is not tied to a particular agency. **NASA is an optional sample configuration**, not a required dependency. DoD CAC and other PIV credentials can be supported when their appropriate trust chains, authentication certificates, policy OIDs and CRLs are provisioned. This does not mean every certificate on a CAC/PIV card is automatically eligible for client authentication.

## Prerequisites

- Docker Desktop, Python 3, OpenSSL, a supported smart-card reader and browser.
- Trusted CA chain for the credential you intend to accept.
- Issuing CA certificate(s), a current signed CRL for each issuer, and your organization's approved client-authentication certificate policy OIDs.
- On macOS, the optional NASA sample uses the built-in `security` command and certificates already installed in Keychain.

## Setup

```bash
git clone https://github.com/jimilinuxguy/piv-proxy.git
cd piv-proxy
bash scripts/setup.sh
```

Setup prompts:

```text
Download and configure NASA PIV certificates and CRL as a sample? [y/N]
```

- **Yes:** Extract the NASA/Federal CA chain from macOS Keychain, verify it, and download and verify the NASA issuer CRL. On a fresh setup, append the NASA sample settings to `.env`.
- **No (default):** Do not download NASA data. Supply your own `pki/client-ca.pem`, issuer certificate bundle and CRLs, and edit `.env` before starting. Setup refuses to start if required CA bundles are missing.
- **Existing `.env`:** Never overwritten. Selecting NASA will provision its files but will not silently replace your existing policy or issuer configuration.
- **Noninteractive setup:** Skips the optional NASA sample.

For a generic deployment, create `.env` from `.env.example` and provision your own CA files **before** running setup. Strict mode intentionally requires explicit approved policy OIDs.

Open https://localhost:8443/, select **Sign in with PIV card**, and choose the certificate appropriate for TLS client authentication. You may need to trust or acknowledge the self-signed localhost server certificate.

## Generic configuration

```dotenv
PIV_STRICT=true
REQUIRED_POLICY_OIDS=<approved-comma-separated-OIDs>
PIV_ISSUER_PATH=/app/pki/issuer.pem
PIV_CRL_PATH=/app/pki/issuer.crl
PIV_CRL_DIRECTORY=/app/pki/crls
```

Replace the policy placeholder with real approved OIDs. `pki/client-ca.pem` is the TLS client trust chain used by NGINX. `PIV_ISSUER_PATH` is the PEM bundle of certificate issuers used for application checks and CRL verification. Both must match your chosen credential ecosystem.

For multiple issuers, place their issuing CA certificates in the issuer PEM bundle and their individually verified, current `.crl` or `.der` files under `pki/crls/`. **If that directory exists, it supersedes `PIV_CRL_PATH`.** Do not put unrelated PEM certificates in the CRL directory.

The app checks certificate validity, clientAuth EKU, an approved policy OID, issuer identity and matching signed CRL. NGINX independently verifies the TLS chain. Unknown issuers and missing, stale or invalid revocation information fail closed. This is certificate authentication, not a substitute for organizational user authorization.

## Optional example: NASA PIV

Selecting **Yes** during setup uses `scripts/fetch-nasa-piv-cas.sh` and `scripts/extract_nasa_cas.py`. The NASA example settings are:

```dotenv
REQUIRED_POLICY_OIDS=2.16.840.1.101.3.2.1.3.13
PIV_ISSUER_PATH=/app/pki/nasa-operational.pem
PIV_CRL_PATH=/app/pki/nasa-leaf.crl
PIV_CRL_URL=http://hc.nasa.gov/combinedCRL5.crl
```

Choose the **PIV Authentication** certificate, not a separate Network-Auth certificate. The NASA sample is designed for macOS with the requisite CA certificates already in Keychain. For other agencies, provision the appropriate CA material and policy rather than reusing NASA settings.

## Refresh CRLs

Each issuer's CRL must be refreshed separately. The updater checks URL host allowlisting, issuer signature, CRL validity and scope before atomically replacing a CRL. It does **not** automatically fetch arbitrary certificate-provided URLs.

```bash
# Example: refresh an issuer CRL using the app's pinned dependencies
docker compose run --rm --no-deps \
  -v "$PWD/scripts:/scripts:ro" -v "$PWD/pki:/crl-output:rw" \
  -e PIV_CRL_ALLOWED_HOSTS=crl.example.gov \
  --user 0 app python /scripts/update-crl.py \
  --url https://crl.example.gov/issuer.crl \
  --issuer /app/pki/issuer.pem --output /crl-output/issuer.crl
```

Replace example URLs, hostnames and files with your organization's verified CRL endpoints. Schedule refreshes before CRLs expire. The updater also accepts `PIV_CRL_ALLOWED_HOSTS` as a comma-separated host allowlist. **A failed refresh preserves the previous CRL, but an expired CRL still fails authentication.**

## Redirect to an existing application after CAC/PIV login

Pass a URL-encoded `return_to` query parameter to the mTLS login endpoint:

```text
https://localhost:8444/login?return_to=https%3A%2F%2Flocalhost%3A3000%2Fdashboard
```

Allow the destination's **exact HTTPS origin** in `.env`:

```dotenv
PIV_CALLBACK_ALLOWED_ORIGINS=https://localhost:8443,https://localhost:3000
```

Then restart: `docker compose up -d --build --force-recreate`.

After certificate validation, the gateway sets the existing `piv_proxy_session` cookie and responds with HTTP 303 to the approved callback. With the **same hostname** (e.g., `localhost` on two HTTPS ports), the browser sends the host-only, Secure, HttpOnly cookie to both applications; ports do not partition cookies. Different hostnames and subdomains do not receive it. A relative callback such as `/app/` is also supported. Without `return_to`, the gateway continues to `https://localhost:8443/app/`.

**Security:** External callbacks require explicit allowlisting; arbitrary redirect URLs, HTTP callbacks, userinfo and fragments are rejected. The destination application still must validate the proxy session through a trusted server-side integration; merely receiving the cookie does not log the user into its own account. Do not expose this local proof of concept publicly.

## Server-to-server session validation API

The authentication service provides **`GET /api/v1/session/validate`** on its internal Docker network at `http://app:8000/api/v1/session/validate`. This endpoint is **not published through NGINX** or bound to a host port. The calling application must join the same trusted Docker network or use an appropriately protected private service connection.

Set a high-entropy shared secret in `.env`:

```bash
openssl rand -hex 32
```

```dotenv
PIV_VALIDATION_API_KEY=<paste-generated-secret>
```

Restart with `docker compose up -d --build --force-recreate`. Configure the same key securely on the receiving application's **backend**, never in browser JavaScript. If the key is unset, validation always returns 403.

The receiving backend forwards the browser's `piv_proxy_session` cookie and authenticates itself:

```http
GET /api/v1/session/validate HTTP/1.1
Host: app:8000
Authorization: Bearer <shared-secret>
Cookie: piv_proxy_session=<browser-cookie>
```

Successful response (`200`):

```json
{"authenticated":true,"identity":"Example User","subject_id":"sha256:<64-hex-digits>","certificate_sha256":"<64-hex-digits>","auth_method":"piv","expires_in":742}
```

Other responses: `401` means missing/invalid/expired session; `403` means invalid or missing API key (or the API is disabled); `503` means Redis is unavailable. All responses use `Cache-Control: no-store`.

Example Python backend integration:

```python
import os
import requests
from flask import request, abort

def validated_piv_identity():
    token = request.cookies.get("piv_proxy_session")
    if not token:
        abort(401)
    response = requests.get(
        "http://app:8000/api/v1/session/validate",
        headers={"Authorization": "Bearer " + os.environ["PIV_VALIDATION_API_KEY"]},
        cookies={"piv_proxy_session": token},
        timeout=3,
    )
    if response.status_code != 200:
        abort(503 if response.status_code == 503 else 401)
    return response.json()["identity"]
```

The receiving application must map the returned **`subject_id`** to an authorized local account, then establish its normal session; this does not automatically bypass a third-party login form. `subject_id` is the `sha256:`-prefixed SHA-256 fingerprint of the **verified leaf certificate**; `certificate_sha256` contains the same digest without a prefix. `identity` remains the certificate common name for display only, **not account mapping**. A certificate fingerprint uniquely identifies a certificate, but **changes on card/certificate renewal**; provision an explicit, reviewed account re-linking workflow or add an organization-approved persistent identifier before production. Sessions created by older versions lack certificate-bound claims and return `401 reauthentication_required` from the validation API; sign in again to issue a new session.

**Security boundaries:** The bearer key authenticates the calling service, not the end user. Keep it secret and rotate it if exposed. Restrict Docker network membership; any application holding both a valid cookie and key can introspect that session. Use TLS/mTLS if validation traverses hosts or untrusted networks. Do not publish this endpoint to the internet. Validate the session on each protected request or carefully constrain any local session lifetime; logout/revocation will not invalidate independent downstream sessions automatically.

## Optional OIDC for applications hosted on other domains

The OIDC authorization-code + PKCE flow is **opt-in**, and does not rely on cross-domain cookies. The current gateway's PIV cookie remains on the authentication host. Remote applications obtain a signed RS256 ID token after a one-time authorization-code exchange and create their own sessions.

1. Generate a **local** RSA key (never commit it):

```bash
mkdir -p oidc
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out oidc/private.pem
chmod 600 oidc/private.pem
```

2. Add to `.env` (register every exact HTTPS callback URI):

```dotenv
OIDC_ENABLED=true
OIDC_ISSUER=https://localhost:8443
OIDC_CLIENTS_JSON={"remote-demo":["https://localhost:3000/oidc/callback"]}
```

3. Restart `docker compose up -d --build --force-recreate`. The issuer and JWKS endpoints are `https://localhost:8443/.well-known/openid-configuration` and `https://localhost:8443/jwks.json`.

4. Your remote application creates a cryptographically random `state`, `nonce`, and PKCE `code_verifier` (43–128 permitted characters); store these in its **server-side login session**. Send the browser to:

```text
https://localhost:8443/authorize?response_type=code&scope=openid&client_id=remote-demo&redirect_uri=https%3A%2F%2Flocalhost%3A3000%2Foidc%2Fcallback&state=RANDOM_STATE&nonce=RANDOM_NONCE&code_challenge=BASE64URL_SHA256_VERIFIER&code_challenge_method=S256
```

5. The proxy redirects to the smart-card mTLS port `8444`, validates CAC/PIV, sets its own session cookie, and redirects the browser to the **registered** callback with `code` and original `state`. Your application verifies `state`, then POSTs to `https://localhost:8443/token` as `application/x-www-form-urlencoded` with `grant_type=authorization_code`, `client_id`, `redirect_uri`, `code`, and the original `code_verifier`.

6. Verify the returned `id_token` RS256 signature against the published JWKS, **issuer**, **audience/client ID**, expiration, and **nonce** before accepting its `sub` (certificate fingerprint) as the mapped account identifier. Use `access_token` as a bearer credential with `GET /userinfo` if desired. Never trust the browser's callback `code` or any decoded token claims without validation.

The code expires in 60 seconds and can be redeemed once; ID and access tokens expire in 5 minutes. Only pre-registered HTTPS redirects are accepted. The `/token`, `/userinfo`, JWKS, discovery, and authorization endpoints are reachable over the configured HTTPS gateway. The older `/api/v1/session/validate` remains **private** to the Docker network.

**Limitations:** This is a development-grade OIDC bridge, **not a certified or production-ready identity provider**. It supports public clients using PKCE S256 only, with one static signing key and no refresh tokens, dynamic registration, discovery-based key rotation, consent management, end-session federation, or cross-system logout. Certificate fingerprints change at renewal. To host applications on other machines, deploy under a real DNS name with trusted HTTPS certificates, carefully protect the signing key, and complete an identity-provider security review.

## Complete local OIDC demo application

The standalone example is at **https://localhost:8445/**. Unlike the legacy `/app/` reverse-proxy example, it initiates its own OIDC authorization-code + PKCE login, exchanges the code on the backend, validates the RS256 ID-token signature against the issuer's JWKS, checks issuer/audience/nonce/expiry, and establishes its own Secure, HttpOnly application cookie. The demo does **not** trust `X-Authenticated-User` headers.

To run the complete proof of concept, first complete CAC/PIV issuer and CRL setup described above. Generate the OIDC signing key:

```bash
mkdir -p oidc
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out oidc/private.pem
chmod 600 oidc/private.pem
```

Set these values in `.env`:

```dotenv
OIDC_ENABLED=true
OIDC_ISSUER=https://localhost:8443
OIDC_CLIENTS_JSON={"piv-demo":["https://localhost:8445/callback"]}
```

Then:

```bash
docker compose up -d --build --force-recreate
bash scripts/run-unit-tests.sh
```

Open **https://localhost:8445/** and select **Sign in with CAC/PIV**. The browser goes to the authorization endpoint, authenticates on port 8444, and returns to the demo callback on port 8445. The demo's backend uses Docker's private `app:8000` service for token/JWKS retrieval; a remote deployment should use a trusted HTTPS issuer URL instead. The demo stores login attempts and application sessions **in memory** and is not horizontally scalable or production-ready. It is intentionally bound to loopback through NGINX.

The old `/app/` example is a reverse-proxy demonstration, **not** an independent OIDC client. Use port 8445 to demonstrate the complete remote-application pattern.

## Testing

```bash
bash scripts/run-unit-tests.sh
docker compose up -d --build
bash scripts/test.sh
```

The unit tests use synthetic issuers and CRLs, without physical smart cards or agency credentials.

Troubleshooting:

- `Strict mode requires approved PIV policy OIDs`: configure `REQUIRED_POLICY_OIDS`.
- `Certificate issuer is not in the configured issuer bundle`: inspect the actual browser-selected certificate and your issuer PEM bundle.
- `Missing approved PIV certificate policy`: ensure the selected certificate has a policy explicitly allowed by your organization.
- `No current, valid issuer CRL for PIV certificate`: check CRL issuer, freshness, signature and directory configuration.
- `Revocation data unavailable or invalid`: check CRL files, formats, mounts and permissions.
- `PIV certificate is revoked`: expected denial.

```bash
docker compose ps
docker compose logs --tail=100 nginx app redis demo
docker compose exec app sh -c 'env | grep -E "PIV_STRICT|REQUIRED_POLICY_OIDS|PIV_ISSUER_PATH|PIV_CRL"'
```

## Security boundaries and limitations

NGINX binds ports 8443 and 8444 to localhost, and the Python app is internal to Compose. The session lasts 15 minutes and uses Secure, HttpOnly, SameSite=Lax cookies. The gateway is a local demonstration: it does not provide personnel directory authorization, full CA-chain revocation, OCSP, delta/indirect or partitioned CRL processing, continuous revocation of existing sessions, or production CSRF hardening. Existing sessions may remain valid until expiry after certificate revocation. Do not expose the service publicly without a security review.
