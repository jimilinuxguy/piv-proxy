# PIV Proxy — local NASA PIV mTLS gateway

**Development demonstration only. Not approved for production use.** Runs on loopback-only ports. Uses a physical PIV smart card through your browser and NGINX client-certificate TLS verification.

## Setup (macOS)

Requires Docker Desktop, Python 3, OpenSSL, and your NASA/Federal CA certificates available in macOS Keychain.

```bash
bash scripts/setup.sh
docker compose ps
```

Visit https://localhost:8443/. The local self-signed HTTPS certificate may require a browser exception.

1. Click **Sign in with NASA PIV** (port 8444).
2. Choose the **PIV Authentication** certificate and enter the smart-card PIN if prompted.
3. NGINX verifies the TLS certificate chain. The Python service checks validity, clientAuth EKU, NASA Operational CA issuer, and optionally policy OIDs.
4. A 15-minute random Redis-backed session cookie is set with Secure, HttpOnly, and SameSite=Lax.
5. The browser returns to https://localhost:8443/app/; NGINX uses `auth_request` to validate the session before proxying to the sample upstream.
6. The upstream receives a server-controlled `X-Authenticated-User` header. The browser cannot override it.

Click **Sign out** on the landing page to revoke the current session.

## Commands

```bash
docker compose up -d --build
docker compose ps
docker compose logs --tail=100 nginx app redis demo
curl -vk https://localhost:8443/
curl -vk https://localhost:8443/app/  # redirects to PIV login when not authenticated
docker compose down
```

## Security and limitations

- **Revocation is NOT implemented** (neither OCSP nor CRL). A revoked PIV certificate could be accepted.
- **Policy OID allowlisting is opt-in** via `REQUIRED_POLICY_OIDS`; identify approved policy OIDs from your organization before enabling. Empty means no policy check.
- **No account authorization** or personnel directory mapping. A NASA-issued credential is not proof of access entitlement.
- The application relies on mTLS verification by NGINX; do not expose the Python service directly or let untrusted services join its Docker network.
- The demo upstream is intentionally simple and does not implement business authorization.
- Redis sessions are ephemeral (no persistence), 15 minutes, with no sliding expiration.
- The self-signed server certificate is for local testing only.
- Do not commit `tls/`, `pki/`, `.env`, session secrets, card certificates, or personal data.

**Before any nonlocal deployment:** implement fail-closed certificate revocation, approved policy OID enforcement, real account authorization, a trusted server certificate, ingress/network restrictions, CSRF protections where applicable, and security review.

## Components

- `nginx/default.conf`: public landing page, PIV-only login, authenticated reverse proxy.
- `app/server.py`: validates the certificate presented by NGINX and manages Redis sessions.
- `demo/server.py`: sample protected upstream.
- `compose.yaml`: NGINX, app, Redis and demo services.
- `scripts/`: CA extraction, local TLS setup, diagnostics.
