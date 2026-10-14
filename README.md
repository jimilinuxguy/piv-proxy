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

Click **Sign out** on the protected demo or landing page to revoke the current session. You will see a signed-out confirmation. Unauthenticated access to `/app/` returns to the landing page rather than silently initiating a new PIV login. Your browser may retain its mTLS client-certificate selection even after the application session is revoked.

## Commands

```bash
docker compose up -d --build
docker compose ps
docker compose logs --tail=100 nginx app redis demo
curl -vk https://localhost:8443/
curl -vk https://localhost:8443/app/  # redirects to landing page when not authenticated
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

## Strict policy and CRL revocation mode (opt-in; fail closed)

**Do not enable until you have an approved policy allowlist and a current complete CRL issued by the CA that signed your PIV Authentication certificate.** Neither the policy OIDs nor CRL can be safely guessed from a NASA issuer name. This implementation verifies the *leaf certificate only*, not revocation of intermediate CAs. It is **not yet production-complete**.

1. Export your **public PIV Authentication certificate** to a local PEM file (never the private key). Inspect it with `bash scripts/inspect-piv-cert.sh /path/to/piv-auth.pem`.
2. Obtain the approved PIV Authentication policy OID(s) from your agency's PKI policy documentation. Verify they appear in the certificate's Certificate Policies extension.
3. Obtain the **complete, current issuer CRL** from the certificate's CRL Distribution Points, using an agency-approved trusted source. Save it as `pki/nasa-leaf.crl` (PEM or DER). **Do not commit it.** If there are multiple issuing CAs or partitioned CRLs, the single-file verifier may not cover your certificate and will reject it.
4. Create a local `.env`:
   ```dotenv
   PIV_STRICT=true
   REQUIRED_POLICY_OIDS=<agency-approved-PIV-authentication-policy-OID>
   ```
   Replace the placeholder with an actual approved numeric OID; do not copy it literally.
5. Run `docker compose up -d --build app` and sign in again. If the CRL is missing, stale, signed by a different CA, or lists the card serial as revoked, login fails.

**Important:** Existing sessions created before enabling strict mode remain valid until expiry or logout. For a clean cutover, revoke all sessions by restarting the ephemeral Redis container with `docker compose restart redis`. This is a local-demo convenience, not production-grade revocation of active sessions.

The strict verifier checks the CRL signature using the matching locally provisioned NASA Operational CA certificate, issuer name, available key identifiers, validity window, and leaf serial number. It rejects delta and indirect CRLs. It does **not** download/refresh CRLs, support OCSP, check CA revocation, or perform authorization. Refresh the CRL securely before `nextUpdate`. If no current CRL is available, strict login fails. For production, implement full path-wide revocation and policy validation, agency authorization, trusted revocation distribution, and session invalidation on revocation.
