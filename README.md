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
