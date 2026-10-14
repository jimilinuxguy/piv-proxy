# PIV Proxy — configurable local PIV mTLS gateway

**Local development demonstration only. Not approved for production use.** Binds HTTPS ports to loopback. Uses the physical PIV card through browser mTLS and NGINX client-certificate verification. Strict PIV policy and leaf CRL verification are **enabled by default**.

## Quick setup (macOS)

Requires Docker Desktop, Python 3, OpenSSL, and the NASA/Federal CA certificates in macOS Keychain.

```bash
git clone https://github.com/jimilinuxguy/piv-proxy.git
cd piv-proxy
bash scripts/setup.sh
bash scripts/test.sh
```

The setup script extracts and verifies NASA CA certificates from macOS Keychain, creates `.env` from `.env.example`, downloads the NASA Operational CA CRL from its documented URL, verifies CRL signature/issuer/freshness, generates a local TLS certificate if necessary, then launches Docker Compose. On CRL validation or download failure it stops rather than silently disabling strict mode.

Navigate to https://localhost:8443/, select **Sign in with PIV card**, and choose the **PIV Authentication** certificate (not the unrelated Network-Auth certificate). You may need a browser exception for the self-signed local HTTPS server certificate.

## Default strict configuration

```dotenv
PIV_STRICT=true
REQUIRED_POLICY_OIDS=2.16.840.1.101.3.2.1.3.13
PIV_CRL_PATH=/app/pki/nasa-leaf.crl
PIV_ISSUER_PATH=/app/pki/nasa-operational.pem
PIV_CRL_DIRECTORY=/app/pki/crls
PIV_CRL_URL=http://hc.nasa.gov/combinedCRL5.crl
```

OID `2.16.840.1.101.3.2.1.3.13` is the federal PIV Authentication policy observed on the NASA PIV Authentication certificate. Confirm these values are appropriate for your agency and specific certificate before deployment. **Do not allowlist the distinct Network-Auth OID `1.3.6.1.4.1.71.1.1.9` as a substitute for PIV Authentication.**

Compose reads these variables from `.env`. Restart after edits with `docker compose up -d --force-recreate`. Never commit `.env`, `pki/`, or `tls/`.

## CRL refresh

The observed NASA Operational CA PIV Authentication CRL URL is:

```text
http://hc.nasa.gov/combinedCRL5.crl
```

Refresh using the application's pinned Python dependencies:

```bash
docker compose run --rm --no-deps -v "$PWD/scripts:/scripts:ro" \
  -v "$PWD/pki:/crl-output:rw" --user 0 app \
  python /scripts/update-crl.py --issuer /app/pki/nasa-operational.pem --output /crl-output/nasa-leaf.crl
```

Or install `cryptography==44.0.3` in host Python and run `bash scripts/refresh-crl.sh`. The updater accepts `PIV_CRL_URL` or `--url`, but only hosts in `PIV_CRL_ALLOWED_HOSTS` (defaults to NASA/Treasury). It verifies CRL authenticity and freshness before atomically replacing the old file; a failed download leaves the existing file untouched. A stale CRL **fails closed** at authentication even if a prior CRL remains on disk.

**Automate the refresh command daily** using a host scheduler (launchd or cron). Docker's read-only mount reflects the atomically replaced file, so no container restart should be required. Refreshes are not performed by individual login requests, and the updater does not follow arbitrary certificate-supplied URLs.

Inspect validity:

```bash
openssl crl -inform DER -in pki/nasa-leaf.crl -noout -issuer -lastupdate -nextupdate
openssl crl -inform DER -in pki/nasa-leaf.crl -CAfile pki/nasa-operational.pem -verify -noout
```

The CRL may be PEM instead of DER; omit `-inform DER` in that case.

## Troubleshooting

- `Strict mode requires approved PIV policy OIDs`: configure `REQUIRED_POLICY_OIDS`.
- `Missing approved PIV certificate policy`: inspect the **actual certificate presented to nginx**. The correct PIV Auth OID above differs from Network-Auth.
- `Revocation data unavailable or invalid`: check `pki/nasa-leaf.crl`, `pki/nasa-operational.pem`, Docker mounts and file permissions.
- `Revocation list is stale or not yet valid`: refresh the CRL; do not disable strict mode.
- `No valid issuer signature for PIV revocation list`: verify CRL scope and issuing CA; do not reuse the NDC Issuing CA 3 CRL for NASA Operational CA credentials.
- `PIV certificate is revoked`: expected hard denial.
- Browser selection issues: select the PIV Authentication certificate and verify the card/reader works in macOS.

```bash
docker compose ps
docker compose logs --tail=100 nginx app redis demo
docker compose exec app sh -c 'env | grep -E "PIV_STRICT|REQUIRED_POLICY_OIDS|NASA_ISSUER"'
docker compose down
```

To invalidate existing demo sessions after changes, `docker compose restart redis`.

## Architecture and limitations

- NGINX on 8444 requires and verifies client TLS certificates against `pki/client-ca.pem`. The app validates validity dates, clientAuth EKU, required PIV policy, matching issuer, and leaf certificate revocation in a signed, current CRL.
- Only the browser-facing TLS client certificate from nginx is accepted; do not publish the Python service or grant untrusted containers access to its network.
- Authenticated sessions last 15 minutes in ephemeral Redis with Secure, HttpOnly and SameSite=Lax cookies. NGINX protects `/app/` using `auth_request`, sending server-controlled identity headers to the demo.
- **Not production authorization:** no personnel directory authorization or role mapping; CA chain-wide revocation, OCSP, delta/indirect or partitioned CRL support, server-side CSRF defenses, and continuous session revocation are outside this demo.
- Existing sessions survive a certificate revocation until session expiry unless invalidated. NGINX's chain verification is separate from Python's leaf-CRL validation.
- Local self-signed TLS is for development. Keep the network loopback-only and do not expose or deploy without independent security review.

## Tests

```bash
python3 -m pip install 'cryptography==44.0.3' 'redis==5.2.1'
python3 -m unittest discover -s tests -v
bash scripts/test.sh
```

Tests use a local synthetic CA and CRLs; no actual NASA certificates or private key material is required.

## Agency-neutral configuration

The Python gateway does not hardcode NASA issuer names. It checks the client certificate issuer against the certificates in `PIV_ISSUER_PATH`, enforces `REQUIRED_POLICY_OIDS`, and verifies a signed current CRL from the matching issuer. NGINX independently verifies the TLS chain using `pki/client-ca.pem`. **Both trust bundles must be provisioned for the target agency.** A certificate issued by another CA is not automatically trusted.

For multiple issuers, put their issuing CA certificates in a PEM bundle at `PIV_ISSUER_PATH`, and put each issuer's verified, current CRL in `pki/crls/` (or `PIV_CRL_DIRECTORY`). When this directory exists, it supersedes the legacy single `PIV_CRL_PATH`. Refresh each CRL separately with `scripts/update-crl.py --issuer ... --output ...`. Set `PIV_CRL_ALLOWED_HOSTS` to an explicit comma-separated host allowlist for your agency; certificate-supplied URLs are never fetched automatically. Never disable strict mode to onboard a new issuer.

`scripts/setup.sh` and `scripts/fetch-nasa-piv-cas.sh` remain a NASA convenience bootstrap; to provision another agency, supply the trusted CA bundle, issuer bundle, CRLs and policy OIDs yourself before starting Compose. The NASA example policy remains the default until you change it.
