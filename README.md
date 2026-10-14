# NASA PIV local NGINX mTLS demo

**Local development only. Not production-approved PIV authentication.** Requires macOS with the NASA PIV card available, Docker Desktop, Python 3, OpenSSL, and the federal/NASA CA certificates in macOS Keychain.

## Quick start

```bash
bash scripts/setup.sh
bash scripts/test.sh
```

Open **https://localhost:8443/**, accept the warning for the *local self-signed server certificate*, then click the PIV login link to **https://localhost:8444/**. Select **Certificate For PIV Authentication**, not Card Authentication, Digital Signature or Key Management. macOS/browser may request the card PIN. For some browsers, certificate selection may be cached until browser restart.

The app checks NGINX's successful client certificate chain verification, validity, clientAuth EKU, NASA Operational CA issuer and NASA OU. Optionally set `REQUIRED_POLICY_OIDS` in `.env` to a comma-separated list of verified PIV Authentication policy OIDs. **Do not invent policy OIDs**; inspect the card's actual certificate and approved policy documentation.

## Commands

```bash
bash scripts/fetch-nasa-piv-cas.sh   # refresh CA bundle from macOS Keychain
docker compose up -d --build         # launch
docker compose logs -f nginx app     # troubleshoot
docker compose down                  # stop
```

## Files

- `scripts/extract_nasa_cas.py`: extracts, deduplicates and cryptographically verifies CA chains from the macOS Keychain.
- `scripts/fetch-nasa-piv-cas.sh`: assembles CA PEM files.
- `nginx/default.conf`: public landing page on 8443 and strict client-certificate mTLS on 8444.
- `app/server.py`: local certificate identity and EKU checks.
- `compose.yaml`: loopback-only exposed ports; app not published to host.

## Security limitations

- **No OCSP or CRL revocation checking.** A revoked but otherwise valid certificate could be accepted. Must be fixed before production use.
- **No verified PIV policy allowlist by default.** Verify and configure approved PIV Authentication policy OIDs before production use.
- **No personnel authorization or account mapping.** NASA OU/issuer is not proof that a user is authorized to your app.
- **No sessions, Redis, or integration with your existing FastAPI application.** This is a standalone end-to-end mTLS smoke test and can be integrated later.
- NGINX trusts the Federal Common Policy chain; the app adds NASA issuer restrictions. Do not expose this deployment publicly.
- Server certificate is a short-lived local self-signed certificate; replace with a trusted certificate for real deployments.
- Certificate-derived headers are trusted only because the Python app is reachable solely from the internal Docker network through NGINX. Never publish the app port directly.
