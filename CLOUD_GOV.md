# Cloud.gov deployment readiness — NASA PIV / VulnTrack

**Status: BLOCKED on verified external-client mTLS ingress.** This repository's Docker Compose configuration is local-only and must not be deployed directly as a public PIV authenticator.

## Target architecture

- VulnTrack relying party: `https://vulntrack-sandbox.app.cloud.gov/`
- PIV-Proxy OIDC issuer: a Cloud.gov-approved HTTPS hostname, **not yet allocated**
- PIV login: dedicated ingress route requiring a verified NASA PIV Authentication client certificate
- OIDC discovery, authorization, JWKS, and token endpoints: HTTPS route without mandatory client certificates
- Private services: Redis-backed one-time codes/sessions, managed signing key, verified NASA/Federal CA trust and current signed CRLs

## Platform approval gate

Track the operator questions and evidence in [issue #3](https://github.com/jimilinuxguy/piv-proxy/issues/3). Do not accept `X-Forwarded-Client-Cert`, `X-PIV-Cert`, or `X-PIV-Verified` from an arbitrary public request. If Cloud.gov cannot provide a trusted verified certificate boundary, this deployment cannot safely authenticate PIV cards using the existing design.

## Integration configuration after ingress approval

Configure PIV-Proxy's issuer and callback registration (illustrative values only):

```dotenv
OIDC_ENABLED=true
OIDC_ISSUER=https://YOUR-APPROVED-PIV-ISSUER
OIDC_CLIENTS_JSON={"vulntrack":["https://vulntrack-sandbox.app.cloud.gov/"]}
PIV_MTLS_ORIGIN=https://YOUR-VERIFIED-MTLS-LOGIN-ORIGIN
```

Set matching `VULNTRACK_OIDC_ISSUER`, `VULNTRACK_OIDC_JWKS_URL`, `VULNTRACK_OIDC_AUTHORIZE_URL`, `VULNTRACK_OIDC_TOKEN_URL`, `VULNTRACK_OIDC_CLIENT_ID`, `VULNTRACK_OIDC_AUDIENCE`, and `VULNTRACK_OIDC_REDIRECT_URI` in the relying party. See VulnTrack's `CLOUD_GOV_PIV_INTEGRATION.md`.

The current PIV-Proxy uses a local Docker Redis service, Nginx mTLS listener, local PEM signing key, and local CRL files. A CF deployment must replace these with approved services and a verified certificate ingress design; merely pushing the Python app is not a complete deployment.

## Required security verification

1. Browser with NASA PIV Authentication certificate completes mTLS and certificate policy checks.
2. Browser without certificate cannot reach authenticated login.
3. Forged forwarded certificate headers do not authenticate.
4. Invalid issuer, wrong certificate policy, expired certificate, and stale/revoked CRL all fail closed.
5. OIDC code is one-time, PKCE verifier and redirect are bound, and the relying party validates issuer, audience, signature, nonce, and expiry.
6. A verified PIV subject without tenant membership cannot read another tenant's findings.
7. Administrator role is granted only through explicit trusted subject provisioning.
8. Key rotation, CRL refresh, Redis persistence requirements, and logout behavior are documented before production.

This is an integration staging plan, **not evidence that Cloud.gov mTLS is enabled or that the PIV login has been deployed**.
