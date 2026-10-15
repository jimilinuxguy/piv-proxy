#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p pki
python3 ./scripts/extract_nasa_cas.py
openssl verify -CAfile pki/federal-root.pem -untrusted pki/nasa-intermediates.pem pki/nasa-operational.pem
cat pki/federal-root.pem pki/nasa-intermediates.pem > pki/client-ca.pem
printf '\nCreated pki/client-ca.pem (root and intermediates).\n'
printf 'IMPORTANT: This config trusts the Federal Common Policy hierarchy; configure approved certificate policies and issuer revocation checks in the app.\n'
