#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v docker >/dev/null || { echo 'Install Docker Desktop first'; exit 1; }
command -v openssl >/dev/null || { echo 'OpenSSL required'; exit 1; }
command -v python3 >/dev/null || { echo 'Python 3 required'; exit 1; }
mkdir -p pki tls
if [ ! -f .env ]; then
  cp .env.example .env
  echo 'Created .env using strict PIV defaults.'
fi
bash scripts/fetch-nasa-piv-cas.sh
# Refresh with the cryptography dependency from the app image, without requiring host pip.
docker compose build app
# Use the configured CRL distribution endpoint; do not evaluate .env as shell code.
CRL_URL="${PIV_CRL_URL:-$(sed -n 's/^PIV_CRL_URL=//p' .env | tail -1)}"
CRL_URL="${CRL_URL:-http://hc.nasa.gov/combinedCRL5.crl}"
docker compose run --rm --no-deps -v "$PWD/scripts:/scripts:ro" \
  -e PIV_CRL_URL="$CRL_URL" \
  --user 0 app python /scripts/update-crl.py --issuer /app/pki/nasa-operational.pem \
  --output /app/pki/nasa-leaf.crl
if [ ! -f tls/localhost.crt ] || [ ! -f tls/localhost.key ]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 30 \
    -keyout tls/localhost.key -out tls/localhost.crt \
    -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
  chmod 600 tls/localhost.key
fi
docker compose up -d --build
echo 'Open https://localhost:8443 then click Authenticate (port 8444).'
echo 'Strict PIV policy and revocation validation are enabled by default.'
echo 'The local HTTPS certificate is self-signed; your browser will warn until trusted.'
