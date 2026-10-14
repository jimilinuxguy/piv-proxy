#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v docker >/dev/null || { echo 'Install Docker Desktop first'; exit 1; }
command -v openssl >/dev/null || { echo 'OpenSSL required'; exit 1; }
mkdir -p pki tls
bash scripts/fetch-nasa-piv-cas.sh
if [ ! -f tls/localhost.crt ] || [ ! -f tls/localhost.key ]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 30 \
    -keyout tls/localhost.key -out tls/localhost.crt \
    -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
  chmod 600 tls/localhost.key
fi
docker compose up -d --build
echo 'Open https://localhost:8443 then click Authenticate (port 8444).'
echo 'The local HTTPS certificate is self-signed; your browser will warn until trusted.'
