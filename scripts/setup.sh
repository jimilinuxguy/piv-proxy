#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v docker >/dev/null || { echo 'Install Docker Desktop first'; exit 1; }
command -v openssl >/dev/null || { echo 'OpenSSL required'; exit 1; }
command -v python3 >/dev/null || { echo 'Python 3 required'; exit 1; }
mkdir -p pki tls
if [ ! -f nginx/default.conf ]; then
  echo 'ERROR: nginx/default.conf missing. Run setup from a complete repository checkout.' >&2
  exit 1
fi
if [ ! -f .env ]; then
  cp .env.example .env
  echo 'Created generic .env configuration.'
fi
printf 'Download and configure NASA PIV certificates and CRL as a sample? [y/N] '
if [ -t 0 ]; then
  read -r answer || answer=""
else
  answer=""
  printf '\nNoninteractive setup: skipping optional NASA sample.\n'
fi
case "$answer" in
  y|Y|yes|YES|Yes)
    bash scripts/fetch-nasa-piv-cas.sh
    docker compose build app
    CRL_URL="${PIV_CRL_URL:-http://hc.nasa.gov/combinedCRL5.crl}"
    docker compose run --rm --no-deps -v "$PWD/scripts:/scripts:ro" \
      -v "$PWD/pki:/crl-output:rw" -e PIV_CRL_URL="$CRL_URL" \
      --user 0 app python /scripts/update-crl.py \
      --issuer /app/pki/nasa-operational.pem --output /crl-output/nasa-leaf.crl
    # Update only the sample profile keys, retaining unrelated user settings.
    python3 - <<'PY'
from pathlib import Path
path = Path(".env")
updates = {
    "REQUIRED_POLICY_OIDS": "2.16.840.1.101.3.2.1.3.13",
    "PIV_ISSUER_PATH": "/app/pki/nasa-operational.pem",
    "PIV_CRL_PATH": "/app/pki/nasa-leaf.crl",
    "PIV_CRL_URL": "http://hc.nasa.gov/combinedCRL5.crl",
}
lines = path.read_text().splitlines()
seen = set()
result = []
for line in lines:
    key = line.split("=", 1)[0].strip()
    if key in updates:
        if key not in seen:
            result.append(f"{key}={updates[key]}")
            seen.add(key)
    else:
        result.append(line)
for key, value in updates.items():
    if key not in seen:
        result.append(f"{key}={value}")
path.write_text("\n".join(result) + "\n")
PY
    echo 'NASA sample settings applied to .env; unrelated settings preserved.'
    ;;
  *)
    echo 'Skipping NASA sample; using your configured CA trust and CRLs.'
    ;;
esac
# Fail before launching a misleading or nonfunctional gateway.
if [ ! -s pki/client-ca.pem ]; then
  echo 'ERROR: Missing pki/client-ca.pem. Supply your trusted CA chain or choose the NASA sample.' >&2
  exit 1
fi
ISSUER_FILE="$(sed -n 's/^PIV_ISSUER_PATH=//p' .env | tail -1)"
ISSUER_FILE="${ISSUER_FILE:-/app/pki/issuer.pem}"
case "$ISSUER_FILE" in
  /app/pki/*) ISSUER_HOST="pki/${ISSUER_FILE#/app/pki/}" ;;
  *) echo 'ERROR: PIV_ISSUER_PATH must point inside /app/pki.' >&2; exit 1 ;;
esac
if [ ! -s "$ISSUER_HOST" ]; then
  echo "ERROR: Missing issuer bundle $ISSUER_HOST. Configure .env and provision issuer certificates." >&2
  exit 1
fi
if [ ! -f tls/localhost.crt ] || [ ! -f tls/localhost.key ]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 30 \
    -keyout tls/localhost.key -out tls/localhost.crt \
    -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
  chmod 600 tls/localhost.key
fi
docker compose up -d --build
echo 'Open https://localhost:8443 and authenticate with your configured CAC/PIV credential.'
echo 'Strict certificate policy and revocation validation are enabled by default.'
