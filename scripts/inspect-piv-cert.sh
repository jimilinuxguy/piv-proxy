#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -ne 1 ]; then
  echo "Usage: bash scripts/inspect-piv-cert.sh /path/to/piv-authentication-cert.pem" >&2
  echo "Use only the PUBLIC certificate, never export your PIV private key." >&2
  exit 2
fi
echo "Certificate policies:"
openssl x509 -in "$1" -noout -text | sed -n '/X509v3 Certificate Policies:/,/X509v3 /p' | sed '$d'
echo
echo "CRL distribution points:"
openssl x509 -in "$1" -noout -text | sed -n '/X509v3 CRL Distribution Points:/,/X509v3 /p' | sed '$d'
echo
echo "Issuer:"
openssl x509 -in "$1" -noout -issuer
