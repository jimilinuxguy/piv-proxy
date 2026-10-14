#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose config --quiet
docker compose exec nginx nginx -t
echo 'Strict-mode environment:'
docker compose exec app sh -c 'printf "PIV_STRICT=%s\nREQUIRED_POLICY_OIDS=%s\n" "$PIV_STRICT" "$REQUIRED_POLICY_OIDS"'
printf '\nWithout a PIV client certificate, port 8444 should reject the request:\n'
curl -sk -o /dev/null -w 'HTTP %{http_code}\n' https://localhost:8444/login || true
printf '\nOpen https://localhost:8443/ with your PIV card inserted.\n'
