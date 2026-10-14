#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose config --quiet
docker compose exec nginx nginx -t
printf '\nWithout a PIV client certificate, port 8444 should reject the request:\n'
curl -sk -o /dev/null -w 'HTTP %{http_code}\n' https://localhost:8444/ || true
printf '\nOpen https://localhost:8444/ in Chrome or Safari with your PIV card inserted.\n'
