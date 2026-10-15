#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Use the same cryptography version as the application; the app image has Python and cryptography.
# Host Python environments may need: python3 -m pip install 'cryptography==44.0.3'
python3 scripts/update-crl.py
