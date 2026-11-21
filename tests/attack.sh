#!/usr/bin/env bash
# PS6 attack replay (Person B). Sends >=6 attack classes through the WAF.
# Delegates to the Python runner so response headers, timeouts and JSON are
# handled correctly. Run from the repo root:  bash tests/attack.sh
set -euo pipefail
cd "$(dirname "$0")/.."
exec python tests/runner.py --suite attack "$@"
