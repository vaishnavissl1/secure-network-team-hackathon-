#!/usr/bin/env bash
# PS6 benign replay (Person B). Sends >=20 normal requests, scored by expected
# outcome. Run from the repo root:  bash tests/benign.sh
set -euo pipefail
cd "$(dirname "$0")/.."
exec python tests/runner.py --suite benign "$@"
