#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
exec python3 tests/shopper.py --out tests/results/benign.jsonl "$@"
