#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
bash scripts/gen-certs.sh
docker compose up -d --pull never --wait --wait-timeout 150
