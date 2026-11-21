#!/usr/bin/env bash
# Score an existing run after checking the current edge configuration.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
results=${1:-tests/results/acceptance.jsonl}
test -s "$results"
bash scripts/verify-edge.sh
bash scripts/verify-waf.sh
python3 dashboard/summarize.py --require full --results "$results" \
    --access logs/nginx/access.log --audit logs/modsec/audit.log --out dashboard/alerts.json
