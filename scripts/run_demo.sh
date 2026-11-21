#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
bash scripts/up.sh
umask 077
run_dir=$(mktemp -d logs/demo-XXXXXXXX)
bash scripts/verify-edge.sh | tee "$run_dir/edge.txt"
bash scripts/verify-waf.sh | tee "$run_dir/waf.txt"
bash scripts/verify-rate-limit.sh | tee "$run_dir/limiter.txt"
bash tests/benign.sh --out "$run_dir/shopper.jsonl" "$@"
python3 dashboard/summarize.py --require benign --results "$run_dir/shopper.jsonl" \
    --access logs/nginx/access.log --audit logs/modsec/audit.log --out "$run_dir/alerts.json"
python3 scripts/publish_demo.py "$run_dir"
