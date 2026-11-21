#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

docker compose exec -T waf cat /etc/modsecurity.d/modsecurity.conf |
    awk 'tolower($1) == "secruleengine" { count++; enabled=(tolower($2) == "on" && NF == 2) } END { exit !(count == 1 && enabled) }'

tls=(--noproxy '*' --cacert certs/server.crt --resolve shield.local:8443:127.0.0.1 --max-time 5)
marker='shield-wall-audit-parts-check'
read -r status request_id < <(
    curl -sS "${tls[@]}" --cookie "probe=$marker" -o /dev/null \
        -w '%{http_code} %header{x-request-id}\n' 'https://shield.local:8443/__shield_wall_waf_probe'
)
[[ "$status" == 403 && "$request_id" =~ ^[[:xdigit:]]{32}$ ]]
printf 'PASS inbound WAF probe returned 403 with request ID %s\n' "$request_id"

log_dir=/var/log/modsecurity/audit
docker compose exec -T waf cat "$log_dir/access.jsonl" |
    python3 -c '
import json
import sys

event = next(row for row in map(json.loads, sys.stdin) if row["request_id"] == sys.argv[1])
assert event["status"] == 403 and event["upstream_status"] == "-", event
' "$request_id"

docker compose exec -T waf cat "$log_dir/modsec.jsonl" |
    python3 -c '
import json
import sys

for line in sys.stdin:
    transaction = json.loads(line)["transaction"]
    if transaction["unique_id"] != sys.argv[1]:
        continue
    assert sys.argv[2] not in line, "Cookie marker was written to the audit log"
    assert transaction["is_interrupted"] is True, "WAF did not interrupt the transaction"
    assert any(str(message["details"]["ruleId"]) == "10001" for message in transaction["messages"])
    break
else:
    sys.exit("No matching WAF audit entry")
' "$request_id" "$marker"

printf '%s\n' 'PASS the proxy and audit logs agree on the request ID, the backend was bypassed, and the cookie marker was omitted'
