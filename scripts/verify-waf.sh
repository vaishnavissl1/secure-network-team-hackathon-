#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

docker compose exec -T waf cat /etc/modsecurity.d/modsecurity.conf |
    awk 'tolower($1) == "secruleengine" { count++; enabled=(tolower($2) == "on" && NF == 2) } END { exit !(count == 1 && enabled) }'

tls=(--noproxy '*' --cacert certs/server.crt --resolve shield.local:8443:127.0.0.1 --max-time 5)
marker='shield-wall-audit-parts-check'
read -r status request_id < <(
    curl -sS "${tls[@]}" --cookie "probe=$marker" -H "Content-Type: application/x-shield-wall-check" --data "$marker" -o /dev/null \
        -w '%{http_code} %header{x-request-id}\n' 'https://shield.local:8443/__shield_wall_crs_probe'
)
[[ "$status" == 403 && "$request_id" =~ ^[[:xdigit:]]{32}$ ]]
printf 'PASS inbound WAF probe returned 403 with request ID %s\n' "$request_id"

python3 -c '
import json
import sys

event = next(row for row in map(json.loads, sys.stdin) if row["request_id"] == sys.argv[1])
assert event["status"] == 403 and event["upstream_status"] == "", event
' "$request_id" < logs/nginx/access.log

python3 -c '
import json
import sys

for line in sys.stdin:
    transaction = json.loads(line)["transaction"]
    if transaction["unique_id"] != sys.argv[1]:
        continue
    assert sys.argv[2] not in line, "Synthetic cookie or body marker was written to the audit log"
    assert transaction["is_interrupted"] is True, "WAF did not interrupt the transaction"
    rule_ids = {str(message["details"]["ruleId"]) for message in transaction["messages"]}
    assert {"920420", "949110"} <= rule_ids, rule_ids
    print("PASS CRS policy rule 920420 and inbound blocking rule 949110 were logged")
    break
else:
    sys.exit("No matching WAF audit entry")
' "$request_id" "$marker" < logs/modsec/audit.log

printf '%s\n' 'PASS the proxy and audit logs agree on the request ID, the request never reached the backend, and the cookie and body markers were omitted'
