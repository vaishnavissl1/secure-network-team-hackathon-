#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

tls=(--noproxy '*' --cacert certs/server.crt --resolve shield.local:8443:127.0.0.1 --max-time 5)
base='https://shield.local:8443'

login_probe() {
    # This checks nginx with empty form fields and uses no account or password.
    curl -sS "${tls[@]}" --json '{}' -o /dev/null \
        -w '%{http_code} %header{x-request-id}\n' "$base/rest/user/login"
}

sleep 6
admitted=0
rejected=0
admitted_id=''
rejected_id=''
for ((probe=1; probe<=12; probe++)); do
    read -r status request_id <<< "$(login_probe)"
    [[ "$request_id" =~ ^[[:xdigit:]]{32}$ ]]
    printf 'Probe %02d status %s request_id %s\n' "$probe" "$status" "$request_id"
    case "$status" in
        400|401)
            admitted=$((admitted + 1))
            admitted_id=$request_id
            ;;
        429)
            rejected=$((rejected + 1))
            rejected_id=$request_id
            ;;
        *)
            printf 'Unexpected server response %s to the no-credential check.\n' "$status" >&2
            exit 1
            ;;
    esac
done

((admitted > 0 && rejected > 0))
curl -fsS "${tls[@]}" -o /dev/null "$base/rest/products/search?q=apple"
printf 'PASS browsing works after the login-only limiter returned 429\n'

python3 -c '
import json
import sys

passed_id, rejected_id = sys.argv[1:]
wanted = {passed_id, rejected_id}
events = {}
for line in sys.stdin:
    event = json.loads(line)
    if event["request_id"] in wanted:
        events[event["request_id"]] = event
passed, rejected = events[passed_id], events[rejected_id]
assert passed["limit_req_status"] == "PASSED" and passed["upstream_status"] in {"400", "401"}, passed
assert rejected["status"] == 429 and rejected["limit_req_status"] == "REJECTED" and rejected["upstream_status"] == "", rejected
' "$admitted_id" "$rejected_id" < logs/nginx/access.log

sleep 6
read -r recovery_status _ <<< "$(login_probe)"
[[ "$recovery_status" == 400 || "$recovery_status" == 401 ]]
printf 'PASS rate limiting and recovery: %d admitted to the app, %d automatically rejected, recovery reached the app\n' \
    "$admitted" "$rejected"
