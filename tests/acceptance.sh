#!/usr/bin/env bash
# PS6 acceptance scorer (Person B). Run from the repo root:  bash tests/acceptance.sh
# Requires the stack up (Person A's docker-compose.yml). Scores the PS6 rubric.
set -uo pipefail
cd "$(dirname "$0")/.."

BASE="${BASE:-https://127.0.0.1:8443}"
HOST="${HOST:-shield.local}"
RESULTS="tests/results/acceptance.jsonl"
ACCESS="logs/nginx/access.log"
AUDIT="logs/modsec/audit.log"
ALERTS="dashboard/alerts.json"

echo "== 0. confirm blocking mode is ACTIVE (env changes need recreate, not restart) =="
if command -v docker >/dev/null 2>&1 && [ -f docker-compose.yml ]; then
  [ -f "$ACCESS" ] && [ -f "$AUDIT" ] || bash scripts/up.sh >/dev/null 2>&1   # A's script creates the bind-mounted log files
  docker compose up -d --force-recreate waf >/dev/null 2>&1 || echo "  (could not recreate waf — is the stack built?)"
  MSYS_NO_PATHCONV=1 docker compose exec -T waf sh -c 'grep -rhi "SecRuleEngine" /etc/modsecurity.d 2>/dev/null | head -1' \
    || echo "  (could not read SecRuleEngine — check manually)"
else
  echo "  SKIP: docker/compose not available here (run on the demo machine)."
fi

echo "== 1. replay attack + benign (writes one row per request) =="
rm -f "$RESULTS" "$ALERTS"   # never score stale data from an earlier run
if ! python tests/runner.py --suite all --base "$BASE" --out "$RESULTS" || [ ! -s "$RESULTS" ]; then
  echo "  [FAIL] runner failed or wrote no rows - refusing to score stale data"; exit 2
fi

echo "== 1b. edge logs: A's compose bind-mounts them on the host (logs/nginx/access.log, logs/modsec/audit.log) =="
for f in "$ACCESS" "$AUDIT"; do
  if [ -s "$f" ]; then echo "  $f: $(wc -l < "$f") lines"; else echo "  WARNING: $f missing or empty - blocked-request rule IDs cannot be joined"; fi
done

echo "== 2. build the summary from schedule + logs =="
python dashboard/summarize.py --results "$RESULTS" --access "$ACCESS" --audit "$AUDIT" --out "$ALERTS" || true

echo "== 3. TLS acceptance (uses --cacert, NOT -k) =="
TLS="SKIP"
if [ -f certs/server.crt ]; then
  code=$(curl -s --cacert certs/server.crt --resolve "$HOST:8443:127.0.0.1" \
         -o /dev/null -w '%{http_code}' "https://$HOST:8443/" 2>/dev/null || echo "000")
  if [ "$code" != "000" ]; then TLS="PASS ($code, cert trusted for $HOST)"; else TLS="FAIL (cert/hostname not trusted)"; fi
fi
if [ -f certs/server.crt ]; then
  old=$(curl -s --cacert certs/server.crt --resolve "$HOST:8443:127.0.0.1" --tls-max 1.1 -o /dev/null -w '%{http_code}' "https://$HOST:8443/" 2>/dev/null || true)
  new12=$(curl -s --cacert certs/server.crt --resolve "$HOST:8443:127.0.0.1" --tlsv1.2 --tls-max 1.2 -o /dev/null -w '%{http_code}' "https://$HOST:8443/" 2>/dev/null || true)
  if [ "${old:-000}" = "000" ] && [ "${new12:-000}" != "000" ]; then
    TLS="$TLS; TLS<=1.1 refused, TLS1.2 accepted"
  else
    TLS="FAIL (legacy TLS accepted or TLS1.2 refused: old=$old tls12=$new12)"
  fi
fi
echo "  TLS: $TLS"

echo "== 4. score =="
python - "$ALERTS" "$TLS" <<'PY'
import json, sys
alerts, tls = sys.argv[1], sys.argv[2]
try:
    d = json.load(open(alerts, encoding="utf-8"))
except Exception as e:
    print("  [FAIL] no alerts.json:", e); sys.exit(1)
b, a = d["benign"], d["attacks"]
def line(ok, msg): print(f"  [{'PASS' if ok else 'FAIL'}] {msg}")
exploit_ok = a["exploit_ok"]
brute = a["bruteforce"]; brute_ok = a["bruteforce_ok"]
benign_ok = b["ok"]
line(exploit_ok, f"5 exploit classes blocked (403): {', '.join(k for k,v in a['exploit'].items() if v['blocked'])}")
for e in a.get("edge_rejected", []):
    print(f"  [INFO] {e['case_id']}: path-form traversal refused by nginx with {e['status']} (upstream_status={e['upstream_status']!r}); not a WAF 403, reported separately")
scan = a["exploit"].get("scanner", {})
print(f"  [INFO] scanner confirmed from audit log rules: {scan.get('rule_ids') or 'NONE FOUND'}")
line(brute_ok, f"brute-force: admitted={brute['admitted']} rejected(429)={brute['rejected']} recovered={brute['recovered']}")
line(benign_ok, f"benign >=95% by expected outcome: {b['passed']}/{b['total']} = {b['pass_rate']*100:.0f}%")
line(tls.startswith('PASS'), f"TLS: {tls}")
allgood = exploit_ok and brute_ok and benign_ok and tls.startswith('PASS')
print("\n  RESULT:", "ALL PASS" if allgood else "NOT YET - see FAILs above")
print("  (report numerator/denominator, not slogans; name any open case)")
sys.exit(0 if allgood else 1)
PY
rc=$?
echo "== done =="
exit $rc
