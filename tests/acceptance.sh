#!/usr/bin/env bash
# PS6 acceptance scorer (Person B). Run from the repo root:  bash tests/acceptance.sh
# Requires the stack up (Person A's docker-compose.yml). Scores the PS6 rubric.
set -uo pipefail
cd "$(dirname "$0")/.."

BASE="${BASE:-https://localhost:8443}"
HOST="${HOST:-shield.local}"
RESULTS="tests/results/acceptance.jsonl"
ACCESS="logs/nginx/access.log"
AUDIT="logs/modsec/audit.log"
ALERTS="dashboard/alerts.json"

echo "== 0. confirm blocking mode is ACTIVE (env changes need recreate, not restart) =="
if command -v docker >/dev/null 2>&1 && [ -f docker-compose.yml ]; then
  docker compose up -d --force-recreate waf >/dev/null 2>&1 || echo "  (could not recreate waf — is the stack built?)"
  docker compose exec -T waf sh -c 'grep -rhi "SecRuleEngine" /etc/modsecurity.d 2>/dev/null | head -1' \
    || echo "  (could not read SecRuleEngine — check manually)"
else
  echo "  SKIP: docker/compose not available here (run on the demo machine)."
fi

echo "== 1. replay attack + benign (writes one row per request) =="
python tests/runner.py --suite all --base "$BASE" --out "$RESULTS" || true

echo "== 2. build the summary from schedule + logs =="
python dashboard/summarize.py --results "$RESULTS" --access "$ACCESS" --audit "$AUDIT" --out "$ALERTS" || true

echo "== 3. TLS acceptance (uses --cacert, NOT -k) =="
TLS="SKIP"
if [ -f certs/server.crt ]; then
  code=$(curl -s --cacert certs/server.crt --resolve "$HOST:8443:127.0.0.1" \
         -o /dev/null -w '%{http_code}' "https://$HOST:8443/" 2>/dev/null || echo "000")
  if [ "$code" != "000" ]; then TLS="PASS ($code, cert trusted for $HOST)"; else TLS="FAIL (cert/hostname not trusted)"; fi
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
line(brute_ok, f"brute-force: admitted={brute['admitted']} rejected(429)={brute['rejected']} recovered={brute['recovered']}")
line(benign_ok, f"benign >=95% by expected outcome: {b['passed']}/{b['total']} = {b['pass_rate']*100:.0f}%")
line(tls.startswith('PASS'), f"TLS: {tls}")
allgood = exploit_ok and brute_ok and benign_ok and tls.startswith('PASS')
print("\n  RESULT:", "ALL PASS ✓" if allgood else "NOT YET — see FAILs above")
print("  (report numerator/denominator, not slogans; name any open case)")
sys.exit(0 if allgood else 1)
PY
rc=$?
echo "== done =="
exit $rc
