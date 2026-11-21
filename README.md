# PS6 Shield Wall

Shield Wall protects a local OWASP Juice Shop lab with nginx, ModSecurity, and the OWASP Core Rule Set. Run the integrated stack in the Ubuntu demo VM with VirtualBox NAT enabled.

## Start and check the edge

On the VM, use Docker Compose v2, Bash, OpenSSL, curl, and Python 3. The Compose file pins the two cached image digests and disables pulls.

```bash
bash scripts/up.sh
bash scripts/verify-edge.sh
```

The entry point is `https://shield.local:8443` on VM loopback. The check script resolves the name locally and trusts `certs/server.crt` explicitly. HTTP on port 8080 redirects to HTTPS. Juice Shop is attached only to the internal Docker network and has no published port.

Run `bash scripts/down.sh` when you need to stop the lab. Keep lab credentials, TLS keys, and raw logs local. Person B can develop the evidence summary and dashboard on Windows and verify against sanitized records from the VM.

## Correlate proxy and WAF events

Run `bash scripts/verify-waf.sh` to check effective blocking mode and trace a harmless request with an unsupported media type. It verifies that CRS rule `920420` contributes to an inbound block by rule `949110` and that the audit event matches the proxy record.

nginx returns `X-Request-ID` on successful and denied requests. Both logs are in the project’s `edge-logs` Docker volume. The nginx record has `request_id`, `status`, `upstream_status`, `limit_result`, `method`, `uri`, and `time`. A WAF event uses `transaction.unique_id` and reports rule IDs in `transaction.messages[].details.ruleId`. An allowed request can have only a proxy record. The access log uses an empty string for upstream status or limiter result when that phase did not run. WAF messages can include match details, so use sanitized fields in shared evidence.

```bash
mkdir -p logs
docker compose exec -T waf cat /var/log/modsecurity/audit/access.jsonl > logs/access.jsonl
docker compose exec -T waf cat /var/log/modsecurity/audit/modsec.jsonl > logs/modsec.jsonl
```

For a before/after comparison inside the isolated lab, set `SHIELD_RULE_ENGINE=DetectionOnly` on the Compose up command, then run Compose up again with `SHIELD_RULE_ENGINE=On` to restore blocking. `verify-waf.sh` requires blocking mode.

## Tuning notes

Start with CRS paranoia level 1 and inbound threshold 5. The before-CRS file starts with zero tuning exclusions. Add an exclusion only after a benign request fails and the audit log identifies the rule and input field. Record the request ID, scoped change, and retest outcome.

## Verify the login limiter

Run `bash scripts/verify-rate-limit.sh` on the VM. It sends a bounded set of requests with no credentials to the fixed loopback endpoint and checks the responses, the nginx limiter decision, browsing, and recovery. The login route allows one request per second per client IP with a burst allowance of five. Excess requests are automatically rejected with HTTP 429 while the excess drains. The check reports how many reached the backend and how many nginx rejected. The separate benign suite needs a successful authenticated login with a disposable lab account.
