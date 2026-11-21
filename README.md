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

Run `bash scripts/verify-waf.sh` to check effective blocking mode and trace a reserved, harmless readiness request. Rule `10001` is a lab check. Its result verifies the WAF and logging path for that request.

nginx returns `X-Request-ID` on successful and denied requests. Both logs are in the project’s `edge-logs` Docker volume. The nginx record has `request_id`, `status`, `upstream_status`, `limit_result`, `method`, `uri`, and `time`. A WAF event uses `transaction.unique_id` and reports rule IDs in `transaction.messages[].details.ruleId`. An allowed request can have only a proxy record. WAF messages can include match details, so use sanitized fields in shared evidence.

```bash
mkdir -p logs
docker compose exec -T waf cat /var/log/modsecurity/audit/access.jsonl > logs/access.jsonl
docker compose exec -T waf cat /var/log/modsecurity/audit/modsec.jsonl > logs/modsec.jsonl
```

For a before/after comparison inside the isolated lab, set `SHIELD_RULE_ENGINE=DetectionOnly` on the Compose up command, then run Compose up again with `SHIELD_RULE_ENGINE=On` to restore blocking. `verify-waf.sh` requires blocking mode.

## Tuning notes

Start with CRS paranoia level 1 and inbound threshold 5. The before-CRS file has the readiness rule and zero tuning exclusions. Add an exclusion only after a benign request fails and the audit log identifies the rule and input field. Record the request ID, scoped change, and retest outcome.
