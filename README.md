# PS6 Shield Wall

Shield Wall protects a local OWASP Juice Shop lab with nginx, ModSecurity, and the OWASP Core Rule Set. Run the integrated stack in the Ubuntu demo VM with VirtualBox NAT enabled.

## Start and check the edge

On the VM, use Docker Compose v2, Bash, OpenSSL, curl, and Python 3. The Compose file pins the two cached image digests and disables pulls.

```bash
bash scripts/up.sh
bash scripts/verify-edge.sh
```

The runner can use `https://localhost:8443` on VM loopback with `certs/server.crt` as its trust certificate. The certificate also covers `shield.local`. HTTP on port 8080 redirects to HTTPS. Juice Shop is attached only to the internal Docker network and has no published port.

Run `bash scripts/down.sh` when you need to stop the lab. Keep lab credentials, TLS keys, and raw logs local. Person B can develop the evidence summary and dashboard on Windows and verify against sanitized records from the VM.

## Correlate proxy and WAF events

Run `bash scripts/verify-waf.sh` to check effective blocking mode and trace a harmless request with an unsupported media type. It verifies that CRS rule `920420` contributes to an inbound block by rule `949110` and that the audit event matches the proxy record.

nginx returns `X-Request-ID` on successful and denied responses. `scripts/up.sh` prepares the two host log files and Compose mounts them for live writes.

| File | Format and fields |
| --- | --- |
| `logs/nginx/access.log` | One JSON object per line with `request_id`, `time`, `method`, `uri`, `status`, `upstream_status`, `limit_req_status`, and `user_agent`. |
| `logs/modsec/audit.log` | One JSON object per line. Join `transaction.unique_id` to `request_id`. Rule IDs are in `transaction.messages[].details.ruleId`. |
| `tests/results/` | Replay results produced by the runner. |

The access log uses numeric `status` and an empty string for `upstream_status` or `limit_req_status` when that phase did not run. `uri` excludes the query string. The health check appears with the `shield-wall-healthcheck` user agent. Join the runner records to the access log by request ID and treat a WAF audit record as optional for ordinary traffic and nginx limiter responses. Use sanitized fields in shared evidence because WAF messages can include match details.

For a before/after comparison inside the isolated lab, recreate the WAF with the requested engine mode and restore blocking before the scored checks. `verify-waf.sh` requires blocking mode.

```bash
SHIELD_RULE_ENGINE=DetectionOnly docker compose up -d --force-recreate waf
SHIELD_RULE_ENGINE=On docker compose up -d --force-recreate waf
```

## Tuning notes

Start with CRS paranoia level 1 and inbound threshold 5. The before-CRS file starts with zero tuning exclusions. Add an exclusion only after a benign request fails and the audit log identifies the rule and input field. Record the request ID, scoped change, and retest outcome.

## Verify the login limiter

Run `bash scripts/verify-rate-limit.sh` on the VM. It sends a bounded set of requests with no credentials to the fixed loopback endpoint and checks the responses, the nginx limiter decision, browsing, and recovery. The login route allows one request per second per client IP with a burst allowance of five. Excess requests are automatically rejected with HTTP 429 while the excess drains. The check reports how many reached the backend and how many nginx rejected. The separate benign suite needs a successful authenticated login with a disposable lab account.
