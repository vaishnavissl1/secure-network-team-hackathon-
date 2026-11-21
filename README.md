# PS6 Shield Wall

Shield Wall is a 23CSE336 Secure Networks Hackathon project that puts an HTTPS security gateway in front of OWASP Juice Shop. nginx receives requests, ModSecurity evaluates them with the OWASP Core Rule Set (CRS), and a login rate limiter rejects excess requests. The dashboard lets an evaluator trace a result to the logs by request ID.

## What is built

| Component | Implementation |
| --- | --- |
| Vulnerable storefront | OWASP Juice Shop on an internal Docker network with no host port |
| Reverse proxy | nginx terminates TLS 1.2 and 1.3, redirects HTTP, and forwards accepted requests to Juice Shop |
| Web application firewall | ModSecurity in blocking mode with CRS, paranoia level 1 and inbound threshold 5 |
| Login rate limiter | Per client IP, 1 request per second with a burst allowance of 5 for login POSTs. Excess requests get HTTP 429. |
| Logging and monitoring | JSON nginx access log, relevant ModSecurity audit events, request-ID correlation, and a dashboard with live activity and published test evidence |

```text
Windows browser ── SSH tunnel ── Ubuntu VM
                                   │
                           nginx + ModSecurity
                            HTTPS :8443 on loopback
                                   │
                         internal Docker network
                                   │
                             Juice Shop :3000

nginx access + ModSecurity audit + shopper outcomes → summary → dashboard :8099
```

## Run the lab on Ubuntu

Use Docker Engine with Compose v2, Bash, OpenSSL, curl, and Python 3. The two image digests in [docker-compose.yml](docker-compose.yml) must be cached locally. Startup is configured for offline use. Keep VirtualBox in NAT mode for the laptop demo.

```bash
bash scripts/up.sh
bash scripts/verify-edge.sh
bash scripts/verify-waf.sh
bash scripts/verify-rate-limit.sh
```

The HTTPS storefront is at `https://localhost:8443/` inside the VM. The local certificate covers `localhost`, `127.0.0.1`, and `shield.local`. To test with certificate validation, run:

```bash
curl --cacert certs/server.crt -fsS https://localhost:8443/healthz
```

Port 8080 redirects to HTTPS. Both edge ports are bound to VM loopback. To stop the lab, run `bash scripts/down.sh`.

## Publish a fresh demo run

Register an ordinary shopper in the local storefront, then run the command below from the project directory and enter the shopper credentials when prompted. The run verifies the edge, policy block, login throttling and recovery, then checks 20 browsing, search, and login cases. It publishes a new summary after the evidence checks pass.

```bash
bash scripts/run_demo.sh
```

Keep shopper credentials, the TLS private key, and raw logs local. Run evidence is stored under `logs/demo-*/`. The [sanitized VM result](report/evidence/vm-run.json) can be shared.

## Open the evaluator dashboard

For the already deployed laptop demo, start the VM and use the loopback SSH forwards in the [six-minute demo guide](report/DEMO.md). Open the [dashboard](http://127.0.0.1:8099/) and [storefront](https://localhost:8443/). Open [Live activity](http://127.0.0.1:8099/activity/) to watch the VM gateway during the demo. Use Evidence for the latest published test run. Overview, Controls, and Demo Guide explain the configuration and walkthrough.

For a fresh UI deployment, build from the licensed Estate Next.js project on your laptop. The repository contains the project-specific overlay. The build requires the licensed template and Node/npm. The resulting site runs offline. The demo guide includes the transfer command.

```powershell
python dashboard/build_estate.py "C:\Users\athis\Downloads\estate-nextjs\nextjs"
```

After deploying `dashboard/site/` to the VM, serve the UI with:

```bash
python3 dashboard/serve.py
```

## Demonstrate live requests

Open the storefront and live activity in separate browser tabs. Live activity can launch the three fixed checks using **Scanner header**, **WAF policy**, or **Login throttling**. Each button selects the verified event from the live logs. Checks are serialized and accept no custom input. Sign in to Juice Shop and filter Live activity for `/rest/user/login`. The new login lists HTTP 200, upstream 200, and the request ID. Run `bash scripts/verify-waf.sh` in the VM and search Live activity for its printed request ID. The matching 403 lists the correlated CRS rules. The live view refreshes every two seconds. It exposes a bounded set of recent events from the two VM logs and omits credentials, header values and bodies.

## Run acceptance checks

On the Ubuntu VM, with the stack running, use:

```bash
bash tests/acceptance.sh
```

This is **defensive verification**. It verifies TLS and edge isolation, the harmless WAF policy block, credential-free login throttling and recovery, and the 20 shopper cases. Use an ordinary lab shopper when prompted. To reuse an existing set of shopper outcomes, pass `--shopper-results logs/demo-XXXXXXXX/shopper.jsonl`. The controls still run live, and the report labels the shopper evidence by its original run ID.

For **replay evidence**, supply the result file and the matching log files. This mode only reads evidence. It runs on Windows Git Bash as well as Ubuntu.

```bash
bash tests/acceptance.sh --replay path/to/results.jsonl --access path/to/access.log --audit path/to/audit.log
```

Each check prints **PASS**, **FAIL**, or **NOT RUN**. Defensive verification always marks Full replay **NOT RUN**. In replay mode, TLS and edge checks are **NOT RUN** and the Full replay verdict depends on a complete, correlated replay. Exit codes are `0` for a passed mode, `1` for a failed check affecting its verdict, and `2` when required evidence or prerequisites are missing. Reports go to `tests/results/acceptance-*/verdict.json`. Use `bash scripts/run_demo.sh` separately to publish the dashboard.


## Follow a request across the logs

| Evidence | What to look for |
| --- | --- |
| Browser response | `X-Request-ID` on success and on 403/429 responses |
| `logs/nginx/access.log` | JSON with the request ID, HTTP status, upstream status, rate-limit decision, URI, and user agent |
| `logs/modsec/audit.log` | Relevant JSON events. `transaction.unique_id` matches the same request ID. Rule IDs explain a WAF decision. |
| `dashboard/alerts.json` | The latest published summary. Includes the ordinary shopper results and defensive control checks. |

An upstream 200 confirms the application answered. A WAF 403 with an interrupted audit transaction and empty upstream status confirms it was stopped at the edge. A 429 with `limit_req_status=REJECTED` identifies rate limiting. The current scoped CRS tuning and its browser retest are in [tuning notes](report/tuning-notes.md).

## Verified results

| Test | Ubuntu VM result |
| --- | --- |
| Ordinary shopper requests | 20/20 passed, including successful login. Target ≥95%. |
| TLS and backend isolation | TLS 1.2 and 1.3 passed. TLS 1.1 failed. Juice Shop had no published port. |
| Harmless WAF policy probe | 403 before upstream processing. CRS rules 920420 and 949110 correlated across the logs. |
| Credential-free login burst | 7/12 reached Juice Shop. nginx rejected 5/12 with 429. Browsing and recovery passed. |
| Browser | Four dashboard pages and the storefront loaded. Evidence filtering and a 390-pixel viewport were checked. |

The earlier Windows run recorded five attack-category WAF blocks and 20 of 25 wrong-password requests rate-limited. A complete six-category replay on Ubuntu remains unverified. The burst allowance admits some requests, so the historical burst does not establish that every attempt was blocked. See the [results and ATT&CK mappings](report/REPORT.md).

## Repository map

| Path | Purpose |
| --- | --- |
| `docker-compose.yml` and `waf/` | Service isolation, HTTPS proxy, rate limiting, CRS policy and tuning |
| `scripts/` | Start and stop, generate certificates, verify controls, and publish a demo run |
| `tests/` | Shopper cases and runner, benign entry point, and passive acceptance scorer entry point |
| `dashboard/` | Correlate JSON logs, build the Estate overlay, and serve the static site and summary |
| `ui/overlay/` | Project-owned Next.js layouts, four routes, and evidence views |
| `report/` | Demo instructions, results, tuning notes, and shareable evidence |
