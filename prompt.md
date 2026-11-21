# PROMPT.md — Person B (Offense / Evidence / UI)

> Feed this file to your AI coding assistant, or follow it yourself. It is the complete brief
> for **Person B's** half of PS6 "Shield Wall". It assumes **Person A has already started
> building the WAF/infra on his Linux VM** and is pushing to the same git repo.

---

## 0. Who you are and the one big idea

You are **Person B**, working on **Windows (Docker Desktop + WSL2/Git Bash)**. You do **not** need a VM.
Everything in this project is Docker, so you **run the whole stack locally on Windows** to develop and
test your parts. You and Person A collaborate **only through git** (configs + scripts), and the team does
the **final scored run on one agreed "demo machine"** (A's VM or your laptop — decide this early).

**You are NOT blocked waiting for A.** Build your scripts and dashboard immediately. Anything that needs the
live WAF, you first build against **sample data**, then point at the real stack once A's compose is in the repo.

**Problem (PS6):** protect a legacy web app at the edge with a WAF. Stand up a vulnerable app, attack it,
prove the WAF blocks every attack while real users pass, with centralized logs, an alert summary, a dashboard,
and an ATT&CK mapping. **One app only: OWASP Juice Shop** (DVWA is a fallback).

---

## 1. Division of ownership (do not build A's files)

**Person A owns (infra / defence) — you consume these from git, you don't write them:**
- `docker-compose.yml` (WAF + Juice Shop, env-driven, pinned digests)
- `certs/` + `scripts/gen-certs.sh` (TLS)
- `waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` (tuning — **you feed A the rule IDs**, A writes them)
- `waf/nginx-ratelimit.conf` (rate limiter), `waf/virtual-patch.conf`
- The nginx logging config (access log + request-id) — **see the contract in §4, which you must give A**

**You (Person B) own (offense / evidence / UI):**
- `tests/attack.sh` — ≥6 attack classes
- `tests/benign.sh` — ≥20 normal requests, **scored by expected outcome**
- `tests/runner.py` (or `.sh`) — the replay runner that assigns run/case IDs and records results
- `tests/acceptance.sh` — the pass/fail scorer
- `tests/samples/` — fake log + replay records to develop the summarizer offline
- `dashboard/summarize.py` — joins access+audit+replay → `alerts.json`
- `dashboard/serve.py` — serves the sanitized dashboard on loopback
- `dashboard/index.html` + `dashboard/vendor/chart.min.js` (offline Chart.js)
- `report/REPORT.md` + `report/evidence/` — tuning notes, alert summary, ATT&CK/CWE/D3FEND, screenshots

---

## 2. Your environment (verified on this laptop)

- Windows 11 + **Docker Desktop (WSL2 backend)** + Docker Compose v2 — present
- **Python 3.14** — present (use **standard library only**; no pip installs needed)
- **Git Bash** + WSL2 — present (run shell scripts with `bash tests/attack.sh`)
- **curl** — present on host
- **NOT on host (don't use directly):** `jq`, `openssl`, `nmap`. Use Python instead of jq; attack tools run in the Kali container.
- Images already pulled: `owasp/modsecurity-crs:nginx`, `bkimminich/juice-shop`, `kalilinux/kali-rolling`, `alpine:3.19`.

---

## 3. GOLDEN RULES (these are where marks are won or lost)

1. **Score benign by EXPECTED OUTCOME, never "not 403".** A `404`, `5xx`, a timeout, or a rate-limited `429`
   on the legitimate login = **FAIL**, not a pass. Browsing must return the intended page; search must return a
   valid search body; login must return `200` + a token/session.
2. **`429` (rate limit) ≠ `403` (WAF block).** They are different mechanisms. Report them separately.
3. **Don't claim "every login blocked."** With `burst=5 nodelay`, early burst requests are admitted. Report
   **admitted vs rejected counts** and recovery.
4. **Summarizer joins FROM THE SCHEDULE, not the logs.** Start with one row per scheduled request (= the
   denominator). LEFT-join logs. A success may have no audit record; a timeout may have no edge record — keep
   them in the denominator. **Missing = failure.** (Self-test: 18 ok + 2 timeouts ⇒ 18/20 = 90% FAIL, never 100%.)
5. **"before the WAF" = DetectionOnly, not a bypass port.** Describe it as "forwarded in detection mode, denied
   in blocking mode." Never expose the app on a second host port.
6. **No jq.** Parse logs in Python.
7. **Offline-first.** Commit a local copy of Chart.js (`dashboard/vendor/chart.min.js`). No CDN. Serve on
   **loopback (127.0.0.1)** only. Strip passwords/cookies/tokens from anything the dashboard shows.
8. **LF line endings.** Ensure `.gitattributes` forces LF on `*.sh`/`*.py`/`*.conf` so your scripts don't break
   on A's Linux VM. Run scripts as `bash x.sh` (not `./x.sh`).

---

## 4. CONTRACT with Person A (send him this — you depend on it)

Your evidence pipeline needs A's nginx to emit correlation data. **Tell A to configure:**

1. **Return the request id in a response header** on **all** responses (200/403/429):
   `add_header X-Request-ID $request_id always;`
2. **Pass it to ModSecurity** so it appears in the audit log:
   `modsecurity_transaction_id $request_id;`
3. **Write a JSON access log** to the shared volume `logs/nginx/access.log` with **at least** these fields:
   ```
   {"request_id","time","method","uri","status","upstream_status","limit_req_status","user_agent"}
   ```
4. **Write the ModSec audit log (JSON)** to `logs/modsec/audit.log` (already in the compose env).
5. Shared volume layout both sides agree on:
   ```
   logs/nginx/access.log      # every request (A produces, B reads)
   logs/modsec/audit.log      # rule hits only (A produces, B reads)
   tests/results/run-*.jsonl  # replay results (B produces)
   ```
6. WAF endpoint for local testing: **https://localhost:8443** (TLS), app is NOT published directly.

If A's config isn't ready yet, develop against `tests/samples/` (see §6) and swap in the real logs later.

---

## 5. Build order (so you never wait on A)

- **Now (no dependency):** write `attack.sh`, `benign.sh`, the runner, and build `summarize.py` + the dashboard
  **against `tests/samples/`**. Prove the summarizer with the 18/20 self-test.
- **When A pushes a working `docker-compose.yml`:** `git pull`, run the stack **locally on Windows**, point your
  runner at `https://localhost:8443`, and replace sample data with real logs.
- **During tuning:** run the suites, collect firing rule IDs + matched variable, **hand them to A** (he writes the
  exclusions). Re-run after each change.
- **Last:** wire the live dashboard, capture evidence, finish the report, rehearse the demo.

---

## 6. Task specs (what to build)

### 6.1 Identify Juice Shop routes (5 min)
Confirm the real routes (command-line, not browser `#/`):
- Home/liveness (end-to-end): `GET /rest/products/search?q=apple` → `200` + JSON (`/healthz` is nginx-only, don't rely on it)
- Product search: `GET /rest/products/search?q=<term>`
- Login: `POST /rest/user/login` with JSON `{"email","password"}` → `200` + `{ "authentication": { "token": ... } }`
- Default creds for a successful login: `admin@juice-sh.op` / `admin123` (verify on your instance)

### 6.2 `tests/attack.sh` — ≥6 classes (all via https://localhost:8443)
Send each through the WAF; expect the status shown. Every request carries a case-id (see 6.4).
| Class | Request | Expect |
|---|---|---|
| SQL injection | `/rest/products/search?q='))%20UNION%20SELECT...--` | 403 |
| XSS | `/rest/products/search?q=<script>alert(1)</script>` | 403 |
| Path traversal | `/ftp/..%2f..%2f..%2fetc%2fpasswd` | 403 |
| OS command injection | search/param containing `;cat /etc/passwd` | 403 |
| Scanner user-agent | any path with `-A sqlmap/1.8` | 403 |
| Login brute-force burst | 20+ rapid `POST /rest/user/login` | 429 (rate-limited) |
Optional: run real `sqlmap`/`ffuf` from the Kali container for the live demo. **Attack only your own lab.**

### 6.3 `tests/benign.sh` — ≥20 requests, expected-outcome
Mix of: home/search/product browsing (expect 200 + body), a couple of category/search queries, and **one or two**
correct-credential logins (expect 200 + token — keep it to 1–2 so the limiter doesn't trip it). Each request
records its **expected outcome** so the runner can judge pass/fail (not just the status code).

### 6.4 `tests/runner.py` — the replay runner (the backbone of your evidence)
- Assigns `run_id` (per run) and `case_id` (per request) up front; stores each request's **expected outcome**.
- Sends the request (via curl or `http.client`), captures the response status **and the `X-Request-ID` header**.
- Writes one JSONL row per scheduled request to `tests/results/run-<id>.jsonl`:
  ```
  {"run_id","case_id","suite":"attack|benign","expected","status","request_id","passed":true|false,"note"}
  ```
- **On timeout/no response:** still write the row (keep `case_id`, `request_id=null`, `passed=false`). This row
  MUST remain in the denominator.
- Test correlation on one 200, one 403, one 429 before trusting it.

### 6.5 `dashboard/summarize.py` — join + score (standard library only)
- Inputs: `tests/results/run-*.jsonl` (schedule = source of truth), `logs/nginx/access.log`, `logs/modsec/audit.log`.
- **Start from the replay rows** (denominator). LEFT-join access + audit by `request_id`.
- Count each blocked request **once** even if multiple CRS rules matched.
- Compute: total, allowed vs blocked, benign pass-rate **by expected outcome**, blocks grouped by attack type,
  top firing rule IDs.
- Write `dashboard/alerts.json`. Strip secrets (passwords/cookies/tokens).
- Provide `--selftest` that asserts the **18 ok + 2 timeout ⇒ 18/20 = 90% FAIL** case using `tests/samples/`.
- Provide `--list-rules <audit.log>` that prints `ruleId | count | matched-var | sample-uri` (replaces jq).

### 6.6 `dashboard/index.html` + `dashboard/serve.py`
- `index.html`: local Chart.js (`vendor/chart.min.js`, committed). Show KPI tiles (total / blocked / allowed /
  pass-rate vs 95%), a bar chart of blocks by attack type, a table of top rule IDs, and the run-id + timestamp
  **on screen** (so a browser refresh never shows a stale run). Each row links to its `request_id` evidence.
- `serve.py`: serve the **sanitized** dashboard dir on `http://127.0.0.1:8099` with `http.server`. Loopback only.
- **Demo hygiene:** re-run `summarize.py` after each attack run to regenerate `alerts.json`.

### 6.7 `tests/acceptance.sh` — the scorer (run before judging)
Prints PASS/FAIL for:
- 5 exploit classes (SQLi, XSS, traversal, cmdi, scanner) return **403**
- brute-force burst: excess logins **429**, reported as admitted/rejected counts in order
- benign ≥ 95% by **expected outcome** (e.g. 19/20); successful login shown separately
- TLS 1.2+ only, cert trusted for `shield.local` (uses `curl --cacert`, never `-k`)
- summary built from access+audit+replay; dashboard renders
> Before scoring, confirm blocking mode is really active (env changes need recreate, not restart):
> `docker compose up -d --force-recreate waf` then grep `SecRuleEngine`.

### 6.8 `report/REPORT.md` + evidence
- Tuning notes (which rule IDs, why each exclusion, kept narrow), the alert-summary table (from `alerts.json`),
  before/after evidence (DetectionOnly forwarded → blocked with engine On), TLS scan output, ordered 429s.
- **ATT&CK / CWE / D3FEND mapping:** T1190 (CWE-89/CAPEC-66; CWE-22/CAPEC-126; CWE-78), T1595.002 (simulated
  scanner indicator), T1110. D3FEND: Inbound Traffic Filtering, Network Traffic Analysis. Mitigations: M1050, M1037, M1031.
- Report numerator/denominator, not slogans. State which case (if any) remained open.

---

## 7. Your "done" checklist
- [ ] `attack.sh` (6 classes) + `benign.sh` (≥20, expected-outcome) written and case-id tagged
- [ ] `runner.py` writes one row per request incl. timeouts; correlation tested on 200/403/429
- [ ] `summarize.py` passes `--selftest` (18/20 = 90% FAIL) and builds `alerts.json`
- [ ] Dashboard renders offline on `127.0.0.1:8099`, shows run-id/timestamp, secrets stripped
- [ ] `acceptance.sh` runs green against the live local stack on Windows
- [ ] REPORT.md + evidence + ATT&CK mapping complete
- [ ] Contract (§4) sent to Person A and confirmed

## 8. Cross-platform / git notes
- Pull A's changes often: `git pull`. Keep `logs/` and `certs/` git-ignored (machine-specific).
- `.gitattributes` must force **LF** on `*.sh *.py *.conf` (ask A to add it, or add it yourself).
- Run shell scripts as `bash tests/attack.sh`. For Docker volume mounts from Git Bash, prefix tricky commands
  with `MSYS_NO_PATHCONV=1`.
- Final scored run happens on the agreed **demo machine**; verify your `acceptance.sh` passes there too.

## 9. First three commands to start right now
```bash
# 1. make your folders
mkdir -p tests/samples tests/results dashboard/vendor report/evidence
# 2. (while A finishes the stack) build + prove the summarizer on fake data
python dashboard/summarize.py --selftest
# 3. once A has pushed docker-compose.yml:
git pull && docker compose up -d && bash tests/acceptance.sh
```
