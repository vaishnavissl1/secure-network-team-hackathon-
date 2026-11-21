# PS6 "Shield Wall" — Report

## Ubuntu VM verification

Run `vm-20261121T060926Z-d776b8` passed **20 of 20** ordinary shopper requests, including a real successful login. Both TLS 1.2 and 1.3 negotiated, TLS 1.1 failed, and Juice Shop had no host port. A harmless content-type probe received 403 before upstream processing. Request `061e2a63a483ed8f34bd6b4893d9f005` matched CRS policy rule 920420 and inbound block rule 949110. Of twelve credential-free login probes, seven reached the application and five received 429 at nginx. Browsing and login-route recovery passed.

The independent VM run covers these controls and shopper traffic. The five attack-category outcomes and original 25-request burst below come from the team's earlier Windows run. The VM evidence does not establish a six-category VM pass. See [demo instructions](DEMO.md) and the [sanitized VM run](evidence/vm-run.json).

Chrome on Windows opened all four VM dashboard pages, filtered the request table from 20 rows to one, and rendered the evidence page at 390 px without horizontal page overflow. The final browser run also displayed the protected Juice Shop catalog. It observed zero dashboard or storefront HTTP/JavaScript errors. The [tuning notes](tuning-notes.md) document the browser false positive and its separate retest.

## 1. Setup
- App behind the WAF: **OWASP Juice Shop** (private backend, no host port).
- WAF: nginx + ModSecurity 3 + OWASP CRS v4, Paranoia Level 1, anomaly threshold 5, TLS 1.2+.
- Image digests (demo machine): `owasp/modsecurity-crs@sha256:697812147e7eada5c668e9728c6439d4663476c69f68635d24fb7878aac0f26a` (CRS 4.30.0, nginx 1.30.7), `bkimminich/juice-shop@sha256:adaf6a6ca50f772dff7d2fe56972c659e81a61e0dbbe607c2b39fefd436e6153`
- Demo machine: Windows 11 laptop (Docker Desktop/WSL2) for this run, re-verified against A's latest `edge-stack` commit (`e45ac8c`): 53 requests in the historical Windows report.

## 2. Historical Windows acceptance results
| Check | Result |
|---|---|
| Exploit classes blocked (SQLi, XSS, traversal, cmdi, scanner) | 5/5 returned 403 with CRS rule hits in the audit log (scanner: rule 913100) |
| Brute-force: admitted / rejected(429) / recovered | 5 admitted (401) / 20 rejected (429) of 25 wrong-password logins / yes (valid login 200 afterwards) |
| Benign pass-rate by expected outcome | 20/20 = 100% (target 95%), includes 1 successful login (200 + token) |
| TLS 1.2+ only, cert trusted for shield.local | PASS: `curl --cacert` OK with TLS 1.2; a client capped at TLS 1.1 is refused |
| Alert summary + dashboard render | PASS: `alerts.json` built from schedule + access + audit; dashboard served on 127.0.0.1:8099 |

> A scored WAF block = a matching CRS rule for the category **+** an inbound block decision **+**
> the backend did not process the request. A bare 403 alone is not enough.

## 3. Tuning notes (false positives)
List each exclusion with evidence (never a global rule removal):
| Benign case | Rule id | Matched var | Scope (route) | Why |
|---|---|---|---|---|
| none | none | none | none | 0 of 20 benign requests were blocked or degraded at PL1 / threshold 5 |
The historical Windows suite had no false positives across its 20 cases. Ubuntu browser testing later found a Socket.IO polling false positive, which was addressed with a scoped media-type adjustment. See [tuning notes](tuning-notes.md).

## 4. Alert summary by attack type
Each blocked request is counted once under its primary attack type (run `20261121-105637`):

| Attack type | Blocked requests (403) | Key CRS rules |
|---|---|---|
| SQL injection | 1 | 942100, 942190, 942270, 942360 |
| XSS | 1 | 941100, 941110, 941160, 941390 |
| Path traversal | 1 | 930100, 930110, 930120 |
| OS command injection | 1 | 930120, 932160 |
| Scanner user-agent (`sqlmap/1.8`) | 1 | 913100 |

Every block also fires 949110 (inbound anomaly score exceeded). Of 53 requests, 5 received a WAF 403, 20 received a limiter 429, 22 succeeded, 5 reached the app and returned 401, and 1 received an nginx 400.

## 5. Brute-force evidence
Ordered responses: valid login (200) → burst of 25 wrong-password logins: first 5 admitted (401), remaining 20 rejected (429) → valid login recovers (200).
This does **not** mean every login was blocked: the burst allowance admits the first 5.
Native nginx `limit_req` enforces the login rate limit.

## 6. Before / after
"Forwarded in detection mode, denied in blocking mode" — same requests, `SecRuleEngine DetectionOnly` vs `On`. Engine change applied with `up -d --force-recreate waf`, not `restart`. Evidence in `report/evidence/`.

| Case | DetectionOnly | Blocking (On) |
|---|---|---|
| SQLi | 500 (reached the app) | 403 |
| XSS | 200 (forwarded) | 403 |
| Path traversal (query form) | 200 (forwarded) | 403 |
| OS command injection | 200 (forwarded) | 403 |
| Scanner UA | 200 (forwarded) | 403 |

The app was only reachable through the WAF in both runs (no bypass port).

## 7. MITRE ATT&CK / CWE / D3FEND mapping
| Activity | ATT&CK | Weakness | D3FEND |
|---|---|---|---|
| Exploiting the app (SQLi/XSS/cmdi/traversal) | T1190 Exploit Public-Facing Application | CWE-89/CAPEC-66; CWE-22/CAPEC-126; CWE-78 | Inbound Traffic Filtering |
| Simulated scanner indicator (user-agent) | T1595.002 Vulnerability Scanning (simulated) | — | Network Traffic Analysis |
| Login brute force | T1110 Brute Force | — | Inbound Traffic Filtering |

Mitigations: M1050 Exploit Protection, M1037 Filter Network Traffic, M1031 Network Intrusion Prevention.
> The scanner row is a header match that *simulates* a scanner, labelled as such.

## 8. Open items
- **Path-form traversal** (`/ftp/..%2f..%2f..%2fetc%2fpasswd`, case `atk-trav-02`): nginx itself answers **400** before ModSecurity runs and never forwards it to the app. That is not a WAF 403, so it is reported separately and is not counted in the 5/5. The query-form traversal (`atk-trav-01`) is the scored 403 case.
- The scanner case is confirmed from the audit log rule 913100 (CRS scanner user-agent detection) and from `user_agent` in the nginx access log, which A added in the latest `edge-stack` commit.
- A complete six-category scored run on the Ubuntu VM remains unverified.
- The current [VM overview screenshot](evidence/vm-overview.png) shows the published defensive run.
- Team-size eligibility confirmation still open.
