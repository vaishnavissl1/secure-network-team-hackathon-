# PS6 "Shield Wall" — Report

> Fill the **TODO** blanks during the run. Report numerator/denominator, not slogans.

## 1. Setup
- App behind the WAF: **OWASP Juice Shop** (private backend, no host port).
- WAF: nginx + ModSecurity 3 + OWASP CRS v4, Paranoia Level 1, anomaly threshold 5, TLS 1.2+.
- Image digests (demo machine): `TODO owasp/modsecurity-crs@sha256:…`, `TODO juice-shop@sha256:…`
- Demo machine: `TODO (Person A's Ubuntu VM / Windows laptop)`

## 2. Acceptance results (from `bash tests/acceptance.sh`)
| Check | Result |
|---|---|
| Exploit classes blocked (SQLi, XSS, traversal, cmdi, scanner) | TODO 5/5 (403) |
| Brute-force: admitted / rejected(429) / recovered | TODO N / M / yes |
| Benign pass-rate by expected outcome | TODO 19/20 = 95% PASS |
| TLS 1.2+ only, cert trusted for shield.local | TODO PASS |
| Alert summary + dashboard render | TODO PASS |

> A scored WAF block = a matching CRS rule for the category **+** an inbound block decision **+**
> the backend did not process the request. A bare 403 alone is not enough.

## 3. Tuning notes (false positives)
List each exclusion with evidence (never a global rule removal):
| Benign case | Rule id | Matched var | Scope (route) | Why |
|---|---|---|---|---|
| TODO | TODO | TODO | TODO | TODO |
> If zero false positives at PL1, say so and keep the original rules.

## 4. Alert summary by attack type
Paste the table from `dashboard/alerts.json` (`by_type` + `top_rules`). The dashboard shows the same data.

## 5. Brute-force evidence
Ordered responses: valid login (200) → burst (admitted then 429) → browsing works → valid login recovers (200).
Native nginx `limit_req` is the control; the optional ModSec counter (if shown) is demoed separately.

## 6. Before / after
"Forwarded in detection mode, denied in blocking mode" — same request, `MODSEC_RULE_ENGINE=DetectionOnly`
(forwarded) vs `On` (403). Engine change applied with `up -d --force-recreate waf`, not `restart`.

## 7. MITRE ATT&CK / CWE / D3FEND mapping
| Activity | ATT&CK | Weakness | D3FEND |
|---|---|---|---|
| Exploiting the app (SQLi/XSS/cmdi/traversal) | T1190 Exploit Public-Facing Application | CWE-89/CAPEC-66; CWE-22/CAPEC-126; CWE-78 | Inbound Traffic Filtering |
| Simulated scanner indicator (user-agent) | T1595.002 Vulnerability Scanning (simulated) | — | Network Traffic Analysis |
| Login brute force | T1110 Brute Force | — | Inbound Traffic Filtering |

Mitigations: M1050 Exploit Protection, M1037 Filter Network Traffic, M1031 Network Intrusion Prevention.
> The scanner row is a header match that *simulates* a scanner, labelled as such.

## 8. Open items
- TODO: any case that remained open, team-size eligibility confirmation, etc.
