# Tuning notes (Person B -> Person A)

Run `20261121-105637`, CRS 4.30.0, paranoia level 1, inbound threshold 5.

## False positives
Benign suite: 20/20 passed by expected outcome (19 GET requests returning 200, 1 correct-credential login returning 200 plus a token). No benign request fired a blocking rule.

No exclusion is proposed. A should leave `waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` as it is.

If a later run does show a false positive, record it here as: request ID, rule ID, matched variable, and a proposed exclusion scoped to that route only, for example
`SecRule REQUEST_URI "@beginsWith /rest/products/search" "id:1000xx,phase:1,pass,nolog,ctl:ruleRemoveTargetById=<ruleId>;ARGS:q"`.
Never remove a rule globally.

## Observations for A (no action required)
- Rule 920350 (numeric-IP Host header) fires on every request if a client connects with `Host: 127.0.0.1`. The runner sends `Host: shield.local:8443` to avoid it. It is not a false positive in the scored run.
- Path-form traversal (`..%2f` in the URI path) is rejected by nginx with 400 before ModSecurity runs. If the team wants a WAF 403 for it, that would be a change on A's side. It is stopped either way.
- On Windows/Docker Desktop a bind-mounted `certs/server.key` created with `umask 077` is unreadable by the nginx user inside the container (`Permission denied`). `scripts/gen-certs.sh` sets umask 077, so on Windows the key must be generated with a permissive umask. This only affects the Windows laptop, not the Linux VM.
