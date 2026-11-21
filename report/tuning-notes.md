# Tuning notes (Person B -> Person A)

Run `20261121-105637`, CRS 4.30.0, paranoia level 1, inbound threshold 5.

## False positives
Benign suite: 20/20 passed by expected outcome (19 GET requests returning 200, 1 correct-credential login returning 200 plus a token). No benign request fired a blocking rule.

The original 20 requests required no exclusion. Browser verification subsequently identified an additional normal route.

If a later run does show a false positive, record it here as: request ID, rule ID, matched variable, and a proposed exclusion scoped to that route only, for example
`SecRule REQUEST_URI "@beginsWith /rest/products/search" "id:1000xx,phase:1,pass,nolog,ctl:ruleRemoveTargetById=<ruleId>;ARGS:q"`.
Never remove a rule globally.

## Observations for A (no action required)
- Rule 920350 (numeric-IP Host header) fires on every request if a client connects with `Host: 127.0.0.1`. The runner sends `Host: shield.local:8443` to avoid it. It is not a false positive in the scored run.
- Path-form traversal (`..%2f` in the URI path) is rejected by nginx with 400 before ModSecurity runs. If the team wants a WAF 403 for it, that would be a change on A's side. It is stopped either way.
- The Ubuntu run passed 20/20 with the checked-in certificate setup and no new CRS exclusions. Preserve the owner-only certificate directory prepared by the VM script.

## Browser regression on the Ubuntu VM

Chrome loaded the catalog but repeated ordinary Engine.IO polling POSTs received a 403. Audit transaction `d36371cc6bfd6958558f7fb691f980ee` identified `TX:content_type`, rule 920420 and the inbound denial 949110. Engine.IO sent text/plain. Rule 1000101 adjusts the allowed media type only for POST /socket.io/ with Engine.IO version 4, polling transport and the exact text/plain header (optionally UTF-8). CRS continues inspecting the request. Refresh the single-file bind mount with a WAF-only Compose recreation after replacing its host file.

After the change the proxy recorded a polling POST with status 200 and upstream 200. A fresh Chrome session displayed the catalog with zero observed HTTP or JavaScript errors. The separate media-policy probe still received 403, correlated to both rules under request ID `395e0ea0b7fcd109629fe5a3c7a214e6`.