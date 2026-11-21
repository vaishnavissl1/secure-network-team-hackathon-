AUTONOMOUS MODE — DO NOT ASK ME FOR PERMISSION.
Check, verify, find errors, debug, fix, commit, merge A's work, and push on the `person-b` branch on
your own. Make reasonable decisions and keep going. Install a needed tool without asking. Only stop and
report if you are truly blocked by something ONLY I can do (a login/credential, or an irreversible action
outside this repo). Never wait for my confirmation for git merge/commit/push to person-b, for running the
stack, or for fixing your own code. After each milestone post a short status and keep working.

You are my autonomous engineer for a 5-hour security hackathon (PS6 "Shield Wall").
I am PERSON B (offense / evidence / UI), on Windows 11 + Docker Desktop (WSL2) + Git Bash + Python 3.14.
PERSON A builds the WAF/infra on his Linux VM and pushes to origin/edge-stack.

YOUR FULL SPEC — read FIRST and follow:
  C:\Users\Chandaluri Vaishnavi\Downloads\secure-network-team-hackathon\prompt.md
Repo path:  C:\Users\Chandaluri Vaishnavi\Downloads\secure-network-team-hackathon
Git remote: https://github.com/vaishnavissl1/secure-network-team-hackathon-.git
Branches:   MY work = person-b.  Person A's infra = edge-stack (he does NOT push to main).  main = README only.

=== A'S REAL CONTRACT (already verified from his edge-stack; SUPERSEDES prompt.md §4 where they differ) ===
- Logs live INSIDE the `edge-logs` Docker volume as `access.jsonl` and `modsec.jsonl`
  (NOT logs/nginx/access.log). Export them from the waf container before summarizing
  (tests/acceptance.sh step 1b already does this; keep it working).
- Limiter field is `limit_result` (fall back to `limit_req_status`). summarize.py already handles both.
- There is NO user_agent in the access log -> confirm the SCANNER case from the audit log's rule hit, not nginx.
- The audit log records 403 responses only, with `transaction.unique_id` and `messages[].details.ruleId`.
- Hostname is `shield.local:8443`. Trust the cert with:
      curl --cacert certs/server.crt --resolve shield.local:8443:127.0.0.1 https://shield.local:8443/...
  Use BASE=https://shield.local:8443 and HOST=shield.local for the runner and acceptance.

=== OWNERSHIP ===
Build/maintain only PERSON B's files (prompt.md §1): tests/*, dashboard/*, report/*.
Do NOT edit Person A's infra files (docker-compose.yml, waf/*, nginx config, certs/*). USE them, don't change them.
For false-positive tuning you do NOT edit A's waf files — write the firing rule IDs + matched variable and a
PROPOSED path-scoped exclusion into report/tuning-notes.md for A to apply.

=== GIT WORKFLOW (run it yourself, autonomously — no asking) ===
- Stay on branch person-b (`git checkout person-b`).
- Integrate A continuously:  `git fetch origin` then `git merge origin/edge-stack`.
  Resolve conflicts yourself: for INFRA files (docker-compose.yml, waf/*, scripts/*, certs/*, .gitattributes,
  .gitignore) prefer A's version; for YOUR files (tests/*, dashboard/*, report/*) keep yours.
- Commit after each milestone: `git add -A` then `git commit -m "<clear msg>"`.
  Commit messages: plain, descriptive, NO AI/tool mention, NO "Co-Authored-By", NO "Generated with" lines.
- Push: `git push origin person-b`. If rejected, `git pull --no-rebase`, resolve, push again. All autonomous.
- HARD RAILS (never break, even in auto mode):
  * Only ever push to `person-b`. NEVER push to `main` or `edge-stack`. NEVER force-push.
  * NEVER commit secrets, keys, logs, or generated files (.gitignore already excludes
    certs/, logs/, tests/results/, dashboard/alerts.json, __pycache__).
  * Keep LF line endings (.gitattributes enforces this).

=== TOOLING / MCP ===
Standard tools already cover everything: bash, Python 3 (standard library only), Docker/Compose, git, curl.
No MCP server is needed. Install a tool only if a task genuinely requires it; prefer built-ins; add no
unnecessary deps (no pip for the summarizer/dashboard; no jq; the dashboard's charts are inline, offline).

=== AUTONOMOUS WORK LOOP ===
1. Read prompt.md + A's real contract above. `git fetch origin`; merge origin/edge-stack into person-b.
2. Verify independent work: `python dashboard/summarize.py --selftest` MUST print 18/20 = 90% FAIL.
   If anything is broken, fix it.
3. Bring the stack up locally on Windows: `docker compose up -d --force-recreate`. Wait for health.
4. Run the real suites against the WAF:
      python tests/runner.py --suite all --base https://shield.local:8443
   then export logs + build the summary + score:
      BASE=https://shield.local:8443 HOST=shield.local bash tests/acceptance.sh
   Debug and FIX any failures yourself (code, paths, field names, timing). Re-run until green or truly blocked.
5. On benign false positives: put rule IDs + matched var + a proposed narrow exclusion in report/tuning-notes.md
   (do NOT edit A's waf files). Keep the suites honest (expected-outcome scoring; 429 != 403; join from schedule).
6. Open the dashboard to confirm it renders (`python dashboard/serve.py` -> http://127.0.0.1:8099).
7. Commit + push person-b. Then `git fetch` again; if A advanced, merge and repeat from step 3.

=== NON-NEGOTIABLE RULES (prompt.md §3) ===
- Score benign by EXPECTED OUTCOME (404/5xx/timeout/login-429 = FAIL, not pass).
- 429 (rate limit) != 403 (WAF block); report separately; never claim "every login blocked".
- summarize.py joins FROM THE SCHEDULE (one row per scheduled request = denominator); missing = fail.
- "before the WAF" = DetectionOnly, never a bypass port. Engine-mode change needs `--force-recreate`.
- Python standard library only; NO jq; offline dashboard; serve on 127.0.0.1 only; strip secrets.
- LF line endings; run shell scripts as `bash x.sh`.

REPORTING: after each milestone, post 3-5 lines (what you did, what you committed/pushed, what's next, anything
truly blocking) and KEEP GOING without waiting for me. Start now: read prompt.md, fetch, merge edge-stack, and run.
