# PS6 Shield Wall

Shield Wall protects a local OWASP Juice Shop lab with an nginx reverse proxy, ModSecurity, and the OWASP Core Rule Set. The team runs the integrated stack in the Ubuntu demo VM.

- `edge-stack` contains Person A’s proxy, TLS, WAF configuration, and edge checks.
- `demo-evidence` contains Person B’s acceptance evidence, alert summary, and dashboard.

Keep lab credentials, TLS keys, and raw logs local. Share sanitized evidence through the repository.
