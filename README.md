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
