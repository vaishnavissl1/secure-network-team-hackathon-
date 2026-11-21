# Laptop evaluator demo

The Ubuntu VM runs Juice Shop, the WAF, and the evidence dashboard. Windows displays them through two loopback SSH forwards. Leave VirtualBox in NAT mode.

## Open the demo

Start the Ubuntu VM. On Windows open [Shield Wall](http://127.0.0.1:8099/) and the [protected storefront](https://localhost:8443/). If the tunnel has closed, open this in PowerShell and leave that window running.

```powershell
ssh -N -o ExitOnForwardFailure=yes -i "$env:USERPROFILE\.ssh\hackvm_ed25519" -p 2222 -L 127.0.0.1:8099:127.0.0.1:8099 -L 127.0.0.1:8443:127.0.0.1:8443 athish@127.0.0.1
```

If SSH reports that a local port is already in use, check whether the existing dashboard and storefront already open. The storefront uses a self-signed lab certificate. To check it before presenting, run the VM command below. Chrome users can compare the certificate's SHA-256 fingerprint with the output. The VM checks trust the specific lab certificate.

```bash
cd ~/hack/shield-wall
openssl x509 -in certs/server.crt -noout -fingerprint -sha256
curl --cacert certs/server.crt -sS -o /dev/null -w '%{http_code}\n' https://localhost:8443/
```

If the VM restarted, open a second PowerShell window and connect to the VM.

```powershell
ssh -i "$env:USERPROFILE\.ssh\hackvm_ed25519" -p 2222 athish@127.0.0.1
```

```bash
cd ~/hack/shield-wall
bash scripts/up.sh
python3 dashboard/serve.py
```

Start the Python server only when the dashboard listener is down. Leave the server running. The published evidence survives a reboot. Use another SSH terminal for live checks.

## Present in six minutes

| Time | Show | Explain |
| --- | --- | --- |
| 0–1 min | Storefront, then Overview | Browse the catalog over HTTPS. Show the run ID. Juice Shop has no published port. |
| 1–2 min | Controls | Show TLS versions, the 403, the two CRS rule IDs and the request ID. The empty upstream status verifies enforcement before the app. |
| 2–3 min | Login limiter on Controls | Give the measured counts. Early requests reach Juice Shop. Excess requests get 429 from nginx. Browsing and login-endpoint recovery were checked. |
| 3–4 min | Evidence | Filter for `ben-20`. Copy its request ID and find it in the proxy log with `grep -F -- 'PASTE_ID' logs/nginx/access.log` on the VM. Show the 20/20 result and the genuine successful shopper login. |
| 4–5 min | VM terminal | Run `bash scripts/verify-waf.sh`. It prints a fresh request ID and verifies the harmless policy block in both logs. This single check leaves the displayed run unchanged. |
| 5–6 min | Controls and the report | Attribute the five attack-category results to the recorded Windows run. Show the mapping table. Explain that a limiter with a burst allowance admits some requests before enforcement. |

To publish another complete defensive run, register an ordinary shopper in the local storefront and keep its login details in your terminal. On the VM run `bash scripts/run_demo.sh` and enter those details when prompted. Each run checks the edge, WAF, limiter and recovery, runs twenty shopper requests, then publishes the correlated evidence. The dashboard refreshes within five seconds. Raw evidence stays under `logs/demo-*/`. The separate `--register` option creates one new disposable account for that run.

## Rebuild the evaluator pages

Your copy of Estate is in Downloads. The build applies the project-owned pages directly to that template. Existing template files being replaced are backed up beside the template project. First-time npm dependency installation needs network access. The deployed pages run offline.

```powershell
python dashboard/build_estate.py "C:\Users\athis\Downloads\estate-nextjs\nextjs"
```

In PowerShell 7.4 or later, from the repository root, transfer the static build to the existing VM deployment. The licensed template and its generated distribution stay on the laptop and VM.

```powershell
tar -cf - -C dashboard/site . | ssh -i "$env:USERPROFILE\.ssh\hackvm_ed25519" -p 2222 athish@127.0.0.1 'cd ~/hack/shield-wall && mkdir -p dashboard/site && tar -xf - -C dashboard/site'
```
