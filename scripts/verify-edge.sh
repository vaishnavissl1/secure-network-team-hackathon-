#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

tls=(--noproxy '*' --cacert certs/server.crt --resolve shield.local:8443:127.0.0.1 --max-time 5)
app_url='https://shield.local:8443/rest/products/search?q=apple'

for ((attempt=1; attempt<=30; attempt++)); do
    if app_json=$(curl -fsS "${tls[@]}" "$app_url" 2>/dev/null); then
        break
    fi
    if (( attempt == 30 )); then
        printf '%s\n' 'Juice Shop did not become reachable through trusted HTTPS.' >&2
        exit 1
    fi
    sleep 2
done

printf '%s' "$app_json" | python3 -c 'import json, sys; result = json.load(sys.stdin); sys.exit(0 if result.get("status") == "success" and isinstance(result.get("data"), list) else 1)'
printf '%s\n' 'PASS trusted HTTPS reached the Juice Shop product search'

redirect=$(curl -fsS --noproxy '*' --max-time 5 -o /dev/null -w '%{http_code} %{redirect_url}' 'http://127.0.0.1:8080/healthz')
[[ "$redirect" == '301 https://shield.local:8443/healthz' ]]
printf '%s\n' 'PASS HTTP redirects to the lab HTTPS name'

for version in 1.2 1.3; do
    curl -fsS "${tls[@]}" "--tlsv$version" --tls-max "$version" -o /dev/null "$app_url"
done
if curl -fsS "${tls[@]}" --tlsv1.1 --tls-max 1.1 -o /dev/null "$app_url" 2>/dev/null; then
    printf '%s\n' 'FAIL TLS 1.1 was accepted' >&2
    exit 1
fi
docker compose exec -T waf nginx -T 2>&1 | awk '$1 == "ssl_protocols" && $2 == "TLSv1.2" && $3 == "TLSv1.3;" && NF == 3 { found=1 } END { exit !found }'
printf '%s\n' 'PASS TLS 1.2 and 1.3 negotiated, TLS 1.1 failed, and nginx has the expected protocols'

backend=$(docker compose ps -q juice-shop)
[[ -n "$backend" ]]
[[ $(docker inspect -f '{{len .HostConfig.PortBindings}}' "$backend") == 0 ]]
[[ $(docker network inspect -f '{{.Internal}}' shield-wall_backend) == true ]]
[[ $(docker compose port waf 8080) == '127.0.0.1:8080' ]]
[[ $(docker compose port waf 8443) == '127.0.0.1:8443' ]]
printf '%s\n' 'PASS Juice Shop is on an internal network with no published port, edge ports use VM loopback'
