#!/usr/bin/env bash
# Generate a self-signed TLS cert for the WAF, valid for the hostname "shield.local"
# (and localhost). TLS 1.2+ is enforced by nginx; this just provides the key pair.
# Runs openssl inside a container so no host install is needed.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p certs

# On Windows Git Bash/MSYS, Docker needs a Windows-style host path for -v.
if command -v cygpath >/dev/null 2>&1; then
  HOSTCERTS="$(cygpath -w "$(pwd)/certs")"
else
  HOSTCERTS="$(pwd)/certs"
fi

MSYS_NO_PATHCONV=1 docker run --rm -v "${HOSTCERTS}:/out" alpine:3.19 sh -c '
  apk add --no-cache openssl >/dev/null 2>&1
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /out/server.key -out /out/server.crt \
    -days 365 -subj "/CN=shield.local/O=PS6 ShieldWall/C=IN" \
    -addext "subjectAltName=DNS:shield.local,DNS:localhost,IP:127.0.0.1"
  chmod 644 /out/server.crt /out/server.key
'
echo "Certs written to ./certs (server.crt, server.key)"
