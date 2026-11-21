#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
umask 077

mkdir -p certs
chmod 700 certs
if [[ ! -e certs/server.crt || ! -e certs/server.key ]]; then
    if [[ -e certs/server.crt || -e certs/server.key ]]; then
        printf '%s\n' 'Incomplete certificate pair in certs/. Inspect it before retrying.' >&2
        exit 1
    fi

    staging=$(mktemp -d certs/.generate.XXXXXX)
    trap 'rm -f -- "$staging/server.crt" "$staging/server.key"; rmdir -- "$staging"' EXIT
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
        -subj '/CN=shield.local' \
        -addext 'subjectAltName=DNS:shield.local,DNS:localhost,IP:127.0.0.1' \
        -keyout "$staging/server.key" -out "$staging/server.crt"
    # Only the host owner can traverse certs/. nginx reads the individually mounted files.
    chmod 644 "$staging/server.crt" "$staging/server.key"
    mv -- "$staging/server.crt" "$staging/server.key" certs/
fi

openssl x509 -in certs/server.crt -noout -checkend 0 -checkhost shield.local
