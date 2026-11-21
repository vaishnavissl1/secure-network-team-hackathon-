#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
bash scripts/gen-certs.sh

# Mount the files individually so the unprivileged nginx worker can write
# them while access from the VM is restricted by the parent directory.
umask 077
for path in logs logs/nginx logs/modsec logs/nginx/access.log logs/modsec/audit.log; do
    if [[ -L "$path" ]]; then
        printf 'Refusing to use a symlink for lab logs: %s\n' "$path" >&2
        exit 1
    fi
done
mkdir -p logs/nginx logs/modsec
chmod 700 logs
touch logs/nginx/access.log logs/modsec/audit.log
chmod 666 logs/nginx/access.log logs/modsec/audit.log

docker compose up -d --pull never --wait --wait-timeout 150
