#!/usr/bin/env bash
# Run defensive verification or score supplied evidence without publishing.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

for interpreter in python3 python; do
    if command -v "$interpreter" >/dev/null 2>&1 && "$interpreter" -c 'import sys; sys.exit(sys.version_info.major != 3)' >/dev/null 2>&1; then
        exec "$interpreter" dashboard/acceptance.py "$@"
    fi
done
printf '%s\n' 'Python 3 is required (python3 or python).' >&2
exit 2
