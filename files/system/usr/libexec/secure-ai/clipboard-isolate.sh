#!/usr/bin/env bash
# Apply and record verifiable guest-side clipboard controls.
set -euo pipefail
umask 077

if [ "$(id -u)" -ne 0 ]; then
    echo "[clipboard-isolate] must run as root" >&2
    exit 1
fi

exec /usr/libexec/secure-ai/secure-clipboard-isolate.py
