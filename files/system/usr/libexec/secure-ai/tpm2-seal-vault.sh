#!/usr/bin/env bash
# Stable compatibility entrypoint for verified systemd TPM2 enrollment.
set -euo pipefail
umask 077

if [ "$#" -eq 0 ]; then
    set -- status
fi
exec /usr/libexec/secure-ai/secure-tpm-vault.py "$@"
