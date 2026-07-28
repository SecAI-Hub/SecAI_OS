#!/usr/bin/env bash
#
# Start SearXNG with its cryptographic secret supplied by systemd credentials.
# Refuse a missing, linked, oversized, or malformed credential instead of
# falling back to the public marker in settings.yml.

set -euo pipefail

credential_path="${SEARXNG_SECRET_PATH:-}"
if [ -z "$credential_path" ] || [ ! -f "$credential_path" ] || [ -L "$credential_path" ]; then
    echo "ERROR: SearXNG credential is unavailable or unsafe" >&2
    exit 1
fi

credential_size=$(stat -c '%s' -- "$credential_path")
credential_links=$(stat -c '%h' -- "$credential_path")
if [ "$credential_size" -lt 64 ] || [ "$credential_size" -gt 65 ] || [ "$credential_links" -ne 1 ]; then
    echo "ERROR: SearXNG credential metadata is unsafe" >&2
    exit 1
fi

secret=$(<"$credential_path")
if [[ ! "$secret" =~ ^[0-9a-f]{64}$ ]]; then
    echo "ERROR: SearXNG credential must be a 256-bit lowercase hex token" >&2
    exit 1
fi

export SEARXNG_SECRET="$secret"
unset secret
exec /usr/bin/python3 -m searx.webapp
