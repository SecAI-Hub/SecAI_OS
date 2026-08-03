#!/usr/bin/env bash
#
# Start SearXNG with its cryptographic secret supplied by systemd credentials.
# Refuse a missing, linked, oversized, or malformed credential instead of
# falling back to the public marker in settings.yml.

set -euo pipefail

credential_path="${SEARXNG_SECRET_PATH:-}"
base_settings_path="${SEARXNG_BASE_SETTINGS_PATH:-/etc/secure-ai/searxng/settings.yml}"
runtime_settings_path="${SEARXNG_RUNTIME_SETTINGS_PATH:-/run/secure-ai-searxng/settings.yml}"
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

umask 077
/usr/bin/python3 /usr/libexec/secure-ai/prepare-searxng-settings.py \
    --base "$base_settings_path" \
    --credential "$credential_path" \
    --output "$runtime_settings_path"
export SEARXNG_SETTINGS_PATH="$runtime_settings_path"
exec /usr/lib/secure-ai/python3.12-venv/bin/python3.12 -m searx.webapp
