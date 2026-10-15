#!/usr/bin/env bash
# Required offline Tor source build inside the image build, before cleanup.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

TOR_SOURCE_DIR=${1:-/tmp/tor-source}
TOR_APPLIANCE_CONFIG=${2:-/etc/secure-ai/tor/torrc}
TOR_CONTRACT_DIR=/tmp/build/tor

[ "$(id -u)" -eq 0 ] || { echo "FATAL: Tor installation requires the owned image build root" >&2; exit 1; }
[ -f "$TOR_CONTRACT_DIR/build.py" ] && [ -f "$TOR_CONTRACT_DIR/source.lock.json" ] || {
    echo "FATAL: committed Tor source build contract is missing" >&2
    exit 1
}
arguments=("$TOR_SOURCE_DIR" "$TOR_APPLIANCE_CONFIG" --contract "$TOR_CONTRACT_DIR/source.lock.json")
if [ -f /tmp/SOURCE_PREP_MANIFEST.json ]; then
    arguments+=(--global-manifest /tmp/SOURCE_PREP_MANIFEST.json)
elif [ "${HERMETIC_BUILD:-}" = true ]; then
    echo "FATAL: global source-prep manifest is required for hermetic Tor build" >&2
    exit 1
fi
# The native builder also limits each subprocess and private tree allocation.
# Preserve receipt/logs on normal failures; a hung process cannot outlive this
# external wall-clock deadline. The owning image build rejects any failure.
# Keep the shell as PID 1. GNU timeout cannot establish its process-group
# deadline correctly when exec makes it PID 1 in the build container.
# Leave 300 seconds beyond the inner contract for failure receipts and cleanup.
timeout --signal=TERM --kill-after=10s 3600s \
    /usr/bin/python3 -B "$TOR_CONTRACT_DIR/build.py" "${arguments[@]}"
