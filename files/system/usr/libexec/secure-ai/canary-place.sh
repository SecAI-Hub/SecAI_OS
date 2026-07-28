#!/usr/bin/env bash
#
# Enroll root-only canary files into an HMAC-authenticated integrity database.
#
set -euo pipefail
umask 077

SECURE_AI_ROOT="${SECURE_AI_ROOT:-/var/lib/secure-ai}"
VAULT_MOUNT="${VAULT_MOUNT:-${SECURE_AI_ROOT}/vault}"
CANARY_DB="${CANARY_DB:-${SECURE_AI_ROOT}/state/canary-db.json}"
CANARY_HMAC_KEY_PATH="${CANARY_HMAC_KEY_PATH:-${SECURE_AI_ROOT}/credentials/canary-hmac.key}"
CANARY_HELPER="${CANARY_HELPER:-/usr/libexec/secure-ai/secure-canary.py}"

CANARY_LOCATIONS=(
    "${SECURE_AI_ROOT}/vault/.canary"
    "${SECURE_AI_ROOT}/registry/.canary"
    "${SECURE_AI_ROOT}/keys/.canary"
    "/etc/secure-ai/.canary"
)

log() {
    printf '[canary-place] %s\n' "$*"
    logger -t canary-place "$*" 2>/dev/null || true
}

fatal() {
    log "ERROR: $*"
    exit 1
}

[ "$(id -u)" -eq 0 ] || fatal "canary enrollment must run as root"
[ -x "$CANARY_HELPER" ] || fatal "authenticated canary helper is unavailable"

args=(
    place
    --database "$CANARY_DB"
    --key "$CANARY_HMAC_KEY_PATH"
    --vault-mount "$VAULT_MOUNT"
)
for location in "${CANARY_LOCATIONS[@]}"; do
    args+=(--location "$location")
done

result=$("$CANARY_HELPER" "${args[@]}") || fatal "canary enrollment failed"
status=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])' <<< "$result")
enrolled=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["enrolled"])' <<< "$result")
if [ "$status" = pending ]; then
    pending=$(python3 -c '
import json, sys
print(", ".join(json.load(sys.stdin)["pending_locations"]))
' <<< "$result")
    log "Authenticated ${enrolled} canary file(s); pending until vault mount: ${pending}"
else
    log "Authenticated canary enrollment complete (${enrolled} files)"
fi
