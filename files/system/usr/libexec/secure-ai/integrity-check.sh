#!/usr/bin/env bash
#
# Secure AI Appliance — Continuous Model Integrity Monitor
#
# Verifies SHA256 hashes of all promoted models against the registry manifest.
# On mismatch: quarantines the tampered model, removes it from the manifest,
# kills any inference process using it, and logs a CRITICAL alert.
#
# Run via secure-ai-integrity.timer (default: every 15 minutes).

set -euo pipefail

SECURE_AI_ROOT="/var/lib/secure-ai"
REGISTRY_URL="${REGISTRY_URL:-http://127.0.0.1:8470}"
REGISTRY_DIR="${REGISTRY_DIR:-/var/lib/secure-ai/registry}"
TAMPERED_DIR="${SECURE_AI_ROOT}/quarantine/tampered"
INTEGRITY_LOG="${SECURE_AI_ROOT}/logs/integrity.jsonl"
RESULT_FILE="${SECURE_AI_ROOT}/logs/integrity-last.json"

log() {
    echo "[integrity-check] $*"
    logger -t secure-ai-integrity "$*"
}

log_json() {
    local status="$1" model="$2" detail="$3"
    local ts
    ts=$(date -Iseconds)
    printf '{"timestamp":"%s","status":"%s","model":"%s","detail":"%s"}\n' \
        "$ts" "$status" "$model" "$detail" >> "$INTEGRITY_LOG"
}

mkdir -p "$(dirname "$INTEGRITY_LOG")" "$TAMPERED_DIR"

# Fetch the manifest from the registry
manifest=$(curl -sf "${REGISTRY_URL}/v1/models" 2>/dev/null) || {
    log "ERROR: cannot reach registry at ${REGISTRY_URL}"
    log_json "error" "" "registry unreachable"
    echo '{"status":"error","detail":"registry unreachable","checked_at":"'"$(date -Iseconds)"'"}' > "$RESULT_FILE"
    exit 1
}

model_count=$(echo "$manifest" | jq 'length')
if [ "$model_count" -eq 0 ]; then
    log "No models in registry. Nothing to verify."
    echo '{"status":"ok","models_checked":0,"failures":0,"checked_at":"'"$(date -Iseconds)"'"}' > "$RESULT_FILE"
    exit 0
fi

log "Verifying ${model_count} model(s)..."

failures=0
checked=0

for i in $(seq 0 $((model_count - 1))); do
    name=$(echo "$manifest" | jq -r ".[$i].name")
    filename=$(echo "$manifest" | jq -r ".[$i].filename")
    expected=$(echo "$manifest" | jq -r ".[$i].sha256")
    filepath="${REGISTRY_DIR}/${filename}"

    if [ ! -f "$filepath" ]; then
        log "CRITICAL: model file missing: ${filename} (${name})"
        log_json "missing" "$name" "file not found: ${filename}"
        failures=$((failures + 1))
        continue
    fi

    actual=$(sha256sum "$filepath" | awk '{print $1}')
    checked=$((checked + 1))

    if [ "$actual" = "$expected" ]; then
        log "OK: ${name} (${expected:0:16}...)"
        log_json "ok" "$name" "hash verified"
    else
        log "CRITICAL: HASH MISMATCH for ${name}!"
        log "  Expected: ${expected}"
        log "  Actual:   ${actual}"
        log_json "tampered" "$name" "expected=${expected} actual=${actual}"
        failures=$((failures + 1))

        # Quarantine the tampered model
        log "Quarantining tampered model: ${filename}"
        mv "$filepath" "${TAMPERED_DIR}/${filename}.tampered.$(date +%s)" 2>/dev/null || true

        # Remove from registry manifest via API
        log "Removing ${name} from registry..."
        curl -sf -X DELETE "${REGISTRY_URL}/v1/model/delete?name=${name}" >/dev/null 2>&1 || {
            log "WARNING: could not remove ${name} from registry via API"
        }

        # Kill any inference process that might be using this model
        # The inference worker loads models by path — killing it forces a clean reload
        if systemctl is-active --quiet secure-ai-inference.service 2>/dev/null; then
            log "Restarting inference worker to drop potentially poisoned model..."
            systemctl restart secure-ai-inference.service 2>/dev/null || true
        fi
        if systemctl is-active --quiet secure-ai-diffusion.service 2>/dev/null; then
            log "Restarting diffusion worker to drop potentially poisoned model..."
            systemctl restart secure-ai-diffusion.service 2>/dev/null || true
        fi
    fi
done

ts=$(date -Iseconds)
status="ok"
if [ "$failures" -gt 0 ]; then
    status="failed"
    log "INTEGRITY CHECK FAILED: ${failures} model(s) tampered or missing out of ${checked} checked"
else
    log "Integrity check passed: ${checked} model(s) verified OK"
fi

# Write summary for the status API
cat > "$RESULT_FILE" <<EOF
{
  "status": "${status}",
  "models_checked": ${checked},
  "failures": ${failures},
  "checked_at": "${ts}"
}
EOF

exit 0
