#!/usr/bin/env bash
#
# Secure AI Appliance — Canary / Tripwire Check (M22)
#
# Verifies all canary files against the integrity database.
# Checks: file exists, content unchanged (token hash), permissions, ownership.
# Also monitors for unexpected new files in sensitive directories.
#
# On tripwire trigger:
#   1. CRITICAL audit log entry (hash-chained)
#   2. Lock vault immediately
#   3. Kill all inference/diffusion workers
#   4. Write alert file for UI
#
# Modes:
#   check   — run all checks (default)
#   watch   — continuous inotify monitoring (foreground)
#
set -euo pipefail

SECURE_AI_ROOT="/var/lib/secure-ai"
CANARY_DB="${SECURE_AI_ROOT}/canary-db.json"
ALERT_FILE="/run/secure-ai/canary-alert.json"
AUDIT_LOG="${SECURE_AI_ROOT}/logs/canary-audit.jsonl"
MODE="${1:-check}"

log() {
    echo "[canary-check] $*"
    logger -t canary-check "$*" 2>/dev/null || true
}

# --- Tripwire trigger actions ---
trigger_alarm() {
    local reason="$1"
    local path="${2:-unknown}"
    local timestamp
    timestamp=$(date -Iseconds)

    log "CRITICAL: TRIPWIRE TRIGGERED — ${reason} (${path})"

    # 1. Write CRITICAL audit log entry
    mkdir -p "$(dirname "$AUDIT_LOG")" 2>/dev/null || true
    local prev_hash=""
    if [ -f "$AUDIT_LOG" ]; then
        prev_hash=$(tail -1 "$AUDIT_LOG" 2>/dev/null | python3 -c "
import sys, json, hashlib
try:
    line = sys.stdin.read().strip()
    if line:
        print(hashlib.sha256(line.encode()).hexdigest())
    else:
        print('')
except: print('')
" 2>/dev/null || echo "")
    fi

    local entry
    entry=$(python3 -c "
import json, hashlib
entry = {
    'timestamp': '${timestamp}',
    'event': 'canary_tripwire',
    'severity': 'CRITICAL',
    'reason': $(python3 -c "import json; print(json.dumps('${reason}'))"),
    'path': '${path}',
    'prev_hash': '${prev_hash}'
}
entry['hash'] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
print(json.dumps(entry))
" 2>/dev/null || echo '{"event":"canary_tripwire","severity":"CRITICAL","reason":"'"${reason}"'"}')
    echo "$entry" >> "$AUDIT_LOG"

    # 2. Write alert file for UI
    mkdir -p "$(dirname "$ALERT_FILE")" 2>/dev/null || true
    cat > "$ALERT_FILE" <<EOF
{
  "triggered": true,
  "timestamp": "${timestamp}",
  "reason": "${reason}",
  "path": "${path}",
  "action_taken": ["audit_logged", "vault_locked", "workers_killed"]
}
EOF
    chmod 644 "$ALERT_FILE"

    # 3. Lock vault immediately
    log "Locking vault..."
    if command -v cryptsetup &>/dev/null; then
        # Stop services that use the vault
        systemctl stop secure-ai-inference.service 2>/dev/null || true
        systemctl stop secure-ai-diffusion.service 2>/dev/null || true
        systemctl stop secure-ai-registry.service 2>/dev/null || true
        sync
        umount "${SECURE_AI_ROOT}" 2>/dev/null || true
        cryptsetup close secure-ai-vault 2>/dev/null || true
        log "Vault locked"
    fi

    # 4. Kill all inference/diffusion workers
    log "Killing inference and diffusion workers..."
    pkill -f "llama-server" 2>/dev/null || true
    pkill -f "diffusion-worker" 2>/dev/null || true
    systemctl stop secure-ai-inference.service 2>/dev/null || true
    systemctl stop secure-ai-diffusion.service 2>/dev/null || true

    log "TRIPWIRE RESPONSE COMPLETE — system secured"
}

# --- Check functions ---
check_canary() {
    local path="$1"
    local expected_hash="$2"
    local expected_perms="$3"
    local expected_owner="$4"

    # Check existence
    if [ ! -f "$path" ]; then
        trigger_alarm "canary file missing" "$path"
        return 1
    fi

    # Check token hash
    local token
    token=$(grep "^token:" "$path" 2>/dev/null | awk '{print $2}' || echo "")
    if [ -z "$token" ]; then
        trigger_alarm "canary file corrupted (no token)" "$path"
        return 1
    fi

    local actual_hash
    actual_hash=$(echo -n "$token" | sha256sum | awk '{print $1}')
    if [ "$actual_hash" != "$expected_hash" ]; then
        trigger_alarm "canary token modified" "$path"
        return 1
    fi

    # Check permissions
    local actual_perms
    actual_perms=$(stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path" 2>/dev/null || echo "unknown")
    if [ "$actual_perms" != "$expected_perms" ]; then
        trigger_alarm "canary permissions changed (expected ${expected_perms}, got ${actual_perms})" "$path"
        return 1
    fi

    # Check ownership
    local actual_owner
    actual_owner=$(stat -c '%U:%G' "$path" 2>/dev/null || stat -f '%Su:%Sg' "$path" 2>/dev/null || echo "unknown")
    if [ "$actual_owner" != "$expected_owner" ]; then
        trigger_alarm "canary ownership changed (expected ${expected_owner}, got ${actual_owner})" "$path"
        return 1
    fi

    return 0
}

check_unexpected_files() {
    # Monitor sensitive directories for unexpected new files
    local sensitive_dirs=(
        "${SECURE_AI_ROOT}/keys"
        "/etc/secure-ai"
    )

    for dir in "${sensitive_dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            continue
        fi

        # Look for files modified in the last 5 minutes (excluding canary and known files)
        while IFS= read -r -d '' file; do
            local basename
            basename=$(basename "$file")
            # Skip known files
            case "$basename" in
                .canary|canary-db.json|*.yaml|*.yml|*.json|*.conf|*.nft)
                    continue
                    ;;
            esac
            log "WARNING: unexpected recent file in sensitive directory: $file"
        done < <(find "$dir" -maxdepth 2 -type f -newer "$CANARY_DB" -print0 2>/dev/null) || true
    done
}

# --- Timer-based check ---
run_check() {
    if [ ! -f "$CANARY_DB" ]; then
        log "WARNING: canary database not found at ${CANARY_DB}"
        log "Run canary-place.sh first to initialize canaries"
        return 1
    fi

    log "Checking canary files..."
    local total=0
    local ok=0
    local failed=0

    # Parse canary database with python3 for reliable JSON handling
    while IFS='|' read -r path hash perms owner; do
        total=$((total + 1))
        if check_canary "$path" "$hash" "$perms" "$owner"; then
            ok=$((ok + 1))
        else
            failed=$((failed + 1))
        fi
    done < <(python3 -c "
import json, sys
try:
    with open('${CANARY_DB}') as f:
        db = json.load(f)
    for c in db.get('canaries', []):
        print(f\"{c['path']}|{c['token_hash']}|{c['permissions']}|{c['owner']}\")
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
" 2>/dev/null)

    # Check for unexpected files
    check_unexpected_files

    log "Canary check complete: ${ok}/${total} OK, ${failed} failed"

    if [ "$failed" -gt 0 ]; then
        return 1
    fi
    return 0
}

# --- inotify-based continuous watch ---
run_watch() {
    if ! command -v inotifywait &>/dev/null; then
        log "inotifywait not available — falling back to timer-based checks"
        exit 0
    fi

    log "Starting inotify watch on canary files and sensitive configs..."

    # Collect paths to watch
    local watch_paths=()
    if [ -f "$CANARY_DB" ]; then
        while IFS= read -r path; do
            if [ -f "$path" ]; then
                watch_paths+=("$path")
            fi
        done < <(python3 -c "
import json
with open('${CANARY_DB}') as f:
    db = json.load(f)
for c in db.get('canaries', []):
    print(c['path'])
" 2>/dev/null)
    fi

    # Add critical config files
    watch_paths+=("/etc/secure-ai/config/appliance.yaml")
    watch_paths+=("/etc/secure-ai/policy/policy.yaml")

    if [ ${#watch_paths[@]} -eq 0 ]; then
        log "No files to watch"
        exit 1
    fi

    # Watch for modifications, deletions, attribute changes
    inotifywait -m -e modify,delete,attrib,move_self "${watch_paths[@]}" 2>/dev/null | while read -r dir event file; do
        log "INOTIFY: ${event} on ${dir}${file}"

        # Re-run full check on any change
        run_check || true
    done
}

# --- Main ---
case "$MODE" in
    check)
        run_check
        ;;
    watch)
        run_watch
        ;;
    *)
        echo "Usage: $0 [check|watch]"
        exit 1
        ;;
esac
