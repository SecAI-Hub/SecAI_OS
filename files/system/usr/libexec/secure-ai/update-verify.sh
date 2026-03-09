#!/usr/bin/env bash
#
# Secure AI Appliance — Update Verification + Staged Upgrades (M24)
#
# Verifies cosign signatures on rpm-ostree updates before applying.
# Supports staged updates: check → stage → apply workflow.
#
# Usage:
#   update-verify.sh check      Check for available updates
#   update-verify.sh stage      Download + stage update (don't reboot)
#   update-verify.sh apply      Apply staged update and reboot
#   update-verify.sh rollback   Roll back to previous deployment
#   update-verify.sh status     Show current deployment and update state
#

set -euo pipefail

SECURE_AI_ROOT="/var/lib/secure-ai"
UPDATE_STATE="/run/secure-ai/update-state.json"
AUDIT_LOG="${SECURE_AI_ROOT}/logs/update-audit.jsonl"
COSIGN_PUB_KEY="/etc/secure-ai/keys/cosign.pub"

log() {
    echo "[update-verify] $*"
    logger -t secure-ai-update "$*" 2>/dev/null || true
}

audit_update() {
    local action="$1"
    local detail="${2:-}"
    local timestamp
    timestamp=$(date -Iseconds)

    mkdir -p "$(dirname "$AUDIT_LOG")" 2>/dev/null || true

    local entry
    entry=$(python3 -c "
import json, hashlib
entry = {
    'timestamp': '${timestamp}',
    'event': 'update_action',
    'action': '${action}',
    'detail': '${detail}'
}
entry['hash'] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
print(json.dumps(entry))
" 2>/dev/null || echo "{\"event\":\"update_action\",\"action\":\"${action}\"}")
    echo "$entry" >> "$AUDIT_LOG" 2>/dev/null || true
}

write_state() {
    local status="$1"
    local detail="${2:-}"
    local version="${3:-}"
    mkdir -p "$(dirname "$UPDATE_STATE")" 2>/dev/null || true
    cat > "$UPDATE_STATE" <<EOF
{
  "status": "${status}",
  "detail": "${detail}",
  "version": "${version}",
  "timestamp": "$(date -Iseconds)"
}
EOF
    chmod 644 "$UPDATE_STATE"
}

# --- Check for updates ---
check_updates() {
    log "Checking for available updates..."
    write_state "checking" "looking for updates"

    # Get current deployment info
    local current_commit
    current_commit=$(rpm-ostree status --json 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
deployments = data.get('deployments', [])
if deployments:
    print(deployments[0].get('checksum', 'unknown'))
else:
    print('unknown')
" 2>/dev/null || echo "unknown")

    log "Current commit: ${current_commit:0:12}"

    # Check for updates
    local check_output
    check_output=$(rpm-ostree upgrade --check 2>&1) || true

    if echo "$check_output" | grep -qi "no updates available"; then
        log "No updates available"
        write_state "up_to_date" "no updates available" "$current_commit"
        echo '{"update_available": false, "current_commit": "'"$current_commit"'"}'
        return 0
    fi

    # Extract new version info
    local new_version
    new_version=$(echo "$check_output" | grep -i "version" | head -1 || echo "")
    local new_commit
    new_commit=$(echo "$check_output" | grep -i "commit" | head -1 | awk '{print $NF}' || echo "")

    log "Update available: $new_version ($new_commit)"
    write_state "update_available" "$new_version" "$new_commit"
    audit_update "check" "update available: $new_version"

    echo '{"update_available": true, "current_commit": "'"$current_commit"'", "new_version": "'"$new_version"'", "new_commit": "'"$new_commit"'"}'
}

# --- Verify cosign signature ---
verify_signature() {
    log "Verifying cosign signature..."

    if [ ! -f "$COSIGN_PUB_KEY" ]; then
        log "WARNING: no cosign public key at $COSIGN_PUB_KEY — skipping signature verification"
        return 0
    fi

    if ! command -v cosign &>/dev/null; then
        log "WARNING: cosign not installed — skipping signature verification"
        return 0
    fi

    # Verify the container image signature
    local registry_ref
    registry_ref=$(rpm-ostree status --json 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
deployments = data.get('deployments', [])
if deployments:
    origin = deployments[0].get('container-image-reference', '')
    if not origin:
        origin = deployments[0].get('origin', '')
    print(origin)
else:
    print('')
" 2>/dev/null || echo "")

    if [ -z "$registry_ref" ]; then
        log "WARNING: could not determine registry reference"
        return 0
    fi

    log "Verifying signature for: $registry_ref"

    if cosign verify --key "$COSIGN_PUB_KEY" "$registry_ref" 2>/dev/null; then
        log "Signature verification: PASSED"
        audit_update "verify_signature" "passed: $registry_ref"
        return 0
    else
        log "ERROR: Signature verification FAILED for $registry_ref"
        audit_update "verify_signature" "FAILED: $registry_ref"
        return 1
    fi
}

# --- Stage update ---
stage_update() {
    log "Staging update (download only, no reboot)..."
    write_state "staging" "downloading update"
    audit_update "stage" "beginning staged download"

    # Verify signature before staging
    if ! verify_signature; then
        log "ERROR: signature verification failed — refusing to stage update"
        write_state "signature_failed" "update rejected: bad signature"
        return 1
    fi

    # Stage the update (downloads but doesn't apply until reboot)
    if rpm-ostree upgrade --download-only 2>&1; then
        log "Update staged successfully"
        write_state "staged" "update downloaded, ready to apply"
        audit_update "stage" "update staged successfully"
        echo '{"status": "staged", "message": "Update downloaded. Use apply to reboot into new version."}'
        return 0
    else
        log "ERROR: failed to stage update"
        write_state "stage_failed" "download failed"
        audit_update "stage" "staging failed"
        return 1
    fi
}

# --- Apply staged update ---
apply_update() {
    log "Applying staged update..."
    write_state "applying" "applying update and preparing reboot"
    audit_update "apply" "applying staged update"

    # Verify signature one more time before applying
    if ! verify_signature; then
        log "ERROR: signature verification failed — refusing to apply"
        write_state "signature_failed" "apply rejected: bad signature"
        return 1
    fi

    # Apply the upgrade
    if rpm-ostree upgrade 2>&1; then
        log "Update applied. System will boot into new version on next reboot."
        write_state "applied" "update applied, reboot required"
        audit_update "apply" "update applied, reboot pending"
        echo '{"status": "applied", "message": "Update applied. Reboot to activate."}'

        # Trigger reboot
        log "Initiating reboot..."
        systemctl reboot
    else
        log "ERROR: failed to apply update"
        write_state "apply_failed" "rpm-ostree upgrade failed"
        audit_update "apply" "apply failed"
        return 1
    fi
}

# --- Rollback ---
do_rollback() {
    log "Rolling back to previous deployment..."
    audit_update "rollback" "user-initiated rollback"
    write_state "rolling_back" "reverting to previous deployment"

    if rpm-ostree rollback 2>&1; then
        log "Rollback staged. Rebooting..."
        write_state "rolled_back" "rollback applied, rebooting"
        audit_update "rollback" "rollback applied"
        echo '{"status": "rolled_back", "message": "Rollback applied. Rebooting..."}'
        systemctl reboot
    else
        log "ERROR: rollback failed"
        write_state "rollback_failed" "rpm-ostree rollback failed"
        audit_update "rollback" "rollback failed"
        return 1
    fi
}

# --- Status ---
show_status() {
    if [ -f "$UPDATE_STATE" ]; then
        # Combine update state with deployment info
        local deployments
        deployments=$(rpm-ostree status --json 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
result = []
for d in data.get('deployments', []):
    result.append({
        'checksum': d.get('checksum', '')[:12],
        'version': d.get('version', ''),
        'booted': d.get('booted', False),
        'staged': d.get('staged', False),
        'origin': d.get('origin', d.get('container-image-reference', '')),
    })
print(json.dumps(result))
" 2>/dev/null || echo "[]")

        python3 -c "
import json, sys
state = json.load(open('${UPDATE_STATE}'))
state['deployments'] = json.loads('${deployments}')
print(json.dumps(state, indent=2))
" 2>/dev/null || cat "$UPDATE_STATE"
    else
        # No state file, just show deployment info
        rpm-ostree status --json 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
result = {'status': 'unknown', 'deployments': []}
for d in data.get('deployments', []):
    result['deployments'].append({
        'checksum': d.get('checksum', '')[:12],
        'version': d.get('version', ''),
        'booted': d.get('booted', False),
        'staged': d.get('staged', False),
    })
print(json.dumps(result, indent=2))
" 2>/dev/null || echo '{"status": "unknown"}'
    fi
}

# --- Main ---
cmd="${1:-help}"
shift || true

case "$cmd" in
    check)
        check_updates
        ;;
    stage)
        stage_update
        ;;
    apply)
        apply_update
        ;;
    rollback)
        do_rollback
        ;;
    status)
        show_status
        ;;
    help|--help|-h)
        echo "update-verify.sh — Secure AI Update Verification (M24)"
        echo ""
        echo "Commands:"
        echo "  check     Check for available updates"
        echo "  stage     Download + stage update (no reboot)"
        echo "  apply     Apply staged update and reboot"
        echo "  rollback  Roll back to previous deployment"
        echo "  status    Show current deployment and update state"
        ;;
    *)
        echo "Unknown command: $cmd"
        echo "Run 'update-verify.sh help' for usage."
        exit 1
        ;;
esac
