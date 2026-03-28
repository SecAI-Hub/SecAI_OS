#!/usr/bin/env bash
#
# SecAI OS — Apply Runtime Profile
#
# Reads the active profile from the runtime state file or operator override,
# then enables/disables systemd services to match the profile definition.
#
# This script runs as root via the secure-ai-apply-profile.service oneshot
# unit (triggered by a path unit watching for a request file).  The UI never
# calls this directly — it writes a request marker file.
#
# Privilege boundary:
#   - Only this script (running as root) changes systemd state.
#   - The request file contains only a profile name (strict allowlist).
#   - The UI process is unprivileged (DynamicUser=yes).
#
# Failure semantics:
#   - On any error: roll back to previous profile, write failure result.
#   - On missing/malformed/invalid state: fall back to offline_private.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
APPLIANCE_CONFIG="/etc/secure-ai/config/appliance.yaml"
PROFILE_STATE="/var/lib/secure-ai/state/profile.json"
OPERATOR_OVERRIDE="/etc/secure-ai/local.d/profile.yaml"
REQUEST_FILE="/run/secure-ai-ui/profile-request"
RESULT_FILE="/run/secure-ai/profile-result.json"
AUDIT_LOG="/var/lib/secure-ai/logs/audit.jsonl"
LOCK_FILE="/var/lib/secure-ai/.profile-change.lock"

DEFAULT_PROFILE="offline_private"
VALID_PROFILES="offline_private research full_lab"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { echo "[apply-profile] $(date -u +%Y-%m-%dT%H:%M:%SZ) $*"; }

write_result() {
    # Reads from env vars: _RES_STATUS, _RES_PROFILE, _RES_PREVIOUS, _RES_DETAIL, _RES_TMPFILE, _RES_FILE
    python3 << 'PYEOF'
import json, os, sys
result = {
    "status": os.environ["_RES_STATUS"],
    "profile": os.environ["_RES_PROFILE"],
    "previous": os.environ["_RES_PREVIOUS"],
    "detail": os.environ.get("_RES_DETAIL", ""),
    "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z"
}
tmpfile = os.environ["_RES_TMPFILE"]
with open(tmpfile, "w") as f:
    json.dump(result, f, indent=2)
    f.write("\n")
os.rename(tmpfile, os.environ["_RES_FILE"])
PYEOF
}
export _RES_FILE="$RESULT_FILE"

write_audit() {
    local event="$1" profile="$2" previous="$3" detail="${4:-}"
    _AUDIT_EVENT="$event" _AUDIT_PROFILE="$profile" \
    _AUDIT_PREVIOUS="$previous" _AUDIT_DETAIL="$detail" \
    _AUDIT_FILE="$AUDIT_LOG" \
    python3 << 'PYEOF'
import json, os
entry = {
    "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
    "event": os.environ["_AUDIT_EVENT"],
    "profile": os.environ["_AUDIT_PROFILE"],
    "previous": os.environ["_AUDIT_PREVIOUS"],
    "detail": os.environ.get("_AUDIT_DETAIL", ""),
    "source": "apply-profile"
}
with open(os.environ["_AUDIT_FILE"], "a") as f:
    f.write(json.dumps(entry) + "\n")
PYEOF
}

validate_profile() {
    local name="$1"
    for valid in $VALID_PROFILES; do
        if [ "$name" = "$valid" ]; then
            return 0
        fi
    done
    return 1
}

read_current_profile() {
    # Operator override takes precedence (hard lock)
    if [ -f "$OPERATOR_OVERRIDE" ]; then
        local override
        override=$(_OVERRIDE_FILE="$OPERATOR_OVERRIDE" python3 -c '
import yaml, os
try:
    with open(os.environ["_OVERRIDE_FILE"]) as f:
        data = yaml.safe_load(f)
    print(data.get("profile", ""))
except Exception:
    print("")
' 2>/dev/null) || true
        if [ -n "$override" ] && validate_profile "$override"; then
            echo "$override"
            return 0
        fi
    fi

    # Read from runtime state
    if [ -f "$PROFILE_STATE" ]; then
        local current
        current=$(_PS_FILE="$PROFILE_STATE" python3 -c '
import json, os
try:
    with open(os.environ["_PS_FILE"]) as f:
        data = json.load(f)
    print(data.get("active", ""))
except Exception:
    print("")
' 2>/dev/null) || true
        if [ -n "$current" ] && validate_profile "$current"; then
            echo "$current"
            return 0
        fi
    fi

    # Fallback
    echo "$DEFAULT_PROFILE"
}

write_profile_state() {
    local profile="$1" changed_by="$2"
    local dir
    dir=$(dirname "$PROFILE_STATE")
    mkdir -p "$dir"
    _PS_PROFILE="$profile" _PS_BY="$changed_by" _PS_FILE="$PROFILE_STATE" \
    python3 << 'PYEOF'
import json, os
state = {
    "active": os.environ["_PS_PROFILE"],
    "changed_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
    "changed_by": os.environ["_PS_BY"]
}
tmpfile = os.environ["_PS_FILE"] + ".tmp"
with open(tmpfile, "w") as f:
    json.dump(state, f, indent=2)
    f.write("\n")
os.chmod(tmpfile, 0o644)
os.rename(tmpfile, os.environ["_PS_FILE"])
PYEOF
}

get_profile_services() {
    # Returns the services_enabled and services_disabled lists for a profile
    local profile="$1" field="$2"  # field: services_enabled or services_disabled
    _GP_CONFIG="$APPLIANCE_CONFIG" _GP_PROFILE="$profile" _GP_FIELD="$field" \
    python3 << 'PYEOF'
import yaml, os
with open(os.environ["_GP_CONFIG"]) as f:
    config = yaml.safe_load(f)
profile = os.environ["_GP_PROFILE"]
field = os.environ["_GP_FIELD"]
defs = config.get("profile", {}).get("definitions", {})
services = defs.get(profile, {}).get(field, [])
for svc in services:
    print(svc)
PYEOF
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    # Acquire lock (non-blocking)
    mkdir -p "$(dirname "$LOCK_FILE")"
    exec 9>"$LOCK_FILE"
    if ! flock -n 9; then
        log "ERROR: another profile change is in progress"
        exit 1
    fi

    # Determine the requested profile
    local requested=""
    local changed_by="unknown"

    if [ -f "$REQUEST_FILE" ]; then
        # Triggered by UI via path unit
        requested=$(head -c 20 "$REQUEST_FILE" | tr -cd 'a-z_')
        changed_by="ui"
        rm -f "$REQUEST_FILE"
    elif [ -n "${1:-}" ]; then
        # Called directly (firstboot, CLI)
        requested="$1"
        changed_by="${2:-cli}"
    else
        # No request — just apply current profile (e.g., at boot)
        requested=$(read_current_profile)
        changed_by="boot"
    fi

    # Validate
    if ! validate_profile "$requested"; then
        log "ERROR: invalid profile name: '$requested'"
        write_audit "profile_change_rejected" "$requested" "$(read_current_profile)" "invalid profile name"
        _RES_STATUS="failed" _RES_PROFILE="$requested" _RES_PREVIOUS="$(read_current_profile)" \
        _RES_DETAIL="Invalid profile name" _RES_TMPFILE="${RESULT_FILE}.tmp" \
        write_result "failed" "$requested" "$(read_current_profile)" "Invalid profile name"
        exit 1
    fi

    local previous
    previous=$(read_current_profile)

    log "Applying profile: $requested (previous: $previous, by: $changed_by)"

    # Write in-progress result
    _RES_STATUS="in_progress" _RES_PROFILE="$requested" _RES_PREVIOUS="$previous" \
    _RES_DETAIL="" _RES_TMPFILE="${RESULT_FILE}.tmp" \
    write_result "in_progress" "$requested" "$previous" ""

    # Get service lists for the requested profile
    local -a to_enable=()
    local -a to_disable=()

    while IFS= read -r svc; do
        [ -n "$svc" ] && to_enable+=("$svc")
    done < <(get_profile_services "$requested" "services_enabled")

    while IFS= read -r svc; do
        [ -n "$svc" ] && to_disable+=("$svc")
    done < <(get_profile_services "$requested" "services_disabled")

    # Apply: disable first, then enable
    local errors=0

    for svc in "${to_disable[@]}"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            log "Stopping $svc"
            systemctl stop "$svc" 2>/dev/null || true
        fi
        if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
            log "Disabling $svc"
            systemctl disable "$svc" 2>/dev/null || true
        fi
    done

    for svc in "${to_enable[@]}"; do
        if ! systemctl is-enabled --quiet "$svc" 2>/dev/null; then
            log "Enabling $svc"
            if ! systemctl enable "$svc" 2>/dev/null; then
                log "WARNING: failed to enable $svc"
                errors=$((errors + 1))
            fi
        fi
        if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
            log "Starting $svc"
            if ! systemctl start "$svc" 2>/dev/null; then
                log "WARNING: failed to start $svc"
                errors=$((errors + 1))
            fi
        fi
    done

    # Validate: check all expected services are in correct state
    local validation_errors=0
    for svc in "${to_enable[@]}"; do
        if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
            log "VALIDATION: $svc should be active but is not"
            validation_errors=$((validation_errors + 1))
        fi
    done
    for svc in "${to_disable[@]}"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            log "VALIDATION: $svc should be inactive but is active"
            validation_errors=$((validation_errors + 1))
        fi
    done

    if [ "$validation_errors" -gt 0 ]; then
        log "ERROR: $validation_errors service(s) in wrong state after apply"
        # Rollback: restore previous profile
        if [ "$previous" != "$requested" ]; then
            log "Rolling back to previous profile: $previous"
            write_profile_state "$previous" "rollback"
            write_audit "profile_change_rolled_back" "$requested" "$previous" \
                "$validation_errors service(s) in wrong state"
            _RES_STATUS="rolled_back" _RES_PROFILE="$previous" _RES_PREVIOUS="$previous" \
            _RES_DETAIL="$validation_errors service(s) failed validation; rolled back to $previous" \
            _RES_TMPFILE="${RESULT_FILE}.tmp" \
            write_result "rolled_back" "$previous" "$previous" \
                "$validation_errors service(s) failed validation"
            # Re-apply previous profile services
            exec "$0" "$previous" "rollback"
        fi
        exit 1
    fi

    # Success: write state and audit
    write_profile_state "$requested" "$changed_by"
    write_audit "profile_changed" "$requested" "$previous" "success"

    _RES_STATUS="success" _RES_PROFILE="$requested" _RES_PREVIOUS="$previous" \
    _RES_DETAIL="" _RES_TMPFILE="${RESULT_FILE}.tmp" \
    write_result "success" "$requested" "$previous" ""

    log "Profile applied successfully: $requested"
}

main "$@"
