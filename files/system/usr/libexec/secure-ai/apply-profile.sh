#!/usr/bin/env bash
#
# SecAI OS privileged runtime-profile applicator.
#
# The unprivileged UI contributes only an O_EXCL request file. This script
# validates the complete baked profile model, snapshots actual systemd state,
# applies the requested transaction, proves both active and enablement state,
# and restores the exact snapshot on any failure.
#
set -euo pipefail
umask 077

APPLIANCE_CONFIG="${APPLIANCE_CONFIG:-/etc/secure-ai/config/appliance.yaml}"
PROFILE_STATE="${PROFILE_STATE:-/var/lib/secure-ai/state/profile.json}"
OPERATOR_OVERRIDE="${OPERATOR_OVERRIDE:-/etc/secure-ai/local.d/profile.yaml}"
REQUEST_FILE="${REQUEST_FILE:-/run/secure-ai-ui/profile-request}"
RESULT_FILE="${RESULT_FILE:-/run/secure-ai/profile-result.json}"
AUDIT_LOG="${AUDIT_LOG:-/var/lib/secure-ai/logs/audit.jsonl}"
UNIT_ROOT="${UNIT_ROOT:-/usr/lib/systemd/system}"
PROFILE_HELPER="${PROFILE_HELPER:-/usr/libexec/secure-ai/secure-profile-plan.py}"
WORK_ROOT="${WORK_ROOT:-/run/secure-ai/profile-control}"
LOCK_FILE="${LOCK_FILE:-/run/secure-ai/profile-control.lock}"

WORK_DIR=""
PROCESSING_REQUEST=""
APPLY_ERRORS=0

log() {
    printf '[apply-profile] %s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

fatal() {
    log "ERROR: $*"
    exit 1
}

cleanup() {
    if [ -n "$PROCESSING_REQUEST" ] && [ -f "$PROCESSING_REQUEST" ] \
        && [[ "$PROCESSING_REQUEST" == "$WORK_DIR/"* ]]; then
        rm -f -- "$PROCESSING_REQUEST"
    fi
    if [ -n "$WORK_DIR" ] && [[ "$WORK_DIR" == "$WORK_ROOT/"* ]] && [ -d "$WORK_DIR" ]; then
        rm -rf -- "$WORK_DIR"
    fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

json_value() {
    local file="$1"
    local field="$2"
    python3 - "$file" "$field" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    value = json.load(handle)[sys.argv[2]]
if isinstance(value, bool):
    print("true" if value else "false")
elif isinstance(value, str):
    print(value)
else:
    raise SystemExit("requested JSON field has an unexpected type")
PY
}

json_list() {
    local file="$1"
    local field="$2"
    python3 - "$file" "$field" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    value = json.load(handle)[sys.argv[2]]
if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
    raise SystemExit("requested JSON field is not a string list")
for item in value:
    print(item)
PY
}

write_result() {
    local status="$1"
    local profile="$2"
    local previous="$3"
    local detail="${4:-}"
    "$PROFILE_HELPER" write-result \
        --file "$RESULT_FILE" \
        --status "$status" \
        --profile "$profile" \
        --previous "$previous" \
        --detail "$detail" >/dev/null
}

write_audit() {
    local event="$1"
    local profile="$2"
    local previous="$3"
    local detail="${4:-}"
    install -d -m 2770 -o root -g secure-ai-logs -- "$(dirname "$AUDIT_LOG")"
    python3 - "$AUDIT_LOG" "$event" "$profile" "$previous" "$detail" <<'PY'
import fcntl
import json
import os
import sys
from datetime import datetime, timezone

path, event, profile, previous, detail = sys.argv[1:]
entry = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "event": event,
    "profile": profile,
    "previous": previous,
    "detail": detail,
    "source": "apply-profile",
}
with open(path, "a", encoding="utf-8") as handle:
    fcntl.flock(handle, fcntl.LOCK_EX)
    handle.write(json.dumps(entry, separators=(",", ":")) + "\n")
    handle.flush()
    os.fsync(handle.fileno())
os.chmod(path, 0o640)
PY
}

snapshot_systemd_state() {
    local plan_file="$1"
    local snapshot_file="$2"
    local -a controlled=()
    while IFS= read -r unit; do
        [ -n "$unit" ] && controlled+=("$unit")
    done < <(json_list "$plan_file" controlled_services)
    [ "${#controlled[@]}" -gt 0 ] || fatal "Validated profile controls no services"

    : > "$snapshot_file"
    chmod 0600 "$snapshot_file"
    local unit enabled active
    for unit in "${controlled[@]}"; do
        enabled=$(systemctl is-enabled "$unit" 2>/dev/null || true)
        active=$(systemctl is-active "$unit" 2>/dev/null || true)
        case "$enabled" in
            enabled|disabled) ;;
            *) fatal "Refusing transition while $unit has unsupported enablement state '$enabled'" ;;
        esac
        case "$active" in
            active|inactive) ;;
            *) fatal "Refusing transition while $unit has unsupported runtime state '$active'" ;;
        esac
        printf '%s|%s|%s\n' "$unit" "$enabled" "$active" >> "$snapshot_file"
    done
    sync -f "$snapshot_file"
}

apply_plan() {
    local plan_file="$1"
    local -a to_enable=()
    local -a to_disable=()
    local unit
    while IFS= read -r unit; do
        [ -n "$unit" ] && to_enable+=("$unit")
    done < <(json_list "$plan_file" services_enabled)
    while IFS= read -r unit; do
        [ -n "$unit" ] && to_disable+=("$unit")
    done < <(json_list "$plan_file" services_disabled)
    APPLY_ERRORS=0

    for unit in "${to_disable[@]}"; do
        if systemctl is-active --quiet "$unit"; then
            log "Stopping $unit"
            if ! systemctl stop "$unit"; then
                log "ERROR: failed to stop $unit"
                APPLY_ERRORS=$((APPLY_ERRORS + 1))
            fi
        fi
        if systemctl is-enabled --quiet "$unit"; then
            log "Disabling $unit"
            if ! systemctl disable "$unit"; then
                log "ERROR: failed to disable $unit"
                APPLY_ERRORS=$((APPLY_ERRORS + 1))
            fi
        fi
    done

    for unit in "${to_enable[@]}"; do
        if ! systemctl is-enabled --quiet "$unit"; then
            log "Enabling $unit"
            if ! systemctl enable "$unit"; then
                log "ERROR: failed to enable $unit"
                APPLY_ERRORS=$((APPLY_ERRORS + 1))
            fi
        fi
        if ! systemctl is-active --quiet "$unit"; then
            log "Starting $unit"
            if ! systemctl start "$unit"; then
                log "ERROR: failed to start $unit"
                APPLY_ERRORS=$((APPLY_ERRORS + 1))
            fi
        fi
    done

    for unit in "${to_enable[@]}"; do
        if ! systemctl is-enabled --quiet "$unit"; then
            log "VALIDATION: $unit should be enabled but is not"
            APPLY_ERRORS=$((APPLY_ERRORS + 1))
        fi
        if ! systemctl is-active --quiet "$unit"; then
            log "VALIDATION: $unit should be active but is not"
            APPLY_ERRORS=$((APPLY_ERRORS + 1))
        fi
    done
    for unit in "${to_disable[@]}"; do
        if systemctl is-enabled --quiet "$unit"; then
            log "VALIDATION: $unit should be disabled but is enabled"
            APPLY_ERRORS=$((APPLY_ERRORS + 1))
        fi
        if systemctl is-active --quiet "$unit"; then
            log "VALIDATION: $unit should be inactive but is active"
            APPLY_ERRORS=$((APPLY_ERRORS + 1))
        fi
    done
}

restore_snapshot() {
    local snapshot_file="$1"
    local rollback_errors=0
    local unit enabled active
    while IFS='|' read -r unit enabled active; do
        [ -n "$unit" ] || continue
        if [ "$enabled" = enabled ]; then
            systemctl enable "$unit" || rollback_errors=$((rollback_errors + 1))
        else
            systemctl disable "$unit" || rollback_errors=$((rollback_errors + 1))
        fi
        if [ "$active" = active ]; then
            systemctl start "$unit" || rollback_errors=$((rollback_errors + 1))
        else
            systemctl stop "$unit" || rollback_errors=$((rollback_errors + 1))
        fi
    done < "$snapshot_file"

    while IFS='|' read -r unit enabled active; do
        [ -n "$unit" ] || continue
        local actual_enabled actual_active
        actual_enabled=$(systemctl is-enabled "$unit" 2>/dev/null || true)
        actual_active=$(systemctl is-active "$unit" 2>/dev/null || true)
        if [ "$actual_enabled" != "$enabled" ] || [ "$actual_active" != "$active" ]; then
            log "ROLLBACK VALIDATION: $unit expected $enabled/$active, got $actual_enabled/$actual_active"
            rollback_errors=$((rollback_errors + 1))
        fi
    done < "$snapshot_file"
    [ "$rollback_errors" -eq 0 ]
}

main() {
    [ "$(id -u)" -eq 0 ] || fatal "profile applicator must run as root"
    [ -x "$PROFILE_HELPER" ] || fatal "profile validation helper is unavailable"
    command -v flock >/dev/null 2>&1 || fatal "flock is required"
    command -v systemctl >/dev/null 2>&1 || fatal "systemctl is required"

    install -d -m 0750 -o root -g secure-ai-services -- "$WORK_ROOT"
    [ ! -L "$WORK_ROOT" ] || fatal "profile work root is a symbolic link"
    WORK_DIR=$(mktemp -d "${WORK_ROOT}/transaction.XXXXXXXX")
    chmod 0700 "$WORK_DIR"

    install -d -m 0750 -o root -g secure-ai-services -- "$(dirname "$LOCK_FILE")"
    exec 9>"$LOCK_FILE"
    chmod 0600 "$LOCK_FILE"
    flock -n 9 || fatal "another profile change is already in progress"

    local current_file="${WORK_DIR}/current.json"
    if ! "$PROFILE_HELPER" current \
        --state "$PROFILE_STATE" \
        --override "$OPERATOR_OVERRIDE" > "$current_file"
    then
        write_result failed offline_private "" "Operator override is invalid; no state was changed" \
            || true
        write_audit profile_change_rejected offline_private "" "invalid operator override" \
            || true
        fatal "operator override is invalid; refusing to change service state"
    fi

    local previous locked source requested changed_by
    previous=$(json_value "$current_file" profile)
    locked=$(json_value "$current_file" locked)
    source=$(json_value "$current_file" source)
    requested=""
    changed_by="boot"

    if [ -e "$REQUEST_FILE" ] || [ -L "$REQUEST_FILE" ]; then
        PROCESSING_REQUEST="${WORK_DIR}/profile-request"
        mv -T -- "$REQUEST_FILE" "$PROCESSING_REQUEST" \
            || fatal "could not atomically consume the UI profile request"
        local request_file="${WORK_DIR}/request.json"
        if ! "$PROFILE_HELPER" request --file "$PROCESSING_REQUEST" > "$request_file"; then
            write_result failed "$previous" "$previous" "Malformed profile request"
            write_audit profile_change_rejected "$previous" "$previous" "malformed UI request"
            fatal "malformed UI profile request"
        fi
        requested=$(json_value "$request_file" profile)
        changed_by="ui"
    elif [ "$#" -gt 0 ]; then
        [ "$#" -le 2 ] || fatal "usage: apply-profile.sh [profile [changed_by]]"
        requested="$1"
        changed_by="${2:-cli}"
        [[ "$changed_by" =~ ^[a-z0-9_-]{1,32}$ ]] || fatal "invalid changed_by value"
    else
        requested="$previous"
    fi

    local plan_file="${WORK_DIR}/plan.json"
    if ! "$PROFILE_HELPER" plan \
        --config "$APPLIANCE_CONFIG" \
        --unit-root "$UNIT_ROOT" \
        --profile "$requested" > "$plan_file"
    then
        write_result failed "$previous" "$previous" "Profile configuration validation failed"
        write_audit profile_change_rejected "$requested" "$previous" "invalid profile configuration"
        fatal "profile configuration validation failed"
    fi

    if [ "$locked" = true ] && [ "$requested" != "$previous" ]; then
        write_result failed "$requested" "$previous" "Profile is locked by operator override"
        write_audit profile_change_rejected "$requested" "$previous" "operator override lock"
        fatal "operator override locks the active profile to $previous"
    fi

    local snapshot_file="${WORK_DIR}/systemd.snapshot"
    snapshot_systemd_state "$plan_file" "$snapshot_file"
    write_result in_progress "$requested" "$previous" ""
    write_audit profile_change_started "$requested" "$previous" "requested by $changed_by" \
        || fatal "cannot audit profile transition; no state was changed"

    log "Applying profile $requested (previous=$previous, source=$source, by=$changed_by)"
    apply_plan "$plan_file"

    if [ "$APPLY_ERRORS" -eq 0 ] && [ "$source" != operator_override ]; then
        if ! "$PROFILE_HELPER" write-state \
            --file "$PROFILE_STATE" \
            --profile "$requested" \
            --changed-by "$changed_by" >/dev/null
        then
            log "ERROR: profile services changed, but persistent state commit failed"
            APPLY_ERRORS=$((APPLY_ERRORS + 1))
        fi
    fi

    if [ "$APPLY_ERRORS" -gt 0 ]; then
        log "Profile transaction failed with $APPLY_ERRORS error(s); restoring exact prior state"
        if restore_snapshot "$snapshot_file"; then
            write_result rolled_back "$previous" "$previous" \
                "$APPLY_ERRORS apply/validation error(s); exact service state restored"
            write_audit profile_change_rolled_back "$requested" "$previous" \
                "$APPLY_ERRORS apply/validation error(s)"
            exit 1
        fi
        write_result rollback_failed "$previous" "$previous" \
            "$APPLY_ERRORS apply/validation error(s); rollback also failed"
        write_audit profile_change_rollback_failed "$requested" "$previous" \
            "$APPLY_ERRORS apply/validation error(s)"
        exit 2
    fi

    write_audit profile_changed "$requested" "$previous" "success"
    write_result success "$requested" "$previous" ""
    log "Profile applied and validated successfully: $requested"
}

main "$@"
