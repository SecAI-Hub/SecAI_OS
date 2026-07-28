#!/usr/bin/env bash
#
# Verify authenticated canaries and submit violations to the fixed containment
# chain. This script never performs mount/cryptsetup/process-kill operations
# itself; the incident recorder and root-owned vault broker own those actions.
#
set -euo pipefail
umask 077

SECURE_AI_ROOT="${SECURE_AI_ROOT:-/var/lib/secure-ai}"
CANARY_DB="${CANARY_DB:-${SECURE_AI_ROOT}/state/canary-db.json}"
CANARY_HMAC_KEY_PATH="${CANARY_HMAC_KEY_PATH:-${SECURE_AI_ROOT}/credentials/canary-hmac.key}"
INCIDENT_RECORDER_TOKEN_PATH="${INCIDENT_RECORDER_TOKEN_PATH:-${SECURE_AI_ROOT}/credentials/incident-reporter-canary.token}"
INCIDENT_RECORDER_URL="${INCIDENT_RECORDER_URL:-http://127.0.0.1:8515}"
CANARY_HELPER="${CANARY_HELPER:-/usr/libexec/secure-ai/secure-canary.py}"
ALERT_FILE="${ALERT_FILE:-${SECURE_AI_ROOT}/state/canary-alert.json}"
RUNTIME_ALERT_FILE="${RUNTIME_ALERT_FILE:-/run/secure-ai/canary-alert.json}"
AUDIT_LOG="${AUDIT_LOG:-${SECURE_AI_ROOT}/logs/canary-audit.jsonl}"
PANIC_STATE="${PANIC_STATE:-/run/secure-ai/panic-state.json}"
WORK_ROOT="${WORK_ROOT:-/run/secure-ai/canary}"
MODE="${1:-check}"
WORK_DIR=""

log() {
    printf '[canary-check] %s\n' "$*"
    logger -t canary-check "$*" 2>/dev/null || true
}

cleanup() {
    if [ -n "$WORK_DIR" ] && [[ "$WORK_DIR" == "$WORK_ROOT/"* ]] && [ -d "$WORK_DIR" ]; then
        rm -rf -- "$WORK_DIR"
    fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

prepare() {
    [ "$(id -u)" -eq 0 ] || {
        log "ERROR: canary verification must run as root"
        return 1
    }
    [ -x "$CANARY_HELPER" ] || {
        log "ERROR: authenticated canary helper is unavailable"
        return 1
    }
    install -d -m 0750 -o root -g secure-ai-services -- "$WORK_ROOT"
    [ ! -L "$WORK_ROOT" ] || {
        log "ERROR: canary work root is a symbolic link"
        return 1
    }
    WORK_DIR=$(mktemp -d "${WORK_ROOT}/check.XXXXXXXX")
    chmod 0700 "$WORK_DIR"
}

json_value() {
    local file="$1"
    local field="$2"
    python3 - "$file" "$field" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    value = json.load(handle)[sys.argv[2]]
if isinstance(value, str):
    print(value)
elif isinstance(value, list):
    print(", ".join(str(item) for item in value))
else:
    raise SystemExit("unexpected result field type")
PY
}

validate_private_token() {
    local path="$1"
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    [ "$(stat -c '%u' "$path")" -eq 0 ] || return 1
    local mode
    mode=$(stat -c '%a' "$path")
    (( (8#$mode & 077) == 0 )) || return 1
    [ -s "$path" ]
}

write_audit() {
    local reason="$1"
    local path="$2"
    local fingerprint="$3"
    install -d -m 2770 -o root -g secure-ai-logs -- "$(dirname "$AUDIT_LOG")"
    python3 - "$AUDIT_LOG" "$reason" "$path" "$fingerprint" <<'PY'
import fcntl
import json
import os
import sys
from datetime import datetime, timezone

log_path, reason, path, fingerprint = sys.argv[1:]
entry = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "event": "canary_tripwire",
    "severity": "critical",
    "data": {
        "reason": reason,
        "path": path,
        "fingerprint": fingerprint,
    },
}
with open(log_path, "a", encoding="utf-8") as handle:
    fcntl.flock(handle, fcntl.LOCK_EX)
    handle.write(json.dumps(entry, separators=(",", ":")) + "\n")
    handle.flush()
    os.fsync(handle.fileno())
os.chmod(log_path, 0o640)
PY
}

same_confirmed_alert_exists() {
    local fingerprint="$1"
    [ -f "$ALERT_FILE" ] && [ ! -L "$ALERT_FILE" ] || return 1
    python3 - "$ALERT_FILE" "$fingerprint" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        alert = json.load(handle)
except (OSError, ValueError):
    raise SystemExit(1)
if (
    alert.get("fingerprint") == sys.argv[2]
    and alert.get("containment_status") == "contained"
):
    raise SystemExit(0)
raise SystemExit(1)
PY
}

write_alert() {
    local reason="$1"
    local path="$2"
    local fingerprint="$3"
    local containment_status="$4"
    local incident_id="${5:-}"
    python3 - \
        "$ALERT_FILE" \
        "$RUNTIME_ALERT_FILE" \
        "$reason" \
        "$path" \
        "$fingerprint" \
        "$containment_status" \
        "$incident_id" <<'PY'
import grp
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

persistent, runtime, reason, path, fingerprint, status, incident_id = sys.argv[1:]
payload = {
    "triggered": True,
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "reason": reason,
    "path": path,
    "fingerprint": fingerprint,
    "containment_status": status,
    "incident_id": incident_id,
}
gid = grp.getgrnam("secure-ai-services").gr_gid
for raw_destination in (persistent, runtime):
    destination = Path(raw_destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.parent.is_symlink():
        raise SystemExit(f"unsafe alert parent: {destination.parent}")
    if destination.exists() or destination.is_symlink():
        metadata = destination.lstat()
        if not destination.is_file() or destination.is_symlink():
            raise SystemExit(f"unsafe alert target: {destination}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        dir=destination.parent,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
            os.fchmod(handle.fileno(), 0o640)
            os.fchown(handle.fileno(), 0, gid)
        os.replace(temporary_name, destination)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise
PY
}

create_incident_report() {
    local destination="$1"
    local reason="$2"
    local path="$3"
    local fingerprint="$4"
    python3 - "$destination" "$reason" "$path" "$fingerprint" <<'PY'
import json
import os
import sys

destination, reason, path, fingerprint = sys.argv[1:]
report = {
    "class": "integrity_violation",
    "severity": "critical",
    "source": "canary-tripwire",
    "description": "Authenticated canary verification failed",
    "evidence": {
        "violation_0_path": path,
        "reason": reason[:512],
        "fingerprint": fingerprint,
    },
}
with open(destination, "x", encoding="utf-8") as handle:
    json.dump(report, handle, separators=(",", ":"))
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
os.chmod(destination, 0o600)
PY
}

validate_containment_response() {
    local response="$1"
    python3 - "$response" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    incident = json.load(handle)
if incident.get("state") != "contained":
    raise SystemExit(1)
actions = set(incident.get("containment_actions") or [])
required = {"freeze_agent", "disable_airlock", "force_vault_relock"}
if not required.issubset(actions):
    raise SystemExit(1)
results = incident.get("containment_results")
if not isinstance(results, list) or not results:
    raise SystemExit(1)
by_action = {
    item.get("action"): item.get("success")
    for item in results
    if isinstance(item, dict)
}
if any(by_action.get(action) is not True for action in required):
    raise SystemExit(1)
incident_id = incident.get("id")
if not isinstance(incident_id, str) or not incident_id:
    raise SystemExit(1)
print(incident_id)
PY
}

submit_for_containment() {
    local reason="$1"
    local path="$2"
    local fingerprint="$3"
    validate_private_token "$INCIDENT_RECORDER_TOKEN_PATH" || return 1
    [[ "$INCIDENT_RECORDER_URL" =~ ^http://(127\.0\.0\.1|localhost|\[::1\]):([0-9]{1,5})$ ]] \
        || return 1
    command -v curl >/dev/null 2>&1 || return 1

    local token
    IFS= read -r token < "$INCIDENT_RECORDER_TOKEN_PATH" || return 1
    [[ "$token" =~ ^[0-9a-fA-F]{64,256}$ ]] || return 1
    local curl_config="${WORK_DIR}/curl.conf"
    printf 'header = "Authorization: Bearer %s"\n' "$token" > "$curl_config"
    chmod 0600 "$curl_config"
    local report="${WORK_DIR}/incident.json"
    local response="${WORK_DIR}/incident-response.json"
    create_incident_report "$report" "$reason" "$path" "$fingerprint"

    curl \
        --config "$curl_config" \
        --proto '=http' \
        --proto-redir '=http' \
        --noproxy '*' \
        --fail \
        --silent \
        --show-error \
        --connect-timeout 2 \
        --max-time 105 \
        --max-filesize 1048576 \
        --header 'Content-Type: application/json' \
        --data-binary "@${report}" \
        --output "$response" \
        "${INCIDENT_RECORDER_URL}/api/v1/incidents/report" \
        || return 1
    validate_containment_response "$response"
}

panic_fallback() {
    command -v systemctl >/dev/null 2>&1 || return 1
    systemctl start secure-ai-panic.service || return 1
    [ -f "$PANIC_STATE" ] && [ ! -L "$PANIC_STATE" ] || return 1
    python3 - "$PANIC_STATE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    state = json.load(handle)
if (
    state.get("panic_active") is not True
    or state.get("level", 0) < 1
    or state.get("status") != "locked"
):
    raise SystemExit(1)
PY
}

trigger_alarm() {
    local reason="$1"
    local path="$2"
    local fingerprint="$3"
    log "CRITICAL: authenticated canary violation: $reason ($path)"
    write_audit "$reason" "$path" "$fingerprint" \
        || log "ERROR: could not append canary audit record"

    if same_confirmed_alert_exists "$fingerprint"; then
        log "Violation remains latched; containment was already confirmed for this fingerprint"
        return 1
    fi

    local incident_id=""
    if incident_id=$(submit_for_containment "$reason" "$path" "$fingerprint"); then
        write_alert "$reason" "$path" "$fingerprint" contained "$incident_id"
        log "Containment confirmed by incident $incident_id"
        return 1
    fi

    log "ERROR: incident containment was unavailable or incomplete; starting panic fallback"
    if panic_fallback; then
        write_alert "$reason" "$path" "$fingerprint" contained "panic-fallback"
        log "Panic fallback confirmed locked"
        return 1
    fi
    write_alert "$reason" "$path" "$fingerprint" containment_failed "" \
        || log "ERROR: could not persist failed-containment alert"
    log "CRITICAL: containment could not be confirmed"
    return 1
}

run_check() {
    local result_file="${WORK_DIR}/result.json"
    local helper_status=0
    "$CANARY_HELPER" check \
        --database "$CANARY_DB" \
        --key "$CANARY_HMAC_KEY_PATH" > "$result_file" || helper_status=$?

    if [ ! -s "$result_file" ]; then
        local fingerprint
        fingerprint=$(printf '%s' "canary verification unavailable" | sha256sum | awk '{print $1}')
        trigger_alarm "canary verification unavailable" "$CANARY_DB" "$fingerprint"
        return 1
    fi

    local status fingerprint
    status=$(json_value "$result_file" status)
    fingerprint=$(json_value "$result_file" fingerprint)
    if { [ "$status" = "ok" ] || [ "$status" = "pending" ]; } \
        && [ "$helper_status" -ne 0 ]; then
        trigger_alarm "canary verifier exit/result mismatch" "$CANARY_DB" "$fingerprint"
        return 1
    fi
    if [ "$status" = "violation" ] && [ "$helper_status" -ne 1 ]; then
        trigger_alarm "canary verifier exit/result mismatch" "$CANARY_DB" "$fingerprint"
        return 1
    fi
    case "$status" in
        ok)
            log "All authenticated canaries verified"
            return 0
            ;;
        pending)
            local pending
            pending=$(json_value "$result_file" pending_locations)
            log "Canary coverage pending until vault enrollment: $pending"
            return 0
            ;;
        violation)
            local violation_file="${WORK_DIR}/first-violation.json"
            python3 - "$result_file" "$violation_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    result = json.load(handle)
violations = result.get("violations")
if not isinstance(violations, list) or not violations:
    raise SystemExit("violation result has no evidence")
with open(sys.argv[2], "x", encoding="utf-8") as handle:
    json.dump(violations[0], handle, separators=(",", ":"))
PY
            local reason path
            reason=$(json_value "$violation_file" reason)
            path=$(json_value "$violation_file" path)
            trigger_alarm "$reason" "$path" "$fingerprint"
            return 1
            ;;
        *)
            trigger_alarm "invalid canary verifier result" "$CANARY_DB" "$fingerprint"
            return 1
            ;;
    esac
}

run_watch() {
    command -v inotifywait >/dev/null 2>&1 || {
        log "ERROR: inotifywait is required for real-time canary monitoring"
        return 1
    }
    local -a paths=()
    local path
    while IFS= read -r path; do
        [ -n "$path" ] && paths+=("$path")
    done < <(
        "$CANARY_HELPER" paths \
            --database "$CANARY_DB" \
            --key "$CANARY_HMAC_KEY_PATH"
    )
    [ "${#paths[@]}" -gt 0 ] || {
        log "ERROR: authenticated canary database has no active paths"
        return 1
    }
    run_check || true
    log "Watching ${#paths[@]} authenticated canary path(s)"
    while IFS= read -r event; do
        log "Filesystem event: $event"
        run_check || true
    done < <(
        inotifywait \
            --monitor \
            --quiet \
            --format '%w|%e' \
            --event close_write,delete_self,attrib,move_self \
            -- "${paths[@]}"
    )
    log "ERROR: inotifywait exited; requesting service restart"
    return 1
}

prepare
case "$MODE" in
    check) run_check ;;
    watch) run_watch ;;
    *)
        log "Usage: $0 [check|watch]"
        exit 2
        ;;
esac
