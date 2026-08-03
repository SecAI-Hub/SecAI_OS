#!/usr/bin/env bash
#
# SecAI OS authenticated restore utility.
#
# Restore input is treated as hostile until age authentication, strict manifest
# verification, bounded type-safe extraction, and a transactional local install
# have all succeeded.
#
set -euo pipefail
umask 077

SECURE_AI_ROOT="/var/lib/secure-ai"
AUDIT_LOG="${SECURE_AI_ROOT}/logs/backup-audit.jsonl"
HEALTH_CHECK="/usr/libexec/secure-ai/first-boot-check.sh"
ARCHIVE_HELPER="${ARCHIVE_HELPER:-/usr/libexec/secure-ai/secure-backup-archive.py}"
WORK_ROOT="${WORK_ROOT:-/run/secure-ai/restore-tmp}"

AGE_IDENTITY=""
RESTORE_LUKS_HEADER=false
VAULT_DEVICE=""
CONFIRM_LUKS_UUID=""
WORK_DIR=""
SERVICES_STOPPED=false
ACTIVE_UNITS=()

SERVICE_UNITS=(
    secure-ai-ui.service
    secure-ai-diffusion.service
    secure-ai-search-mediator.service
    secure-ai-searxng.service
    secure-ai-tor.service
    secure-ai-airlock.service
    secure-ai-agent.service
    secure-ai-mcp-firewall.service
    secure-ai-tool-firewall.service
    secure-ai-quarantine-watcher.service
    secure-ai-inference.service
    secure-ai-gpu-integrity-watch.service
    secure-ai-integrity-monitor.service
    secure-ai-registry.service
    secure-ai-policy-engine.service
    secure-ai-incident-recorder.service
    secure-ai-runtime-attestor.service
)

if [ -t 1 ]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
    CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; NC=''
fi

info()  { printf '%s[+]%s %s\n' "$GREEN" "$NC" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$YELLOW" "$NC" "$*" >&2; }
error() { printf '%s[x]%s %s\n' "$RED" "$NC" "$*" >&2; }
fatal() { error "$*"; exit 1; }
step()  { printf '\n%s%s=== %s ===%s\n' "$BOLD" "$CYAN" "$*" "$NC"; }

usage() {
    cat <<'USAGE'
SecAI OS — Authenticated Restore

Usage:
  secai-restore.sh full    FILE.age [--identity FILE]
  secai-restore.sh config  FILE.age [--identity FILE]
  secai-restore.sh logs    FILE.age [--identity FILE]
  secai-restore.sh keys    FILE.age [--identity FILE]
  secai-restore.sh inspect FILE.age [--identity FILE]

LUKS header restore is never inferred from archived /etc data and is skipped by
default. It is permitted only when all three explicit options are supplied:

  --restore-luks-header
  --vault-device /dev/<exact-block-device>
  --confirm-luks-uuid <uuid-read-from-that-device>

The archive UUID, current target UUID, and explicit confirmation must all match;
the target must be a closed, unmounted LUKS block device with no holders.

Options:
  --identity FILE          age identity used for decryption
  --restore-luks-header    opt in to the irreversible LUKS header operation
  --vault-device DEVICE    exact underlying LUKS block device
  --confirm-luks-uuid UUID explicit target identity proof
  --help                   show this help
USAGE
    exit 0
}

restart_services() {
    if [ "$SERVICES_STOPPED" != true ]; then
        return 0
    fi
    if [ "${#ACTIVE_UNITS[@]}" -eq 0 ]; then
        SERVICES_STOPPED=false
        return 0
    fi
    systemctl start "${ACTIVE_UNITS[@]}" || return 1
    SERVICES_STOPPED=false
}

cleanup() {
    local status=$?
    if [ "$SERVICES_STOPPED" = true ]; then
        restart_services || warn "Failed to restore the pre-restore service state"
    fi
    if [ -n "$WORK_DIR" ] && [[ "$WORK_DIR" == "$WORK_ROOT/"* ]] && [ -d "$WORK_DIR" ]; then
        rm -rf -- "$WORK_DIR"
    fi
    return "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

require_root_and_tools() {
    [ "$(id -u)" -eq 0 ] || fatal "Restore and inspection must be run as root (sudo)"
    local tool
    for tool in age python3 sha256sum; do
        command -v "$tool" >/dev/null 2>&1 || fatal "Required command is missing: $tool"
    done
    [ -x "$ARCHIVE_HELPER" ] || fatal "Archive helper is missing or not executable: $ARCHIVE_HELPER"
}

prepare_work_dir() {
    install -d -m 0700 -o root -g root -- "$WORK_ROOT"
    [ ! -L "$WORK_ROOT" ] || fatal "Refusing symbolic-link work directory: $WORK_ROOT"
    WORK_DIR=$(mktemp -d "${WORK_ROOT}/restore.XXXXXXXX")
    chmod 0700 "$WORK_DIR"
}

audit_event() {
    local action="$1"
    local detail="$2"
    install -d -m 2770 -o root -g secure-ai-logs -- "$(dirname "$AUDIT_LOG")"
    python3 - "$AUDIT_LOG" "$action" "$detail" <<'PY'
import fcntl
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

path, action, detail = sys.argv[1:]
timestamp = datetime.now(timezone.utc).isoformat()
with open(path, "a+", encoding="utf-8") as handle:
    fcntl.flock(handle, fcntl.LOCK_EX)
    handle.seek(0)
    previous = ""
    for raw_line in handle:
        if raw_line.strip():
            previous = json.loads(raw_line)["entry_hash"]
    data = {"action": action, "detail": detail}
    canonical = json.dumps(
        {
            "prev_hash": previous,
            "event": "restore",
            "data": data,
            "timestamp": timestamp,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    entry = {
        "timestamp": timestamp,
        "event": "restore",
        "data": data,
        "prev_hash": previous,
        "entry_hash": hashlib.sha256(canonical).hexdigest(),
        "algorithm": "sha256",
    }
    handle.seek(0, os.SEEK_END)
    handle.write(json.dumps(entry, separators=(",", ":")) + "\n")
    handle.flush()
    os.fsync(handle.fileno())
os.chmod(path, 0o640)
PY
}

verify_transport_checksum() {
    local artifact="$1"
    local sidecar="${artifact}.sha256"
    if [ ! -f "$sidecar" ] || [ -L "$sidecar" ]; then
        fatal "Required transport checksum is missing or unsafe: $sidecar"
    fi
    local expected declared extra
    IFS=' ' read -r expected declared extra < "$sidecar" || fatal "Cannot read checksum sidecar"
    declared="${declared#\\*}"
    [ -z "${extra:-}" ] || fatal "Checksum sidecar has unexpected fields"
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || fatal "Checksum sidecar has an invalid SHA-256"
    [ "$declared" = "$(basename "$artifact")" ] \
        || fatal "Checksum sidecar names a different artifact"
    local actual
    actual=$(sha256sum -- "$artifact" | awk '{print $1}')
    [ "$expected" = "$actual" ] || fatal "Encrypted backup transport checksum mismatch"
}

decrypt_to_tmpfs() {
    local artifact="$1"
    local plaintext="$2"
    local -a args=(-d)
    if [ -n "$AGE_IDENTITY" ]; then
        if [ ! -f "$AGE_IDENTITY" ] || [ -L "$AGE_IDENTITY" ]; then
            fatal "Age identity is missing or unsafe: $AGE_IDENTITY"
        fi
        [ "$(stat -c '%u' "$AGE_IDENTITY")" -eq 0 ] \
            || fatal "Age identity must be owned by root"
        local identity_mode
        identity_mode=$(stat -c '%a' "$AGE_IDENTITY")
        (( (8#$identity_mode & 077) == 0 )) \
            || fatal "Age identity must not be accessible by group or other users"
        args+=(-i "$AGE_IDENTITY")
    fi
    age "${args[@]}" -- "$artifact" > "$plaintext" || fatal "Age authentication/decryption failed"
    chmod 0600 "$plaintext"
}

authenticate_and_extract() {
    local artifact="$1"
    local plaintext="${WORK_DIR}/authenticated.tar.gz"
    local staging="${WORK_DIR}/staging"
    mkdir -m 0700 -- "$staging"

    verify_transport_checksum "$artifact"
    decrypt_to_tmpfs "$artifact" "$plaintext"
    "$ARCHIVE_HELPER" extract --archive "$plaintext" --destination "$staging" >/dev/null \
        || fatal "Backup archive failed strict manifest or extraction validation"
    printf '%s\n' "$staging"
}

manifest_value() {
    local manifest="$1"
    local field="$2"
    python3 - "$manifest" "$field" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)
field = sys.argv[2]
if field == "category":
    print(manifest["category"])
elif field == "luks_uuid":
    print(manifest["luks_header"]["uuid"])
elif field == "luks_included":
    print("true" if manifest["luks_header"]["included"] else "false")
else:
    raise SystemExit("unsupported manifest field")
PY
}

validate_requested_category() {
    local requested="$1"
    local archived="$2"
    if [ "$requested" = "full" ]; then
        [ "$archived" = "full" ] \
            || fatal "A full restore requires a full backup, not category '$archived'"
    else
        [ "$archived" = "full" ] || [ "$archived" = "$requested" ] \
            || fatal "Backup category '$archived' cannot satisfy a '$requested' restore"
    fi
}

stop_active_services() {
    [ -d /run/systemd/system ] || {
        warn "systemd is not running; service state will not be managed"
        return 0
    }
    local unit
    ACTIVE_UNITS=()
    for unit in "${SERVICE_UNITS[@]}"; do
        if systemctl is-active --quiet "$unit"; then
            ACTIVE_UNITS+=("$unit")
        fi
    done
    if [ "${#ACTIVE_UNITS[@]}" -gt 0 ]; then
        SERVICES_STOPPED=true
        systemctl stop "${ACTIVE_UNITS[@]}" \
            || fatal "Could not stop all active services before the restore transaction"
    fi
}

restore_luks_header_if_requested() {
    local staging="$1"
    local manifest="${staging}/manifest.json"
    local included
    included=$(manifest_value "$manifest" luks_included)

    if [ "$RESTORE_LUKS_HEADER" != true ]; then
        if [ "$included" = true ]; then
            info "LUKS header is present but was safely skipped (explicit opt-in required)"
        fi
        return 0
    fi

    [ "$included" = true ] || fatal "LUKS header restore requested, but archive has no header"
    [ -n "$VAULT_DEVICE" ] || fatal "--vault-device is required with --restore-luks-header"
    [ -n "$CONFIRM_LUKS_UUID" ] \
        || fatal "--confirm-luks-uuid is required with --restore-luks-header"
    command -v cryptsetup >/dev/null 2>&1 || fatal "cryptsetup is required for header restore"
    command -v lsblk >/dev/null 2>&1 || fatal "lsblk is required for header restore"

    local target
    target=$(readlink -f -- "$VAULT_DEVICE") || fatal "Cannot resolve vault device"
    [[ "$target" == /dev/* ]] || fatal "Vault target must resolve beneath /dev"
    [ -b "$target" ] || fatal "Vault target is not a block device: $target"
    cryptsetup isLuks "$target" >/dev/null 2>&1 \
        || fatal "Vault target is not currently a LUKS device: $target"

    local actual_uuid archived_uuid header_uuid
    actual_uuid=$(cryptsetup luksUUID "$target") || fatal "Could not read target LUKS UUID"
    archived_uuid=$(manifest_value "$manifest" luks_uuid)
    actual_uuid=${actual_uuid,,}
    archived_uuid=${archived_uuid,,}
    CONFIRM_LUKS_UUID=${CONFIRM_LUKS_UUID,,}
    [ "$actual_uuid" = "$archived_uuid" ] \
        || fatal "Archive LUKS UUID does not match the selected target"
    [ "$actual_uuid" = "$CONFIRM_LUKS_UUID" ] \
        || fatal "Explicit LUKS UUID confirmation does not match the selected target"

    local header="${staging}/luks-header-backup"
    if [ ! -f "$header" ] || [ -L "$header" ]; then
        fatal "Validated archive header is missing"
    fi
    header_uuid=$(cryptsetup luksUUID "$header" 2>/dev/null || true)
    [ -n "$header_uuid" ] || fatal "Archived LUKS header cannot be parsed by cryptsetup"
    [ "${header_uuid,,}" = "$archived_uuid" ] \
        || fatal "Archived header UUID does not match its authenticated manifest"

    local block_line_count
    block_line_count=$(lsblk -nrpo NAME "$target" | wc -l | tr -d ' ')
    [ "$block_line_count" -eq 1 ] \
        || fatal "Vault target has active holders; close all mappings before header restore"
    if lsblk -nrpo MOUNTPOINTS "$target" | grep -q '[^[:space:]]'; then
        fatal "Vault target is mounted; unmount and close it before header restore"
    fi

    step "Restoring explicitly verified LUKS header"
    cryptsetup luksHeaderRestore "$target" \
        --header-backup-file "$header" \
        --batch-mode \
        || fatal "LUKS header restore failed"
    local restored_uuid
    restored_uuid=$(cryptsetup luksUUID "$target") \
        || fatal "Header was restored but the resulting UUID cannot be read"
    [ "${restored_uuid,,}" = "$archived_uuid" ] \
        || fatal "Header restore completed with an unexpected UUID"
    info "LUKS header restored to verified target $target"
}

do_inspect() {
    local artifact="$1"
    require_root_and_tools
    if [ ! -f "$artifact" ] || [ -L "$artifact" ]; then
        fatal "Backup must be a regular encrypted file: $artifact"
    fi
    [[ "$artifact" == *.age ]] || fatal "Plaintext and legacy non-age backups are not accepted"
    prepare_work_dir
    step "Authenticating and inspecting backup"
    verify_transport_checksum "$artifact"
    local plaintext="${WORK_DIR}/authenticated.tar.gz"
    decrypt_to_tmpfs "$artifact" "$plaintext"
    "$ARCHIVE_HELPER" inspect --archive "$plaintext"
}

do_restore() {
    local category="$1"
    local artifact="$2"
    require_root_and_tools
    if [ ! -f "$artifact" ] || [ -L "$artifact" ]; then
        fatal "Backup must be a regular encrypted file: $artifact"
    fi
    [[ "$artifact" == *.age ]] || fatal "Plaintext and legacy non-age backups are not accepted"
    prepare_work_dir

    step "Authenticating and safely extracting backup"
    local staging
    staging=$(authenticate_and_extract "$artifact")
    local archived_category
    archived_category=$(manifest_value "${staging}/manifest.json" category)
    validate_requested_category "$category" "$archived_category"

    step "Stopping active appliance services"
    stop_active_services

    step "Applying atomic restore transaction"
    local result
    result=$(
        "$ARCHIVE_HELPER" apply \
            --staging "$staging" \
            --category "$category" \
            --etc-root /etc \
            --secure-root "$SECURE_AI_ROOT"
    ) || fatal "Restore transaction failed"
    info "Restore transaction result: $result"

    restore_luks_header_if_requested "$staging"

    step "Restoring previous service state"
    restart_services || fatal "Files were restored, but one or more prior services did not restart"

    step "Running post-restore health verification"
    if [ -x "$HEALTH_CHECK" ]; then
        "$HEALTH_CHECK" || fatal "Restore completed, but post-restore health verification failed"
    else
        fatal "Post-restore health checker is missing: $HEALTH_CHECK"
    fi

    audit_event "$category" "authenticated restore from: $(basename "$artifact")" \
        || fatal "Restore completed but could not be recorded in the audit chain"
    info "Authenticated $category restore completed"
}

COMMAND=""
CATEGORY=""
ARTIFACT=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        full|config|logs|keys)
            [ -z "$COMMAND" ] || fatal "Only one command may be specified"
            [ "$#" -ge 2 ] || fatal "$1 requires an encrypted backup path"
            COMMAND="restore"; CATEGORY="$1"; ARTIFACT="$2"; shift 2 ;;
        inspect)
            [ -z "$COMMAND" ] || fatal "Only one command may be specified"
            [ "$#" -ge 2 ] || fatal "inspect requires an encrypted backup path"
            COMMAND="inspect"; ARTIFACT="$2"; shift 2 ;;
        --identity)
            [ "$#" -ge 2 ] || fatal "--identity requires a file"
            AGE_IDENTITY="$2"; shift 2 ;;
        --restore-luks-header)
            RESTORE_LUKS_HEADER=true; shift ;;
        --vault-device)
            [ "$#" -ge 2 ] || fatal "--vault-device requires a block device"
            VAULT_DEVICE="$2"; shift 2 ;;
        --confirm-luks-uuid)
            [ "$#" -ge 2 ] || fatal "--confirm-luks-uuid requires a UUID"
            CONFIRM_LUKS_UUID="$2"; shift 2 ;;
        --help|-h)
            usage ;;
        *)
            fatal "Unknown argument: $1 (use --help)" ;;
    esac
done

[ -n "$COMMAND" ] || usage
if [ "$RESTORE_LUKS_HEADER" != true ] && [ -n "$VAULT_DEVICE$CONFIRM_LUKS_UUID" ]; then
    fatal "--vault-device/--confirm-luks-uuid require --restore-luks-header"
fi
if [ "$COMMAND" = inspect ] && {
    [ "$RESTORE_LUKS_HEADER" = true ] || [ -n "$VAULT_DEVICE$CONFIRM_LUKS_UUID" ];
}; then
    fatal "LUKS restore options are invalid with inspect"
fi

case "$COMMAND" in
    inspect) do_inspect "$ARTIFACT" ;;
    restore) do_restore "$CATEGORY" "$ARTIFACT" ;;
esac
