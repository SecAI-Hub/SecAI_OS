#!/usr/bin/env bash
#
# SecAI OS authenticated backup utility.
#
# Every backup is encrypted with age before it leaves a root-only tmpfs.
# Plain tar archives and unauthenticated restores are intentionally unsupported.
#
set -euo pipefail
umask 077

SECURE_AI_ROOT="/var/lib/secure-ai"
BACKUP_DIR="${BACKUP_DIR:-${SECURE_AI_ROOT}/backups}"
AUDIT_LOG="${SECURE_AI_ROOT}/logs/backup-audit.jsonl"
ARCHIVE_HELPER="${ARCHIVE_HELPER:-/usr/libexec/secure-ai/secure-backup-archive.py}"
WORK_ROOT="${WORK_ROOT:-/run/secure-ai/backup-tmp}"

CONFIG_PATHS=(
    /etc/secure-ai/policy
    /etc/secure-ai/config/appliance.yaml
    /etc/secure-ai/model-catalog.yaml
)
LOG_PATHS=(
    "${SECURE_AI_ROOT}/data/incidents.jsonl"
    "${SECURE_AI_ROOT}/logs"
)
KEY_PATHS=("${SECURE_AI_ROOT}/keys")
REGISTRY_PATHS=("${SECURE_AI_ROOT}/registry/manifest.json")

OUTPUT_DIR=""
AGE_RECIPIENT=""
AGE_IDENTITY=""
WORK_DIR=""
LUKS_UUID=""

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
SecAI OS — Authenticated Backup

Usage:
  secai-backup.sh full   [--output DIR] [--recipient AGE_RECIPIENT]
  secai-backup.sh config [--output DIR] [--recipient AGE_RECIPIENT]
  secai-backup.sh logs   [--output DIR] [--recipient AGE_RECIPIENT]
  secai-backup.sh keys   [--output DIR] [--recipient AGE_RECIPIENT]
  secai-backup.sh verify FILE [--identity AGE_IDENTITY_FILE]
  secai-backup.sh list [DIR]

All backup categories are encrypted and authenticated with age. Without
--recipient, age prompts for a passphrase using its protected terminal input.
The plaintext archive exists only in root-owned /run tmpfs and is removed when
the command exits. The .sha256 sidecar is a transport-corruption check; archive
authenticity is established by successful age decryption plus manifest checks.

Options:
  --recipient VALUE   Encrypt to an age recipient (recommended for automation)
  --identity FILE     Identity used to decrypt during verify
  --output DIR        Destination directory
  --encrypt           Accepted for compatibility; encryption is always enabled
  --help              Show this help
USAGE
    exit 0
}

cleanup() {
    if [ -n "$WORK_DIR" ] && [[ "$WORK_DIR" == "$WORK_ROOT/"* ]] && [ -d "$WORK_DIR" ]; then
        rm -rf -- "$WORK_DIR"
    fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

require_root() {
    [ "$(id -u)" -eq 0 ] || fatal "This command must be run as root (sudo)"
}

require_tools() {
    local tool
    for tool in age python3 sha256sum; do
        command -v "$tool" >/dev/null 2>&1 || fatal "Required command is missing: $tool"
    done
    [ -x "$ARCHIVE_HELPER" ] || fatal "Archive helper is missing or not executable: $ARCHIVE_HELPER"
}

prepare_work_dir() {
    install -d -m 0700 -o root -g root -- "$WORK_ROOT"
    [ ! -L "$WORK_ROOT" ] || fatal "Refusing symbolic-link work directory: $WORK_ROOT"
    WORK_DIR=$(mktemp -d "${WORK_ROOT}/backup.XXXXXXXX")
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
            "event": "backup",
            "data": data,
            "timestamp": timestamp,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    entry = {
        "timestamp": timestamp,
        "event": "backup",
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

copy_source() {
    local source="$1"
    local staging="$2"
    [ ! -L "$source" ] || fatal "Refusing symbolic-link backup source: $source"
    [ -e "$source" ] || return 1
    local destination="${staging}${source}"
    mkdir -p -- "$(dirname "$destination")"
    cp -a --reflink=auto -- "$source" "$destination" \
        || fatal "Failed to stage required backup source: $source"
}

collect_paths() {
    local category="$1"
    local staging="$2"
    local count=0
    local -a paths=()
    case "$category" in
        config) paths=("${CONFIG_PATHS[@]}") ;;
        logs) paths=("${LOG_PATHS[@]}") ;;
        keys) paths=("${KEY_PATHS[@]}") ;;
        registry) paths=("${REGISTRY_PATHS[@]}") ;;
        *) fatal "Internal error: unknown collection category $category" ;;
    esac
    local source
    for source in "${paths[@]}"; do
        if copy_source "$source" "$staging"; then
            count=$((count + 1))
        fi
    done
    printf '%s\n' "$count"
}

resolve_luks_device() {
    [ -f /etc/crypttab ] || return 1
    local -a specifications=()
    mapfile -t specifications < <(
        awk '!/^[[:space:]]*#/ && $1 == "secure-ai-vault" { print $2 }' /etc/crypttab
    )
    [ "${#specifications[@]}" -le 1 ] \
        || fatal "Multiple secure-ai-vault entries exist in /etc/crypttab"
    [ "${#specifications[@]}" -eq 1 ] || return 1

    local specification="${specifications[0]}"
    local candidate="$specification"
    case "$specification" in
        UUID=*) candidate="/dev/disk/by-uuid/${specification#UUID=}" ;;
        PARTUUID=*) candidate="/dev/disk/by-partuuid/${specification#PARTUUID=}" ;;
    esac
    candidate=$(readlink -f -- "$candidate") || return 1
    [ -b "$candidate" ] || fatal "Configured vault source is not a block device: $candidate"
    cryptsetup isLuks "$candidate" >/dev/null 2>&1 \
        || fatal "Configured vault source is not a LUKS device: $candidate"
    printf '%s\n' "$candidate"
}

backup_luks_header() {
    local staging="$1"
    command -v cryptsetup >/dev/null 2>&1 || fatal "cryptsetup is required for a key backup"
    local device
    if ! device=$(resolve_luks_device); then
        warn "No secure-ai-vault LUKS device is configured; no header was included"
        return 0
    fi
    LUKS_UUID=$(cryptsetup luksUUID "$device") \
        || fatal "Could not read the configured vault UUID"
    [[ "$LUKS_UUID" =~ ^[0-9a-fA-F-]{36}$ ]] \
        || fatal "Configured vault returned an invalid LUKS UUID"
    cryptsetup luksHeaderBackup "$device" \
        --header-backup-file "${staging}/luks-header-backup" \
        || fatal "LUKS header backup failed"
    chmod 0600 "${staging}/luks-header-backup"
    info "Included LUKS header for vault UUID ${LUKS_UUID}"
}

write_transport_checksum() {
    local artifact="$1"
    local sidecar="${artifact}.sha256"
    if [ -e "$sidecar" ] || [ -L "$sidecar" ]; then
        fatal "Refusing to overwrite checksum sidecar: $sidecar"
    fi
    local checksum
    checksum=$(sha256sum -- "$artifact" | awk '{print $1}')
    [[ "$checksum" =~ ^[0-9a-f]{64}$ ]] || fatal "Could not compute artifact SHA-256"
    local temporary
    temporary=$(mktemp "$(dirname "$artifact")/.checksum.XXXXXXXX")
    printf '%s  %s\n' "$checksum" "$(basename "$artifact")" > "$temporary"
    chmod 0600 "$temporary"
    sync -f "$temporary"
    mv -- "$temporary" "$sidecar"
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

do_backup() {
    local category="$1"
    require_root
    require_tools
    prepare_work_dir

    local destination_dir="${OUTPUT_DIR:-$BACKUP_DIR}"
    mkdir -p -- "$destination_dir"
    if [ ! -d "$destination_dir" ] || [ -L "$destination_dir" ]; then
        fatal "Backup destination must be a real directory: $destination_dir"
    fi

    local timestamp random_suffix name
    timestamp=$(date -u +%Y%m%d-%H%M%S)
    random_suffix=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
    name="secai-backup-${category}-${timestamp}-${random_suffix}"
    local staging="${WORK_DIR}/staging"
    mkdir -m 0700 -- "$staging"

    step "Staging ${category} backup"
    local total=0 collected
    case "$category" in
        full)
            local collection
            for collection in config logs keys registry; do
                collected=$(collect_paths "$collection" "$staging")
                total=$((total + collected))
            done
            backup_luks_header "$staging"
            ;;
        config|logs)
            total=$(collect_paths "$category" "$staging")
            ;;
        keys)
            total=$(collect_paths "keys" "$staging")
            backup_luks_header "$staging"
            ;;
        *) fatal "Unknown backup category: $category" ;;
    esac
    [ "$total" -gt 0 ] || [ -f "${staging}/luks-header-backup" ] \
        || fatal "No files were available for the requested backup category"

    step "Creating bounded manifest archive in tmpfs"
    local plaintext="${WORK_DIR}/${name}.tar.gz"
    local -a create_args=(
        create --root "$staging" --output "$plaintext" --category "$category"
    )
    [ -z "$LUKS_UUID" ] || create_args+=(--luks-uuid "$LUKS_UUID")
    "$ARCHIVE_HELPER" "${create_args[@]}" >/dev/null \
        || fatal "Secure archive creation failed"

    step "Encrypting and authenticating with age"
    local final="${destination_dir}/${name}.tar.gz.age"
    if [ -e "$final" ] || [ -L "$final" ]; then
        fatal "Refusing to overwrite existing backup: $final"
    fi
    local partial
    partial=$(mktemp "${destination_dir}/.${name}.partial.XXXXXXXX")
    if [ -n "$AGE_RECIPIENT" ]; then
        if ! age -r "$AGE_RECIPIENT" -- "$plaintext" > "$partial"; then
            rm -f -- "$partial"
            fatal "Age recipient encryption failed"
        fi
    else
        if ! age -p -- "$plaintext" > "$partial"; then
            rm -f -- "$partial"
            fatal "Age passphrase encryption failed"
        fi
    fi
    [ -s "$partial" ] || fatal "Age produced an empty encrypted artifact"
    chmod 0600 "$partial" 2>/dev/null \
        || warn "Destination filesystem cannot enforce mode 0600; content remains encrypted"
    sync -f "$partial"
    mv -- "$partial" "$final"
    write_transport_checksum "$final"
    audit_event "$category" "encrypted backup created: $(basename "$final")" \
        || fatal "Backup was created but could not be recorded in the audit chain"

    info "Backup complete: $final"
    info "Plaintext staging was confined to tmpfs and will be removed on exit"
}

do_verify() {
    local artifact="$1"
    require_root
    require_tools
    if [ ! -f "$artifact" ] || [ -L "$artifact" ]; then
        fatal "Backup must be a regular encrypted file: $artifact"
    fi
    [[ "$artifact" == *.age ]] || fatal "Plaintext and legacy non-age backups are not accepted"
    prepare_work_dir
    step "Checking encrypted artifact transport integrity"
    verify_transport_checksum "$artifact"
    local plaintext="${WORK_DIR}/verified.tar.gz"
    step "Authenticating, decrypting, and validating bounded archive contents"
    decrypt_to_tmpfs "$artifact" "$plaintext"
    "$ARCHIVE_HELPER" verify --archive "$plaintext" \
        || fatal "Backup manifest or archive validation failed"
    info "Backup verification passed"
}

do_list() {
    local directory="${1:-$BACKUP_DIR}"
    if [ ! -d "$directory" ] || [ -L "$directory" ]; then
        fatal "Backup directory must be a real directory: $directory"
    fi
    step "Encrypted backups in $directory"
    local count=0
    while IFS= read -r -d '' artifact; do
        printf '  %10s  %s\n' "$(du -h "$artifact" | awk '{print $1}')" "$(basename "$artifact")"
        count=$((count + 1))
    done < <(find "$directory" -maxdepth 1 -type f -name 'secai-backup-*.tar.gz.age' -print0 | sort -z)
    info "$count encrypted backup(s) found"
}

COMMAND=""
COMMAND_ARG=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        full|config|logs|keys)
            [ -z "$COMMAND" ] || fatal "Only one command may be specified"
            COMMAND="backup"; COMMAND_ARG="$1"; shift ;;
        verify)
            [ -z "$COMMAND" ] || fatal "Only one command may be specified"
            [ "$#" -ge 2 ] || fatal "verify requires an encrypted backup path"
            COMMAND="verify"; COMMAND_ARG="$2"; shift 2 ;;
        list)
            [ -z "$COMMAND" ] || fatal "Only one command may be specified"
            COMMAND="list"; shift
            if [ "$#" -gt 0 ] && [[ "$1" != --* ]]; then
                COMMAND_ARG="$1"; shift
            fi
            ;;
        --recipient)
            [ "$#" -ge 2 ] || fatal "--recipient requires a value"
            AGE_RECIPIENT="$2"; shift 2 ;;
        --identity)
            [ "$#" -ge 2 ] || fatal "--identity requires a file"
            AGE_IDENTITY="$2"; shift 2 ;;
        --output)
            [ "$#" -ge 2 ] || fatal "--output requires a directory"
            OUTPUT_DIR="$2"; shift 2 ;;
        --encrypt)
            shift ;;
        --help|-h)
            usage ;;
        *)
            fatal "Unknown argument: $1 (use --help)" ;;
    esac
done

[ -n "$COMMAND" ] || usage
case "$COMMAND" in
    backup)
        [ -z "$AGE_IDENTITY" ] || fatal "--identity is only valid with verify"
        do_backup "$COMMAND_ARG"
        ;;
    verify)
        [ -z "$OUTPUT_DIR" ] || fatal "--output is only valid with a backup command"
        [ -z "$AGE_RECIPIENT" ] || fatal "--recipient is only valid with a backup command"
        do_verify "$COMMAND_ARG"
        ;;
    list)
        [ -z "$OUTPUT_DIR$AGE_RECIPIENT$AGE_IDENTITY" ] \
            || fatal "Encryption/output options are not valid with list"
        do_list "${COMMAND_ARG:-$BACKUP_DIR}"
        ;;
esac
