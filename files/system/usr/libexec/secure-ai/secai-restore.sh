#!/usr/bin/env bash
#
# SecAI OS — Restore Script (M50)
#
# Restores appliance state from a backup created by secai-backup.sh.
# Supports full restore or selective restore by category.
#
# Usage:
#   secai-restore.sh full    <backup-file>  Restore everything
#   secai-restore.sh config  <backup-file>  Restore policy + config only
#   secai-restore.sh logs    <backup-file>  Restore logs + incidents only
#   secai-restore.sh keys    <backup-file>  Restore keys + LUKS header only
#   secai-restore.sh inspect <backup-file>  List backup contents
#   secai-restore.sh --help                 Show help
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SECURE_AI_ROOT="/var/lib/secure-ai"
AUDIT_LOG="${SECURE_AI_ROOT}/logs/backup-audit.jsonl"
HEALTH_CHECK="/usr/libexec/secure-ai/first-boot-check.sh"

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' BOLD='' NC=''
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*" >&2; }
fatal() { error "$*"; exit 1; }
step()  { echo -e "\n${BOLD}${CYAN}=== $* ===${NC}"; }

usage() {
    cat <<'USAGE'
SecAI OS — Restore Script

Usage:
  secai-restore.sh <command> <backup-file>

Commands:
  full    <file>    Restore everything from backup
  config  <file>    Restore policy and appliance configuration only
  logs    <file>    Restore audit logs and incident store only
  keys    <file>    Restore signing keys and LUKS vault header only
  inspect <file>    Show backup contents without restoring

Options:
  --help            Show this help message

Backups must be created by secai-backup.sh.
USAGE
    exit 0
}

audit_event() {
    local action="$1"
    local detail="$2"
    mkdir -p "$(dirname "$AUDIT_LOG")" 2>/dev/null || true
    python3 -c "
import json, hashlib
from datetime import datetime, timezone
entry = {
    'timestamp': datetime.now(timezone.utc).isoformat(),
    'event': 'restore',
    'action': '${action}',
    'detail': '${detail}'
}
entry['hash'] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
print(json.dumps(entry))
" >> "$AUDIT_LOG" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Decrypt if needed
# ---------------------------------------------------------------------------
decrypt_if_needed() {
    local file="$1"
    if [[ "$file" == *.age ]]; then
        info "Decrypting with age..."
        local decrypted="${file%.age}"
        age -d -o "$decrypted" "$file" || fatal "age decryption failed"
        echo "$decrypted"
    elif [[ "$file" == *.gpg ]]; then
        info "Decrypting with gpg..."
        local decrypted="${file%.gpg}"
        gpg --decrypt --batch --yes -o "$decrypted" "$file" 2>/dev/null \
            || fatal "gpg decryption failed"
        echo "$decrypted"
    else
        echo "$file"
    fi
}

# ---------------------------------------------------------------------------
# Verify backup integrity
# ---------------------------------------------------------------------------
verify_backup() {
    local file="$1"
    local sha_file="${file}.sha256"
    if [ -f "$sha_file" ]; then
        local expected actual
        expected=$(cut -d' ' -f1 "$sha_file")
        actual=$(sha256sum "$file" | cut -d' ' -f1)
        if [ "$expected" != "$actual" ]; then
            fatal "Backup checksum mismatch — archive may be corrupted"
        fi
        info "Backup integrity: verified"
    else
        warn "No .sha256 sidecar — skipping external integrity check"
    fi
}

# ---------------------------------------------------------------------------
# do_inspect <file>
# ---------------------------------------------------------------------------
do_inspect() {
    local file="$1"
    [ -f "$file" ] || fatal "File not found: ${file}"

    step "Inspecting backup: $(basename "$file")"

    local work_file
    work_file=$(decrypt_if_needed "$file")

    local tmp
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT

    tar xzf "$work_file" -C "$tmp" 2>/dev/null || fatal "Cannot extract archive"

    if [ -f "${tmp}/manifest.json" ]; then
        python3 -c "
import json
with open('${tmp}/manifest.json') as f:
    m = json.load(f)
print(f\"Created:  {m.get('created', 'unknown')}\")
print(f\"Hostname: {m.get('hostname', 'unknown')}\")
print(f\"Files:    {m.get('file_count', 0)}\")
print()
for rel, info in sorted(m.get('files', {}).items()):
    size = info.get('size', 0)
    if size > 1048576:
        s = f'{size/1048576:.1f} MB'
    elif size > 1024:
        s = f'{size/1024:.1f} KB'
    else:
        s = f'{size} B'
    print(f'  {s:>10s}  {rel}')
" 2>/dev/null || warn "Could not parse manifest"
    else
        info "Contents:"
        tar tzf "$work_file" 2>/dev/null | head -50
    fi
}

# ---------------------------------------------------------------------------
# do_restore <category> <file>
# ---------------------------------------------------------------------------
do_restore() {
    local category="$1"
    local file="$2"

    [ "$(id -u)" -eq 0 ] || fatal "Restore must be run as root (sudo)"
    [ -f "$file" ] || fatal "File not found: ${file}"

    step "Restoring ${category} from $(basename "$file")"

    # Verify integrity
    verify_backup "$file"

    # Decrypt if needed
    local work_file
    work_file=$(decrypt_if_needed "$file")

    # Extract to staging
    local staging
    staging=$(mktemp -d "/tmp/secai-restore.XXXXXX")
    trap 'rm -rf "$staging"' EXIT

    tar xzf "$work_file" -C "$staging" 2>/dev/null || fatal "Cannot extract archive"

    # Restore by category
    local restored=0

    # Config
    if [ "$category" = "full" ] || [ "$category" = "config" ]; then
        if [ -d "${staging}/etc/secure-ai" ]; then
            cp -a "${staging}/etc/secure-ai/." /etc/secure-ai/ 2>/dev/null || true
            info "Restored: /etc/secure-ai/ (policy + config)"
            restored=$((restored + 1))
        fi
    fi

    # Logs + incidents
    if [ "$category" = "full" ] || [ "$category" = "logs" ]; then
        if [ -f "${staging}${SECURE_AI_ROOT}/data/incidents.jsonl" ]; then
            mkdir -p "${SECURE_AI_ROOT}/data"
            cp -a "${staging}${SECURE_AI_ROOT}/data/incidents.jsonl" \
                "${SECURE_AI_ROOT}/data/incidents.jsonl"
            info "Restored: incidents.jsonl"
            restored=$((restored + 1))
        fi
        if [ -d "${staging}${SECURE_AI_ROOT}/logs" ]; then
            mkdir -p "${SECURE_AI_ROOT}/logs"
            cp -a "${staging}${SECURE_AI_ROOT}/logs/." "${SECURE_AI_ROOT}/logs/" 2>/dev/null || true
            info "Restored: audit logs"
            restored=$((restored + 1))
        fi
    fi

    # Keys + LUKS header
    if [ "$category" = "full" ] || [ "$category" = "keys" ]; then
        if [ -d "${staging}${SECURE_AI_ROOT}/keys" ]; then
            mkdir -p "${SECURE_AI_ROOT}/keys"
            cp -a "${staging}${SECURE_AI_ROOT}/keys/." "${SECURE_AI_ROOT}/keys/" 2>/dev/null || true
            chmod 700 "${SECURE_AI_ROOT}/keys"
            info "Restored: signing keys"
            restored=$((restored + 1))
        fi

        # LUKS header — double confirmation required
        if [ -f "${staging}/luks-header-backup" ]; then
            echo ""
            echo -e "  ${RED}${BOLD}WARNING: Restoring a LUKS header is irreversible.${NC}"
            echo -e "  An incorrect header will make the vault unrecoverable."
            echo -e "  Only proceed if you are sure this header matches the vault device."
            echo ""
            echo -en "  Type ${BOLD}YES${NC} to restore the LUKS header: "
            local confirm
            read -r confirm
            if [ "$confirm" = "YES" ]; then
                local vault_dev=""
                if [ -f /etc/crypttab ]; then
                    vault_dev=$(awk '/secure-ai-vault/ {print $2}' /etc/crypttab 2>/dev/null || true)
                fi
                if [ -n "$vault_dev" ]; then
                    if cryptsetup luksHeaderRestore "$vault_dev" \
                        --header-backup-file "${staging}/luks-header-backup" 2>/dev/null; then
                        info "Restored: LUKS header to ${vault_dev}"
                        restored=$((restored + 1))
                    else
                        error "LUKS header restore failed"
                    fi
                else
                    warn "Vault device not found in /etc/crypttab — LUKS header not restored"
                    warn "Manual restore: cryptsetup luksHeaderRestore /dev/<device> --header-backup-file ${staging}/luks-header-backup"
                fi
            else
                info "LUKS header restore skipped"
            fi
        fi
    fi

    # Registry manifest
    if [ "$category" = "full" ]; then
        if [ -f "${staging}${SECURE_AI_ROOT}/registry/manifest.json" ]; then
            mkdir -p "${SECURE_AI_ROOT}/registry"
            cp -a "${staging}${SECURE_AI_ROOT}/registry/manifest.json" \
                "${SECURE_AI_ROOT}/registry/manifest.json"
            info "Restored: registry manifest"
            restored=$((restored + 1))
        fi
    fi

    if [ "$restored" -eq 0 ]; then
        warn "No matching files found in backup for category '${category}'"
        exit 0
    fi

    # Restart services
    step "Restarting services"
    systemctl restart secure-ai-\*.service 2>/dev/null || warn "Some services failed to restart"
    info "Services restarted"

    # Health check
    step "Post-restore health check"
    if [ -x "$HEALTH_CHECK" ]; then
        $HEALTH_CHECK || warn "Health check reported issues — review output above"
    else
        warn "Health check script not found — verify manually"
    fi

    # Audit
    audit_event "$category" "restored from: $(basename "$file")"

    echo ""
    info "Restore complete (${restored} items restored)"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
CMD=""
CATEGORY=""
FILE_ARG=""

while [ $# -gt 0 ]; do
    case "$1" in
        full|config|logs|keys)
            CMD="restore"; CATEGORY="$1"; shift
            [ -z "${1:-}" ] && fatal "${CATEGORY} requires a backup file path"
            FILE_ARG="$1"; shift ;;
        inspect)
            CMD="inspect"; shift
            [ -z "${1:-}" ] && fatal "inspect requires a backup file path"
            FILE_ARG="$1"; shift ;;
        --help|-h)
            usage ;;
        *)
            fatal "Unknown argument: $1  (use --help for usage)" ;;
    esac
done

[ -z "$CMD" ] && usage

case "$CMD" in
    restore) do_restore "$CATEGORY" "$FILE_ARG" ;;
    inspect) do_inspect "$FILE_ARG" ;;
esac
