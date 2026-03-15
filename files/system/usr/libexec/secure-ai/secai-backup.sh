#!/usr/bin/env bash
#
# SecAI OS — Backup Script (M50)
#
# Creates a timestamped, optionally encrypted backup of all critical
# appliance state: configuration, incidents, audit logs, registry
# manifest, signing keys, and the LUKS vault header.
#
# Model files (GGUF binaries) are NOT included due to their size.
# The registry manifest IS backed up so you know what to re-download.
#
# Usage:
#   secai-backup.sh full    [--encrypt] [--output DIR]  Full backup
#   secai-backup.sh config  [--encrypt] [--output DIR]  Policy + config only
#   secai-backup.sh logs    [--encrypt] [--output DIR]  Logs + incidents only
#   secai-backup.sh keys    [--encrypt] [--output DIR]  Keys + LUKS header only
#   secai-backup.sh verify  <backup-file>               Verify backup integrity
#   secai-backup.sh list    [DIR]                        List available backups
#   secai-backup.sh --help                               Show help
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SECURE_AI_ROOT="/var/lib/secure-ai"
BACKUP_DIR="${BACKUP_DIR:-${SECURE_AI_ROOT}/backups}"
AUDIT_LOG="${SECURE_AI_ROOT}/logs/backup-audit.jsonl"

# Paths by category
CONFIG_PATHS=(
    /etc/secure-ai/policy
    /etc/secure-ai/config/appliance.yaml
    /etc/secure-ai/model-catalog.yaml
)
LOG_PATHS=(
    "${SECURE_AI_ROOT}/data/incidents.jsonl"
    "${SECURE_AI_ROOT}/logs"
)
KEY_PATHS=(
    "${SECURE_AI_ROOT}/keys"
)
REGISTRY_PATHS=(
    "${SECURE_AI_ROOT}/registry/manifest.json"
)

ENCRYPT=false
OUTPUT_DIR=""

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
SecAI OS — Backup Script

Usage:
  secai-backup.sh <command> [options]

Commands:
  full              Back up everything (config, logs, keys, manifest)
  config            Back up policy and appliance configuration only
  logs              Back up audit logs and incident store only
  keys              Back up signing keys and LUKS vault header only
  verify <file>     Verify a backup archive's integrity
  list [dir]        List available backup archives

Options:
  --encrypt         Encrypt the backup archive (uses age or gpg)
  --output DIR      Output directory (default: /var/lib/secure-ai/backups)
  --help            Show this help message
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
    'event': 'backup',
    'action': '${action}',
    'detail': '${detail}'
}
entry['hash'] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
print(json.dumps(entry))
" >> "$AUDIT_LOG" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Collect files for a given category
# ---------------------------------------------------------------------------
collect_paths() {
    local category="$1"
    local staging="$2"
    local count=0

    local -a paths=()
    case "$category" in
        config)   paths=("${CONFIG_PATHS[@]}") ;;
        logs)     paths=("${LOG_PATHS[@]}") ;;
        keys)     paths=("${KEY_PATHS[@]}") ;;
        registry) paths=("${REGISTRY_PATHS[@]}") ;;
    esac

    for src in "${paths[@]}"; do
        if [ -e "$src" ]; then
            local dest="${staging}${src}"
            mkdir -p "$(dirname "$dest")"
            cp -a "$src" "$dest" 2>/dev/null || warn "Could not copy ${src}"
            count=$((count + 1))
        fi
    done
    echo "$count"
}

# ---------------------------------------------------------------------------
# LUKS header backup
# ---------------------------------------------------------------------------
backup_luks_header() {
    local staging="$1"
    local vault_dev=""

    if [ -f /etc/crypttab ]; then
        vault_dev=$(awk '/secure-ai-vault/ {print $2}' /etc/crypttab 2>/dev/null || true)
    fi

    if [ -z "$vault_dev" ]; then
        warn "Vault device not found in /etc/crypttab — skipping LUKS header backup"
        return 0
    fi

    # Resolve UUID= or PARTUUID= references
    if [[ "$vault_dev" == UUID=* ]]; then
        vault_dev="/dev/disk/by-uuid/${vault_dev#UUID=}"
    elif [[ "$vault_dev" == PARTUUID=* ]]; then
        vault_dev="/dev/disk/by-partuuid/${vault_dev#PARTUUID=}"
    fi

    if [ ! -e "$vault_dev" ]; then
        warn "Vault device ${vault_dev} does not exist — skipping LUKS header backup"
        return 0
    fi

    local dest="${staging}/luks-header-backup"
    mkdir -p "$(dirname "$dest")"
    if cryptsetup luksHeaderBackup "$vault_dev" --header-backup-file "$dest" 2>/dev/null; then
        info "LUKS header backed up from ${vault_dev}"
    else
        warn "Failed to backup LUKS header (may require root)"
    fi
}

# ---------------------------------------------------------------------------
# Generate manifest
# ---------------------------------------------------------------------------
generate_manifest() {
    local staging="$1"
    python3 -c "
import json, hashlib, os
from datetime import datetime, timezone
manifest = {
    'created': datetime.now(timezone.utc).isoformat(),
    'hostname': os.uname().nodename,
    'files': {}
}
for root, dirs, files in os.walk('${staging}'):
    for f in files:
        if f == 'manifest.json':
            continue
        full = os.path.join(root, f)
        rel = os.path.relpath(full, '${staging}')
        h = hashlib.sha256(open(full, 'rb').read()).hexdigest()
        manifest['files'][rel] = {'sha256': h, 'size': os.path.getsize(full)}
manifest['file_count'] = len(manifest['files'])
with open(os.path.join('${staging}', 'manifest.json'), 'w') as out:
    json.dump(manifest, out, indent=2)
    out.write('\n')
print(manifest['file_count'])
" 2>/dev/null || echo "0"
}

# ---------------------------------------------------------------------------
# Encrypt tarball
# ---------------------------------------------------------------------------
encrypt_file() {
    local file="$1"
    if command -v age &>/dev/null; then
        info "Encrypting with age (passphrase)..."
        age -p -o "${file}.age" "$file" || fatal "age encryption failed"
        rm -f "$file"
        echo "${file}.age"
    elif command -v gpg &>/dev/null; then
        info "Encrypting with gpg (symmetric)..."
        gpg --symmetric --batch --yes --cipher-algo AES256 -o "${file}.gpg" "$file" \
            || fatal "gpg encryption failed"
        rm -f "$file"
        echo "${file}.gpg"
    else
        fatal "Encryption requested but neither 'age' nor 'gpg' is installed"
    fi
}

# ---------------------------------------------------------------------------
# do_backup <category>
# ---------------------------------------------------------------------------
do_backup() {
    local category="$1"
    local dest_dir="${OUTPUT_DIR:-$BACKUP_DIR}"
    local timestamp
    timestamp=$(date +%Y%m%d-%H%M%S)
    local name="secai-backup-${category}-${timestamp}"
    local staging
    staging=$(mktemp -d "/tmp/${name}.XXXXXX")

    trap 'rm -rf "$staging"' EXIT

    [ "$(id -u)" -eq 0 ] || fatal "Backups must be run as root (sudo)"

    mkdir -p "$dest_dir"

    step "Creating ${category} backup"

    # Collect files by category
    local total=0
    case "$category" in
        full)
            for cat in config logs keys registry; do
                n=$(collect_paths "$cat" "$staging")
                total=$((total + n))
            done
            backup_luks_header "$staging"
            ;;
        config)
            total=$(collect_paths "config" "$staging")
            ;;
        logs)
            total=$(collect_paths "logs" "$staging")
            ;;
        keys)
            total=$(collect_paths "keys" "$staging")
            backup_luks_header "$staging"
            ;;
        *)
            fatal "Unknown backup category: ${category}"
            ;;
    esac

    if [ "$total" -eq 0 ]; then
        warn "No files found to back up"
        exit 0
    fi

    # Generate manifest
    step "Generating manifest"
    file_count=$(generate_manifest "$staging")
    info "${file_count} files inventoried"

    # Create tarball
    step "Creating archive"
    local tarball="${dest_dir}/${name}.tar.gz"
    tar czf "$tarball" -C "$staging" . || fatal "Failed to create archive"

    # SHA256 sidecar
    local checksum
    checksum=$(sha256sum "$tarball" | cut -d' ' -f1)
    echo "${checksum}  $(basename "$tarball")" > "${tarball}.sha256"
    info "Archive: ${tarball} ($(du -h "$tarball" | cut -f1))"
    info "SHA256:  ${checksum}"

    # Optional encryption
    if [ "$ENCRYPT" = true ]; then
        step "Encrypting archive"
        tarball=$(encrypt_file "$tarball")
        info "Encrypted: ${tarball}"
    fi

    # Audit
    audit_event "$category" "backup created: $(basename "$tarball")"

    echo ""
    info "Backup complete: ${tarball}"
}

# ---------------------------------------------------------------------------
# do_verify <file>
# ---------------------------------------------------------------------------
do_verify() {
    local file="$1"
    [ -f "$file" ] || fatal "File not found: ${file}"

    step "Verifying backup integrity"

    # Check sidecar SHA256
    local sha_file="${file}.sha256"
    if [ -f "$sha_file" ]; then
        local expected actual
        expected=$(cut -d' ' -f1 "$sha_file")
        actual=$(sha256sum "$file" | cut -d' ' -f1)
        if [ "$expected" = "$actual" ]; then
            info "External checksum: PASS"
        else
            error "External checksum: FAIL"
            error "  Expected: ${expected}"
            error "  Actual:   ${actual}"
            exit 1
        fi
    else
        warn "No sidecar .sha256 file found — skipping external check"
    fi

    # Extract and verify internal manifest
    local tmp
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT

    tar xzf "$file" -C "$tmp" 2>/dev/null || fatal "Cannot extract archive"

    if [ -f "${tmp}/manifest.json" ]; then
        local failures=0
        while IFS='|' read -r rel expected_hash; do
            local full="${tmp}/${rel}"
            if [ -f "$full" ]; then
                actual_hash=$(sha256sum "$full" | cut -d' ' -f1)
                if [ "$expected_hash" = "$actual_hash" ]; then
                    info "  ${rel}: OK"
                else
                    error "  ${rel}: MISMATCH"
                    failures=$((failures + 1))
                fi
            else
                warn "  ${rel}: missing from archive"
                failures=$((failures + 1))
            fi
        done < <(python3 -c "
import json
with open('${tmp}/manifest.json') as f:
    m = json.load(f)
for rel, info in m.get('files', {}).items():
    print(f\"{rel}|{info['sha256']}\")
" 2>/dev/null)
        echo ""
        if [ "$failures" -eq 0 ]; then
            info "All files verified OK"
        else
            error "${failures} file(s) failed verification"
            exit 1
        fi
    else
        warn "No manifest.json in archive — cannot verify internal integrity"
    fi
}

# ---------------------------------------------------------------------------
# do_list [dir]
# ---------------------------------------------------------------------------
do_list() {
    local dir="${1:-$BACKUP_DIR}"
    [ -d "$dir" ] || fatal "Directory not found: ${dir}"

    step "Backups in ${dir}"
    local count=0
    for f in "${dir}"/secai-backup-*.tar.gz*; do
        [ -f "$f" ] || continue
        local size
        size=$(du -h "$f" | cut -f1)
        local encrypted=""
        if [[ "$f" == *.age ]] || [[ "$f" == *.gpg ]]; then
            encrypted=" (encrypted)"
        fi
        echo "  ${size}  $(basename "$f")${encrypted}"
        count=$((count + 1))
    done
    if [ "$count" -eq 0 ]; then
        info "No backups found"
    else
        info "${count} backup(s) found"
    fi
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
CMD=""
CMD_ARG=""

while [ $# -gt 0 ]; do
    case "$1" in
        full|config|logs|keys)
            CMD="backup"; CMD_ARG="$1"; shift ;;
        verify)
            CMD="verify"; shift
            [ -z "${1:-}" ] && fatal "verify requires a file path"
            CMD_ARG="$1"; shift ;;
        list)
            CMD="list"; shift
            CMD_ARG="${1:-$BACKUP_DIR}"; [ "${1:-}" ] && shift ;;
        --encrypt)
            ENCRYPT=true; shift ;;
        --output)
            [ -z "${2:-}" ] && fatal "--output requires a directory"
            OUTPUT_DIR="$2"; shift 2 ;;
        --help|-h)
            usage ;;
        *)
            fatal "Unknown argument: $1  (use --help for usage)" ;;
    esac
done

[ -z "$CMD" ] && usage

case "$CMD" in
    backup) do_backup "$CMD_ARG" ;;
    verify) do_verify "$CMD_ARG" ;;
    list)   do_list   "$CMD_ARG" ;;
esac
