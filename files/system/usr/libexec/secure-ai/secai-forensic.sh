#!/usr/bin/env bash
#
# SecAI OS — Forensic Bundle Export/Verify (M51)
#
# Exports a signed forensic bundle from the incident recorder, or
# verifies the integrity of a previously exported bundle.
#
# Usage:
#   secai-forensic export  [--output FILE]   Export a signed forensic bundle
#   secai-forensic verify  <FILE>            Verify bundle hash integrity
#   secai-forensic --help                    Show help
#
set -euo pipefail

INCIDENT_RECORDER_URL="${INCIDENT_RECORDER_URL:-http://127.0.0.1:8515}"
SERVICE_TOKEN_PATH="${SERVICE_TOKEN_PATH:-/run/secure-ai/service-token}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

usage() {
    cat <<'EOF'
secai-forensic — Forensic bundle export and verification

Usage:
  secai-forensic export [--output FILE]   Export a signed forensic bundle
  secai-forensic verify <FILE>            Verify bundle hash integrity
  secai-forensic --help                   Show this help

The export subcommand downloads a signed forensic bundle from the local
incident recorder service.  The bundle contains all incidents, audit log
entries, system state, and a policy digest, signed with HMAC-SHA256.

The verify subcommand recomputes the bundle hash and checks it against
the stored hash to detect tampering.

Environment:
  INCIDENT_RECORDER_URL   (default: http://127.0.0.1:8515)
  SERVICE_TOKEN_PATH      (default: /run/secure-ai/service-token)
EOF
    exit 0
}

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
cmd_export() {
    local output="${1:-}"
    if [[ -z "$output" ]]; then
        output="forensic-bundle-$(date -u +%Y%m%d-%H%M%S).json"
    fi

    # Read service token if available
    local auth_args=()
    if [[ -f "$SERVICE_TOKEN_PATH" ]]; then
        local token
        token=$(cat "$SERVICE_TOKEN_PATH")
        auth_args=(-H "Authorization: Bearer ${token}")
    else
        warn "Service token not found at ${SERVICE_TOKEN_PATH} — trying without auth"
    fi

    info "Exporting forensic bundle from ${INCIDENT_RECORDER_URL}..."

    local http_code
    http_code=$(curl -sf -w "%{http_code}" \
        "${auth_args[@]+"${auth_args[@]}"}" \
        "${INCIDENT_RECORDER_URL}/api/v1/forensic/export" \
        -o "$output" 2>/dev/null) || true

    if [[ ! -f "$output" ]] || [[ ! -s "$output" ]]; then
        err "Export failed (HTTP ${http_code:-unknown}). Is the incident recorder running?"
        rm -f "$output"
        exit 1
    fi

    # Show summary
    local size
    size=$(wc -c < "$output" | tr -d ' ')
    info "Exported: ${output} (${size} bytes)"

    # Extract and show bundle hash
    if command -v python3 &>/dev/null; then
        python3 -c "
import json, sys
try:
    b = json.load(open('${output}'))
    print('Bundle hash:  ' + b.get('bundle_hash', 'N/A'))
    print('Exported at:  ' + b.get('exported_at', 'N/A'))
    print('Incidents:    ' + str(len(b.get('incidents', []))))
    print('Audit lines:  ' + str(len(b.get('audit_entries', []))))
    print('Signed:       ' + ('yes' if b.get('signature') else 'no'))
except Exception as e:
    print('Could not parse bundle: ' + str(e), file=sys.stderr)
"
    fi
}

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
cmd_verify() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        err "File not found: ${file}"
        exit 1
    fi

    if ! command -v python3 &>/dev/null; then
        err "python3 is required for bundle verification"
        exit 1
    fi

    python3 -c "
import json, hashlib, sys

bundle = json.load(open('${file}'))

# Recompute hash over content fields (same structure as Go ExportForensicBundle)
hash_input = json.dumps({
    'exported_at':   bundle['exported_at'],
    'incidents':     bundle['incidents'],
    'audit_entries': bundle['audit_entries'],
    'system_state':  bundle['system_state'],
    'policy_digest': bundle['policy_digest'],
}, separators=(',', ':'), sort_keys=False).encode()

computed = hashlib.sha256(hash_input).hexdigest()
stored = bundle.get('bundle_hash', '')

if stored == computed:
    print('VERIFIED: Bundle hash matches.')
    print('  Hash: ' + stored)
    print('  Incidents: ' + str(len(bundle.get('incidents', []))))
    print('  Exported at: ' + bundle.get('exported_at', 'N/A'))
    sys.exit(0)
else:
    print('FAILED: Bundle hash mismatch — content may have been tampered.', file=sys.stderr)
    print('  Expected: ' + stored, file=sys.stderr)
    print('  Computed: ' + computed, file=sys.stderr)
    sys.exit(1)
"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
case "${1:-}" in
    export)
        shift
        output=""
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --output)
                    [[ $# -lt 2 ]] && { err "--output requires a filename"; exit 1; }
                    output="$2"
                    shift 2
                    ;;
                *)
                    err "Unknown option: $1"
                    usage
                    ;;
            esac
        done
        cmd_export "$output"
        ;;
    verify)
        shift
        [[ $# -lt 1 ]] && { err "verify requires a filename"; usage; }
        cmd_verify "$1"
        ;;
    --help|-h)
        usage
        ;;
    *)
        err "Unknown command: ${1:-}"
        echo ""
        usage
        ;;
esac
