#!/usr/bin/env bash
#
# SecAI OS authenticated forensic bundle export and offline verification.
#
set -euo pipefail
umask 077

INCIDENT_RECORDER_URL="${INCIDENT_RECORDER_URL:-http://127.0.0.1:8515}"
FORENSIC_TOKEN_PATH="${FORENSIC_TOKEN_PATH:-/var/lib/secure-ai/credentials/incident-forensic.token}"
FORENSIC_HMAC_KEY_PATH="${FORENSIC_HMAC_KEY_PATH:-/var/lib/secure-ai/credentials/forensic-hmac.key}"
WORK_ROOT="${WORK_ROOT:-/run/secure-ai/forensic-tmp}"
VERIFY_HELPER="${VERIFY_HELPER:-/usr/libexec/secure-ai/secure-forensic-verify.py}"
MAX_BUNDLE_BYTES=67108864
WORK_DIR=""
PARTIAL_OUTPUT=""

if [ -t 1 ]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; NC=$'\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; NC=''
fi

info() { printf '%s[INFO]%s  %s\n' "$GREEN" "$NC" "$*"; }
warn() { printf '%s[WARN]%s  %s\n' "$YELLOW" "$NC" "$*" >&2; }
err()  { printf '%s[ERROR]%s %s\n' "$RED" "$NC" "$*" >&2; }
fatal() { err "$*"; exit 1; }

usage() {
    cat <<'USAGE'
secai-forensic — authenticated forensic export and verification

Usage:
  sudo secai-forensic export [--output FILE]
  sudo secai-forensic verify FILE
  secai-forensic --help

Export authenticates to the loopback-only incident recorder and writes through
a mode-0600 temporary file before an atomic rename. Verify requires the
root-only, dedicated forensic HMAC key and checks all of the following:

  1. the exact canonical payload decodes as strict JSON;
  2. its SHA-256 equals bundle_hash;
  3. HMAC-SHA256(raw SHA-256 digest) equals signature; and
  4. canonical payload fields exactly equal the exposed bundle fields.

The dedicated forensic bearer token is never placed in the process command line.
USAGE
    exit 0
}

cleanup() {
    if [ -n "$PARTIAL_OUTPUT" ] && [ -f "$PARTIAL_OUTPUT" ] && [ ! -L "$PARTIAL_OUTPUT" ]; then
        rm -f -- "$PARTIAL_OUTPUT"
    fi
    if [ -n "$WORK_DIR" ] && [[ "$WORK_DIR" == "$WORK_ROOT/"* ]] && [ -d "$WORK_DIR" ]; then
        rm -rf -- "$WORK_DIR"
    fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

require_root() {
    [ "$(id -u)" -eq 0 ] || fatal "Forensic export and verification require root"
}

prepare_work_dir() {
    install -d -m 0700 -o root -g root -- "$WORK_ROOT"
    [ ! -L "$WORK_ROOT" ] || fatal "Refusing symbolic-link work directory: $WORK_ROOT"
    WORK_DIR=$(mktemp -d "${WORK_ROOT}/forensic.XXXXXXXX")
    chmod 0700 "$WORK_DIR"
}

validate_private_file() {
    local path="$1"
    local label="$2"
    if [ ! -f "$path" ] || [ -L "$path" ]; then
        fatal "$label is missing or not a regular file"
    fi
    [ "$(stat -c '%u' "$path")" -eq 0 ] || fatal "$label must be owned by root"
    local mode
    mode=$(stat -c '%a' "$path")
    (( (8#$mode & 077) == 0 )) || fatal "$label must not be readable by group or other users"
    [ -s "$path" ] || fatal "$label is empty"
}

validate_loopback_url() {
    [[ "$INCIDENT_RECORDER_URL" =~ ^http://(127\.0\.0\.1|localhost|\[::1\]):([0-9]{1,5})$ ]] \
        || fatal "INCIDENT_RECORDER_URL must be an explicit loopback HTTP origin"
    local port="${BASH_REMATCH[2]}"
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        fatal "INCIDENT_RECORDER_URL has an invalid port"
    fi
}

verify_bundle() {
    local bundle="$1"
    validate_private_file "$FORENSIC_HMAC_KEY_PATH" "Forensic HMAC key"
    [ -x "$VERIFY_HELPER" ] || fatal "Forensic verifier is missing: $VERIFY_HELPER"
    "$VERIFY_HELPER" \
        --bundle "$bundle" \
        --key "$FORENSIC_HMAC_KEY_PATH" \
        --maximum-bytes "$MAX_BUNDLE_BYTES"
}

cmd_export() {
    local output="${1:-}"
    [ -n "$output" ] || output="forensic-bundle-$(date -u +%Y%m%d-%H%M%S).json"
    require_root
    command -v curl >/dev/null 2>&1 || fatal "curl is required for export"
    command -v python3 >/dev/null 2>&1 || fatal "python3 is required for verification"
    validate_loopback_url
    validate_private_file "$FORENSIC_TOKEN_PATH" "Incident-recorder forensic token"
    validate_private_file "$FORENSIC_HMAC_KEY_PATH" "Forensic HMAC key"
    prepare_work_dir

    local token
    IFS= read -r token < "$FORENSIC_TOKEN_PATH" || fatal "Could not read forensic token"
    [[ "$token" =~ ^[0-9a-fA-F]{64,256}$ ]] \
        || fatal "Incident-recorder token has an invalid encoding"

    local output_parent output_name
    output_parent=$(dirname -- "$output")
    output_name=$(basename -- "$output")
    if [ ! -d "$output_parent" ] || [ -L "$output_parent" ]; then
        fatal "Output parent must be an existing real directory"
    fi
    if [ "$output_name" = "." ] || [ "$output_name" = ".." ]; then
        fatal "Invalid output filename"
    fi
    if [ -e "$output" ] || [ -L "$output" ]; then
        fatal "Refusing to overwrite output: $output"
    fi

    local curl_config="${WORK_DIR}/curl.conf"
    printf 'header = "Authorization: Bearer %s"\n' "$token" > "$curl_config"
    chmod 0600 "$curl_config"

    PARTIAL_OUTPUT=$(mktemp "${output_parent}/.${output_name}.partial.XXXXXXXX")
    chmod 0600 "$PARTIAL_OUTPUT"
    info "Exporting an authenticated bundle from the loopback incident recorder"
    if ! curl \
        --config "$curl_config" \
        --proto '=http' \
        --proto-redir '=http' \
        --noproxy '*' \
        --fail \
        --silent \
        --show-error \
        --connect-timeout 2 \
        --max-time 30 \
        --max-filesize "$MAX_BUNDLE_BYTES" \
        --output "$PARTIAL_OUTPUT" \
        "${INCIDENT_RECORDER_URL}/api/v1/forensic/export"
    then
        fatal "Forensic export failed"
    fi
    [ -s "$PARTIAL_OUTPUT" ] || fatal "Incident recorder returned an empty bundle"
    verify_bundle "$PARTIAL_OUTPUT" || fatal "Exported bundle failed authenticity verification"
    sync -f "$PARTIAL_OUTPUT"
    mv -- "$PARTIAL_OUTPUT" "$output"
    PARTIAL_OUTPUT=""
    chmod 0600 "$output"
    info "Authenticated forensic bundle written atomically: $output"
}

cmd_verify() {
    local bundle="$1"
    require_root
    command -v python3 >/dev/null 2>&1 || fatal "python3 is required for verification"
    if [ ! -f "$bundle" ] || [ -L "$bundle" ]; then
        fatal "Bundle must be a regular file: $bundle"
    fi
    verify_bundle "$bundle"
}

case "${1:-}" in
    export)
        shift
        OUTPUT=""
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --output)
                    [ "$#" -ge 2 ] || fatal "--output requires a filename"
                    OUTPUT="$2"; shift 2 ;;
                *) fatal "Unknown export option: $1" ;;
            esac
        done
        cmd_export "$OUTPUT"
        ;;
    verify)
        shift
        [ "$#" -eq 1 ] || fatal "verify requires exactly one bundle path"
        cmd_verify "$1"
        ;;
    --help|-h)
        usage
        ;;
    *)
        err "Unknown command: ${1:-}"
        usage
        ;;
esac
