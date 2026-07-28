#!/usr/bin/env bash
#
# Provision persistent, root-only inputs for systemd credential delivery.
#
# Individual services receive private, read-only copies through
# LoadCredential=; they never receive DAC access to this root-only source
# directory. The host OS volume must itself use full-disk encryption because
# setup/status services need these credentials while the separate model/data
# vault is locked. This unit runs on every boot and refuses altered sources.

set -euo pipefail
umask 077
export LC_ALL=C

CREDENTIAL_DIR="${SECURE_AI_CREDENTIAL_DIR:-/var/lib/secure-ai/credentials}"

log() {
    echo "[secure-ai-credentials] $*"
    logger -t secure-ai-credentials "$*" 2>/dev/null || true
}

generate_hex_secret() {
    local destination="$1"
    local temporary

    temporary=$(mktemp "${CREDENTIAL_DIR}/.credential.XXXXXX")
    if ! head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$temporary"; then
        rm -f -- "$temporary"
        return 1
    fi
    printf '\n' >> "$temporary"
    chmod 0600 "$temporary"
    sync -f "$temporary"
    if ! ln -- "$temporary" "$destination"; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary"
    sync -f "$CREDENTIAL_DIR"
}

validate_or_create() {
    local name="$1"
    local path="${CREDENTIAL_DIR}/${name}"
    local metadata

    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        generate_hex_secret "$path"
        log "Created credential source: $name"
    fi
    metadata=$(stat -c '%F:%u:%g:%a:%h:%s' -- "$path" 2>/dev/null) || {
        log "ERROR: cannot inspect credential source: $path"
        return 1
    }
    case "$metadata" in
        regular\ file:0:0:600:1:64|regular\ file:0:0:600:1:65) ;;
        *)
            log "ERROR: credential source has unsafe type/owner/mode/link-count/size: $name"
            return 1
            ;;
    esac
    if ! LC_ALL=C grep -Eq '^[0-9a-f]{64}$' -- "$path"; then
        log "ERROR: credential source is not a canonical 256-bit secret: $name"
        return 1
    fi
}

if [ ! -e "$CREDENTIAL_DIR" ] && [ ! -L "$CREDENTIAL_DIR" ]; then
    install -d -m 0700 -o root -g root "$CREDENTIAL_DIR"
fi
credential_dir_metadata=$(
    stat -c '%F:%u:%g:%a:%h' -- "$CREDENTIAL_DIR" 2>/dev/null
) || {
    log "ERROR: cannot inspect credential directory"
    exit 1
}
if [ "$credential_dir_metadata" != "directory:0:0:700:2" ]; then
    log "ERROR: credential directory has unsafe type/owner/mode/link count"
    exit 1
fi

case "${SECURE_AI_REQUIRE_ENCRYPTED_HOST_STATE:-true}" in
    true)
        /usr/libexec/secure-ai/verify-host-state-encryption.py
        ;;
    false)
        log "WARNING: encrypted host-state verification explicitly disabled (non-production)"
        ;;
    *)
        log "ERROR: SECURE_AI_REQUIRE_ENCRYPTED_HOST_STATE must be true or false"
        exit 1
        ;;
esac

# One credential per target service.  Callers receive only the downstream
# credentials they need; compromise of one service no longer grants a
# universal control-plane identity.
for target in \
    policy-engine \
    tool-firewall \
    mcp-firewall \
    runtime-attestor \
    integrity-monitor \
    gpu-integrity-watch \
    airlock \
    search-mediator \
    diffusion
do
    validate_or_create "${target}.token"
done
validate_or_create registry-read.token
validate_or_create registry-verify.token
validate_or_create registry-promote.token
validate_or_create registry-admin.token
validate_or_create ui-setup.token
validate_or_create ui-flask-session.key
validate_or_create agent-signing.key
validate_or_create agent-ui.token
validate_or_create agent-containment.token
validate_or_create airlock-containment.token
validate_or_create registry-containment.token
validate_or_create incident-read.token
validate_or_create incident-operator.token
validate_or_create incident-recovery-admin.token
validate_or_create incident-forensic.token
validate_or_create incident-reporter-canary.token
validate_or_create incident-reporter-gpu-integrity.token
validate_or_create incident-reporter-integrity-monitor.token
validate_or_create incident-reporter-runtime-attestor.token
validate_or_create searxng-secret.key
validate_or_create integrity-hmac.key
validate_or_create attestation-hmac.key
validate_or_create forensic-hmac.key
validate_or_create canary-hmac.key
validate_or_create agent-audit-hmac.key
validate_or_create quarantine-audit-hmac.key
validate_or_create search-audit-hmac.key
validate_or_create ui-audit-hmac.key
validate_or_create panic-audit-hmac.key

log "Credential sources validated"
