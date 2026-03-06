#!/usr/bin/env bash
#
# Secure AI Appliance — First Boot Setup
#
# Runs once on initial boot. Creates:
#   - Directory structure for vault, registry, quarantine, logs
#   - Local cosign key pair for signing promotion records
#   - Restrictive permissions and ownership
#   - Marker file to prevent re-running

set -euo pipefail
umask 077

SECURE_AI_ROOT="/var/lib/secure-ai"
MARKER="${SECURE_AI_ROOT}/.initialized"

log() {
    echo "[secure-ai-firstboot] $*"
    logger -t secure-ai-firstboot "$*"
}

if [ -f "$MARKER" ]; then
    log "Already initialized, skipping."
    exit 0
fi

log "=== Secure AI Appliance First Boot Setup ==="

# Create directory structure
log "Creating directory structure..."
dirs=(
    "${SECURE_AI_ROOT}/vault"
    "${SECURE_AI_ROOT}/vault/user_docs"
    "${SECURE_AI_ROOT}/vault/outputs"
    "${SECURE_AI_ROOT}/registry"
    "${SECURE_AI_ROOT}/quarantine"
    "${SECURE_AI_ROOT}/quarantine/incoming"
    "${SECURE_AI_ROOT}/logs"
    "${SECURE_AI_ROOT}/keys"
)
for d in "${dirs[@]}"; do
    mkdir -p "$d"
done

# Set restrictive permissions
chmod 700 "${SECURE_AI_ROOT}/vault"
chmod 700 "${SECURE_AI_ROOT}/keys"
chmod 750 "${SECURE_AI_ROOT}/registry"
chmod 770 "${SECURE_AI_ROOT}/quarantine"
chmod 750 "${SECURE_AI_ROOT}/logs"

# Generate local signing key pair for promotion records
if [ ! -f "${SECURE_AI_ROOT}/keys/local-cosign.key" ]; then
    log "Generating local signing key pair..."
    if command -v cosign &>/dev/null; then
        COSIGN_PASSWORD="" cosign generate-key-pair \
            --output-key-prefix="${SECURE_AI_ROOT}/keys/local-cosign" 2>/dev/null || {
            log "WARNING: cosign key generation failed. Promotion signing will be unavailable."
        }
        if [ -f "${SECURE_AI_ROOT}/keys/local-cosign.key" ]; then
            chmod 600 "${SECURE_AI_ROOT}/keys/local-cosign.key"
            chmod 644 "${SECURE_AI_ROOT}/keys/local-cosign.pub"
            log "Local signing keys created."
        fi
    else
        log "WARNING: cosign not found. Skipping key generation."
    fi
fi

# Create initial empty registry manifest
if [ ! -f "${SECURE_AI_ROOT}/registry/manifest.json" ]; then
    log "Creating empty registry manifest..."
    cat > "${SECURE_AI_ROOT}/registry/manifest.json" <<'EOF'
{
  "version": 1,
  "models": []
}
EOF
    chmod 644 "${SECURE_AI_ROOT}/registry/manifest.json"
fi

# Disable swap (belt-and-suspenders alongside kernel arg)
log "Ensuring swap is disabled..."
swapoff -a 2>/dev/null || true

# Verify nftables is loaded
if command -v nft &>/dev/null; then
    if nft list ruleset 2>/dev/null | grep -q "secure_ai"; then
        log "Firewall rules verified: secure_ai table active."
    else
        log "WARNING: secure_ai nftables table not found. Loading..."
        nft -f /etc/nftables/secure-ai.nft 2>/dev/null || log "WARNING: failed to load firewall rules."
    fi
fi

# Set ptrace scope if available (restrict debugging)
if [ -w /proc/sys/kernel/yama/ptrace_scope ]; then
    echo 1 > /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || true
fi

# Write marker (read-only to prevent tampering)
date -Iseconds > "$MARKER"
chmod 444 "$MARKER"
log "First boot setup complete."
log "Vault directory: ${SECURE_AI_ROOT}/vault"
log "Drop model files into: ${SECURE_AI_ROOT}/quarantine/incoming"
log "=== Setup Done ==="
