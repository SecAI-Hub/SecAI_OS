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

# Generate service-to-service auth token
SERVICE_TOKEN_DIR="/run/secure-ai"
SERVICE_TOKEN_PATH="${SERVICE_TOKEN_DIR}/service-token"
if [ ! -f "$SERVICE_TOKEN_PATH" ]; then
    mkdir -p "$SERVICE_TOKEN_DIR"
    head -c 32 /dev/urandom | xxd -p -c 64 > "$SERVICE_TOKEN_PATH"
    chmod 0640 "$SERVICE_TOKEN_PATH"
    chgrp secure-ai "$SERVICE_TOKEN_PATH" 2>/dev/null || true
    log "Service token generated at $SERVICE_TOKEN_PATH"
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

# Detect VM environment
log "Running VM detection..."
/usr/libexec/secure-ai/detect-vm.sh 2>&1 | while IFS= read -r line; do log "$line"; done || {
    log "WARNING: VM detection failed."
    cat > "${SECURE_AI_ROOT}/vm.env" <<'VMEOF'
IS_VM=false
HYPERVISOR=unknown
GPU_PASSTHROUGH=false
VM_GPU_ENABLED=false
VMEOF
}

# Log VM warnings if applicable
if [ -f "${SECURE_AI_ROOT}/vm.env" ]; then
    # shellcheck source=/dev/null
    source "${SECURE_AI_ROOT}/vm.env"
    if [ "${IS_VM:-false}" = "true" ]; then
        log "============================================"
        log "WARNING: Running inside a virtual machine (${HYPERVISOR})"
        log "  - Host OS can inspect VM memory (decrypted vault, inference data)"
        log "  - VM snapshots may capture decrypted secrets"
        log "  - Disable clipboard sharing for better isolation"
        if [ "${GPU_PASSTHROUGH:-false}" = "true" ]; then
            log "  - GPU passthrough detected but DISABLED by default"
            log "  - Enable via UI Settings or set VM_GPU_ENABLED=true in vm.env"
            log "  - GPU passthrough exposes GPU memory to host hypervisor"
        fi
        log "  For maximum security, use bare-metal installation"
        log "============================================"
    fi
fi

# Detect GPU and write inference.env
log "Running GPU detection..."
/usr/libexec/secure-ai/detect-gpu.sh 2>&1 | while IFS= read -r line; do log "$line"; done || {
    log "WARNING: GPU detection failed. Defaulting to CPU."
    cat > "${SECURE_AI_ROOT}/inference.env" <<'GPUEOF'
GPU_BACKEND=cpu
GPU_NAME=CPU (detection failed)
GPU_LAYERS=0
GPUEOF
}

# In VM mode with GPU passthrough disabled, force CPU-only
if [ -f "${SECURE_AI_ROOT}/vm.env" ]; then
    # shellcheck source=/dev/null
    source "${SECURE_AI_ROOT}/vm.env"
    if [ "${IS_VM:-false}" = "true" ] && [ "${VM_GPU_ENABLED:-false}" = "false" ]; then
        log "VM mode: forcing CPU-only inference (GPU passthrough disabled)"
        cat > "${SECURE_AI_ROOT}/inference.env" <<'CPUEOF'
GPU_BACKEND=cpu
GPU_NAME=CPU (VM mode - GPU disabled for security)
GPU_LAYERS=0
CPUEOF
    fi
fi

# --- Memory protection checks (M18) ---
log "Ensuring swap is disabled..."
swapoff -a 2>/dev/null || true

# Verify zswap is disabled
if [ -f /sys/module/zswap/parameters/enabled ]; then
    if [ "$(cat /sys/module/zswap/parameters/enabled 2>/dev/null)" = "Y" ]; then
        log "WARNING: zswap is enabled — disabling to prevent secrets in compressed swap"
        echo N > /sys/module/zswap/parameters/enabled 2>/dev/null || true
    else
        log "zswap is disabled (good)"
    fi
fi

# Verify core dumps are disabled
if [ -f /proc/sys/kernel/core_pattern ]; then
    local_core_pattern=$(cat /proc/sys/kernel/core_pattern 2>/dev/null || echo "")
    if [ "$local_core_pattern" = "|/bin/false" ]; then
        log "Core dumps: disabled via core_pattern (good)"
    else
        log "WARNING: core_pattern is '${local_core_pattern}', forcing to |/bin/false"
        echo '|/bin/false' > /proc/sys/kernel/core_pattern 2>/dev/null || true
    fi
fi

# Verify vm.swappiness=0
current_swappiness=$(cat /proc/sys/vm/swappiness 2>/dev/null || echo "unknown")
if [ "$current_swappiness" != "0" ]; then
    log "WARNING: vm.swappiness=${current_swappiness}, setting to 0"
    echo 0 > /proc/sys/vm/swappiness 2>/dev/null || true
else
    log "vm.swappiness=0 (good)"
fi

# Detect TEE (AMD SEV / Intel TDX / TME)
log "Running TEE detection..."
/usr/libexec/secure-ai/detect-tee.sh 2>&1 | while IFS= read -r line; do log "$line"; done || {
    log "WARNING: TEE detection failed"
    cat > "${SECURE_AI_ROOT}/tee.env" <<'TEEEOF'
TEE_TYPE=none
TEE_ACTIVE=false
TEE_DETAIL=detection failed
MEM_ENCRYPT=false
TEEEOF
}

# Log TEE results
if [ -f "${SECURE_AI_ROOT}/tee.env" ]; then
    # shellcheck source=/dev/null
    source "${SECURE_AI_ROOT}/tee.env"
    if [ "${MEM_ENCRYPT:-false}" = "true" ]; then
        log "Hardware memory encryption: ACTIVE (${TEE_TYPE})"
    else
        log "Hardware memory encryption: NOT DETECTED"
        log "Consider hardware with AMD SEV, Intel TDX/TME for maximum protection."
    fi
fi

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

# --- Secure Boot + TPM2 checks (M17) ---
log "Checking Secure Boot status..."
/usr/libexec/secure-ai/enroll-secureboot.sh --check-only 2>&1 | while IFS= read -r line; do log "$line"; done || true

log "Checking TPM2 status..."
/usr/libexec/secure-ai/tpm2-seal-vault.sh status 2>&1 | while IFS= read -r line; do log "$line"; done || true

# Create TPM2 key directory
mkdir -p "${SECURE_AI_ROOT}/keys/tpm2"
chmod 700 "${SECURE_AI_ROOT}/keys/tpm2"

# If TPM2 is available and vault key is not yet sealed, log instructions
if [ -e /dev/tpmrm0 ] || [ -e /dev/tpm0 ]; then
    if [ ! -f "${SECURE_AI_ROOT}/keys/tpm2/vault-key.sealed.pub" ]; then
        log ""
        log "TPM2 detected. To seal the vault key to the boot chain:"
        log "  sudo /usr/libexec/secure-ai/tpm2-seal-vault.sh seal"
        log "This binds vault auto-unlock to the current firmware + kernel state."
        log ""
    fi
fi

# --- Clipboard isolation (M21) ---
log "Running clipboard isolation..."
/usr/libexec/secure-ai/clipboard-isolate.sh 2>&1 | while IFS= read -r line; do log "$line"; done || {
    log "WARNING: clipboard isolation check failed"
}

# Log clipboard results
if [ -f "${SECURE_AI_ROOT}/clipboard.env" ]; then
    # shellcheck source=/dev/null
    source "${SECURE_AI_ROOT}/clipboard.env"
    if [ "${CLIPBOARD_ISOLATED:-false}" = "true" ]; then
        log "Clipboard isolation: ACTIVE"
    else
        log "WARNING: Clipboard may not be fully isolated"
    fi
    if [ -n "${CLIP_AGENTS_DISABLED:-}" ]; then
        log "Disabled clipboard agents: ${CLIP_AGENTS_DISABLED}"
    fi
fi

# Run boot chain verification
log "Running boot chain integrity verification..."
/usr/libexec/secure-ai/verify-boot-chain.sh 2>&1 | while IFS= read -r line; do log "$line"; done || {
    log "WARNING: boot chain verification failed"
}

# --- Canary / Tripwire placement (M22) ---
log "Placing canary files in sensitive directories..."
/usr/libexec/secure-ai/canary-place.sh 2>&1 | while IFS= read -r line; do log "$line"; done || {
    log "WARNING: canary placement failed"
}

# Run initial canary verification
log "Running initial canary verification..."
/usr/libexec/secure-ai/canary-check.sh check 2>&1 | while IFS= read -r line; do log "$line"; done || {
    log "WARNING: initial canary check failed"
}

# --- Emergency wipe verification (M23) ---
if [ -x /usr/libexec/secure-ai/securectl ]; then
    log "Emergency wipe tool (securectl) available"
    # Verify panic state directory exists
    mkdir -p /run/secure-ai 2>/dev/null || true
else
    log "WARNING: securectl not found or not executable"
fi

# --- Update verification + greenboot (M24) ---
if [ -x /usr/libexec/secure-ai/update-verify.sh ]; then
    log "Update verification tool available"
else
    log "WARNING: update-verify.sh not found or not executable"
fi

if [ -x /etc/greenboot/check/required.d/01-secure-ai-health.sh ]; then
    log "Greenboot health check script available"
else
    log "WARNING: greenboot health check not found"
fi

# Write marker (read-only to prevent tampering)
date -Iseconds > "$MARKER"
chmod 444 "$MARKER"
log "First boot setup complete."
log "Vault directory: ${SECURE_AI_ROOT}/vault"
log "Drop model files into: ${SECURE_AI_ROOT}/quarantine/incoming"
log "=== Setup Done ==="
