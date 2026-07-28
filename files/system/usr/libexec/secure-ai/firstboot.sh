#!/usr/bin/env bash
#
# Secure AI Appliance — First Boot Setup
#
# Runs once on initial boot. Creates:
#   - Directory structure for vault, registry, quarantine, logs
#   - Authenticated runtime integrity baseline and canary records
#   - Restrictive permissions and ownership
#   - Marker file to prevent re-running

set -euo pipefail
umask 077

SECURE_AI_ROOT="/var/lib/secure-ai"
MARKER="${SECURE_AI_ROOT}/state/firstboot-complete"

log() {
    echo "[secure-ai-firstboot] $*"
    logger -t secure-ai-firstboot "$*" 2>/dev/null || true
}

fatal() {
    log "ERROR: $*"
    exit 1
}

if [ -f "$MARKER" ]; then
    log "Already initialized, skipping."
    exit 0
fi

log "=== Secure AI Appliance First Boot Setup ==="

# Apply the single resource-scoped DAC contract from tmpfiles.d.  Keeping the
# modes in one declarative file prevents first boot from undoing setgid groups.
log "Creating directory structure..."
systemd-tmpfiles --create --prefix="${SECURE_AI_ROOT}" \
    /usr/lib/tmpfiles.d/secure-ai.conf

# Promotion records are authenticated by the registry/incident audit chains.
# Do not generate an unencrypted software cosign private key: no runtime
# component consumes one, and its presence would create a misleading trust
# signal.

# Root-only credential sources are provisioned on every boot by
# secure-ai-credentials.service and delivered privately with LoadCredential=.

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
vm_detection=$(/usr/libexec/secure-ai/detect-vm.sh)
while IFS= read -r line; do log "$line"; done <<< "$vm_detection"
vm_state=$(/usr/libexec/secure-ai/secure-hardware-detect.py show vm)
is_vm=$(printf '%s' "$vm_state" | jq -er '.is_vm | if type == "boolean" then . else error("is_vm") end')
hypervisor=$(printf '%s' "$vm_state" | jq -er '.hypervisor | select(type == "string" and test("^[a-z0-9_-]{1,64}$"))')
gpu_passthrough=$(printf '%s' "$vm_state" | jq -er '.gpu_passthrough | if type == "boolean" then . else error("gpu_passthrough") end')
gpu_enabled=$(printf '%s' "$vm_state" | jq -er '.gpu_enabled | if type == "boolean" then . else error("gpu_enabled") end')
if [ "$is_vm" = "true" ]; then
    log "============================================"
    log "WARNING: Running inside a virtual machine (${hypervisor})"
    log "  - Host OS can inspect VM memory (decrypted vault, inference data)"
    log "  - VM snapshots may capture decrypted secrets"
    log "  - Disable clipboard and drag-and-drop in the hypervisor"
    if [ "$gpu_passthrough" = "true" ] && [ "$gpu_enabled" != "true" ]; then
        log "  - GPU passthrough detected but DISABLED by default"
        log "  - Local opt-in: secure-hardware-detect.py vm-gpu enable"
        log "  - GPU passthrough exposes GPU memory to the host"
    fi
    log "  For maximum security, use bare-metal installation"
    log "============================================"
fi

# Detect GPU and write inference.env
log "Running GPU detection..."
gpu_detection=""
if gpu_detection=$(/usr/libexec/secure-ai/detect-gpu.sh 2>&1); then
    while IFS= read -r line; do log "$line"; done <<< "$gpu_detection"
else
    while IFS= read -r line; do log "$line"; done <<< "$gpu_detection"
    log "WARNING: GPU detection failed; installing a typed CPU-only policy."
    /usr/libexec/secure-ai/detect-gpu.sh --force-cpu
fi

# --- Memory protection checks (M18) ---
log "Ensuring swap is disabled..."
swapoff -a 2>/dev/null || fatal "swapoff failed"
if swapon --show --noheadings 2>/dev/null | grep '[^[:space:]]' >/dev/null; then
    fatal "one or more swap devices remain active"
fi

# Verify zswap is disabled
if [ -f /sys/module/zswap/parameters/enabled ]; then
    if [ "$(cat /sys/module/zswap/parameters/enabled 2>/dev/null)" = "Y" ]; then
        log "zswap is enabled — disabling it to protect decrypted data"
        echo N > /sys/module/zswap/parameters/enabled 2>/dev/null || \
            fatal "could not disable zswap"
        zswap_state=$(cat /sys/module/zswap/parameters/enabled 2>/dev/null || true)
        case "$zswap_state" in
            N|0) ;;
            *) fatal "zswap remains enabled after the disable request" ;;
        esac
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
        log "core_pattern is '${local_core_pattern}', forcing it to |/bin/false"
        echo '|/bin/false' > /proc/sys/kernel/core_pattern 2>/dev/null || \
            fatal "could not disable core dumps"
        [ "$(cat /proc/sys/kernel/core_pattern 2>/dev/null)" = "|/bin/false" ] || \
            fatal "core dumps remain enabled"
    fi
fi

# Verify vm.swappiness=0
current_swappiness=$(cat /proc/sys/vm/swappiness 2>/dev/null || echo "unknown")
if [ "$current_swappiness" != "0" ]; then
    log "vm.swappiness=${current_swappiness}, setting it to 0"
    echo 0 > /proc/sys/vm/swappiness 2>/dev/null || \
        fatal "could not set vm.swappiness=0"
    [ "$(cat /proc/sys/vm/swappiness 2>/dev/null)" = "0" ] || \
        fatal "vm.swappiness remains nonzero"
else
    log "vm.swappiness=0 (good)"
fi

# Detect TEE (AMD SEV / Intel TDX / TME)
log "Running TEE detection..."
tee_detection=""
if tee_detection=$(/usr/libexec/secure-ai/detect-tee.sh 2>&1); then
    while IFS= read -r line; do log "$line"; done <<< "$tee_detection"
    tee_state=$(/usr/libexec/secure-ai/secure-hardware-detect.py show tee)
    tee_active=$(printf '%s' "$tee_state" | jq -er '.active | if type == "boolean" then . else error("active") end')
    tee_type=$(printf '%s' "$tee_state" | jq -er '.type | select(type == "string")')
    if [ "$tee_active" = "true" ]; then
        log "Hardware memory encryption: ACTIVE and evidenced (${tee_type})"
    else
        log "Hardware memory encryption: NOT VERIFIED"
        log "CPU capability flags alone are not treated as proof of active protection."
    fi
else
    while IFS= read -r line; do log "$line"; done <<< "$tee_detection"
    log "Hardware memory encryption: NOT VERIFIED (detection failed)"
fi

# Verify nftables is loaded
command -v nft >/dev/null 2>&1 || fatal "nftables is unavailable"
if nft list ruleset 2>/dev/null | grep -F "table inet secure_ai" >/dev/null; then
    log "Firewall rules verified: secure_ai table active."
else
    log "secure_ai nftables table not found; loading it now"
    nft -f /etc/nftables/secure-ai.nft 2>/dev/null || \
        fatal "failed to load firewall rules"
    nft list ruleset 2>/dev/null | grep -F "table inet secure_ai" >/dev/null || \
        fatal "secure_ai firewall table is still inactive"
fi

# Set ptrace scope if available (restrict debugging)
if [ -e /proc/sys/kernel/yama/ptrace_scope ]; then
    ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || true)
    if [ "$ptrace_scope" = "0" ]; then
        echo 1 > /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || \
            fatal "could not restrict ptrace"
    fi
    ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || true)
    case "$ptrace_scope" in
        1|2|3) ;;
        *) fatal "kernel.yama.ptrace_scope is not restrictive" ;;
    esac
fi

# --- Secure Boot + TPM2 checks (M17) ---
log "Checking Secure Boot status..."
/usr/libexec/secure-ai/enroll-secureboot.sh --check-only 2>&1 | while IFS= read -r line; do log "$line"; done || true

log "Checking TPM2 status..."
tpm2_result=""
if tpm2_result=$(/usr/libexec/secure-ai/tpm2-seal-vault.sh status 2>&1); then
    tpm2_status=0
else
    tpm2_status=$?
fi
while IFS= read -r line; do log "$line"; done <<< "$tpm2_result"

if [ -e /dev/tpmrm0 ] || [ -e /dev/tpm0 ]; then
    if [ "$tpm2_status" -ne 0 ]; then
        log ""
        log "TPM2 auto-unlock is not production-verified for this vault."
        log "After configuring the vault, enroll it from a local console:"
        log "  sudo /usr/libexec/secure-ai/tpm2-seal-vault.sh seal"
        log "A passphrase recovery keyslot is retained. vTPM and disabled"
        log "Secure Boot require explicit degraded-mode acknowledgements."
        log ""
    fi
fi

# --- Clipboard isolation (M21) ---
log "Running clipboard isolation..."
clipboard_result=""
if clipboard_result=$(/usr/libexec/secure-ai/clipboard-isolate.sh 2>&1); then
    while IFS= read -r line; do log "$line"; done <<< "$clipboard_result"
    log "Clipboard isolation: no VM host channel detected"
else
    clipboard_status=$?
    while IFS= read -r line; do log "$line"; done <<< "$clipboard_result"
    if [ "$clipboard_status" -eq 2 ]; then
        log "WARNING: clipboard status requires_hypervisor_verification"
        log "Review ${SECURE_AI_ROOT}/state/clipboard.json and disable both"
        log "shared clipboard and drag-and-drop in the host VM configuration."
    else
        log "WARNING: guest clipboard controls failed closed; review"
        log "${SECURE_AI_ROOT}/state/clipboard.json before handling sensitive data."
    fi
fi

# Run boot chain verification
log "Running boot chain integrity verification..."
/usr/libexec/secure-ai/verify-boot-chain.sh 2>&1 | while IFS= read -r line; do log "$line"; done || {
    fatal "boot chain verification failed"
}

# --- Canary / Tripwire placement (M22) ---
log "Placing canary files in sensitive directories..."
/usr/libexec/secure-ai/canary-place.sh 2>&1 | while IFS= read -r line; do log "$line"; done || {
    fatal "canary placement failed"
}

# Run initial canary verification
log "Running initial canary verification..."
/usr/libexec/secure-ai/canary-check.sh check 2>&1 | while IFS= read -r line; do log "$line"; done || {
    fatal "initial canary check failed"
}

# --- Emergency wipe verification (M23) ---
if [ -x /usr/libexec/secure-ai/securectl ]; then
    log "Emergency wipe tool (securectl) available"
    # Verify panic state directory exists
    mkdir -p /run/secure-ai 2>/dev/null || true
else
    fatal "securectl is missing or not executable"
fi

# --- Update verification + greenboot (M24) ---
if [ -x /usr/libexec/secure-ai/update-verify.sh ]; then
    log "Update verification tool available"
else
    fatal "update-verify.sh is missing or not executable"
fi

if [ -x /etc/greenboot/check/required.d/01-secure-ai-health.sh ]; then
    log "Greenboot health check script available"
else
    fatal "greenboot health check is missing or not executable"
fi

# Initialize the authenticated integrity baseline exactly once, before writing
# the persistent first-boot marker.  Subsequent service restarts load and
# verify this file rather than blessing current filesystem contents.
if [ ! -f "${SECURE_AI_ROOT}/integrity/baseline.json" ]; then
    log "Initializing authenticated integrity baseline..."
    HMAC_KEY_PATH="${SECURE_AI_ROOT}/credentials/integrity-hmac.key" \
    BASELINE_PATH="${SECURE_AI_ROOT}/integrity/baseline.json" \
    EXPECTED_BASELINE_PATH="/usr/share/secure-ai/integrity/release-baseline.json" \
    MONITOR_POLICY_PATH="/etc/secure-ai/policy/integrity-monitor.yaml" \
        /usr/libexec/secure-ai/integrity-monitor --initialize-baseline
    chmod 0644 "${SECURE_AI_ROOT}/integrity/baseline.json"
fi

# Write marker (read-only to prevent tampering)
mkdir -p "$(dirname "$MARKER")"
date -Iseconds > "$MARKER"
chmod 444 "$MARKER"
log "First boot setup complete."
log "Vault directory: ${SECURE_AI_ROOT}/vault"
log "Drop model files into: ${SECURE_AI_ROOT}/quarantine/incoming"
log ""
log "Run the setup wizard to complete configuration:"
log "  sudo /usr/libexec/secure-ai/secai-setup-wizard.sh"
log "=== Setup Done ==="
