#!/usr/bin/env bash
#
# Secure AI Appliance — Trusted Execution Environment Detection
#
# Detects hardware memory encryption / confidential computing features:
#   - AMD SEV (Secure Encrypted Virtualization)
#   - AMD SEV-ES / SEV-SNP
#   - Intel TDX (Trust Domain Extensions)
#   - Intel TME / MKTME (Total Memory Encryption)
#   - ARM CCA (Confidential Compute Architecture)
#
# Writes results to /var/lib/secure-ai/tee.env
# Non-fatal: logs findings but does not block boot.
#
set -euo pipefail

SECURE_AI_ROOT="/var/lib/secure-ai"
TEE_ENV="${SECURE_AI_ROOT}/tee.env"

log() {
    echo "[detect-tee] $*"
    logger -t detect-tee "$*" 2>/dev/null || true
}

# Default values
TEE_TYPE="none"
TEE_ACTIVE="false"
TEE_DETAIL=""
MEM_ENCRYPT="false"

# --- AMD SEV detection ---
detect_amd_sev() {
    # Check /sys/module/kvm_amd/parameters/sev
    if [ -f /sys/module/kvm_amd/parameters/sev ]; then
        local sev_val
        sev_val=$(cat /sys/module/kvm_amd/parameters/sev 2>/dev/null || echo "N")
        if [ "$sev_val" = "Y" ] || [ "$sev_val" = "1" ]; then
            TEE_TYPE="amd-sev"
            TEE_ACTIVE="true"
            TEE_DETAIL="AMD SEV enabled (host)"
            MEM_ENCRYPT="true"
        fi
    fi

    # Check if running as SEV guest
    if [ -f /sys/kernel/security/sev ]; then
        TEE_TYPE="amd-sev-guest"
        TEE_ACTIVE="true"
        MEM_ENCRYPT="true"
    fi

    # Check dmesg for SEV indicators
    if dmesg 2>/dev/null | grep -qi "SEV-SNP"; then
        TEE_TYPE="amd-sev-snp"
        TEE_ACTIVE="true"
        TEE_DETAIL="AMD SEV-SNP active"
        MEM_ENCRYPT="true"
    elif dmesg 2>/dev/null | grep -qi "SEV-ES"; then
        TEE_TYPE="amd-sev-es"
        TEE_ACTIVE="true"
        TEE_DETAIL="AMD SEV-ES active"
        MEM_ENCRYPT="true"
    elif dmesg 2>/dev/null | grep -qi "AMD Memory Encryption Features active: SEV"; then
        TEE_TYPE="amd-sev"
        TEE_ACTIVE="true"
        TEE_DETAIL="AMD SEV active"
        MEM_ENCRYPT="true"
    fi

    # CPUID check for SME/SEV capability (leaf 0x8000001f)
    if [ -f /proc/cpuinfo ] && grep -q "sme\|sev" /proc/cpuinfo 2>/dev/null; then
        if [ "$TEE_TYPE" = "none" ]; then
            TEE_TYPE="amd-sev-capable"
            TEE_DETAIL="AMD SEV capable but not active"
        fi
    fi
}

# --- Intel TDX detection ---
detect_intel_tdx() {
    # Check if running inside a TD (Trust Domain)
    if [ -c /dev/tdx-guest ] || [ -c /dev/tdx_guest ]; then
        TEE_TYPE="intel-tdx-guest"
        TEE_ACTIVE="true"
        TEE_DETAIL="Intel TDX guest (trust domain)"
        MEM_ENCRYPT="true"
        return
    fi

    # Check host TDX support
    if [ -d /sys/firmware/acpi/tables ] && [ -f /sys/module/kvm_intel/parameters/tdx ] 2>/dev/null; then
        local tdx_val
        tdx_val=$(cat /sys/module/kvm_intel/parameters/tdx 2>/dev/null || echo "N")
        if [ "$tdx_val" = "Y" ] || [ "$tdx_val" = "1" ]; then
            TEE_TYPE="intel-tdx"
            TEE_ACTIVE="true"
            TEE_DETAIL="Intel TDX enabled (host)"
            MEM_ENCRYPT="true"
            return
        fi
    fi

    # Check dmesg for TDX
    if dmesg 2>/dev/null | grep -qi "TDX"; then
        if [ "$TEE_TYPE" = "none" ]; then
            TEE_TYPE="intel-tdx-capable"
            TEE_DETAIL="Intel TDX mentioned in dmesg"
        fi
    fi
}

# --- Intel TME / MKTME detection ---
detect_intel_tme() {
    # TME (Total Memory Encryption) — always-on AES encryption of DRAM
    if [ -f /proc/cpuinfo ] && grep -q "tme" /proc/cpuinfo 2>/dev/null; then
        if [ "$TEE_TYPE" = "none" ]; then
            TEE_TYPE="intel-tme"
            MEM_ENCRYPT="true"
            TEE_DETAIL="Intel TME (Total Memory Encryption)"
        else
            MEM_ENCRYPT="true"
            TEE_DETAIL="${TEE_DETAIL} + Intel TME"
        fi
    fi

    # MKTME — Multi-Key TME (per-VM keys)
    if dmesg 2>/dev/null | grep -qi "MKTME"; then
        MEM_ENCRYPT="true"
        TEE_DETAIL="${TEE_DETAIL:+${TEE_DETAIL} + }Intel MKTME"
    fi
}

# --- ARM CCA detection ---
detect_arm_cca() {
    if [ "$(uname -m)" != "aarch64" ]; then
        return
    fi

    # Check for Realm Management Monitor
    if dmesg 2>/dev/null | grep -qi "RMM\|Realm Management"; then
        TEE_TYPE="arm-cca"
        TEE_ACTIVE="true"
        TEE_DETAIL="ARM CCA (Confidential Compute Architecture)"
        MEM_ENCRYPT="true"
    fi
}

# --- Main ---
log "=== Trusted Execution Environment Detection ==="

detect_amd_sev
detect_intel_tdx
detect_intel_tme
detect_arm_cca

# Write results
mkdir -p "$(dirname "$TEE_ENV")" 2>/dev/null || true
cat > "$TEE_ENV" <<EOF
TEE_TYPE=${TEE_TYPE}
TEE_ACTIVE=${TEE_ACTIVE}
TEE_DETAIL=${TEE_DETAIL}
MEM_ENCRYPT=${MEM_ENCRYPT}
EOF
chmod 644 "$TEE_ENV"

log "TEE type: ${TEE_TYPE}"
log "TEE active: ${TEE_ACTIVE}"
log "Memory encryption: ${MEM_ENCRYPT}"
if [ -n "$TEE_DETAIL" ]; then
    log "Detail: ${TEE_DETAIL}"
fi

if [ "$MEM_ENCRYPT" = "true" ]; then
    log "Hardware memory encryption is active — DRAM contents are protected."
else
    log "No hardware memory encryption detected."
    log "For maximum security, use hardware with AMD SEV/Intel TDX/TME support."
fi

log "=== TEE Detection Complete ==="
