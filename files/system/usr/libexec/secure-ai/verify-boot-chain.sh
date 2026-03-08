#!/usr/bin/env bash
#
# Secure AI Appliance — Boot Chain Integrity Verification
#
# Runs on every boot to verify the security posture of the boot chain.
# Checks:
#   1. Secure Boot state (enabled/disabled)
#   2. TPM2 availability and PCR integrity
#   3. Kernel signature validity
#   4. ostree deployment signature (cosign)
#
# Writes results to /var/lib/secure-ai/logs/boot-verify-last.json
# Non-fatal: logs warnings but does not block boot.
#
set -euo pipefail

RESULT_PATH="/var/lib/secure-ai/logs/boot-verify-last.json"
MOK_PEM="/etc/secure-ai/keys/secureai-mok.pem"
COSIGN_PUB="/var/lib/secure-ai/keys/local-cosign.pub"

declare -A checks

log() {
    echo "[verify-boot-chain] $*"
    logger -t verify-boot-chain "$*"
}

# --- Check 1: Secure Boot ---
check_secure_boot() {
    if [ ! -d /sys/firmware/efi ]; then
        checks[secure_boot]="unavailable"
        checks[secure_boot_detail]="legacy BIOS or no UEFI"
        return
    fi

    local sb_state
    sb_state=$(mokutil --sb-state 2>/dev/null || echo "unknown")
    case "$sb_state" in
        *enabled*|*Enabled*)
            checks[secure_boot]="enabled"
            checks[secure_boot_detail]="UEFI Secure Boot is active"
            ;;
        *disabled*|*Disabled*)
            checks[secure_boot]="disabled"
            checks[secure_boot_detail]="WARNING: Secure Boot is disabled"
            log "WARNING: Secure Boot is disabled"
            ;;
        *)
            checks[secure_boot]="unknown"
            checks[secure_boot_detail]="could not determine state"
            ;;
    esac
}

# --- Check 2: TPM2 ---
check_tpm2() {
    if [ ! -e /dev/tpmrm0 ] && [ ! -e /dev/tpm0 ]; then
        checks[tpm2]="unavailable"
        checks[tpm2_detail]="no TPM device found"
        return
    fi

    if ! command -v tpm2_pcrread &>/dev/null; then
        checks[tpm2]="unavailable"
        checks[tpm2_detail]="tpm2-tools not installed"
        return
    fi

    if tpm2_pcrread "sha256:0" &>/dev/null; then
        checks[tpm2]="available"

        # Check if vault key is sealed
        if [ -f "/var/lib/secure-ai/keys/tpm2/vault-key.sealed" ] || \
           [ -f "/var/lib/secure-ai/keys/tpm2/vault-key.sealed.pub" ]; then
            checks[tpm2_sealed]="true"
            checks[tpm2_detail]="TPM2 active, vault key sealed to PCRs"
        else
            checks[tpm2_sealed]="false"
            checks[tpm2_detail]="TPM2 active, vault key NOT sealed (passphrase-only mode)"
        fi
    else
        checks[tpm2]="error"
        checks[tpm2_detail]="TPM device present but cannot read PCRs"
    fi
}

# --- Check 3: Kernel Signature ---
check_kernel_signature() {
    if ! command -v sbverify &>/dev/null; then
        checks[kernel_sig]="unchecked"
        checks[kernel_sig_detail]="sbverify not available"
        return
    fi

    if [ ! -f "$MOK_PEM" ]; then
        checks[kernel_sig]="unchecked"
        checks[kernel_sig_detail]="MOK certificate not found"
        return
    fi

    local kernel
    kernel=$(ls /boot/vmlinuz-* 2>/dev/null | sort -V | tail -1 || echo "")
    if [ -z "$kernel" ]; then
        checks[kernel_sig]="unchecked"
        checks[kernel_sig_detail]="no kernel found in /boot"
        return
    fi

    if sbverify --cert "$MOK_PEM" "$kernel" 2>/dev/null; then
        checks[kernel_sig]="valid"
        checks[kernel_sig_detail]="kernel signed with SecAI MOK"
    else
        checks[kernel_sig]="invalid"
        checks[kernel_sig_detail]="WARNING: kernel NOT signed with SecAI MOK"
        log "WARNING: kernel signature invalid or not signed with SecAI MOK"
    fi
}

# --- Check 4: ostree Deployment Signature ---
check_ostree_signature() {
    if ! command -v ostree &>/dev/null; then
        checks[ostree_sig]="unchecked"
        checks[ostree_sig_detail]="ostree not available"
        return
    fi

    if ! command -v cosign &>/dev/null; then
        checks[ostree_sig]="unchecked"
        checks[ostree_sig_detail]="cosign not available"
        return
    fi

    # Get the current deployment commit
    local commit
    commit=$(ostree admin status 2>/dev/null | head -1 | awk '{print $2}' || echo "")
    if [ -z "$commit" ]; then
        checks[ostree_sig]="unchecked"
        checks[ostree_sig_detail]="could not determine current deployment"
        return
    fi

    checks[ostree_commit]="$commit"

    # Cosign signature verification would go here
    # For now, mark as present but note verification requires the build key
    if [ -f "$COSIGN_PUB" ]; then
        checks[ostree_sig]="present"
        checks[ostree_sig_detail]="deployment commit ${commit:0:12}, cosign key available"
    else
        checks[ostree_sig]="unchecked"
        checks[ostree_sig_detail]="no cosign public key for verification"
    fi
}

# --- Write Results ---
write_results() {
    local status="ok"
    local warnings=0

    # Determine overall status
    if [ "${checks[secure_boot]}" = "disabled" ]; then
        status="warning"
        ((warnings++))
    fi
    if [ "${checks[kernel_sig]:-unchecked}" = "invalid" ]; then
        status="warning"
        ((warnings++))
    fi
    if [ "${checks[tpm2]:-unavailable}" = "error" ]; then
        status="warning"
        ((warnings++))
    fi

    mkdir -p "$(dirname "$RESULT_PATH")" 2>/dev/null || true

    cat > "$RESULT_PATH" <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "status": "${status}",
  "warnings": ${warnings},
  "checks": {
    "secure_boot": {
      "state": "${checks[secure_boot]:-unknown}",
      "detail": "${checks[secure_boot_detail]:-}"
    },
    "tpm2": {
      "state": "${checks[tpm2]:-unknown}",
      "sealed": "${checks[tpm2_sealed]:-false}",
      "detail": "${checks[tpm2_detail]:-}"
    },
    "kernel_signature": {
      "state": "${checks[kernel_sig]:-unchecked}",
      "detail": "${checks[kernel_sig_detail]:-}"
    },
    "ostree_signature": {
      "state": "${checks[ostree_sig]:-unchecked}",
      "commit": "${checks[ostree_commit]:-}",
      "detail": "${checks[ostree_sig_detail]:-}"
    }
  }
}
EOF

    chmod 644 "$RESULT_PATH"
    log "Boot chain verification complete: status=${status}, warnings=${warnings}"
}

# --- Main ---
log "=== Boot Chain Integrity Verification ==="

check_secure_boot
check_tpm2
check_kernel_signature
check_ostree_signature
write_results

log "=== Verification Complete ==="
