#!/usr/bin/env bash
#
# Secure AI Appliance — Secure Boot MOK Enrollment
#
# Enrolls the SecAI Machine Owner Key (MOK) into the system's UEFI MOK
# database. After enrollment, only kernels/bootloaders signed with this
# key will be trusted.
#
# This script is called during firstboot. The user must reboot and
# confirm enrollment in the MOK Manager (MokManager.efi) screen.
#
# Usage: enroll-secureboot.sh [--check-only]
#
set -euo pipefail

MOK_DER="/etc/secure-ai/keys/secureai-mok.der"
MOK_PEM="/etc/secure-ai/keys/secureai-mok.pem"
STATE_FILE="/run/secure-ai/secureboot-state"

log() {
    echo "[enroll-secureboot] $*"
    logger -t enroll-secureboot "$*"
}

write_state() {
    mkdir -p "$(dirname "$STATE_FILE")" 2>/dev/null || true
    echo "{\"secure_boot\":\"$1\",\"mok_enrolled\":\"$2\",\"detail\":\"$3\"}" > "$STATE_FILE"
}

check_secure_boot() {
    # Check if Secure Boot is enabled
    if [ -d /sys/firmware/efi ]; then
        local sb_state
        sb_state=$(mokutil --sb-state 2>/dev/null || echo "unknown")
        case "$sb_state" in
            *enabled*|*Enabled*)
                echo "enabled"
                return 0
                ;;
            *disabled*|*Disabled*)
                echo "disabled"
                return 1
                ;;
        esac
    fi
    echo "unavailable"
    return 1
}

check_mok_enrolled() {
    # Check if our MOK is already enrolled
    if [ ! -f "$MOK_DER" ]; then
        return 1
    fi

    if command -v mokutil &>/dev/null; then
        # Get the fingerprint of our cert
        local our_fp
        our_fp=$(openssl x509 -in "$MOK_PEM" -noout -fingerprint -sha256 2>/dev/null | \
                 sed 's/.*=//;s/://g' | tr '[:upper:]' '[:lower:]')

        # Check enrolled keys
        if mokutil --list-enrolled 2>/dev/null | grep -qi "$our_fp"; then
            return 0
        fi
    fi
    return 1
}

cmd_check() {
    echo "=== Secure Boot Status ==="

    local sb_state
    sb_state=$(check_secure_boot)
    echo "UEFI Secure Boot: ${sb_state}"

    if [ "$sb_state" = "unavailable" ]; then
        echo "System does not support UEFI Secure Boot."
        echo "This may be a legacy BIOS system or a VM without UEFI."
        write_state "unavailable" "false" "no_uefi"
        return
    fi

    if [ "$sb_state" = "disabled" ]; then
        echo "Secure Boot is disabled in firmware."
        echo "Enable it in BIOS/UEFI settings for full boot chain verification."
        write_state "disabled" "false" "sb_disabled"
        return
    fi

    # Check MOK enrollment
    if [ ! -f "$MOK_DER" ]; then
        echo "SecAI MOK certificate not found at ${MOK_DER}"
        echo "Run generate-mok.sh during image build to create it."
        write_state "enabled" "false" "no_mok_cert"
        return
    fi

    if check_mok_enrolled; then
        echo "SecAI MOK: ENROLLED"
        write_state "enabled" "true" "fully_configured"
    else
        echo "SecAI MOK: NOT ENROLLED"
        echo "Run: enroll-secureboot.sh (without --check-only) to enroll."
        write_state "enabled" "false" "mok_not_enrolled"
    fi

    # Check if kernel is signed
    if command -v sbverify &>/dev/null; then
        local kernel
        kernel=$(ls /boot/vmlinuz-* 2>/dev/null | sort -V | tail -1 || echo "")
        if [ -n "$kernel" ]; then
            if sbverify --cert "$MOK_PEM" "$kernel" 2>/dev/null; then
                echo "Kernel signature: VALID"
            else
                echo "Kernel signature: NOT SIGNED or INVALID"
                echo "  The kernel may not be signed with the SecAI MOK."
            fi
        fi
    fi

    echo "=== End Secure Boot Status ==="
}

cmd_enroll() {
    log "Starting MOK enrollment..."

    if [ ! -f "$MOK_DER" ]; then
        log "ERROR: MOK certificate not found at ${MOK_DER}"
        log "Generate it first: /usr/libexec/secure-ai/generate-mok.sh"
        exit 1
    fi

    local sb_state
    sb_state=$(check_secure_boot)

    if [ "$sb_state" = "unavailable" ]; then
        log "WARNING: UEFI not available. MOK enrollment skipped."
        write_state "unavailable" "false" "no_uefi"
        exit 0
    fi

    if check_mok_enrolled; then
        log "SecAI MOK is already enrolled."
        write_state "$sb_state" "true" "already_enrolled"
        exit 0
    fi

    if ! command -v mokutil &>/dev/null; then
        log "ERROR: mokutil not found. Install it: dnf install mokutil"
        exit 1
    fi

    log "Importing MOK certificate..."
    log "You will be prompted for a one-time password."
    log "Remember this password — you'll need it on the next reboot"
    log "when the MOK Manager asks you to confirm enrollment."

    mokutil --import "$MOK_DER"

    log ""
    log "MOK import request registered."
    log "IMPORTANT: Reboot the system. At the MOK Manager screen:"
    log "  1. Select 'Enroll MOK'"
    log "  2. Select 'Continue'"
    log "  3. Enter the one-time password you just set"
    log "  4. Select 'Reboot'"
    log ""
    log "After reboot, the SecAI signing key will be trusted."

    write_state "$sb_state" "pending" "enrollment_pending_reboot"
}

# --- Main ---
case "${1:---check-only}" in
    --check-only|check|status) cmd_check ;;
    enroll|--enroll)           cmd_enroll ;;
    *)
        echo "Usage: $0 [--check-only | enroll]"
        exit 1
        ;;
esac
