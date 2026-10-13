#!/usr/bin/env bash
#
# Secure AI Appliance — Secure Boot MOK Enrollment
#
# Enrolls the SecAI Machine Owner Key (MOK) into the system's UEFI MOK
# database. Enrollment adds this certificate to shim's trust list; existing
# platform trust anchors remain in place.
#
# This script is called during firstboot. The user must reboot and
# confirm enrollment in the MOK Manager (MokManager.efi) screen.
#
# Usage: enroll-secureboot.sh [--check-only | --enroll]
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
        if sb_state=$(mokutil --sb-state 2>/dev/null); then
            if grep -Fxq 'SecureBoot validation is disabled in shim' <<< "$sb_state" ||
               grep -Fxq 'SecureBoot disabled' <<< "$sb_state"; then
                echo "disabled"
                return 1
            elif grep -Fxq 'SecureBoot enabled' <<< "$sb_state"; then
                echo "enabled"
                return 0
            fi
        fi
    fi
    echo "unavailable"
    return 1
}

check_mok_enrolled() {
    # Check if our MOK is already enrolled
    if [ ! -f "$MOK_DER" ] || [ -L "$MOK_DER" ]; then
        return 1
    fi

    if command -v mokutil &>/dev/null; then
        # Ask about the exact DER certificate that enrollment would import.
        # Text fingerprints can use a different digest or be empty on failure.
        local enrollment
        if enrollment=$(LC_ALL=C mokutil --test-key "$MOK_DER" 2>/dev/null); then
            # Exit 0 also covers a pending request or a certificate in db/dbx.
            # Only the exact MokListRT result establishes completed enrollment.
            [[ "$enrollment" == "$MOK_DER is already enrolled" ]] && return 0
        fi
    fi
    return 1
}

cmd_check() {
    echo "=== Secure Boot Status ==="

    local sb_state
    # Disabled/unavailable are expected status outcomes, not shell failures.
    sb_state=$(check_secure_boot) || :
    echo "UEFI Secure Boot: ${sb_state}"

    if [ "$sb_state" = "unavailable" ]; then
        echo "Secure Boot status could not be established."
        echo "Check UEFI support and whether mokutil can read firmware state."
        write_state "unavailable" "false" "sb_unavailable"
        return
    fi

    if [ "$sb_state" = "disabled" ]; then
        echo "Secure Boot validation is disabled."
        echo "Check both firmware Secure Boot and shim validation settings."
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
        echo "Run: sudo /usr/libexec/secure-ai/enroll-secureboot.sh --enroll"
        write_state "enabled" "false" "mok_not_enrolled"
    fi

    # Check if kernel is signed
    if command -v sbverify &>/dev/null; then
        local kernel
        # shellcheck disable=SC2012  # ls is fine here — vmlinuz filenames are predictable
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

    if [ ! -f "$MOK_DER" ] || [ -L "$MOK_DER" ]; then
        log "ERROR: MOK certificate not found at ${MOK_DER}"
        log "Generate it first: /usr/libexec/secure-ai/generate-mok.sh"
        exit 1
    fi

    local sb_state
    sb_state=$(check_secure_boot) || :

    if [ "$sb_state" = "unavailable" ]; then
        log "WARNING: Secure Boot status unavailable. MOK enrollment skipped."
        write_state "unavailable" "false" "sb_unavailable"
        exit 0
    fi

    if [ "$sb_state" = "disabled" ]; then
        log "WARNING: Enrolling a key does not enable firmware or shim validation."
        log "Recheck Secure Boot after enabling validation and completing enrollment."
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
