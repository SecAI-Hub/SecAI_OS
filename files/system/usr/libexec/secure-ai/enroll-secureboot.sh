#!/usr/bin/env bash
#
# Secure AI Appliance — Secure Boot MOK Enrollment
#
# Enrolls a reviewed module-signing certificate into the system's UEFI MOK
# database. Enrollment adds this certificate to shim's trust list; existing
# platform trust anchors remain in place.
#
# Firstboot calls the status path. Explicit enrollment requires a reboot and
# confirmation in the MOK Manager (MokManager.efi) screen.
#
# Usage: enroll-secureboot.sh [--check-only | --enroll]
#        [--certificate /path/to/reviewed.der --sha256 <release-certificate-sha256>]
#
set -euo pipefail

MOK_DER="/etc/secure-ai/keys/secureai-mok.der"
STATE_FILE="/run/secure-ai/secureboot-state"
CERT_STAGE_DIR=""

stage_reviewed_certificate() {
    # Copy the exact pinned public certificate into a private directory before
    # mokutil reopens it. Source replacement cannot substitute another key.
    python3 - "$1" "$2" <<'PY'
import hashlib, os, re, stat, subprocess, sys, tempfile
from pathlib import Path

if os.geteuid() != 0 or not re.fullmatch(r"[0-9a-f]{64}", sys.argv[2]):
    raise SystemExit("root and a canonical release certificate SHA256 are required")
descriptor = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try:
    before = os.fstat(descriptor)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
            or before.st_mode & 0o022 or not 0 < before.st_size <= 131072):
        raise SystemExit("certificate must be a protected root-owned regular file")
    with os.fdopen(descriptor, "rb", closefd=False) as handle:
        data = handle.read(131073)
    after = os.fstat(descriptor)
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    if (identity(before) != identity(after) or len(data) != before.st_size
            or hashlib.sha256(data).hexdigest() != sys.argv[2]):
        raise SystemExit("certificate identity or release SHA256 does not match")
finally:
    os.close(descriptor)
result = subprocess.run(["openssl", "x509", "-inform", "DER", "-outform", "DER"],
                        input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                        timeout=5, check=False)
if result.returncode != 0 or result.stdout != data:
    raise SystemExit("selected file must contain exactly one canonical DER X.509 certificate")
temporary_root = Path("/tmp").lstat()
if (not stat.S_ISDIR(temporary_root.st_mode) or temporary_root.st_uid != 0
        or (temporary_root.st_mode & 0o022 and not temporary_root.st_mode & stat.S_ISVTX)):
    raise SystemExit("protected temporary directory is unavailable")
directory = Path(tempfile.mkdtemp(prefix="secai-mok-", dir="/tmp"))
target = directory / "certificate.der"
try:
    with target.open("xb") as handle:
        os.fchmod(handle.fileno(), 0o400)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
except BaseException:
    if target.exists():
        target.unlink()
    directory.rmdir()
    raise
print(target)
PY
}

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
        echo "Use the reviewed certificate and SHA256 supplied by the release."
        echo "A new generated key does not sign the prebuilt GPU modules."
        write_state "enabled" "false" "no_mok_cert"
        return
    fi

    if check_mok_enrolled; then
        echo "Selected MOK certificate: ENROLLED"
        write_state "enabled" "true" "certificate_enrolled"
    else
        echo "Selected MOK certificate: NOT ENROLLED"
        echo "Run this utility with --enroll and the same certificate/SHA256 options."
        write_state "enabled" "false" "mok_not_enrolled"
    fi

    echo "Verify the running boot chain separately with verify-boot-chain.sh."
    echo "Module-key enrollment does not prove the kernel or GPU driver loaded."

    echo "=== End Secure Boot Status ==="
}

cmd_enroll() {
    log "Starting MOK enrollment..."

    if [ ! -f "$MOK_DER" ] || [ -L "$MOK_DER" ]; then
        log "ERROR: MOK certificate not found at ${MOK_DER}"
        log "Use --certificate and --sha256 with the release's reviewed module-signing certificate."
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
        log "Selected MOK certificate is already enrolled."
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
    log "After firmware confirmation and reboot, recheck this exact certificate's enrollment."

    write_state "$sb_state" "pending" "enrollment_pending_reboot"
}

# --- Main ---
action=--check-only
action_set=false
certificate=""
certificate_sha256=""
usage() {
    echo "Usage: $0 [--check-only | --enroll] [--certificate /path/to/reviewed.der --sha256 <release-certificate-sha256>]"
}
while [ "$#" -gt 0 ]; do
    case "$1" in
        --check-only|check|status|enroll|--enroll)
            [ "$action_set" = false ] || { usage >&2; exit 2; }
            action="$1"; action_set=true; shift ;;
        --certificate)
            [ "$#" -ge 2 ] && [[ "$2" == /* ]] && [ -z "$certificate" ] || { usage >&2; exit 2; }
            certificate="$2"; shift 2 ;;
        --sha256)
            [ "$#" -ge 2 ] && [[ "$2" =~ ^[0-9a-f]{64}$ ]] && [ -z "$certificate_sha256" ] || { usage >&2; exit 2; }
            certificate_sha256="$2"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
if [ -n "$certificate" ] || [ -n "$certificate_sha256" ]; then
    [ -n "$certificate" ] && [ -n "$certificate_sha256" ] || { usage >&2; exit 2; }
    MOK_DER=$(stage_reviewed_certificate "$certificate" "$certificate_sha256") || exit 1
    CERT_STAGE_DIR=$(dirname -- "$MOK_DER")
    trap 'rm -f -- "$CERT_STAGE_DIR/certificate.der"; rmdir -- "$CERT_STAGE_DIR"' EXIT
fi
case "$action" in
    --check-only|check|status) cmd_check ;;
    enroll|--enroll) cmd_enroll ;;
esac
