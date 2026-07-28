#!/usr/bin/env bash
#
# SecAI OS — First-Boot Setup Wizard
#
# Interactive walkthrough that verifies system integrity, sets up the vault,
# and confirms the appliance is healthy after installation.
#
# Usage:
#   sudo /usr/libexec/secure-ai/secai-setup-wizard.sh [--vault-device /dev/...]
#
# This wizard runs once after the first rebase+reboot and guides the user
# through verification, vault setup, optional TPM2 sealing, and a health
# check. Results are written to a marker file so the wizard is not
# accidentally re-run on subsequent boots.
#
set -euo pipefail
umask 077

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SECURE_AI_ROOT="/var/lib/secure-ai"
COSIGN_PUB="/etc/pki/containers/secai-cosign.pub"
WIZARD_MARKER="${SECURE_AI_ROOT}/.wizard-complete"
REGISTRY="ghcr.io/secai-hub/secai_os"
HEALTH_CHECK="/usr/libexec/secure-ai/first-boot-check.sh"
SETUP_VAULT="/usr/libexec/secure-ai/setup-vault.sh"
VAULT_VERIFY="/usr/libexec/secure-ai/verify-vault-mount.py"
TPM2_SEAL="/usr/libexec/secure-ai/tpm2-seal-vault.sh"
BOOT_VERIFY="/var/lib/secure-ai/logs/boot-verify-last.json"
BOOT_VERIFY_SCRIPT="/usr/libexec/secure-ai/verify-boot-chain.sh"
VAULT_MOUNT="${SECURE_AI_ROOT}/vault"
VAULT_DEVICE=""

ERRORS=0
WARNINGS=0
REBOOT_REQUIRED=false

while [ "$#" -gt 0 ]; do
    case "$1" in
        --vault-device)
            [ "$#" -ge 2 ] || { echo "ERROR: --vault-device requires a path" >&2; exit 2; }
            VAULT_DEVICE="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--vault-device /dev/<partition>]"
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    DIM='\033[2m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' BOLD='' DIM='' NC=''
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
pass()    { echo -e "  ${GREEN}PASS${NC}  $*"; }
fail()    { echo -e "  ${RED}FAIL${NC}  $*"; ERRORS=$((ERRORS + 1)); }
warn_msg() { echo -e "  ${YELLOW}WARN${NC}  $*"; WARNINGS=$((WARNINGS + 1)); }
info()    { echo -e "  ${DIM}INFO${NC}  $*"; }
step()    { echo -e "\n${BOLD}${CYAN}[$1/7] $2${NC}"; echo -e "${DIM}$(printf '%.0s─' {1..60})${NC}"; }

ask_yes_no() {
    local prompt="$1"
    local default="${2:-n}"
    local reply
    while true; do
        if [ "$default" = "y" ]; then
            echo -en "  ${prompt} [Y/n] "
        else
            echo -en "  ${prompt} [y/N] "
        fi
        read -r reply
        reply="${reply:-$default}"
        case "$reply" in
            [Yy]*) return 0 ;;
            [Nn]*) return 1 ;;
            *) echo "  Please answer y or n." ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Preamble
# ---------------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || { echo "This wizard must be run as root (sudo)."; exit 1; }

if [ -f "$WIZARD_MARKER" ]; then
    echo -e "${YELLOW}The setup wizard has already been completed.${NC}"
    echo -e "Marker: ${WIZARD_MARKER}"
    if ask_yes_no "Run it again anyway?" "n"; then
        echo ""
    else
        exit 0
    fi
fi

echo ""
echo -e "${BOLD}${CYAN}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║         SecAI OS — First-Boot Setup Wizard        ║${NC}"
echo -e "${BOLD}${CYAN}╚════════════════════════════════════════════════════╝${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# Step 1: Welcome & System Identity
# ═══════════════════════════════════════════════════════════════════════════
step "1" "System Identity"

# OS version
OS_VERSION=$(cat /etc/secai-version 2>/dev/null || echo "unknown")
info "SecAI OS version: ${OS_VERSION}"

# Current deployment
DEPLOY_INFO=$(rpm-ostree status --json 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
booted = [item for item in data.get('deployments', []) if item.get('booted') is True]
if len(booted) != 1:
    raise SystemExit('expected exactly one booted deployment')
dep = booted[0]
origin = dep.get('container-image-reference', dep.get('origin', 'unknown'))
version = dep.get('version', 'unknown')
checksum = dep.get('checksum', 'unknown')[:12]
print(f'{origin}')
print(f'{version}')
print(f'{checksum}')
" 2>/dev/null || echo -e "unknown\nunknown\nunknown")

DEPLOY_ORIGIN=$(echo "$DEPLOY_INFO" | sed -n '1p')
DEPLOY_VERSION=$(echo "$DEPLOY_INFO" | sed -n '2p')
DEPLOY_CHECKSUM=$(echo "$DEPLOY_INFO" | sed -n '3p')
DEPLOY_IMAGE_REF="$DEPLOY_ORIGIN"
for prefix in \
    "ostree-image-signed:docker://" \
    "ostree-unverified-registry:" \
    "ostree-unverified-image:docker://" \
    "docker://"; do
    if [[ "$DEPLOY_IMAGE_REF" == "$prefix"* ]]; then
        DEPLOY_IMAGE_REF="${DEPLOY_IMAGE_REF#"$prefix"}"
        break
    fi
done
DEPLOY_REF_APPROVED=false
if [[ "$DEPLOY_IMAGE_REF" =~ ^${REGISTRY//./\\.}(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[0-9a-f]{64}$ ]]; then
    DEPLOY_REF_APPROVED=true
fi

info "Deployment origin: ${DEPLOY_ORIGIN}"
info "Deployment version: ${DEPLOY_VERSION}"
info "Deployment checksum: ${DEPLOY_CHECKSUM}"

# Detect signed vs unsigned transport
if echo "$DEPLOY_ORIGIN" | grep -q "ostree-image-signed"; then
    pass "Transport: signed (ostree-image-signed)"
elif echo "$DEPLOY_ORIGIN" | grep -q "ostree-unverified"; then
    warn_msg "Transport: UNVERIFIED (ostree-unverified-registry)"
    warn_msg "This system was installed via the recovery path."
else
    info "Transport: ${DEPLOY_ORIGIN}"
fi

# Secure Boot and TPM2 summary from boot-verify
if [ -f "$BOOT_VERIFY" ]; then
    BOOT_STATES=$(python3 - "$BOOT_VERIFY" <<'PY' 2>/dev/null || printf 'unknown\nunknown\nunknown\n'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
checks = data.get("checks", {})
print(checks.get("secure_boot", {}).get("state", "unknown"))
print(checks.get("tpm2", {}).get("state", "unknown"))
print(checks.get("ostree_signature", {}).get("state", "unknown"))
PY
)
    SECURE_BOOT=$(printf '%s\n' "$BOOT_STATES" | sed -n '1p')
    TPM2_STATUS=$(printf '%s\n' "$BOOT_STATES" | sed -n '2p')
    OSTREE_STATUS=$(printf '%s\n' "$BOOT_STATES" | sed -n '3p')

    if [ "$SECURE_BOOT" = "enabled" ]; then
        pass "Secure Boot: enabled"
    elif [ "$SECURE_BOOT" = "disabled" ]; then
        warn_msg "Secure Boot: disabled (recommended for production)"
    else
        info "Secure Boot: ${SECURE_BOOT}"
    fi

    if [ "$TPM2_STATUS" = "available" ]; then
        pass "TPM2: available"
    elif [ "$TPM2_STATUS" = "error" ]; then
        warn_msg "TPM2: not available"
    else
        info "TPM2: ${TPM2_STATUS}"
    fi
else
    info "Boot verification log not found (verify-boot-chain.sh may not have run yet)"
fi

# ═══════════════════════════════════════════════════════════════════════════
# Step 2: Image Integrity Verification
# ═══════════════════════════════════════════════════════════════════════════
step "2" "Image Integrity Verification"

if [ "$DEPLOY_REF_APPROVED" != true ]; then
    fail "Booted image is not bound to an approved ${REGISTRY}@sha256 digest"
    info "Reinstall/rebase with secai-bootstrap.sh --tag <release-channel> --digest sha256:<release-digest>."
elif [ ! -f "$COSIGN_PUB" ] || [ -L "$COSIGN_PUB" ]; then
    fail "Cosign public key is missing or unsafe at ${COSIGN_PUB}"
elif [ "${OSTREE_STATUS:-unknown}" = "valid_offline" ] || \
     [ "${OSTREE_STATUS:-unknown}" = "valid" ]; then
    pass "Image signature policy: verified offline for ${DEPLOY_IMAGE_REF}"
    info "The signed rpm-ostree transport, exact digest, signing policy, and release baseline agree."
else
    info "Boot evidence is unavailable; attempting an exact-digest online check."
    if command -v cosign >/dev/null 2>&1 && \
       cosign verify --key "$COSIGN_PUB" "$DEPLOY_IMAGE_REF" >/dev/null 2>&1; then
        pass "Image signature: verified for exact digest ${DEPLOY_IMAGE_REF}"
    else
        fail "Image signature could not be verified for the exact booted digest"
        info "Run ${BOOT_VERIFY_SCRIPT} and correct its reported signing-policy error."
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# Step 3: Signing Transport Check
# ═══════════════════════════════════════════════════════════════════════════
step "3" "Signing Transport Verification"

if echo "$DEPLOY_ORIGIN" | grep -q "ostree-image-signed" && \
   [ "$DEPLOY_REF_APPROVED" = true ]; then
    pass "System is on signed transport — all future updates will be verified"
elif echo "$DEPLOY_ORIGIN" | grep -q "ostree-unverified"; then
    warn_msg "System is on UNVERIFIED transport"
    echo ""
    echo -e "  ${BOLD}The system should be switched to the signed transport.${NC}"
    echo -e "  Future updates must use update-verify.sh check/stage/apply so the"
    echo -e "  candidate signature, exact digest, and anti-rollback state are enforced."
    echo ""
    if [ "$DEPLOY_REF_APPROVED" != true ]; then
        fail "Cannot safely switch a mutable or foreign deployment to signed transport"
        info "Use secai-bootstrap.sh --tag <release-channel> --digest sha256:<release-digest>."
    elif ask_yes_no "Re-import this exact digest through signed transport now?" "y"; then
        echo ""
        info "Verifying and switching the exact booted digest..."
        if cosign verify --key "$COSIGN_PUB" "$DEPLOY_IMAGE_REF" >/dev/null 2>&1 && \
           rpm-ostree rebase "ostree-image-signed:docker://${DEPLOY_IMAGE_REF}" 2>&1; then
            pass "Switched to signed transport (takes effect after reboot)"
            REBOOT_REQUIRED=true
        else
            fail "Failed to switch to signed transport"
            info "No mutable fallback was attempted. Check network/key/policy and rerun."
        fi
    else
        warn_msg "Skipped — system remains on unverified transport"
        info "Rerun this wizard to switch the same exact digest later."
    fi
else
    info "Transport: ${DEPLOY_ORIGIN} (not a standard rebase)"
fi

# ═══════════════════════════════════════════════════════════════════════════
# Step 4: Vault Setup
# ═══════════════════════════════════════════════════════════════════════════
step "4" "Encrypted Vault"

VAULT_READY=false
if [ -x "$VAULT_VERIFY" ] && "$VAULT_VERIFY" >/dev/null 2>&1; then
    VAULT_READY=true
    pass "Vault: exact LUKS mount and DAC contract verified at ${VAULT_MOUNT}"
else
    warn_msg "Vault is not exactly verified; a pre-created directory or mapper alone is insufficient"
    echo ""
    if [ -x "$SETUP_VAULT" ]; then
        echo -e "  ${BOLD}The encrypted vault stores models, outputs, and secrets.${NC}"
        echo -e "  You will be prompted to choose a passphrase. Store it securely —"
        echo -e "  there is no recovery mechanism."
        echo ""
        if ask_yes_no "Set up the encrypted vault now?" "y"; then
            echo ""
            if [ -z "$VAULT_DEVICE" ]; then
                lsblk -o NAME,PATH,SIZE,TYPE,FSTYPE,MOUNTPOINTS
                echo ""
                read -r -p "  Exact unused partition to ERASE (for example /dev/nvme1n1p1): " VAULT_DEVICE
            fi
            RESOLVED_VAULT_DEVICE=$(readlink -f -- "$VAULT_DEVICE" 2>/dev/null || true)
            if [[ "$RESOLVED_VAULT_DEVICE" != /dev/* ]] || \
               [ ! -b "$RESOLVED_VAULT_DEVICE" ]; then
                fail "Vault target is not a valid block device: ${VAULT_DEVICE}"
            elif lsblk -nrpo NAME,MOUNTPOINTS "$RESOLVED_VAULT_DEVICE" | \
                 grep -Eq '[[:space:]]+/'; then
                fail "Vault target or one of its children is mounted; refusing destructive setup"
            elif "$SETUP_VAULT" "$RESOLVED_VAULT_DEVICE"; then
                if [ -x "$VAULT_VERIFY" ] && \
                   "$VAULT_VERIFY" >/dev/null 2>&1; then
                    VAULT_READY=true
                    pass "Vault setup completed and the exact encrypted mount contract passed"
                else
                    fail "Vault setup returned success but exact mount verification failed"
                fi
            else
                fail "Vault setup failed"
                info "Retry with: sudo ${SETUP_VAULT} /dev/<unused-partition>"
            fi
        else
            warn_msg "Skipped vault setup — models cannot be stored until vault is ready"
        fi
    else
        info "Vault setup script not found at ${SETUP_VAULT}"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# Step 5: TPM2 Sealing (optional)
# ═══════════════════════════════════════════════════════════════════════════
step "5" "TPM2 Key Sealing (optional)"

TPM2_AVAILABLE=false
if [ -c /dev/tpmrm0 ] || [ -c /dev/tpm0 ]; then
    TPM2_AVAILABLE=true
fi

if [ "$TPM2_AVAILABLE" = true ] && [ "$VAULT_READY" = true ]; then
    SEALED_KEY="/var/lib/secure-ai/keys/tpm2/vault-key.sealed"
    if [ -f "$SEALED_KEY" ]; then
        pass "Vault key: sealed to TPM2 PCRs"
        info "Auto-unlock will work as long as the boot chain is unchanged"
    else
        info "TPM2 is available but vault key is not sealed"
        echo ""
        echo -e "  ${BOLD}TPM2 sealing enables auto-unlock of the vault on trusted boots.${NC}"
        echo -e "  If the boot chain is tampered with (firmware, bootloader, kernel),"
        echo -e "  the TPM will refuse to release the key and you'll need the passphrase."
        echo ""
        if [ -x "$TPM2_SEAL" ]; then
            if ask_yes_no "Seal vault key to TPM2 now?" "n"; then
                echo ""
                echo "  You will be prompted for your vault passphrase."
                $TPM2_SEAL seal || {
                    fail "TPM2 sealing failed"
                    info "Try manually: sudo ${TPM2_SEAL} seal"
                }
            else
                info "Skipped — seal later: sudo ${TPM2_SEAL} seal"
            fi
        else
            info "TPM2 sealing script not found at ${TPM2_SEAL}"
        fi
    fi
elif [ "$TPM2_AVAILABLE" = true ]; then
    warn_msg "TPM2 is available, but key sealing is blocked until the vault is mounted"
else
    info "TPM2: not available (virtual machine or no TPM hardware)"
    info "Vault will require passphrase on every boot"
fi

# ═══════════════════════════════════════════════════════════════════════════
# Step 6: Health Check
# ═══════════════════════════════════════════════════════════════════════════
step "6" "System Health Check"

if [ -x "$HEALTH_CHECK" ]; then
    echo ""
    if $HEALTH_CHECK; then
        pass "All health checks passed"
    else
        fail "Health check reported errors"
        info "Review output above for details"
    fi
else
    warn_msg "Health check script not found at ${HEALTH_CHECK}"
    info "Check services manually: systemctl status 'secure-ai-*'"
fi

# ═══════════════════════════════════════════════════════════════════════════
# Step 7: Summary
# ═══════════════════════════════════════════════════════════════════════════
step "7" "Summary"

echo ""
echo -e "${BOLD}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║              Security Posture Summary              ║${NC}"
echo -e "${BOLD}╠════════════════════════════════════════════════════╣${NC}"

# Collect summary items
SUMMARY_ITEMS=()

# Transport
if echo "$DEPLOY_ORIGIN" | grep -q "ostree-image-signed"; then
    SUMMARY_ITEMS+=("${GREEN}PASS${NC}  Signed transport active")
else
    SUMMARY_ITEMS+=("${YELLOW}WARN${NC}  Unsigned transport — switch recommended")
fi

# Vault
if [ "$VAULT_READY" = true ]; then
    SUMMARY_ITEMS+=("${GREEN}PASS${NC}  Encrypted vault initialized")
else
    SUMMARY_ITEMS+=("${RED}FAIL${NC}  Encrypted vault is not active at ${VAULT_MOUNT}")
    ERRORS=$((ERRORS + 1))
fi

# TPM2
if [ -f "/var/lib/secure-ai/keys/tpm2/vault-key.sealed" ] 2>/dev/null; then
    SUMMARY_ITEMS+=("${GREEN}PASS${NC}  TPM2 key sealing active")
elif [ "$TPM2_AVAILABLE" = true ]; then
    SUMMARY_ITEMS+=("${YELLOW}WARN${NC}  TPM2 available but key not sealed")
else
    SUMMARY_ITEMS+=("${DIM}INFO${NC}  TPM2 not available")
fi

# Cosign key
if [ -f "$COSIGN_PUB" ]; then
    SUMMARY_ITEMS+=("${GREEN}PASS${NC}  Signing key installed")
else
    SUMMARY_ITEMS+=("${RED}FAIL${NC}  Signing key missing")
fi

for item in "${SUMMARY_ITEMS[@]}"; do
    echo -e "${BOLD}║${NC}  ${item}"
done

echo -e "${BOLD}╠════════════════════════════════════════════════════╣${NC}"

if [ "$ERRORS" -eq 0 ] && [ "$WARNINGS" -eq 0 ]; then
    echo -e "${BOLD}║${NC}  ${GREEN}${BOLD}All checks passed.${NC}"
elif [ "$ERRORS" -eq 0 ]; then
    echo -e "${BOLD}║${NC}  ${YELLOW}${BOLD}${WARNINGS} warning(s), 0 errors.${NC}"
else
    echo -e "${BOLD}║${NC}  ${RED}${BOLD}${ERRORS} error(s), ${WARNINGS} warning(s).${NC}"
fi

echo -e "${BOLD}╚════════════════════════════════════════════════════╝${NC}"

echo ""
echo -e "${BOLD}Next steps:${NC}"
echo "  - Open the UI:         http://localhost:8480"
echo "  - Import a model:      Models tab → Download"
echo "  - Check service logs:  journalctl -u 'secure-ai-*' --since '5 min ago'"
echo "  - Production ops:      /usr/share/doc/secure-ai/production-operations.md"
echo ""

if [ "$ERRORS" -gt 0 ]; then
    echo -e "${RED}Setup is incomplete; no completion marker was written.${NC}"
    exit 1
fi
if [ "$REBOOT_REQUIRED" = true ]; then
    echo -e "${YELLOW}Reboot into the signed deployment, then rerun this wizard.${NC}"
    echo "No completion marker was written yet."
    exit 2
fi

# Mark completion only after every required step succeeds. The marker is
# replaced atomically so an interrupted/failed run cannot look complete.
mkdir -p "$(dirname "$WIZARD_MARKER")"
MARKER_TMP="${WIZARD_MARKER}.tmp.$$"
python3 - "$MARKER_TMP" "$DEPLOY_IMAGE_REF" <<'PY'
import datetime as dt
import json
import os
import sys

payload = {
    "completed_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "image_ref": sys.argv[2],
    "status": "complete",
}
with open(sys.argv[1], "x", encoding="utf-8") as handle:
    json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
os.chmod(sys.argv[1], 0o400)
PY
mv -f -- "$MARKER_TMP" "$WIZARD_MARKER"
exit 0
