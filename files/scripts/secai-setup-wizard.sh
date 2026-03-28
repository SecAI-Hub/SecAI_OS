#!/usr/bin/env bash
#
# SecAI OS — First-Boot Setup Wizard
#
# Interactive walkthrough that verifies system integrity, sets up the vault,
# and confirms the appliance is healthy after installation.
#
# Usage:
#   sudo /usr/libexec/secure-ai/secai-setup-wizard.sh
#
# This wizard runs once after the first rebase+reboot and guides the user
# through verification, vault setup, optional TPM2 sealing, and a health
# check. Results are written to a marker file so the wizard is not
# accidentally re-run on subsequent boots.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SECURE_AI_ROOT="/var/lib/secure-ai"
COSIGN_PUB="/etc/pki/containers/secai-cosign.pub"
WIZARD_MARKER="${SECURE_AI_ROOT}/.wizard-complete"
REGISTRY="ghcr.io/secai-hub/secai_os"
HEALTH_CHECK="/usr/libexec/secure-ai/first-boot-check.sh"
SETUP_VAULT="/usr/libexec/secure-ai/setup-vault.sh"
TPM2_SEAL="/usr/libexec/secure-ai/tpm2-seal-vault.sh"
BOOT_VERIFY="/var/lib/secure-ai/logs/boot-verify-last.json"

ERRORS=0
WARNINGS=0

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
dep = data.get('deployments', [{}])[0]
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
    SECURE_BOOT=$(python3 -c "
import json
with open('${BOOT_VERIFY}') as f:
    data = json.load(f)
for c in data.get('checks', []):
    if c.get('name') == 'secure_boot':
        print(c.get('status', 'unknown'))
        break
else:
    print('unknown')
" 2>/dev/null || echo "unknown")

    TPM2_STATUS=$(python3 -c "
import json
with open('${BOOT_VERIFY}') as f:
    data = json.load(f)
for c in data.get('checks', []):
    if c.get('name') == 'tpm2':
        print(c.get('status', 'unknown'))
        break
else:
    print('unknown')
" 2>/dev/null || echo "unknown")

    if [ "$SECURE_BOOT" = "ok" ]; then
        pass "Secure Boot: enabled"
    elif [ "$SECURE_BOOT" = "warning" ]; then
        warn_msg "Secure Boot: disabled (recommended for production)"
    else
        info "Secure Boot: ${SECURE_BOOT}"
    fi

    if [ "$TPM2_STATUS" = "ok" ]; then
        pass "TPM2: available"
    elif [ "$TPM2_STATUS" = "warning" ]; then
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

if [ -f "$COSIGN_PUB" ]; then
    info "Using signing key: ${COSIGN_PUB}"

    # Determine what to verify — use the registry ref from the deployment
    VERIFY_REF="${REGISTRY}:latest"
    if echo "$DEPLOY_ORIGIN" | grep -q "${REGISTRY}"; then
        # Extract the actual ref (strip ostree transport prefix)
        VERIFY_REF=$(echo "$DEPLOY_ORIGIN" | sed 's|^ostree-image-signed:docker://||' | sed 's|^ostree-unverified-registry:||')
    fi

    if cosign verify --key "$COSIGN_PUB" "$VERIFY_REF" >/dev/null 2>&1; then
        pass "Image signature: verified (${VERIFY_REF})"
    else
        warn_msg "Image signature verification failed (offline or key mismatch)"
        info "This may be expected if the system is not connected to the network."
        info "Verify manually: cosign verify --key ${COSIGN_PUB} ${VERIFY_REF}"
    fi
else
    warn_msg "Cosign public key not found at ${COSIGN_PUB}"
    info "Image signature cannot be verified without the public key."
fi

# ═══════════════════════════════════════════════════════════════════════════
# Step 3: Signing Transport Check
# ═══════════════════════════════════════════════════════════════════════════
step "3" "Signing Transport Verification"

if echo "$DEPLOY_ORIGIN" | grep -q "ostree-image-signed"; then
    pass "System is on signed transport — all future updates will be verified"
elif echo "$DEPLOY_ORIGIN" | grep -q "ostree-unverified"; then
    warn_msg "System is on UNVERIFIED transport"
    echo ""
    echo -e "  ${BOLD}The system should be switched to the signed transport.${NC}"
    echo -e "  This ensures all future rpm-ostree upgrades are cryptographically"
    echo -e "  verified before they are applied."
    echo ""
    if ask_yes_no "Switch to signed transport now?" "y"; then
        echo ""
        info "Switching to signed transport..."
        if rpm-ostree rebase "ostree-image-signed:docker://${REGISTRY}:latest" 2>&1; then
            pass "Switched to signed transport (takes effect after reboot)"
        else
            fail "Failed to switch to signed transport"
            info "Try manually: sudo rpm-ostree rebase ostree-image-signed:docker://${REGISTRY}:latest"
        fi
    else
        warn_msg "Skipped — system remains on unverified transport"
        info "Switch later: sudo rpm-ostree rebase ostree-image-signed:docker://${REGISTRY}:latest"
    fi
else
    info "Transport: ${DEPLOY_ORIGIN} (not a standard rebase)"
fi

# ═══════════════════════════════════════════════════════════════════════════
# Step 4: Vault Setup
# ═══════════════════════════════════════════════════════════════════════════
step "4" "Encrypted Vault"

if [ -d "${SECURE_AI_ROOT}/vault" ]; then
    # Check if LUKS device is active
    if cryptsetup status secure-ai-vault >/dev/null 2>&1; then
        pass "Vault: active (LUKS encrypted)"
        LUKS_INFO=$(cryptsetup luksDump /dev/mapper/secure-ai-vault 2>/dev/null | head -5 || true)
        if [ -n "$LUKS_INFO" ]; then
            info "Encryption: LUKS2 / AES-256-XTS"
        fi
    elif [ -f "${SECURE_AI_ROOT}/.initialized" ]; then
        pass "Vault directory exists (initialized)"
        info "LUKS device may not be mapped yet — check after reboot"
    else
        warn_msg "Vault directory exists but system not initialized"
    fi
else
    warn_msg "Vault not set up yet"
    echo ""
    if [ -x "$SETUP_VAULT" ]; then
        echo -e "  ${BOLD}The encrypted vault stores models, outputs, and secrets.${NC}"
        echo -e "  You will be prompted to choose a passphrase. Store it securely —"
        echo -e "  there is no recovery mechanism."
        echo ""
        if ask_yes_no "Set up the encrypted vault now?" "y"; then
            echo ""
            $SETUP_VAULT || {
                fail "Vault setup failed"
                info "Try manually: sudo ${SETUP_VAULT}"
            }
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

if [ "$TPM2_AVAILABLE" = true ]; then
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
if [ -d "${SECURE_AI_ROOT}/vault" ]; then
    SUMMARY_ITEMS+=("${GREEN}PASS${NC}  Encrypted vault initialized")
else
    SUMMARY_ITEMS+=("${RED}FAIL${NC}  Vault not set up")
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

# Write marker
mkdir -p "$(dirname "$WIZARD_MARKER")" 2>/dev/null || true
date -Iseconds > "$WIZARD_MARKER"
chmod 444 "$WIZARD_MARKER"

echo ""
echo -e "${BOLD}Next steps:${NC}"
echo "  - Open the UI:         http://localhost:8480"
echo "  - Import a model:      Models tab → Download"
echo "  - Check service logs:  journalctl -u 'secure-ai-*' --since '5 min ago'"
echo "  - Production ops:      /usr/share/doc/secure-ai/production-operations.md"
echo ""

if [ "$ERRORS" -gt 0 ]; then
    exit 1
fi
exit 0
