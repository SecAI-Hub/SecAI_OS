#!/usr/bin/env bash
#
# SecAI OS — Signed Bootstrap Script
#
# Configures the container signing policy on a fresh Fedora Silverblue (F42+)
# so that the very first rpm-ostree rebase uses the SIGNED transport.
# This eliminates the need for an unverified pull entirely.
#
# Usage:
#   sudo bash secai-bootstrap.sh --digest sha256:abc123...   # Production (pinned)
#   sudo bash secai-bootstrap.sh --tag v1.0.0                # Tag-based
#   sudo bash secai-bootstrap.sh                             # Latest (default)
#   sudo bash secai-bootstrap.sh --dry-run                   # Verify only
#   sudo bash secai-bootstrap.sh --help                      # Help
#
# What this script does:
#   1. Checks prerequisites (Fedora Atomic, root, required tools)
#   2. Installs cosign if missing
#   3. Fetches and verifies the SecAI public signing key
#   4. Configures the container signing policy (policy.json + registries.d)
#   5. Verifies the image signature using cosign
#   6. Rebases to the signed image using ostree-image-signed: transport
#   7. Prompts for reboot
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
REGISTRY="ghcr.io/secai-hub/secai_os"
COSIGN_PUB_URL="https://raw.githubusercontent.com/SecAI-Hub/SecAI_OS/main/cosign.pub"
# SHA256 fingerprint of the expected cosign.pub — update after key rotation
COSIGN_PUB_SHA256="de6a17ed1cd444a2671798f14d6bf98c1658259dc443a130eba9f40855a7d310"

COSIGN_PUB_DEST="/etc/pki/containers/secai-cosign.pub"
REGISTRIES_YAML="/etc/containers/registries.d/secai-os.yaml"
POLICY_JSON="/etc/containers/policy.json"

TAG="latest"
DIGEST=""
DRY_RUN=false

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' BOLD='' NC=''
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*" >&2; }
fatal() { error "$*"; exit 1; }
step()  { echo -e "\n${BOLD}${CYAN}=== $* ===${NC}"; }

usage() {
    cat <<'USAGE'
SecAI OS — Signed Bootstrap Script

Usage:
  sudo bash secai-bootstrap.sh [OPTIONS]

Options:
  --digest DIGEST    Pin to a specific image digest (sha256:...)
                     Production installs should ALWAYS use this.
  --tag TAG          Use a specific image tag (default: latest)
  --dry-run          Verify everything but do not rebase
  --help             Show this help message

Examples:
  # Production install (digest-pinned)
  sudo bash secai-bootstrap.sh --digest sha256:abc123...

  # Install a specific release
  sudo bash secai-bootstrap.sh --tag v1.0.0

  # Verify-only (no changes)
  sudo bash secai-bootstrap.sh --dry-run
USAGE
    exit 0
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --digest)
            [ -z "${2:-}" ] && fatal "--digest requires a value (sha256:...)"
            DIGEST="$2"; shift 2 ;;
        --tag)
            [ -z "${2:-}" ] && fatal "--tag requires a value"
            TAG="$2"; shift 2 ;;
        --dry-run)
            DRY_RUN=true; shift ;;
        --help|-h)
            usage ;;
        *)
            fatal "Unknown option: $1  (use --help for usage)" ;;
    esac
done

if [ -n "$DIGEST" ] && ! printf '%s' "$DIGEST" | grep -Eq '^sha256:[0-9A-Fa-f]{64}$'; then
    fatal "--digest must be a sha256 digest in the form sha256:<64 hex characters>"
fi

if ! printf '%s' "$TAG" | grep -Eq '^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$'; then
    fatal "--tag contains unsupported characters. Use an OCI tag such as latest or v1.2.3."
fi

# Build the image reference
if [ -n "$DIGEST" ]; then
    IMAGE_REF="${REGISTRY}@${DIGEST}"
else
    IMAGE_REF="${REGISTRY}:${TAG}"
fi

# ---------------------------------------------------------------------------
# Step 1: Prerequisites
# ---------------------------------------------------------------------------
step "Checking prerequisites"

# Must be root
[ "$(id -u)" -eq 0 ] || fatal "This script must be run as root (sudo)"

# Must be Fedora Atomic / Silverblue
if ! command -v rpm-ostree &>/dev/null; then
    fatal "rpm-ostree not found. This script requires Fedora Atomic (Silverblue/Kinoite)."
fi
info "rpm-ostree: available"

# Check Fedora version
FEDORA_VERSION=$(rpm -E %fedora 2>/dev/null || echo "unknown")
info "Fedora release: ${FEDORA_VERSION}"

if [ "$FEDORA_VERSION" != "unknown" ] && [ "$FEDORA_VERSION" -lt 42 ] 2>/dev/null; then
    warn "SecAI OS targets Fedora 42+. You are running Fedora ${FEDORA_VERSION}."
    warn "The install may still work but is not officially supported."
fi

# Check for required tools
for tool in curl grep python3 sha256sum; do
    command -v "$tool" &>/dev/null || fatal "Required tool not found: $tool"
done
info "Required tools: present"

# ---------------------------------------------------------------------------
# Step 2: Install cosign
# ---------------------------------------------------------------------------
step "Ensuring cosign is installed"

if command -v cosign &>/dev/null; then
    info "cosign: already installed ($(cosign version 2>/dev/null | head -1 || echo 'unknown version'))"
else
    if [ "$DRY_RUN" = true ]; then
        warn "DRY RUN — would install cosign via dnf before verifying the image signature."
        fatal "cosign is required for --dry-run verification; install cosign or rerun without --dry-run."
    fi
    info "Installing cosign via dnf..."
    dnf install -y cosign || fatal "Failed to install cosign"
    command -v cosign &>/dev/null || fatal "cosign not available after install"
    info "cosign: installed"
fi

# ---------------------------------------------------------------------------
# Step 3: Fetch and verify the public key
# ---------------------------------------------------------------------------
step "Fetching SecAI signing key"

TEMP_KEY=$(mktemp /tmp/secai-cosign-XXXXXX.pub)
trap 'rm -f "$TEMP_KEY"' EXIT

curl -sSfL "$COSIGN_PUB_URL" -o "$TEMP_KEY" || fatal "Failed to download cosign public key from ${COSIGN_PUB_URL}"
info "Downloaded cosign.pub from GitHub"

# Verify the key fingerprint
ACTUAL_SHA256=$(sha256sum "$TEMP_KEY" | cut -d' ' -f1)
if [ "$ACTUAL_SHA256" != "$COSIGN_PUB_SHA256" ]; then
    error "Public key fingerprint mismatch!"
    error "  Expected: ${COSIGN_PUB_SHA256}"
    error "  Got:      ${ACTUAL_SHA256}"
    fatal "The downloaded key does not match the expected fingerprint. Aborting."
fi
info "Key fingerprint verified: ${ACTUAL_SHA256:0:16}..."

# ---------------------------------------------------------------------------
# Step 4: Install signing policy
# ---------------------------------------------------------------------------
step "Configuring container signing policy"

VERIFY_KEY="$COSIGN_PUB_DEST"

if [ "$DRY_RUN" = true ]; then
    VERIFY_KEY="$TEMP_KEY"
    warn "DRY RUN — would install public key: ${COSIGN_PUB_DEST}"
    warn "DRY RUN — would write registries config: ${REGISTRIES_YAML}"
    warn "DRY RUN — would merge sigstore policy into: ${POLICY_JSON}"
else
    # Install the public key
    mkdir -p "$(dirname "$COSIGN_PUB_DEST")"
    cp "$TEMP_KEY" "$COSIGN_PUB_DEST"
    chmod 0644 "$COSIGN_PUB_DEST"
    info "Installed public key: ${COSIGN_PUB_DEST}"

    # Write registries.d config
    mkdir -p "$(dirname "$REGISTRIES_YAML")"
    cat > "$REGISTRIES_YAML" <<'YAML'
## SecAI OS — enable sigstore signature attachments for cosign-signed images.
docker:
  ghcr.io/secai-hub/secai_os:
    use-sigstore-attachments: true
YAML
    chmod 0644 "$REGISTRIES_YAML"
    info "Wrote registries config: ${REGISTRIES_YAML}"

    # Merge sigstore verification into policy.json
    if [ -f "$POLICY_JSON" ]; then
        # Back up the original
        cp "$POLICY_JSON" "${POLICY_JSON}.pre-secai"
        info "Backed up original policy: ${POLICY_JSON}.pre-secai"

        python3 -c "
import json, sys

with open('${POLICY_JSON}') as f:
    policy = json.load(f)

policy.setdefault('transports', {})
policy['transports'].setdefault('docker', {})

policy['transports']['docker']['ghcr.io/secai-hub/secai_os'] = [{
    'type': 'sigstoreSigned',
    'keyPath': '${COSIGN_PUB_DEST}',
    'signedIdentity': {'type': 'matchRepository'}
}]

with open('${POLICY_JSON}', 'w') as f:
    json.dump(policy, f, indent=2)
    f.write('\n')
" || fatal "Failed to update ${POLICY_JSON}"
        info "Updated policy.json with sigstoreSigned entry for ${REGISTRY}"
    else
        # Create a minimal policy from scratch. Fail closed for all other
        # remote image pulls on hosts that do not already define a policy.
        python3 -c "
import json

policy = {
    'default': [{'type': 'reject'}],
    'transports': {
        'docker': {
            'ghcr.io/secai-hub/secai_os': [{
                'type': 'sigstoreSigned',
                'keyPath': '${COSIGN_PUB_DEST}',
                'signedIdentity': {'type': 'matchRepository'}
            }]
        },
        'docker-daemon': {'': [{'type': 'insecureAcceptAnything'}]}
    }
}

with open('${POLICY_JSON}', 'w') as f:
    json.dump(policy, f, indent=2)
    f.write('\n')
" || fatal "Failed to create ${POLICY_JSON}"
        info "Created policy.json with sigstoreSigned entry and reject-by-default fallback"
    fi
fi

# ---------------------------------------------------------------------------
# Step 5: Verify the image signature
# ---------------------------------------------------------------------------
step "Verifying image signature"

info "Image: ${IMAGE_REF}"
if cosign verify --key "$VERIFY_KEY" "$IMAGE_REF" 2>&1; then
    info "Image signature: VERIFIED"
else
    fatal "Image signature verification FAILED for ${IMAGE_REF}. Aborting."
fi

# ---------------------------------------------------------------------------
# Step 6: Rebase to signed image
# ---------------------------------------------------------------------------
step "Rebasing to SecAI OS (signed transport)"

REBASE_REF="ostree-image-signed:docker://${IMAGE_REF}"

if [ "$DRY_RUN" = true ]; then
    warn "DRY RUN — would execute:"
    warn "  rpm-ostree rebase ${REBASE_REF}"
    echo ""
    info "Dry run complete. All checks passed."
    info "Run again without --dry-run to install."
    exit 0
fi

info "Rebasing: ${REBASE_REF}"
rpm-ostree rebase "$REBASE_REF" || fatal "rpm-ostree rebase failed"
info "Rebase complete — image staged for next boot"

# ---------------------------------------------------------------------------
# Step 7: Done
# ---------------------------------------------------------------------------
step "Bootstrap complete"

echo ""
echo -e "${GREEN}SecAI OS has been staged successfully.${NC}"
echo ""
echo "Next steps:"
echo "  1. Reboot:  sudo systemctl reboot"
echo "  2. After reboot, run the setup wizard:"
echo "     sudo /usr/libexec/secure-ai/secai-setup-wizard.sh"
echo ""
if [ -n "$DIGEST" ]; then
    echo -e "Image pinned to digest: ${BOLD}${DIGEST}${NC}"
else
    echo -e "Image tag: ${BOLD}${TAG}${NC}"
    warn "For production installs, use --digest to pin to a specific build."
fi
echo ""
