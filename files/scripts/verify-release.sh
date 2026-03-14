#!/usr/bin/env bash
#
# verify-release.sh — Verify the supply-chain integrity of a SecAI_OS release.
#
# This script is intended for auditors and operators who want to independently
# verify that a published SecAI_OS image has not been tampered with.  It checks:
#
#   1. Cosign signature on the container image
#   2. CycloneDX SBOM attestation
#   3. SLSA3 provenance attestation
#   4. SHA256 checksum of local release artifacts
#
# Prerequisites:
#   - cosign   (https://docs.sigstore.dev/cosign/overview/)
#   - jq       (for JSON output parsing)
#   - sha256sum (coreutils)
#
# Usage:
#   ./verify-release.sh <image-ref>
#   ./verify-release.sh ghcr.io/secai-hub/secai_os:v1.0.0
#   ./verify-release.sh --help
#
# Configuration:
#   Set COSIGN_PUB_KEY to the path of the cosign public key used to sign
#   the release.  Defaults to ./cosign.pub in the current directory.
#
#   Set SHA256SUMS_FILE to the path of the SHA256SUMS file from the release
#   bundle.  Defaults to ./SHA256SUMS in the current directory.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration — override via environment variables
# ---------------------------------------------------------------------------
COSIGN_PUB_KEY="${COSIGN_PUB_KEY:-./cosign.pub}"
SHA256SUMS_FILE="${SHA256SUMS_FILE:-./SHA256SUMS}"

# ---------------------------------------------------------------------------
# Colour helpers (disabled when stdout is not a terminal)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    GREEN='' RED='' YELLOW='' BOLD='' RESET=''
fi

pass() { printf "${GREEN}[PASS]${RESET} %s\n" "$*"; }
fail() { printf "${RED}[FAIL]${RESET} %s\n" "$*"; FAILURES=$((FAILURES + 1)); }
warn() { printf "${YELLOW}[WARN]${RESET} %s\n" "$*"; }
info() { printf "${BOLD}[INFO]${RESET} %s\n" "$*"; }

FAILURES=0

# ---------------------------------------------------------------------------
# --help
# ---------------------------------------------------------------------------
usage() {
    cat <<'USAGE'
Usage: verify-release.sh [OPTIONS] <image-ref>

Verify the supply-chain integrity of a SecAI_OS release image.

Arguments:
  <image-ref>   Full container image reference
                Example: ghcr.io/secai-hub/secai_os:v1.0.0

Options:
  --help        Show this help message and exit

Environment variables:
  COSIGN_PUB_KEY    Path to cosign public key  (default: ./cosign.pub)
  SHA256SUMS_FILE   Path to SHA256SUMS file     (default: ./SHA256SUMS)

Steps performed:
  1. Verify cosign image signature
  2. Verify CycloneDX SBOM attestation
  3. Verify SLSA3 provenance attestation
  4. Verify SHA256 checksums of local artifacts

Exit codes:
  0   All checks passed
  1   One or more checks failed
  2   Missing prerequisites or invalid arguments

Examples:
  # Verify with default key location
  ./verify-release.sh ghcr.io/secai-hub/secai_os:v1.0.0

  # Verify with a custom key path
  COSIGN_PUB_KEY=/path/to/release-key.pub \
    ./verify-release.sh ghcr.io/secai-hub/secai_os:v1.0.0

  # Verify with custom SHA256SUMS location
  SHA256SUMS_FILE=./release-artifacts/SHA256SUMS \
    ./verify-release.sh ghcr.io/secai-hub/secai_os:v1.0.0
USAGE
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi

# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
    echo "Error: image reference is required." >&2
    echo "Run '$0 --help' for usage information." >&2
    exit 2
fi

IMAGE="$1"

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------
info "Verifying release: ${IMAGE}"
echo ""

missing_prereqs=0
for cmd in cosign sha256sum; do
    if ! command -v "$cmd" &>/dev/null; then
        fail "Required command not found: ${cmd}"
        missing_prereqs=1
    fi
done

if [[ ! -f "${COSIGN_PUB_KEY}" ]]; then
    fail "Cosign public key not found: ${COSIGN_PUB_KEY}"
    echo "  Set COSIGN_PUB_KEY to the correct path." >&2
    missing_prereqs=1
fi

if [[ $missing_prereqs -eq 1 ]]; then
    echo ""
    echo "Cannot continue — fix the above issues first." >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Step 1: Verify cosign image signature
# ---------------------------------------------------------------------------
info "Step 1/4: Verifying cosign image signature..."

if cosign verify \
    --key "${COSIGN_PUB_KEY}" \
    "${IMAGE}" \
    >/dev/null 2>&1; then
    pass "Cosign image signature is valid"
else
    fail "Cosign image signature verification FAILED"
fi

echo ""

# ---------------------------------------------------------------------------
# Step 2: Verify CycloneDX SBOM attestation
# ---------------------------------------------------------------------------
info "Step 2/4: Verifying CycloneDX SBOM attestation..."

if cosign verify-attestation \
    --type cyclonedx \
    --key "${COSIGN_PUB_KEY}" \
    "${IMAGE}" \
    >/dev/null 2>&1; then
    pass "CycloneDX SBOM attestation is valid"
else
    fail "CycloneDX SBOM attestation verification FAILED"
fi

echo ""

# ---------------------------------------------------------------------------
# Step 3: Verify SLSA provenance attestation
# ---------------------------------------------------------------------------
info "Step 3/4: Verifying SLSA provenance attestation..."

if cosign verify-attestation \
    --type slsaprovenance \
    --key "${COSIGN_PUB_KEY}" \
    "${IMAGE}" \
    >/dev/null 2>&1; then
    pass "SLSA provenance attestation is valid"
else
    fail "SLSA provenance attestation verification FAILED"
fi

echo ""

# ---------------------------------------------------------------------------
# Step 4: Verify SHA256 checksums
# ---------------------------------------------------------------------------
info "Step 4/4: Verifying SHA256 checksums..."

if [[ -f "${SHA256SUMS_FILE}" ]]; then
    pushd "$(dirname "${SHA256SUMS_FILE}")" >/dev/null
    sums_file="$(basename "${SHA256SUMS_FILE}")"

    # Also verify the signature on the SHA256SUMS file if .sig exists
    if [[ -f "${sums_file}.sig" ]]; then
        if cosign verify-blob \
            --key "${COSIGN_PUB_KEY}" \
            --signature "${sums_file}.sig" \
            "${sums_file}" \
            >/dev/null 2>&1; then
            pass "SHA256SUMS signature is valid"
        else
            fail "SHA256SUMS signature verification FAILED"
        fi
    else
        warn "SHA256SUMS.sig not found — skipping checksum file signature verification"
    fi

    # Verify individual file checksums
    checksum_errors=0
    checksum_total=0
    while IFS= read -r line; do
        hash_expected="$(echo "$line" | awk '{print $1}')"
        file_name="$(echo "$line" | awk '{print $2}')"

        # Skip the SHA256SUMS file itself and its signature
        if [[ "${file_name}" == "SHA256SUMS" || "${file_name}" == "SHA256SUMS.sig" ]]; then
            continue
        fi

        checksum_total=$((checksum_total + 1))

        if [[ ! -f "${file_name}" ]]; then
            warn "File listed in SHA256SUMS not found locally: ${file_name} (skipped)"
            continue
        fi

        hash_actual="$(sha256sum "${file_name}" | awk '{print $1}')"
        if [[ "${hash_expected}" == "${hash_actual}" ]]; then
            pass "Checksum OK: ${file_name}"
        else
            fail "Checksum MISMATCH: ${file_name}"
            echo "  Expected: ${hash_expected}" >&2
            echo "  Actual:   ${hash_actual}" >&2
            checksum_errors=$((checksum_errors + 1))
        fi
    done < "${sums_file}"

    if [[ $checksum_total -eq 0 ]]; then
        warn "SHA256SUMS file is empty or contains no verifiable entries"
    fi

    popd >/dev/null
else
    warn "SHA256SUMS file not found: ${SHA256SUMS_FILE} — skipping checksum verification"
    echo "  Set SHA256SUMS_FILE to the correct path if you have release artifacts." >&2
fi

echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=========================================="
if [[ $FAILURES -eq 0 ]]; then
    pass "All verification checks passed"
    exit 0
else
    fail "${FAILURES} verification check(s) FAILED"
    exit 1
fi
