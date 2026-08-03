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
#   5. Signed install media, release manifest, and readiness evidence
#
# Prerequisites:
#   - cosign >= 3.1.1 (https://docs.sigstore.dev/cosign/overview/)
#   - jq       (for JSON output parsing and OpenVEX validation)
#   - sha256sum (coreutils)
#
# Usage:
#   ./verify-release.sh <image-ref@sha256:digest>
#   ./verify-release.sh --json ghcr.io/secai-hub/secai_os@sha256:<digest>
#   ./verify-release.sh --report report.txt ghcr.io/secai-hub/secai_os@sha256:<digest>
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
COSIGN_PUB_KEYS_DIR="${COSIGN_PUB_KEYS_DIR:-./release-keys}"
SHA256SUMS_FILE="${SHA256SUMS_FILE:-./SHA256SUMS}"
RELEASE_MANIFEST_FILE="${RELEASE_MANIFEST_FILE:-./RELEASE_MANIFEST.json}"
RELEASE_READINESS_FILE="${RELEASE_READINESS_FILE:-./RELEASE_READINESS.json}"
readonly COSIGN_MIN_VERSION="3.1.1"

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
# Result tracking for --json and --report output
# ---------------------------------------------------------------------------
CHECKS=()
STARTED_AT=""
KEY_FILES=()
LAST_SUCCESS_KEY=""

cosign_version_is_supported() {
    local raw_version="$1"
    local version_re='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
    if [[ ! "$raw_version" =~ $version_re ]]; then
        return 1
    fi
    local major="${BASH_REMATCH[1]}"
    local minor="${BASH_REMATCH[2]}"
    local patch="${BASH_REMATCH[3]}"
    (( major > 3 ||
       (major == 3 && minor > 1) ||
       (major == 3 && minor == 1 && patch >= 1) ))
}

# Record a check result for structured output
record_check() {
    local step="$1" name="$2" result="$3" detail="${4:-}"
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    # Sanitise double quotes in detail for JSON safety
    detail="${detail//\"/\'}"
    CHECKS+=("${step}|${name}|${result}|${detail}|${ts}")
}

collect_key_files() {
    KEY_FILES=()
    if [[ -f "${COSIGN_PUB_KEY}" ]]; then
        KEY_FILES+=("$(
            cd "$(dirname "${COSIGN_PUB_KEY}")"
            printf '%s/%s\n' "$PWD" "$(basename "${COSIGN_PUB_KEY}")"
        )")
    fi

    if [[ -d "${COSIGN_PUB_KEYS_DIR}" ]]; then
        while IFS= read -r -d '' key_path; do
            if [[ "${key_path}" != "${COSIGN_PUB_KEY}" ]]; then
                KEY_FILES+=("$(
                    cd "$(dirname "${key_path}")"
                    printf '%s/%s\n' "$PWD" "$(basename "${key_path}")"
                )")
            fi
        done < <(find "${COSIGN_PUB_KEYS_DIR}" -maxdepth 1 -type f -name '*.pub' -print0 | sort -z)
    fi
}

verify_image_with_any_key() {
    LAST_SUCCESS_KEY=""
    for key_path in "${KEY_FILES[@]}"; do
        if cosign verify --key "${key_path}" "${IMAGE}" >/dev/null 2>&1; then
            LAST_SUCCESS_KEY="${key_path}"
            return 0
        fi
    done
    return 1
}

verify_attestation_with_any_key() {
    local attestation_type="$1"
    LAST_SUCCESS_KEY=""
    for key_path in "${KEY_FILES[@]}"; do
        if cosign verify-attestation \
            --type "${attestation_type}" \
            --key "${key_path}" \
            "${IMAGE}" >/dev/null 2>&1; then
            LAST_SUCCESS_KEY="${key_path}"
            return 0
        fi
    done
    return 1
}

verify_blob_with_any_key() {
    local signature_path="$1"
    local blob_path="$2"
    LAST_SUCCESS_KEY=""
    for key_path in "${KEY_FILES[@]}"; do
        if cosign verify-blob \
            --key "${key_path}" \
            --signature "${signature_path}" \
            "${blob_path}" >/dev/null 2>&1; then
            LAST_SUCCESS_KEY="${key_path}"
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# --help
# ---------------------------------------------------------------------------
usage() {
    cat <<'USAGE'
Usage: verify-release.sh [OPTIONS] <image-ref>

Verify the supply-chain integrity of a SecAI_OS release image.

Arguments:
  <image-ref>   Immutable container image reference
                Example: ghcr.io/secai-hub/secai_os@sha256:<64 hex>

Options:
  --help          Show this help message and exit
  --json          Print machine-readable JSON summary to stdout
  --report FILE   Write a human-readable verification report to FILE

Requirements:
  cosign 3.1.1 or newer (stable release) for Rekor v2 attestations

Environment variables:
  COSIGN_PUB_KEY    Path to cosign public key  (default: ./cosign.pub)
  COSIGN_PUB_KEYS_DIR
                    Directory of archived/public verification keys
                    tried after COSIGN_PUB_KEY (default: ./release-keys)
  SHA256SUMS_FILE   Path to SHA256SUMS file     (default: ./SHA256SUMS)

Steps performed:
  1. Verify cosign image signature
  2. Verify CycloneDX SBOM attestation
  3. Verify SLSA3 provenance attestation
  4. Verify SHA256 checksums of local artifacts
  5. Validate custom-python.vex.json when it is present

Exit codes:
  0   All checks passed
  1   One or more checks failed
  2   Missing prerequisites or invalid arguments

Examples:
  # Verify with default key location
  ./verify-release.sh ghcr.io/secai-hub/secai_os@sha256:<digest>

  # Verify with a custom key path
  COSIGN_PUB_KEY=/path/to/release-key.pub \
    ./verify-release.sh ghcr.io/secai-hub/secai_os@sha256:<digest>

  # Verify with custom SHA256SUMS location
  SHA256SUMS_FILE=./release-artifacts/SHA256SUMS \
    ./verify-release.sh ghcr.io/secai-hub/secai_os@sha256:<digest>

  # Machine-readable JSON output
  ./verify-release.sh --json ghcr.io/secai-hub/secai_os@sha256:<digest>

  # Save a human-readable report
  ./verify-release.sh --report verification-report.txt \
    ghcr.io/secai-hub/secai_os@sha256:<digest>
USAGE
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
OUTPUT_JSON=0
REPORT_FILE=""
IMAGE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            usage
            exit 0
            ;;
        --json)
            OUTPUT_JSON=1
            shift
            ;;
        --report)
            if [[ -z "${2:-}" ]]; then
                echo "Error: --report requires a file path." >&2
                exit 2
            fi
            REPORT_FILE="$2"
            shift 2
            ;;
        -*)
            echo "Error: unknown option: $1" >&2
            echo "Run '$0 --help' for usage information." >&2
            exit 2
            ;;
        *)
            if [[ -z "${IMAGE}" ]]; then
                IMAGE="$1"
                shift
            else
                echo "Error: unexpected argument: $1" >&2
                exit 2
            fi
            ;;
    esac
done

if [[ -z "${IMAGE}" ]]; then
    echo "Error: image reference is required." >&2
    echo "Run '$0 --help' for usage information." >&2
    exit 2
fi

if [[ ! "${IMAGE}" =~ @sha256:[0-9a-f]{64}$ ]]; then
    echo "Error: image reference must be immutable (repository@sha256:<64 hex>)." >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

info "Verifying release: ${IMAGE}"
echo ""

missing_prereqs=0
for cmd in cosign jq sha256sum; do
    if ! command -v "$cmd" &>/dev/null; then
        fail "Required command not found: ${cmd}"
        missing_prereqs=1
    fi
done

if command -v cosign >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
    cosign_version_json=""
    cosign_git_version=""
    if ! cosign_version_json="$(cosign version --json 2>/dev/null)"; then
        fail "Unable to query Cosign version; stable Cosign v${COSIGN_MIN_VERSION} or newer is required for Rekor v2"
        missing_prereqs=1
    elif ! cosign_git_version="$(
        jq -er '.gitVersion | select(type == "string")' \
            <<<"$cosign_version_json"
    )"; then
        fail "Cosign returned invalid version metadata; stable Cosign v${COSIGN_MIN_VERSION} or newer is required for Rekor v2"
        missing_prereqs=1
    elif ! cosign_version_is_supported "$cosign_git_version"; then
        fail "Unsupported Cosign version ${cosign_git_version}; stable Cosign v${COSIGN_MIN_VERSION} or newer is required for Rekor v2"
        missing_prereqs=1
    fi
fi

collect_key_files
if [[ ${#KEY_FILES[@]} -eq 0 ]]; then
    fail "No cosign public keys found"
    echo "  Checked: ${COSIGN_PUB_KEY} and ${COSIGN_PUB_KEYS_DIR}/*.pub" >&2
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
info "Step 1/5: Verifying cosign image signature..."

if verify_image_with_any_key; then
    pass "Cosign image signature is valid"
    record_check 1 "cosign_image_signature" "PASS" "key=${LAST_SUCCESS_KEY}"
else
    fail "Cosign image signature verification FAILED"
    record_check 1 "cosign_image_signature" "FAIL" "keys_checked=${#KEY_FILES[@]}"
fi

echo ""

# ---------------------------------------------------------------------------
# Step 2: Verify CycloneDX SBOM attestation
# ---------------------------------------------------------------------------
info "Step 2/5: Verifying CycloneDX SBOM attestation..."

if verify_attestation_with_any_key "cyclonedx"; then
    pass "CycloneDX SBOM attestation is valid"
    record_check 2 "sbom_attestation" "PASS" "key=${LAST_SUCCESS_KEY}"
else
    fail "CycloneDX SBOM attestation verification FAILED"
    record_check 2 "sbom_attestation" "FAIL" "keys_checked=${#KEY_FILES[@]}"
fi

echo ""

# ---------------------------------------------------------------------------
# Step 3: Verify SLSA provenance attestation
# ---------------------------------------------------------------------------
info "Step 3/5: Verifying SLSA provenance attestation..."

if verify_attestation_with_any_key "slsaprovenance"; then
    pass "SLSA provenance attestation is valid"
    record_check 3 "slsa_provenance" "PASS" "key=${LAST_SUCCESS_KEY}"
else
    fail "SLSA provenance attestation verification FAILED"
    record_check 3 "slsa_provenance" "FAIL" "keys_checked=${#KEY_FILES[@]}"
fi

echo ""

# ---------------------------------------------------------------------------
# Step 4: Verify SHA256 checksums and OpenVEX metadata
# ---------------------------------------------------------------------------
info "Step 4/5: Verifying signed SHA256 checksums and release metadata..."

if [[ -f "${SHA256SUMS_FILE}" ]]; then
    pushd "$(dirname "${SHA256SUMS_FILE}")" >/dev/null
    sums_file="$(basename "${SHA256SUMS_FILE}")"

    # The checksum manifest is a trust boundary and must always be signed.
    if [[ -f "${sums_file}.sig" ]]; then
        if verify_blob_with_any_key "${sums_file}.sig" "${sums_file}"; then
            pass "SHA256SUMS signature is valid"
            record_check 4 "checksum_signature" "PASS" "key=${LAST_SUCCESS_KEY}"
        else
            fail "SHA256SUMS signature verification FAILED"
            record_check 4 "checksum_signature" "FAIL" "keys_checked=${#KEY_FILES[@]}"
        fi
    else
        fail "SHA256SUMS.sig not found"
        record_check 4 "checksum_signature" "FAIL" "SHA256SUMS.sig not found"
    fi

    # Verify individual file checksums
    checksum_total=0
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        if [[ ! "$line" =~ ^([0-9a-f]{64})[[:space:]][[:space:]]([^[:space:]]+)$ ]]; then
            fail "Malformed SHA256SUMS entry"
            record_check 4 "checksum_manifest_entry" "FAIL" "malformed entry"
            continue
        fi
        hash_expected="${BASH_REMATCH[1]}"
        file_name="${BASH_REMATCH[2]#./}"

        # Skip the SHA256SUMS file itself and its signature
        if [[ "${file_name}" == "SHA256SUMS" || "${file_name}" == "SHA256SUMS.sig" ]]; then
            fail "SHA256SUMS contains a self-referential entry: ${file_name}"
            record_check 4 "checksum_self_reference" "FAIL" "${file_name}"
            continue
        fi
        if [[ "$file_name" == */* || "$file_name" == .* ]]; then
            fail "Unsafe path in SHA256SUMS: ${file_name}"
            record_check 4 "checksum_path_${checksum_total}" "FAIL" "unsafe path"
            continue
        fi

        checksum_total=$((checksum_total + 1))

        if [[ ! -f "${file_name}" ]]; then
            fail "File listed in SHA256SUMS not found locally: ${file_name}"
            record_check 4 "checksum_${file_name}" "FAIL" "file missing"
            continue
        fi

        hash_actual="$(sha256sum "${file_name}" | awk '{print $1}')"
        if [[ "${hash_expected}" == "${hash_actual}" ]]; then
            pass "Checksum OK: ${file_name}"
            record_check 4 "checksum_${file_name}" "PASS"
        else
            fail "Checksum MISMATCH: ${file_name}"
            echo "  Expected: ${hash_expected}" >&2
            echo "  Actual:   ${hash_actual}" >&2
            record_check 4 "checksum_${file_name}" "FAIL" "expected=${hash_expected} actual=${hash_actual}"
        fi
    done < "${sums_file}"

    if [[ $checksum_total -eq 0 ]]; then
        fail "SHA256SUMS file is empty or contains no verifiable entries"
        record_check 4 "checksum_entries" "FAIL" "no artifact entries"
    fi

    if [[ -f "custom-python.vex.json" ]]; then
        if jq -e '."@context" == "https://openvex.dev/ns/v0.2.0" and (.statements | type == "array") and (.statements | length > 0)' \
            custom-python.vex.json >/dev/null; then
            pass "OpenVEX document is structurally valid: custom-python.vex.json"
            record_check 4 "openvex_structure" "PASS"
        else
            fail "OpenVEX document is invalid: custom-python.vex.json"
            record_check 4 "openvex_structure" "FAIL"
        fi
    else
        warn "custom-python.vex.json not found locally - skipping OpenVEX validation"
        record_check 4 "openvex_structure" "SKIP" "custom-python.vex.json not found"
    fi

    manifest_name="$(basename "${RELEASE_MANIFEST_FILE}")"
    readiness_name="$(basename "${RELEASE_READINESS_FILE}")"
    image_repo="${IMAGE%@*}"
    image_digest="${IMAGE##*@}"
    manifest_commit=""

    if [[ -f "$manifest_name" ]] &&
       jq -e \
         --arg image_repo "$image_repo" \
         --arg image_digest "$image_digest" \
         --arg image "$IMAGE" \
         '.schema_version >= 2
          and .image.ref == $image_repo
          and .image.digest == $image_digest
          and .image.ref_pinned == $image
          and (.build.commit_sha | test("^[0-9a-f]{40}$"))
          and .deployment.required_service_profile == "offline-private"' \
         "$manifest_name" >/dev/null; then
        manifest_commit="$(jq -r '.build.commit_sha' "$manifest_name")"
        pass "Release manifest is bound to the verified image"
        record_check 4 "release_manifest" "PASS"
    else
        fail "Release manifest is missing, invalid, or bound to another image"
        record_check 4 "release_manifest" "FAIL"
    fi

    if [[ -n "$manifest_commit" && -f RELEASE_BASELINE.json ]]; then
        baseline_expected="$(
            jq -r '.image.release_baseline.sha256 // empty' "$manifest_name"
        )"
        baseline_actual="$(sha256sum RELEASE_BASELINE.json | awk '{print $1}')"
        if [[ "$baseline_expected" == "$baseline_actual" ]] &&
           jq -e --arg source_commit "$manifest_commit" \
             '.source_commit == $source_commit
              and (.files | type == "array" and length > 0)' \
             RELEASE_BASELINE.json >/dev/null; then
            pass "Release integrity baseline matches the manifest and source"
            record_check 4 "release_baseline" "PASS"
        else
            fail "Release integrity baseline is missing or misbound"
            record_check 4 "release_baseline" "FAIL"
        fi
    else
        fail "RELEASE_BASELINE.json not found"
        record_check 4 "release_baseline" "FAIL"
    fi

    if [[ -f "$manifest_name" && -f "$readiness_name" &&
          -f "${readiness_name}.sig" ]]; then
        if verify_blob_with_any_key "${readiness_name}.sig" "$readiness_name" &&
           jq -e \
             --arg image "$IMAGE" \
             --arg source_commit "$manifest_commit" \
             --arg manifest_sha "$(sha256sum "$manifest_name" | awk '{print $1}')" \
             '.schema_version >= 2
              and .image.ref_pinned == $image
              and .source.commit == $source_commit
              and .release_manifest.sha256 == $manifest_sha
              and (
                .release.designation != "stable"
                or .release.mandatory_evidence_complete == true
              )' "$readiness_name" >/dev/null; then
            pass "Signed release-readiness evidence is valid"
            record_check 4 "release_readiness" "PASS" "key=${LAST_SUCCESS_KEY}"
        else
            fail "Release-readiness evidence signature or binding is invalid"
            record_check 4 "release_readiness" "FAIL"
        fi
    else
        fail "Signed RELEASE_READINESS.json evidence is required"
        record_check 4 "release_readiness" "FAIL" "file or signature missing"
    fi

    popd >/dev/null
else
    fail "SHA256SUMS file not found: ${SHA256SUMS_FILE}"
    record_check 4 "checksum_file" "FAIL" "SHA256SUMS not found"
fi

echo ""

# ---------------------------------------------------------------------------
# Step 5: Verify install artifact signatures (optional)
# ---------------------------------------------------------------------------
info "Step 5/5: Verifying install artifact signatures (if present)..."

install_artifact_dir="$(dirname "${SHA256SUMS_FILE}")"
pushd "$install_artifact_dir" >/dev/null
install_artifacts_found=0
for pattern in "secai-os-*.iso" "secai-os-*-usb.raw.xz" "secai-os-*.qcow2" "secai-os-*.ova"; do
    for artifact in $pattern; do
        [ -f "$artifact" ] || continue
        install_artifacts_found=$((install_artifacts_found + 1))
        sig_file="${artifact}.sig"
        if [[ -f "$sig_file" ]]; then
            if verify_blob_with_any_key "$sig_file" "$artifact"; then
                pass "Install artifact signature OK: ${artifact}"
                record_check 5 "install_sig_${artifact}" "PASS" "key=${LAST_SUCCESS_KEY}"
            else
                fail "Install artifact signature FAILED: ${artifact}"
                record_check 5 "install_sig_${artifact}" "FAIL" "keys_checked=${#KEY_FILES[@]}"
            fi
        else
            fail "No .sig file for ${artifact}"
            record_check 5 "install_sig_${artifact}" "FAIL" "no .sig file"
        fi
    done
done

if [[ $install_artifacts_found -eq 0 ]]; then
    info "No install artifacts (ISO/USB/QCOW2/OVA) found — skipping Step 5"
    record_check 5 "install_artifacts" "SKIP" "no install artifacts present"
fi
popd >/dev/null

echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TOTAL_CHECKS=${#CHECKS[@]}
PASSED=$((TOTAL_CHECKS - FAILURES))

# Build JSON summary string
build_json_summary() {
    local checks_json="["
    local first=1
    for entry in "${CHECKS[@]}"; do
        IFS='|' read -r step name result detail ts <<< "$entry"
        if [[ $first -eq 1 ]]; then first=0; else checks_json+=","; fi
        checks_json+="{\"step\":${step},\"name\":\"${name}\",\"result\":\"${result}\",\"detail\":\"${detail}\",\"timestamp\":\"${ts}\"}"
    done
    checks_json+="]"

    local verdict="PASS"
    if [[ $FAILURES -gt 0 ]]; then verdict="FAIL"; fi

    printf '{"image":"%s","cosign_key":"%s","cosign_key_dir":"%s","resolved_key_count":%d,"started_at":"%s","finished_at":"%s","total_checks":%d,"passed":%d,"failed":%d,"verdict":"%s","checks":%s}\n' \
        "$IMAGE" "$COSIGN_PUB_KEY" "$COSIGN_PUB_KEYS_DIR" "${#KEY_FILES[@]}" "$STARTED_AT" "$FINISHED_AT" \
        "$TOTAL_CHECKS" "$PASSED" "$FAILURES" \
        "$verdict" "$checks_json"
}

# Build human-readable report
build_report() {
    echo "=============================================="
    echo "  SecAI OS Release Verification Report"
    echo "=============================================="
    echo ""
    echo "Image:       ${IMAGE}"
    echo "Cosign key:  ${COSIGN_PUB_KEY}"
    echo "Key dir:     ${COSIGN_PUB_KEYS_DIR}"
    echo "Resolved verification keys: ${#KEY_FILES[@]}"
    echo "Started:     ${STARTED_AT}"
    echo "Finished:    ${FINISHED_AT}"
    echo ""
    echo "--- Results ---"
    echo ""
    for entry in "${CHECKS[@]}"; do
        IFS='|' read -r step name result detail ts <<< "$entry"
        if [[ -n "$detail" ]]; then
            printf "  Step %s  %-35s  %-6s  %s\n" "$step" "$name" "$result" "$detail"
        else
            printf "  Step %s  %-35s  %s\n" "$step" "$name" "$result"
        fi
    done
    echo ""
    echo "--- Verdict ---"
    echo ""
    echo "  Passed: ${PASSED}/${TOTAL_CHECKS}"
    if [[ $FAILURES -eq 0 ]]; then
        echo "  Status: ALL VERIFIED"
    else
        echo "  Status: VERIFICATION FAILED (${FAILURES} check(s) failed)"
    fi
    echo ""
    echo "=============================================="
}

# Default terminal summary
echo "=========================================="
if [[ $FAILURES -eq 0 ]]; then
    pass "All verification checks passed (${PASSED}/${TOTAL_CHECKS})"
else
    printf "${RED}[FAIL]${RESET} %s\n" \
        "${FAILURES} verification check(s) FAILED (${PASSED}/${TOTAL_CHECKS} passed)"
fi

# Conditional structured output
if [[ $OUTPUT_JSON -eq 1 ]]; then
    build_json_summary
fi

if [[ -n "${REPORT_FILE}" ]]; then
    build_report > "${REPORT_FILE}"
    info "Report written to: ${REPORT_FILE}"
fi

if [[ $FAILURES -eq 0 ]]; then
    exit 0
else
    exit 1
fi
