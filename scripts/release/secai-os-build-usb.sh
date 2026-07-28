#!/usr/bin/env bash
#
# Build a SecAI OS portable USB raw image from the published bootc image.
#
set -euo pipefail

REGISTRY="ghcr.io/secai-hub/secai_os"
DIGEST=""
IMAGE_REF=""
VERSION=""
OUTPUT_DIR="./secai-os-usb"
BUILDER_IMAGE="quay.io/centos-bootc/bootc-image-builder:latest@sha256:754fc17718f977313885379e2c779066aba7d15af88fe04b486baec74759f574"
ROOTFS="btrfs"
XZ_LEVEL="-3"
INSTALL_DEPS=true
DRY_RUN=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/cosign.pub" ]]; then
    COSIGN_KEY="${SCRIPT_DIR}/cosign.pub"
else
    COSIGN_KEY="${SCRIPT_DIR}/../../cosign.pub"
fi

usage() {
    cat <<'USAGE'
Usage: secai-os-build-usb.sh [options]

Build a direct-flash SecAI OS USB image (*.usb.raw.xz).

Options:
  --digest DIGEST        Exact image digest, e.g. sha256:<64 lowercase hex>
  --image-ref REF        Exact OCI ref in repository@sha256:<digest> form
  --cosign-key PATH      Trusted cosign public key (default: bundled cosign.pub)
  --version VERSION      Version text used in the output filename
  --output-dir DIR       Output directory (default: ./secai-os-usb)
  --builder-image REF    bootc-image-builder image ref
  --rootfs TYPE          Root filesystem type: btrfs, ext4, or xfs
  --xz-level LEVEL       xz compression level, e.g. -3 or -9 (default: -3)
  --install-deps         Install missing distro-packaged dependencies (default)
  --no-install-deps      Fail if dependencies are missing
  --dry-run              Validate options and print the planned build
  --help                 Show this help text

Examples:
  bash secai-os-build-usb.sh --digest sha256:0123...
  bash secai-os-build-usb.sh --image-ref ghcr.io/example/os@sha256:0123...
USAGE
}

info() { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
fatal() { printf '[x] %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --digest)
            DIGEST="${2:-}"; shift 2 ;;
        --image-ref)
            IMAGE_REF="${2:-}"; shift 2 ;;
        --cosign-key)
            COSIGN_KEY="${2:-}"; shift 2 ;;
        --version)
            VERSION="${2:-}"; shift 2 ;;
        --output-dir)
            OUTPUT_DIR="${2:-}"; shift 2 ;;
        --builder-image)
            BUILDER_IMAGE="${2:-}"; shift 2 ;;
        --rootfs)
            ROOTFS="${2:-}"; shift 2 ;;
        --xz-level)
            XZ_LEVEL="${2:-}"; shift 2 ;;
        --install-deps)
            INSTALL_DEPS=true; shift ;;
        --no-install-deps)
            INSTALL_DEPS=false; shift ;;
        --dry-run)
            DRY_RUN=true; shift ;;
        --help|-h)
            usage; exit 0 ;;
        *)
            fatal "Unknown argument: $1" ;;
    esac
done

validate_image_ref() {
    local label="$1"
    local ref="$2"
    case "$ref" in
        ""|*[!A-Za-z0-9._:/@+-]*)
            fatal "Invalid ${label} image reference: ${ref}" ;;
    esac
}

validate_version() {
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || \
        fatal "--version contains unsupported characters"
}

if [[ -n "$DIGEST" && ! "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    fatal "--digest must be in the form sha256:<64 lowercase hex characters>"
fi

validate_image_ref "--builder-image" "$BUILDER_IMAGE"

case "$ROOTFS" in
    btrfs|ext4|xfs) ;;
    *) fatal "Unsupported --rootfs value: ${ROOTFS}" ;;
esac

case "$XZ_LEVEL" in
    -[0-9]) ;;
    *) fatal "Unsupported --xz-level value: ${XZ_LEVEL}" ;;
esac

if [[ -z "$IMAGE_REF" ]]; then
    if [[ -n "$DIGEST" ]]; then
        IMAGE_REF="${REGISTRY}@${DIGEST}"
    else
        fatal "an immutable --image-ref or --digest is required"
    fi
elif [[ -n "$DIGEST" ]]; then
    fatal "--image-ref and --digest are mutually exclusive"
fi
validate_image_ref "--image-ref" "$IMAGE_REF"
if [[ ! "$IMAGE_REF" =~ ^[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]]; then
    fatal "--image-ref must be an exact repository@sha256:<64 lowercase hex> reference"
fi
[[ -f "$COSIGN_KEY" && -r "$COSIGN_KEY" ]] || \
    fatal "trusted cosign public key is missing or unreadable: ${COSIGN_KEY}"

if [[ -z "$VERSION" ]]; then
    digest_short="${IMAGE_REF##*@sha256:}"
    VERSION="sha256-${digest_short:0:12}"
fi
validate_version "$VERSION"

install_packages() {
    if [[ "$INSTALL_DEPS" != true ]]; then
        return 1
    fi

    local sudo_cmd=()
    if [[ "$(id -u)" -ne 0 ]]; then
        command -v sudo >/dev/null 2>&1 || return 1
        sudo_cmd=(sudo)
    fi

    if command -v apt-get >/dev/null 2>&1; then
        info "Installing missing dependencies with apt-get"
        "${sudo_cmd[@]}" apt-get update
        DEBIAN_FRONTEND=noninteractive "${sudo_cmd[@]}" apt-get install -y "$@"
    elif command -v dnf >/dev/null 2>&1; then
        info "Installing missing dependencies with dnf"
        "${sudo_cmd[@]}" dnf install -y "$@"
    elif command -v rpm-ostree >/dev/null 2>&1; then
        warn "Installing packages with rpm-ostree may require a reboot before retrying."
        "${sudo_cmd[@]}" rpm-ostree install -y "$@"
    else
        return 1
    fi
}

require_commands() {
    local missing=()
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        return 0
    fi

    if install_packages "${missing[@]}"; then
        missing=()
        for cmd in "$@"; do
            command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
        done
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        fatal "Missing required command(s): ${missing[*]}"
    fi
}

if [[ "$DRY_RUN" == true ]]; then
    info "Dry run: USB image build plan"
    printf '  image:        %s\n' "$IMAGE_REF"
    printf '  builder:      %s\n' "$BUILDER_IMAGE"
    printf '  rootfs:       %s\n' "$ROOTFS"
    printf '  xz level:     %s\n' "$XZ_LEVEL"
    printf '  output:       %s/secai-os-%s-x86_64-usb.raw.xz\n' "$OUTPUT_DIR" "$VERSION"
    exit 0
fi

require_commands podman cosign xz find id mkdir mv rm

mkdir -p "$OUTPUT_DIR"

storage_src="${HOME}/.local/share/containers/storage"
in_vm_flag=()
if [[ "$(id -u)" -eq 0 ]]; then
    storage_src="/var/lib/containers/storage"
elif [[ -e /dev/kvm ]]; then
    in_vm_flag+=(--in-vm)
else
    fatal "Rootless USB builds need /dev/kvm. Rerun with sudo on hosts without nested virtualization."
fi

mkdir -p "$storage_src"

info "Verifying signed source image ${IMAGE_REF}"
cosign verify --key "$COSIGN_KEY" "$IMAGE_REF" >/dev/null

info "Building portable USB image from ${IMAGE_REF}"
if podman image exists "$IMAGE_REF"; then
    info "Using existing local image ${IMAGE_REF}"
else
    podman pull "$IMAGE_REF" >/dev/null
fi

podman run \
    --rm \
    --privileged \
    --pull=newer \
    --security-opt label=type:unconfined_t \
    -v "${OUTPUT_DIR}:/output" \
    -v "${storage_src}:/var/lib/containers/storage" \
    "$BUILDER_IMAGE" \
    "${in_vm_flag[@]}" \
    --type raw \
    --use-librepo=True \
    --rootfs "$ROOTFS" \
    "$IMAGE_REF"

raw_source="$(find "$OUTPUT_DIR" -type f \( -name '*.raw' -o -name 'disk.raw' \) | head -1)"
[[ -n "$raw_source" ]] || fatal "raw image not found after build"

raw_target="${OUTPUT_DIR}/secai-os-${VERSION}-x86_64-usb.raw"
xz_target="${raw_target}.xz"
rm -f "$raw_target" "$xz_target"
mv "$raw_source" "$raw_target"
xz -T0 "$XZ_LEVEL" -c "$raw_target" > "$xz_target"

info "Portable USB image written to ${raw_target}"
info "Compressed artifact written to ${xz_target}"
