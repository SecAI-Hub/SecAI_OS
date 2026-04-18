#!/usr/bin/env bash
#
# Build a portable SecAI OS USB image from the published bootc container.
#
set -euo pipefail

IMAGE_REF="ghcr.io/secai-hub/secai_os:latest"
OUTPUT_DIR="./output"
VERSION="dev"
BUILDER_IMAGE="quay.io/centos-bootc/bootc-image-builder:latest"
ROOTFS="btrfs"
XZ_LEVEL="-3"

usage() {
    cat <<'EOF'
Usage: build-usb-image.sh [options]

Options:
  --image-ref <ref>      OCI image reference to build from
  --output-dir <dir>     Output directory (default: ./output)
  --version <version>    Version label used in output filenames
  --builder-image <ref>  bootc-image-builder container image
  --rootfs <type>        Root filesystem type (default: btrfs)
  --xz-level <level>     xz compression level, e.g. -3 or -9 (default: -3)
  --help                 Show this help text
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image-ref)
            IMAGE_REF="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        --builder-image)
            BUILDER_IMAGE="$2"
            shift 2
            ;;
        --rootfs)
            ROOTFS="$2"
            shift 2
            ;;
        --xz-level)
            XZ_LEVEL="$2"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage
            exit 2
            ;;
    esac
done

if ! command -v podman >/dev/null 2>&1; then
    echo "podman is required to build the portable USB image" >&2
    exit 2
fi

if ! command -v xz >/dev/null 2>&1; then
    echo "xz is required to compress the portable USB image" >&2
    exit 2
fi

mkdir -p "$OUTPUT_DIR"

STORAGE_SRC="${HOME}/.local/share/containers/storage"
IN_VM_FLAG=()
if [ "$(id -u)" -eq 0 ]; then
    STORAGE_SRC="/var/lib/containers/storage"
else
    if [ ! -e /dev/kvm ]; then
        echo "rootless builds need /dev/kvm; rerun with sudo on hosts without nested virtualization" >&2
        exit 2
    fi
    IN_VM_FLAG+=(--in-vm)
fi

mkdir -p "$STORAGE_SRC"

echo "Building portable USB image from ${IMAGE_REF}"
if podman image exists "$IMAGE_REF"; then
    echo "Using existing local image ${IMAGE_REF}"
else
    podman pull "$IMAGE_REF" >/dev/null
fi
podman run \
    --rm \
    --privileged \
    --pull=newer \
    --security-opt label=type:unconfined_t \
    -v "${OUTPUT_DIR}:/output" \
    -v "${STORAGE_SRC}:/var/lib/containers/storage" \
    "$BUILDER_IMAGE" \
    "${IN_VM_FLAG[@]}" \
    --type raw \
    --use-librepo=True \
    --rootfs "$ROOTFS" \
    "$IMAGE_REF"

RAW_SOURCE="$(find "$OUTPUT_DIR" -type f \( -name '*.raw' -o -name 'disk.raw' \) | head -1)"
if [ -z "$RAW_SOURCE" ]; then
    echo "raw image not found after build" >&2
    exit 1
fi

RAW_TARGET="${OUTPUT_DIR}/secai-os-${VERSION}-x86_64-usb.raw"
XZ_TARGET="${RAW_TARGET}.xz"
mv "$RAW_SOURCE" "$RAW_TARGET"

rm -f "$XZ_TARGET"
xz -T0 "$XZ_LEVEL" -c "$RAW_TARGET" > "$XZ_TARGET"

echo "Portable USB image written to:"
echo "  ${RAW_TARGET}"
echo "Compressed artifact written to:"
echo "  ${XZ_TARGET}"
