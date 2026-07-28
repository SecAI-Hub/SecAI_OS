#!/usr/bin/env bash
#
# Rebuild Linux/x86_64 diffusion locks for CPython 3.12.13/3.14.5 and
# the CPython 3.12 on-demand wheel manifest.
#
# The resolver is pinned because changes in resolver/index behavior can change
# both the selected graph and the set of artifact hashes. All outputs are
# staged first; checked-in files are replaced only after every backend succeeds.
#
# Usage:
#   scripts/generate-diffusion-locks.sh
#   scripts/generate-diffusion-locks.sh --locks-only
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPTS_DIR="${REPO_ROOT}/files/scripts"
MANIFEST="${SCRIPTS_DIR}/diffusion-runtime-manifest.yaml"
UV_VERSION="0.11.21"
PYTHON_BIN="${PYTHON_BIN:-python3}"
LOCKS_ONLY=false

case "${1:-}" in
    "") ;;
    --locks-only) LOCKS_ONLY=true ;;
    *)
        echo "usage: $0 [--locks-only]" >&2
        exit 64
        ;;
esac

if ! command -v uv >/dev/null 2>&1; then
    echo "ERROR: uv ${UV_VERSION} is required to regenerate diffusion locks" >&2
    exit 69
fi
if [ "$(uv --version | awk '{print $2}')" != "$UV_VERSION" ]; then
    echo "ERROR: expected uv ${UV_VERSION}, found: $(uv --version)" >&2
    exit 69
fi

# Stage beside the checked-in artifacts so each final rename is guaranteed to
# be atomic (not a cross-filesystem copy). Nothing is published until every
# requested lock and the manifest have passed generation.
WORK_DIR="$(mktemp -d "${SCRIPTS_DIR}/.diffusion-locks.XXXXXX")"
trap 'rm -rf -- "$WORK_DIR"' EXIT
UV_CACHE_DIR="${UV_CACHE_DIR:-${WORK_DIR}/uv-cache}"
mkdir -p "${WORK_DIR}/locks" "${WORK_DIR}/pylocks" "$UV_CACHE_DIR"

backend_config() {
    case "$1" in
        cpu)
            index="https://download.pytorch.org/whl/cpu"
            uv_torch_backend="cpu"
            ;;
        cuda)
            index="https://download.pytorch.org/whl/cu129"
            uv_torch_backend="cu129"
            ;;
        rocm)
            index="https://download.pytorch.org/whl/rocm7.1"
            uv_torch_backend="rocm7.1"
            ;;
        *)
            echo "ERROR: unsupported diffusion backend: $1" >&2
            exit 64
            ;;
    esac
}

echo "=== SecAI diffusion lock generator ==="
echo "  resolver: uv ${UV_VERSION}"
echo "  targets:  CPython 3.12.13 and 3.14.5, x86_64-manylinux_2_28"

for python_version in 3.12.13 3.14.5; do
    python_suffix=""
    if [ "$python_version" = "3.14.5" ]; then
        python_suffix="-py314"
    fi
    for backend in cpu cuda rocm; do
        input="${SCRIPTS_DIR}/diffusion-${backend}.in"
        output="${WORK_DIR}/locks/diffusion-${backend}${python_suffix}.lock"
        backend_config "$backend"
        echo "  resolving ${backend} for Python ${python_version}"
        uv pip compile "$input" \
            --python-version "$python_version" \
            --python-platform x86_64-manylinux_2_28 \
            --extra-index-url "$index" \
            --index-strategy unsafe-best-match \
            --generate-hashes \
            --only-binary=:all: \
            --emit-index-url \
            --cache-dir "$UV_CACHE_DIR" \
            --upgrade \
            --output-file "$output" \
            --custom-compile-command "scripts/generate-diffusion-locks.sh --locks-only" \
            >/dev/null

        # pip does not provide per-package index selection. Leaving PyTorch as
        # an extra index allows mirrored packages such as MarkupSafe to win
        # over PyPI, which breaks reviewed hashes and creates dependency-
        # confusion risk. Restrict secondary locations to package listings.
        source_rewrite="${output}.sources"
        awk -v baseurl="$index" -v backend="$backend" '
            /^--extra-index-url / {
                print "--find-links " baseurl "/torch/"
                print "--find-links " baseurl "/torchvision/"
                if (backend == "cuda") {
                    print "--find-links " baseurl "/triton/"
                } else if (backend == "rocm") {
                    print "--find-links " baseurl "/triton-rocm/"
                }
                next
            }
            { print }
        ' "$output" > "$source_rewrite"
        mv "$source_rewrite" "$output"
    done
done

if [ "$LOCKS_ONLY" = false ]; then
    if ! "$PYTHON_BIN" -c 'import sys, tomllib, yaml; assert sys.version_info >= (3, 11)' >/dev/null 2>&1; then
        echo "ERROR: ${PYTHON_BIN} must be Python 3.11+ with PyYAML installed" >&2
        exit 69
    fi

    # PEP 751 output records the exact compatible Linux wheel URL. The
    # PyTorch backend option keeps non-PyTorch packages on PyPI instead of
    # selecting duplicate packages mirrored by the PyTorch index.
    for backend in cpu cuda rocm; do
        backend_config "$backend"
        uv pip compile "${SCRIPTS_DIR}/diffusion-${backend}.in" \
            --python-version 3.12.13 \
            --python-platform x86_64-manylinux_2_28 \
            --torch-backend "$uv_torch_backend" \
            --generate-hashes \
            --only-binary=:all: \
            --cache-dir "$UV_CACHE_DIR" \
            --upgrade \
            --format pylock.toml \
            --output-file "${WORK_DIR}/pylocks/pylock.${backend}.toml" \
            --custom-compile-command "scripts/generate-diffusion-locks.sh" \
            >/dev/null
    done

    "$PYTHON_BIN" "${REPO_ROOT}/scripts/generate-diffusion-manifest.py" \
        --template "$MANIFEST" \
        --lock-dir "${WORK_DIR}/locks" \
        --pylock-dir "${WORK_DIR}/pylocks" \
        --output "${WORK_DIR}/diffusion-runtime-manifest.yaml"
fi

# Publish only after all requested outputs have been generated and validated.
chmod 0644 "${WORK_DIR}/locks/"*.lock
if [ "$LOCKS_ONLY" = false ]; then
    chmod 0644 "${WORK_DIR}/diffusion-runtime-manifest.yaml"
fi
for python_suffix in "" "-py314"; do
    for backend in cpu cuda rocm; do
        mv "${WORK_DIR}/locks/diffusion-${backend}${python_suffix}.lock" \
           "${SCRIPTS_DIR}/diffusion-${backend}${python_suffix}.lock"
    done
done
if [ "$LOCKS_ONLY" = false ]; then
    mv "${WORK_DIR}/diffusion-runtime-manifest.yaml" "$MANIFEST"
fi

echo "=== Diffusion dependency artifacts regenerated successfully ==="
