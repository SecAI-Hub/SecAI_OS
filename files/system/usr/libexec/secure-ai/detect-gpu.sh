#!/bin/bash
#
# Detect available GPU compute backends and write results to inference.env.
# Called by secure-ai-firstboot.service and can be re-run manually.
# Writes: GPU_BACKEND, GPU_NAME, GPU_LAYERS to /var/lib/secure-ai/inference.env
#
set -euo pipefail

ENV_FILE="/var/lib/secure-ai/inference.env"
BACKEND="cpu"
GPU_NAME="CPU (no GPU detected)"
GPU_LAYERS="0"

echo "=== SecAI GPU Detection ==="

# --- NVIDIA (CUDA) ---
if command -v nvidia-smi &>/dev/null && nvidia-smi &>/dev/null; then
    BACKEND="cuda"
    GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader,nounits | head -1)
    GPU_LAYERS="-1"
    echo "Detected NVIDIA GPU: ${GPU_NAME}"

# --- AMD (ROCm) ---
elif [ -e /dev/kfd ] && [ -e /dev/dri/renderD128 ]; then
    BACKEND="rocm"
    # Try rocminfo first, fall back to DRI
    if command -v rocminfo &>/dev/null; then
        GPU_NAME=$(rocminfo 2>/dev/null | grep -m1 "Marketing Name" | sed 's/.*: *//' || echo "AMD GPU")
    else
        GPU_NAME=$(cat /sys/class/drm/card0/device/product_name 2>/dev/null || echo "AMD GPU")
    fi
    GPU_LAYERS="-1"
    echo "Detected AMD GPU (ROCm): ${GPU_NAME}"

# --- Intel (XPU / Arc / integrated) ---
elif [ -e /dev/dri/renderD128 ]; then
    # Check if it's an Intel GPU via sysfs
    DRM_VENDOR=$(cat /sys/class/drm/card0/device/vendor 2>/dev/null || echo "")
    if [ "$DRM_VENDOR" = "0x8086" ]; then
        BACKEND="xpu"
        GPU_NAME=$(cat /sys/class/drm/card0/device/product_name 2>/dev/null || echo "Intel GPU")
        # Intel Arc discrete GPUs get full offload; integrated gets partial
        if command -v intel_gpu_top &>/dev/null || [[ "$GPU_NAME" == *"Arc"* ]]; then
            GPU_LAYERS="-1"
        else
            GPU_LAYERS="0"  # integrated Intel — CPU inference is usually faster
        fi
        echo "Detected Intel GPU: ${GPU_NAME}"
    else
        echo "DRI device found but vendor ${DRM_VENDOR} not recognized for compute"
    fi
fi

# --- Vulkan fallback check ---
if [ "$BACKEND" = "cpu" ] && command -v vulkaninfo &>/dev/null; then
    VULKAN_GPU=$(vulkaninfo --summary 2>/dev/null | grep -m1 "deviceName" | sed 's/.*= *//' || echo "")
    if [ -n "$VULKAN_GPU" ]; then
        BACKEND="vulkan"
        GPU_NAME="$VULKAN_GPU (Vulkan)"
        GPU_LAYERS="-1"
        echo "Detected Vulkan-capable GPU: ${GPU_NAME}"
    fi
fi

echo "Result: backend=${BACKEND} gpu=${GPU_NAME} layers=${GPU_LAYERS}"

# Write environment file for inference and diffusion services
mkdir -p "$(dirname "$ENV_FILE")"
cat > "$ENV_FILE" <<EOF
# Auto-detected by detect-gpu.sh — re-run to update
GPU_BACKEND=${BACKEND}
GPU_NAME=${GPU_NAME}
GPU_LAYERS=${GPU_LAYERS}
EOF

echo "Written to ${ENV_FILE}"
echo "=== GPU Detection Complete ==="
