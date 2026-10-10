#!/usr/bin/env bash
#
# Secure AI Appliance — Model Selector
#
# Resolves a model only from the trusted registry manifest, re-hashes it, and
# writes validated worker configuration for start-inference.sh.

set -euo pipefail

ENV_FILE="${1:-/run/secure-ai-inference/model.env}"
REGISTRY_DIR="${REGISTRY_DIR:-/var/lib/secure-ai/vault/models}"
MANIFEST_FILE="${REGISTRY_MANIFEST_PATH:-/var/lib/secure-ai/registry/manifest.json}"
SELECTION_FILE="${INFERENCE_SELECTION_PATH:-/var/lib/secure-ai/inference/selection.json}"
INFERENCE_HELPER_DIR=$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")
CONFIG_FILE="/etc/secure-ai/config/appliance.yaml"

log() {
    echo "[select-model] $*"
    logger -t secure-ai-select-model "$*"
}

# GPU execution policy is written by secure-hardware-detect.py and delivered
# through the unit's EnvironmentFile. Do not let the generic appliance config
# override the fail-safe CPU/VM decision.
GPU_LAYERS="${GPU_LAYERS:-0}"
if ! GPU_LAYERS=$(python3 "$INFERENCE_HELPER_DIR/apply-inference-model.py" gpu-layers "$GPU_LAYERS"); then
    log "GPU assurance execution policy could not be verified. Inference will not start."
    exit 1
fi
CTX_SIZE="${CTX_SIZE:-8192}"
THREADS="${THREADS:-4}"

if [ -f "$CONFIG_FILE" ] && command -v python3 &>/dev/null; then
    configured_context=$(python3 - "$CONFIG_FILE" <<'PY' 2>/dev/null || true
import sys

import yaml

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    value = config.get("inference", {}).get("context_size", 8192)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("context_size must be an integer")
    print(value)
except (AttributeError, OSError, ValueError, yaml.YAMLError):
    pass
PY
    )
    if [[ "$configured_context" =~ ^[0-9]+$ ]] \
        && [ "$configured_context" -ge 256 ] \
        && [ "$configured_context" -le 131072 ]; then
        CTX_SIZE="$configured_context"
    fi
fi

if [[ ! "$GPU_LAYERS" =~ ^(-1|0)$ ]]; then
    log "Refusing invalid typed GPU_LAYERS policy: $GPU_LAYERS"
    exit 1
fi
if [[ ! "$CTX_SIZE" =~ ^[0-9]+$ ]] \
    || [ "$CTX_SIZE" -lt 256 ] \
    || [ "$CTX_SIZE" -gt 131072 ]; then
    log "Refusing invalid CTX_SIZE: $CTX_SIZE"
    exit 1
fi
if [[ ! "$THREADS" =~ ^[0-9]+$ ]] \
    || [ "$THREADS" -lt 1 ] \
    || [ "$THREADS" -gt 512 ]; then
    log "Refusing invalid THREADS: $THREADS"
    exit 1
fi

# Explicit selections are root-owned and bind one filename/hash. The shared
# resolver never falls back when that selection is invalid or unavailable.
if ! MODEL_PATH=$(REGISTRY_DIR="$REGISTRY_DIR" REGISTRY_MANIFEST_PATH="$MANIFEST_FILE" \
    INFERENCE_SELECTION_PATH="$SELECTION_FILE" \
    python3 "$INFERENCE_HELPER_DIR/apply-inference-model.py" resolve); then
    log "Model selection could not be verified. Inference will not start."
    exit 1
fi

log "Selected manifest-bound model: $MODEL_PATH"
log "GPU layers: $GPU_LAYERS, context: $CTX_SIZE, threads: $THREADS"

mkdir -p "$(dirname "$ENV_FILE")"
{
    printf 'MODEL_PATH=%q\n' "$MODEL_PATH"
    printf 'GPU_LAYERS=%q\n' "$GPU_LAYERS"
    printf 'CTX_SIZE=%q\n' "$CTX_SIZE"
    printf 'THREADS=%q\n' "$THREADS"
} > "$ENV_FILE"
chmod 0600 "$ENV_FILE"
