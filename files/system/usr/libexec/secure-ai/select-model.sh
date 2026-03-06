#!/usr/bin/env bash
#
# Secure AI Appliance — Model Selector
#
# Called by secure-ai-inference.service as ExecStartPre.
# Writes /var/lib/secure-ai/inference.env with the model path and config
# based on the first available model in the registry.

set -euo pipefail

ENV_FILE="/var/lib/secure-ai/inference.env"
REGISTRY_DIR="/var/lib/secure-ai/registry"
CONFIG_FILE="/etc/secure-ai/config/appliance.yaml"

log() {
    echo "[select-model] $*"
    logger -t secure-ai-select-model "$*"
}

# Read GPU layers from appliance config (default: -1 = all layers)
GPU_LAYERS="-1"
CTX_SIZE="8192"
THREADS="4"

if [ -f "$CONFIG_FILE" ] && command -v python3 &>/dev/null; then
    GPU_LAYERS=$(python3 -c "
import yaml
try:
    c = yaml.safe_load(open('$CONFIG_FILE'))
    print(c.get('inference',{}).get('gpu_layers', -1))
except: print(-1)
" 2>/dev/null || echo "-1")
    CTX_SIZE=$(python3 -c "
import yaml
try:
    c = yaml.safe_load(open('$CONFIG_FILE'))
    print(c.get('inference',{}).get('context_size', 8192))
except: print(8192)
" 2>/dev/null || echo "8192")
fi

# Find the first .gguf model in the registry
MODEL_PATH=""
if [ -d "$REGISTRY_DIR" ]; then
    for f in "$REGISTRY_DIR"/*.gguf; do
        if [ -f "$f" ]; then
            MODEL_PATH="$f"
            break
        fi
    done
fi

if [ -z "$MODEL_PATH" ]; then
    log "No model found in $REGISTRY_DIR. Inference will not start."
    log "Import a model via the web UI at http://127.0.0.1:8480"
    # Write empty env so the service fails gracefully
    echo "MODEL_PATH=" > "$ENV_FILE"
    exit 1
fi

log "Selected model: $MODEL_PATH"
log "GPU layers: $GPU_LAYERS, context: $CTX_SIZE, threads: $THREADS"

cat > "$ENV_FILE" <<EOF
MODEL_PATH=$MODEL_PATH
GPU_LAYERS=$GPU_LAYERS
CTX_SIZE=$CTX_SIZE
THREADS=$THREADS
EOF

chmod 644 "$ENV_FILE"
