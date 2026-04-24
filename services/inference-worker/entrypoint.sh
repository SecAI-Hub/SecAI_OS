#!/bin/sh
set -eu

# Defaults (overridable via environment)
BIND="${BIND_ADDR:-0.0.0.0:8465}"
MODEL="${MODEL_PATH:-}"
CTX_SIZE="${CONTEXT_SIZE:-8192}"
GPU_LAYERS="${GPU_LAYERS:--1}"
REGISTRY_DIR="${REGISTRY_DIR:-/var/lib/secure-ai/registry}"

if [ -z "$MODEL" ]; then
    MODEL_CANDIDATES=$(find "$REGISTRY_DIR" -maxdepth 1 -type f -name '*.gguf' | sort || true)
    MODEL_COUNT=$(printf '%s\n' "$MODEL_CANDIDATES" | sed '/^$/d' | wc -l | tr -d ' ')
    if [ "$MODEL_COUNT" -eq 1 ]; then
        MODEL=$(printf '%s\n' "$MODEL_CANDIDATES" | sed '/^$/d')
        echo "Auto-selected promoted model from registry: $MODEL"
    elif [ "$MODEL_COUNT" -gt 1 ]; then
        echo "ERROR: MODEL_PATH not set and multiple promoted models are present in $REGISTRY_DIR"
        printf '%s\n' "$MODEL_CANDIDATES" | sed '/^$/d'
        echo "Set MODEL_PATH explicitly to the desired .gguf file."
        exit 1
    fi
fi

if [ -z "$MODEL" ]; then
    echo "ERROR: MODEL_PATH not set. No model loaded in registry?"
    echo "Set MODEL_PATH to the full path of a promoted .gguf file."
    exit 1
fi

if [ ! -f "$MODEL" ]; then
    echo "ERROR: Model file not found: $MODEL"
    exit 1
fi

echo "Starting llama-server"
echo "  model:      $MODEL"
echo "  bind:       $BIND"
echo "  ctx_size:   $CTX_SIZE"
echo "  gpu_layers: $GPU_LAYERS"

HOST=$(echo "$BIND" | cut -d: -f1)
PORT=$(echo "$BIND" | cut -d: -f2)
LLAMA_SERVER_BIN="${LLAMA_SERVER_BIN:-}"

if [ -z "$LLAMA_SERVER_BIN" ]; then
    if command -v llama-server >/dev/null 2>&1; then
        LLAMA_SERVER_BIN=$(command -v llama-server)
    elif [ -x /opt/llama-server/llama-server ]; then
        LLAMA_SERVER_BIN=/opt/llama-server/llama-server
    elif [ -x /app/llama-server ]; then
        LLAMA_SERVER_BIN=/app/llama-server
    else
        echo "ERROR: llama-server binary not found in PATH, /opt/llama-server/llama-server, or /app/llama-server"
        exit 1
    fi
fi

exec "$LLAMA_SERVER_BIN" \
    --model "$MODEL" \
    --host "$HOST" \
    --port "$PORT" \
    --ctx-size "$CTX_SIZE" \
    --n-gpu-layers "$GPU_LAYERS" \
    --log-disable
