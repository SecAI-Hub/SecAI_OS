#!/bin/sh
set -eu

# Defaults (overridable via environment)
BIND="${BIND_ADDR:-0.0.0.0:8465}"
MODEL="${MODEL_PATH:-}"
CTX_SIZE="${CONTEXT_SIZE:-8192}"
GPU_LAYERS="${GPU_LAYERS:--1}"

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

exec llama-server \
    --model "$MODEL" \
    --host "$HOST" \
    --port "$PORT" \
    --ctx-size "$CTX_SIZE" \
    --n-gpu-layers "$GPU_LAYERS" \
    --log-disable
