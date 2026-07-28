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
CONFIG_FILE="/etc/secure-ai/config/appliance.yaml"

log() {
    echo "[select-model] $*"
    logger -t secure-ai-select-model "$*"
}

# GPU execution policy is written by secure-hardware-detect.py and delivered
# through the unit's EnvironmentFile. Do not let the generic appliance config
# override the fail-safe CPU/VM decision.
GPU_LAYERS="${GPU_LAYERS:-0}"
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

# Select only a GGUF entry recorded in the manifest.  The helper rejects path
# traversal, links, non-regular files, and hash drift before returning a path.
MODEL_PATH=""
if [ -f "$MANIFEST_FILE" ]; then
    MODEL_PATH=$(python3 - "$REGISTRY_DIR" "$MANIFEST_FILE" <<'PY'
import hashlib
import json
import os
import stat
import sys

root, manifest_path = sys.argv[1:]
with open(manifest_path, "r", encoding="utf-8") as handle:
    manifest = json.load(handle)

root_real = os.path.realpath(root)
for model in manifest.get("models", []):
    if model.get("format") != "gguf":
        continue
    filename = model.get("filename", "")
    expected = model.get("sha256", "").lower()
    if not filename or filename != os.path.basename(filename):
        continue
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        continue
    candidate = os.path.join(root_real, filename)
    try:
        st = os.lstat(candidate)
    except OSError:
        continue
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
        continue
    if os.path.dirname(os.path.realpath(candidate)) != root_real:
        continue
    digest = hashlib.sha256()
    with open(candidate, "rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() == expected:
        print(candidate)
        break
PY
    )
fi

if [ -z "$MODEL_PATH" ]; then
    log "No model found in $REGISTRY_DIR. Inference will not start."
    log "Import a model via the web UI at http://127.0.0.1:8480"
    # Write empty env so the service fails gracefully
    echo "MODEL_PATH=" > "$ENV_FILE"
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
