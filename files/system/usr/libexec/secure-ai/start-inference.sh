#!/usr/bin/env bash
# Resolve a manifest-bound model and start the watchdog-enabled inference worker.

set -euo pipefail
umask 077

MODEL_ENV="${RUNTIME_DIRECTORY:-/run/secure-ai-inference}/model.env"
/usr/libexec/secure-ai/select-model.sh "$MODEL_ENV"

# select-model.sh writes only validated, shell-escaped keys owned by this service.
# shellcheck source=/dev/null
source "$MODEL_ENV"

# Model selection and hash verification need the registry manifest and the
# private RuntimeDirectory. Apply Landlock immediately afterwards so the
# long-lived watchdog and llama-server inherit the filesystem allowlist.
exec /usr/libexec/secure-ai/landlock-apply.py --require inference -- \
    /usr/libexec/secure-ai/inference-wrapper.sh \
    --host 127.0.0.1 \
    --port "${PORT:-8465}" \
    --model "$MODEL_PATH" \
    --n-gpu-layers "$GPU_LAYERS" \
    --ctx-size "$CTX_SIZE" \
    --threads "$THREADS"
