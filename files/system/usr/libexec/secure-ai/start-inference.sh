#!/usr/bin/env bash
# Resolve a manifest-bound model and start the watchdog-enabled inference worker.

set -euo pipefail
umask 077

MODEL_ENV="${RUNTIME_DIRECTORY:-/run/secure-ai-inference}/model.env"
/usr/libexec/secure-ai/select-model.sh "$MODEL_ENV"

# select-model.sh writes only validated, shell-escaped keys owned by this service.
# shellcheck source=/dev/null
source "$MODEL_ENV"

# llama interprets commas as multiple aliases. Bind one exact registry filename.
MODEL_ALIAS="${MODEL_PATH##*/}"
case "$MODEL_ALIAS" in
    ''|*,*) echo "ERROR: selected model has an invalid API alias" >&2; exit 1 ;;
esac

API_KEY_FILE=$(/usr/libexec/secure-ai/prepare-inference-auth.sh "${RUNTIME_DIRECTORY:-/run/secure-ai-inference}")
unset LLAMA_API_KEY LLAMA_ARG_API_KEY_FILE LLAMA_ARG_ALIAS

# Model selection and hash verification need the registry manifest and the
# private RuntimeDirectory. Apply Landlock immediately afterwards so the
# long-lived watchdog and llama-server inherit the filesystem allowlist.
exec /usr/libexec/secure-ai/landlock-apply.py --require inference -- \
    /usr/libexec/secure-ai/inference-wrapper.sh \
    --host 127.0.0.1 \
    --port "${PORT:-8465}" \
    --api-key-file "$API_KEY_FILE" \
    --model "$MODEL_PATH" \
    --alias "$MODEL_ALIAS" \
    --no-ui \
    --offline \
    --n-gpu-layers "$GPU_LAYERS" \
    --ctx-size "$CTX_SIZE" \
    --threads "$THREADS"
