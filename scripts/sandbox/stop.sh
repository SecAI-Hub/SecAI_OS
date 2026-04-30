#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)
SANDBOX_DIR="$REPO_ROOT/deploy/sandbox"
RUNTIME_DIR="$SANDBOX_DIR/runtime"
ENV_FILE="$SANDBOX_DIR/.env"
CONTROL_TOKEN_FILE="$RUNTIME_DIR/control-token"

read_env_value() {
    key="$1"
    if [ -f "$ENV_FILE" ]; then
        awk -F= -v key="$key" '$1 == key { value=$2 } END { print value }' "$ENV_FILE" | tr -d '\r'
    fi
    return 0
}

stop_control_server() {
    PYTHON_BIN=$(command -v python3 || command -v python || true)
    if [ -z "$PYTHON_BIN" ]; then
        return
    fi
    CONTROL_PORT=${SECAI_CONTROL_PORT:-$(read_env_value SECAI_CONTROL_PORT)}
    CONTROL_PORT=${CONTROL_PORT:-8498}
    "$PYTHON_BIN" "$REPO_ROOT/scripts/sandbox/control_server.py" \
        --repo-root "$REPO_ROOT" \
        --runtime-dir "$RUNTIME_DIR" \
        --token-path "$CONTROL_TOKEN_FILE" \
        --host 127.0.0.1 \
        --port "$CONTROL_PORT" \
        --stop >/dev/null 2>&1 || true
}

if command -v docker >/dev/null 2>&1; then
    docker compose -f "$SANDBOX_DIR/compose.yaml" --profile search --profile llm --profile diffusion down --remove-orphans
    status=$?
    stop_control_server
    exit "$status"
elif command -v podman >/dev/null 2>&1; then
    podman compose -f "$SANDBOX_DIR/compose.yaml" --profile search --profile llm --profile diffusion down --remove-orphans
    status=$?
    stop_control_server
    exit "$status"
else
    echo "Neither docker nor podman was found in PATH." >&2
    exit 1
fi
