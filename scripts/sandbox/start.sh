#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)
SANDBOX_DIR="$REPO_ROOT/deploy/sandbox"
RUNTIME_DIR="$SANDBOX_DIR/runtime"
ENV_EXAMPLE="$SANDBOX_DIR/.env.example"
ENV_FILE="$SANDBOX_DIR/.env"
TOKEN_FILE="$RUNTIME_DIR/service-token"
CONTROL_TOKEN_FILE="$RUNTIME_DIR/control-token"
STATE_VOLUME="secai-sandbox_secai-state"
RUN_VOLUME="secai-sandbox_secai-run"
ALPINE_HELPER_IMAGE="docker.io/library/alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11"

WITH_INFERENCE=0
WITH_DIFFUSION=0
WITH_SEARCH=0
WITH_AIRLOCK=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --with-inference) WITH_INFERENCE=1 ;;
        --with-diffusion) WITH_DIFFUSION=1 ;;
        --with-search) WITH_SEARCH=1 ;;
        --with-airlock) WITH_AIRLOCK=1 ;;
        *)
            echo "Unknown argument: $1" >&2
            echo "Usage: $0 [--with-inference] [--with-diffusion] [--with-search] [--with-airlock]" >&2
            exit 1
            ;;
    esac
    shift
done

mkdir -p "$RUNTIME_DIR"

if [ ! -f "$ENV_FILE" ]; then
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    echo "Created $ENV_FILE from template."
fi

if [ ! -f "$TOKEN_FILE" ] || [ ! -s "$TOKEN_FILE" ]; then
    PYTHON_BIN=$(command -v python3 || command -v python || true)
    if [ -z "$PYTHON_BIN" ]; then
        echo "python3 or python is required to generate the sandbox token." >&2
        exit 1
    fi
    "$PYTHON_BIN" - <<'PY' > "$TOKEN_FILE"
import secrets
print(secrets.token_hex(32), end="")
PY
    echo "Created sandbox service token at $TOKEN_FILE."
fi

if [ ! -f "$CONTROL_TOKEN_FILE" ] || [ ! -s "$CONTROL_TOKEN_FILE" ]; then
    PYTHON_BIN=$(command -v python3 || command -v python || true)
    if [ -z "$PYTHON_BIN" ]; then
        echo "python3 or python is required to generate the sandbox control token." >&2
        exit 1
    fi
    "$PYTHON_BIN" - <<'PY' > "$CONTROL_TOKEN_FILE"
import secrets
print(secrets.token_hex(32), end="")
PY
    echo "Created sandbox control token at $CONTROL_TOKEN_FILE."
fi

PYTHON_BIN=${PYTHON_BIN:-$(command -v python3 || command -v python || true)}
if [ -z "$PYTHON_BIN" ]; then
    echo "python3 or python is required to render the sandbox runtime configuration." >&2
    exit 1
fi

read_env_value() {
    key="$1"
    if [ -f "$ENV_FILE" ]; then
        awk -F= -v key="$key" '$1 == key { value=$2 } END { print value }' "$ENV_FILE" | tr -d '\r'
    fi
    return 0
}

CONTROL_PORT=${SECAI_CONTROL_PORT:-$(read_env_value SECAI_CONTROL_PORT)}
CONTROL_PORT=${CONTROL_PORT:-8498}
if ! "$PYTHON_BIN" - "$CONTROL_PORT" <<'PY' >/dev/null 2>&1; then
import sys
from urllib.request import urlopen
port = sys.argv[1]
with urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as resp:
    raise SystemExit(0 if resp.status == 200 else 1)
PY
    nohup "$PYTHON_BIN" "$REPO_ROOT/scripts/sandbox/control_server.py" \
        --repo-root "$REPO_ROOT" \
        --runtime-dir "$RUNTIME_DIR" \
        --token-path "$CONTROL_TOKEN_FILE" \
        --host 127.0.0.1 \
        --port "$CONTROL_PORT" \
        > "$RUNTIME_DIR/control-server.out.log" \
        2> "$RUNTIME_DIR/control-server.err.log" &
    echo "Started sandbox control server on http://127.0.0.1:$CONTROL_PORT."
fi

set -- "$PYTHON_BIN" "$REPO_ROOT/scripts/sandbox/render_runtime.py" \
    --repo-root "$REPO_ROOT" \
    --runtime-dir "$RUNTIME_DIR"
if [ "$WITH_SEARCH" -eq 1 ] && [ "$WITH_AIRLOCK" -eq 0 ]; then
    WITH_AIRLOCK=1
    echo "Search mode implies the airlock policy in sandbox mode; enabling airlock."
fi
if [ "$WITH_SEARCH" -eq 1 ]; then
    set -- "$@" --enable-search
fi
if [ "$WITH_AIRLOCK" -eq 1 ]; then
    set -- "$@" --enable-airlock
fi
if [ "$WITH_DIFFUSION" -eq 1 ]; then
    set -- "$@" --enable-diffusion
fi
"$@"

if command -v docker >/dev/null 2>&1; then
    RUNTIME_CMD="docker"
    COMPOSE_RUNTIME="docker"
elif command -v podman >/dev/null 2>&1; then
    RUNTIME_CMD="podman"
    COMPOSE_RUNTIME="podman"
else
    echo "Neither docker nor podman was found in PATH." >&2
    exit 1
fi

"$RUNTIME_CMD" volume create "$STATE_VOLUME" >/dev/null
"$RUNTIME_CMD" volume create "$RUN_VOLUME" >/dev/null
"$RUNTIME_CMD" run --rm \
    -v "$STATE_VOLUME:/state" \
    -v "$RUNTIME_DIR:/overlay:ro" \
    "$ALPINE_HELPER_IMAGE" \
    sh -c "mkdir -p /state/auth /state/import-staging /state/logs /state/quarantine /state/registry /state/state /state/vault/user_docs /state/vault/outputs && if [ -f /overlay/state/profile.json ]; then cp /overlay/state/profile.json /state/state/profile.json; chmod 0644 /state/state/profile.json; fi && chown -R 65534:65534 /state" >/dev/null
"$RUNTIME_CMD" run --rm \
    -v "$RUN_VOLUME:/runstate" \
    "$ALPINE_HELPER_IMAGE" \
    sh -c "mkdir -p /runstate && chown -R 65534:65534 /runstate && chmod 0770 /runstate" >/dev/null

DISABLED_SERVICES=""
if [ "$WITH_SEARCH" -eq 0 ]; then
    DISABLED_SERVICES="$DISABLED_SERVICES tor searxng"
fi
if [ "$WITH_INFERENCE" -eq 0 ]; then
    DISABLED_SERVICES="$DISABLED_SERVICES inference"
fi
if [ "$WITH_DIFFUSION" -eq 0 ]; then
    DISABLED_SERVICES="$DISABLED_SERVICES diffusion"
fi
if [ -n "$DISABLED_SERVICES" ]; then
    # shellcheck disable=SC2086
    "$COMPOSE_RUNTIME" compose -f "$SANDBOX_DIR/compose.yaml" \
        --profile search --profile llm --profile diffusion \
        rm -sf $DISABLED_SERVICES >/dev/null
fi

set -- "$COMPOSE_RUNTIME" compose -f "$SANDBOX_DIR/compose.yaml"
if [ "$WITH_INFERENCE" -eq 1 ]; then
    set -- "$@" --profile llm
fi
if [ "$WITH_DIFFUSION" -eq 1 ]; then
    set -- "$@" --profile diffusion
fi
if [ "$WITH_SEARCH" -eq 1 ]; then
    set -- "$@" --profile search
fi
set -- "$@" up -d --build --remove-orphans
if [ "$RUNTIME_CMD" = "docker" ]; then
    set -- "$@" --wait
fi

"$@"

echo "SecAI Sandbox is ready. Open http://127.0.0.1:$(awk -F= '/^SECAI_UI_PORT=/{print $2}' "$ENV_FILE" | tail -n1 | tr -d '\r')"
