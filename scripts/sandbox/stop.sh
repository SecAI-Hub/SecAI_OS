#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)
SANDBOX_DIR="$REPO_ROOT/deploy/sandbox"
RUNTIME_DIR="$SANDBOX_DIR/runtime"
CONTROL_TOKEN_FILE="$RUNTIME_DIR/control-token"
RUNTIME_STATE_FILE="$RUNTIME_DIR/container-runtime"
LAUNCHER_LOCK_DIR="$RUNTIME_DIR/launcher.lock"
GENERATION_STATUS_SCRIPT="$REPO_ROOT/scripts/sandbox/generation_status.py"
ENV_FILE="$SANDBOX_DIR/.env"

if [ -L "$RUNTIME_DIR" ]; then
    echo "Sandbox runtime path must be a real directory, not a symlink." >&2
    exit 1
fi
mkdir -p "$RUNTIME_DIR"
if [ ! -d "$RUNTIME_DIR" ] || [ -L "$RUNTIME_DIR" ]; then
    echo "Sandbox runtime path must be a real directory, not a symlink." >&2
    exit 1
fi
chmod 700 "$RUNTIME_DIR"

LAUNCHER_LOCK_HELD=0

report_unowned_launcher_lock() {
    echo "The sandbox operation lock at $LAUNCHER_LOCK_DIR cannot be verified safely." >&2
    echo "It may belong to another PID namespace or an interrupted launcher with active container-engine children." >&2
    echo "Verify no sandbox launcher, profile apply, or container-engine command is running, then remove only that lock entry manually and retry." >&2
}

# Called by the EXIT/signal trap below.
# shellcheck disable=SC2329
release_launcher_lock() {
    if [ "$LAUNCHER_LOCK_HELD" -ne 1 ]; then
        return
    fi
    if [ ! -d "$LAUNCHER_LOCK_DIR" ] || [ -L "$LAUNCHER_LOCK_DIR" ]; then
        LAUNCHER_LOCK_HELD=0
        return
    fi
    lock_owner=""
    if [ -f "$LAUNCHER_LOCK_DIR/pid" ] && [ ! -L "$LAUNCHER_LOCK_DIR/pid" ]; then
        lock_owner=$(LC_ALL=C sed -n '1p' "$LAUNCHER_LOCK_DIR/pid")
    fi
    if [ -z "$lock_owner" ] || [ "$lock_owner" = "$$" ]; then
        if [ -e "$LAUNCHER_LOCK_DIR/pid" ]; then
            rm -f "$LAUNCHER_LOCK_DIR/pid"
        fi
        rmdir "$LAUNCHER_LOCK_DIR" 2>/dev/null || true
    fi
    LAUNCHER_LOCK_HELD=0
}

acquire_launcher_lock() {
    if [ -L "$LAUNCHER_LOCK_DIR" ] || {
        [ -e "$LAUNCHER_LOCK_DIR" ] && [ ! -d "$LAUNCHER_LOCK_DIR" ]
    }; then
        report_unowned_launcher_lock
        return 1
    fi
    if ! mkdir "$LAUNCHER_LOCK_DIR" 2>/dev/null; then
        if [ ! -d "$LAUNCHER_LOCK_DIR" ] || [ -L "$LAUNCHER_LOCK_DIR" ]; then
            report_unowned_launcher_lock
            return 1
        fi
        if [ ! -f "$LAUNCHER_LOCK_DIR/pid" ] || [ -L "$LAUNCHER_LOCK_DIR/pid" ]; then
            report_unowned_launcher_lock
            return 1
        fi
        lock_owner=$(LC_ALL=C sed -n '1p' "$LAUNCHER_LOCK_DIR/pid")
        case "$lock_owner" in
            ""|*[!0-9]*)
                report_unowned_launcher_lock
                return 1
                ;;
        esac
        if kill -0 "$lock_owner" 2>/dev/null; then
            echo "Another sandbox start, stop, or profile apply is already running (PID $lock_owner)." >&2
            return 1
        fi
        report_unowned_launcher_lock
        return 1
    fi
    LAUNCHER_LOCK_HELD=1
    if ! (set -C; umask 077 && printf '%s' "$$" > "$LAUNCHER_LOCK_DIR/pid"); then
        release_launcher_lock
        return 1
    fi
    if ! chmod 600 "$LAUNCHER_LOCK_DIR/pid"; then
        release_launcher_lock
        return 1
    fi
}

# shellcheck disable=SC2329
cleanup_launcher_lock() {
    exit_code=$?
    trap - EXIT HUP INT TERM
    release_launcher_lock
    exit "$exit_code"
}

trap cleanup_launcher_lock EXIT
trap 'exit 130' HUP INT TERM
acquire_launcher_lock

read_env_value() {
    key="$1"
    if [ -f "$ENV_FILE" ]; then
        awk -F= -v key="$key" '$1 == key { value=$2 } END { print value }' "$ENV_FILE" | tr -d '\r'
    fi
    return 0
}

version_at_least() {
    version="${1%%-*}"
    minimum_major="$2"
    minimum_minor="$3"
    major="${version%%.*}"
    remainder="${version#*.}"
    minor="${remainder%%.*}"
    case "$major:$minor" in
        *[!0-9:]*|:|*:) return 1 ;;
    esac
    [ "$major" -gt "$minimum_major" ] || {
        [ "$major" -eq "$minimum_major" ] && [ "$minor" -ge "$minimum_minor" ]
    }
}

podman_is_usable() {
    [ "$(uname -s)" = "Linux" ] || return 1
    command -v podman >/dev/null 2>&1 || return 1
    podman info >/dev/null 2>&1 || return 1
    podman compose version >/dev/null 2>&1 || return 1
    rootless=$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null) || return 1
    [ "$rootless" = "false" ] || return 1
    version=$(podman version --format '{{.Server.Version}}' 2>/dev/null) || return 1
    version_at_least "$version" 5 3
}

docker_is_usable() {
    command -v docker >/dev/null 2>&1 || return 1
    docker info >/dev/null 2>&1 || return 1
    docker compose version >/dev/null 2>&1 || return 1
    version=$(docker version --format '{{.Server.Version}}' 2>/dev/null) || return 1
    version_at_least "$version" 28 0
}

read_persisted_runtime() {
    if [ ! -e "$RUNTIME_STATE_FILE" ]; then
        return 1
    fi
    if [ ! -f "$RUNTIME_STATE_FILE" ] || [ -L "$RUNTIME_STATE_FILE" ]; then
        echo "Sandbox runtime state must be a regular, non-symlink file." >&2
        return 2
    fi
    runtime_bytes=$(wc -c < "$RUNTIME_STATE_FILE" | tr -d ' ')
    persisted_runtime=$(LC_ALL=C sed -n '1p' "$RUNTIME_STATE_FILE")
    if [ "$runtime_bytes" != "6" ] || {
        [ "$persisted_runtime" != "docker" ] &&
        [ "$persisted_runtime" != "podman" ]
    }; then
        echo "Sandbox runtime state is malformed; refusing to guess an engine." >&2
        return 2
    fi
    chmod 600 "$RUNTIME_STATE_FILE"
    printf '%s\n' "$persisted_runtime"
}

resolve_recorded_runtime() {
    requested="${SECAI_CONTAINER_RUNTIME:-$(read_env_value SECAI_CONTAINER_RUNTIME)}"
    requested="${requested:-auto}"
    case "$requested" in
        auto|podman|docker) ;;
        *)
            echo "SECAI_CONTAINER_RUNTIME must be auto, podman, or docker." >&2
            return 1
            ;;
    esac
    if [ -e "$RUNTIME_STATE_FILE" ]; then
        persisted_runtime=$(read_persisted_runtime) || return 1
        if [ "$requested" != "auto" ] && [ "$requested" != "$persisted_runtime" ]; then
            echo "The sandbox is pinned to $persisted_runtime; use that runtime to stop it before selecting $requested." >&2
            return 1
        fi
        printf '%s\n' "$persisted_runtime"
        return 0
    fi
    case "$requested" in
        podman|docker) printf '%s\n' "$requested" ;;
        auto) printf '%s\n' auto ;;
    esac
}

if ! RUNTIME_CMD=$(resolve_recorded_runtime); then
    echo "Could not resolve the recorded sandbox runtime safely." >&2
    exit 1
fi
COMPOSE_PROJECT_NAME=secai-sandbox
export COMPOSE_PROJECT_NAME
PODMAN_CONTROL_NETWORK="${COMPOSE_PROJECT_NAME}_ingress"
PODMAN_ANCHOR_SCRIPT="$REPO_ROOT/scripts/sandbox/podman_anchor.py"
ALPINE_HELPER_IMAGE="docker.io/library/alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40"
PYTHON_BIN=$(command -v python3 || command -v python || true)

stop_control_server() {
    if [ -z "$PYTHON_BIN" ]; then
        return 1
    fi
    "$PYTHON_BIN" "$REPO_ROOT/scripts/sandbox/control_server.py" \
        --repo-root "$REPO_ROOT" \
        --runtime-dir "$RUNTIME_DIR" \
        --token-path "$CONTROL_TOKEN_FILE" \
        --host auto \
        --runtime "$RUNTIME_CMD" \
        --podman-network "$PODMAN_CONTROL_NETWORK" \
        --port 8498 \
        --stop >/dev/null 2>&1
}

set +e
stop_control_server
control_status=$?
set -e
if [ "$control_status" -ne 0 ] &&
    [ -n "$PYTHON_BIN" ] &&
    podman_is_usable
then
    case "$RUNTIME_CMD" in
        podman|auto)
            if "$PYTHON_BIN" "$PODMAN_ANCHOR_SCRIPT" \
                --runtime-dir "$RUNTIME_DIR" \
                --network "$PODMAN_CONTROL_NETWORK" \
                prepare \
                --image "$ALPINE_HELPER_IMAGE" >/dev/null
            then
                set +e
                stop_control_server
                control_status=$?
                set -e
            fi
            ;;
    esac
fi
if [ "$control_status" -ne 0 ]; then
    echo "The sandbox controller did not confirm a clean stop; Compose teardown was not attempted." >&2
    echo "Wait for any active profile change to finish, then retry this command." >&2
    exit "$control_status"
fi

if [ -z "$PYTHON_BIN" ] ||
    ! "$PYTHON_BIN" "$GENERATION_STATUS_SCRIPT" \
        --runtime-dir "$RUNTIME_DIR" \
        invalidate >/dev/null
then
    echo "The sandbox controller is stopped, but the ready-generation marker could not be invalidated safely; Compose teardown was not attempted." >&2
    exit 1
fi

# Compose requires a syntactically valid generation for interpolation even
# during `down`. This value is never used for `up`: prefer the safely validated
# active pointer, but fall back to a fixed non-authoritative ID so a missing or
# corrupt pointer cannot prevent teardown after the controller is stopped.
SECAI_RUNTIME_GENERATION=$(
    "$PYTHON_BIN" - "$RUNTIME_DIR/active-generation" <<'PY' 2>/dev/null
import os
import re
import stat
import sys
from pathlib import Path

path = Path(sys.argv[1])
metadata = os.lstat(path)
if (
    not stat.S_ISREG(metadata.st_mode)
    or metadata.st_size != 64
    or metadata.st_nlink != 1
    or getattr(metadata, "st_file_attributes", 0) & 0x400
):
    raise SystemExit(1)
descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
try:
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_size != 64
        or opened.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
    ):
        raise SystemExit(1)
    payload = os.read(descriptor, 65)
finally:
    os.close(descriptor)
try:
    generation = payload.decode("ascii")
except UnicodeDecodeError:
    raise SystemExit(1)
if not re.fullmatch(r"[0-9a-f]{64}", generation):
    raise SystemExit(1)
print(generation)
PY
) || SECAI_RUNTIME_GENERATION="0000000000000000000000000000000000000000000000000000000000000000"
export SECAI_RUNTIME_GENERATION

if [ "$RUNTIME_CMD" = "auto" ]; then
    if podman_is_usable; then
        RUNTIME_CMD=podman
    elif docker_is_usable; then
        RUNTIME_CMD=docker
    else
        echo "The controller is stopped, but no supported legacy runtime is ready for Compose teardown." >&2
        exit 1
    fi
elif [ "$RUNTIME_CMD" = "podman" ]; then
    if ! podman_is_usable; then
        echo "The controller is stopped, but the recorded rootful Podman 5.3+ runtime is not ready for Compose teardown." >&2
        exit 1
    fi
elif ! docker_is_usable; then
    echo "The controller is stopped, but the recorded Docker Server 28+ runtime is not ready for Compose teardown." >&2
    exit 1
fi

if [ "$RUNTIME_CMD" = "podman" ]; then
    if [ -z "$PYTHON_BIN" ] ||
        ! "$PYTHON_BIN" "$PODMAN_ANCHOR_SCRIPT" \
            --runtime-dir "$RUNTIME_DIR" \
            --network "$PODMAN_CONTROL_NETWORK" \
            remove-recorded
    then
        echo "The controller is stopped, but the recorded Podman control-network anchor could not be removed safely." >&2
        exit 1
    fi
fi

if [ "$RUNTIME_CMD" = "docker" ]; then
    set +e
    docker compose -f "$SANDBOX_DIR/compose.yaml" --profile search --profile llm --profile diffusion down --remove-orphans
    status=$?
    set -e
else
    set +e
    podman compose -f "$SANDBOX_DIR/compose.yaml" --profile search --profile llm --profile diffusion down --remove-orphans
    status=$?
    set -e
fi

if [ "$status" -eq 0 ]; then
    rm -f "$RUNTIME_STATE_FILE"
fi
exit "$status"
