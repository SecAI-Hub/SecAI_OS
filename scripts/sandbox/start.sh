#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)
SANDBOX_DIR="$REPO_ROOT/deploy/sandbox"
RUNTIME_DIR="$SANDBOX_DIR/runtime"
ENV_EXAMPLE="$SANDBOX_DIR/.env.example"
ENV_FILE="$SANDBOX_DIR/.env"
CONTROL_TOKEN_FILE="$RUNTIME_DIR/control-token"
RUNTIME_STATE_FILE="$RUNTIME_DIR/container-runtime"
LAUNCHER_LOCK_DIR="$RUNTIME_DIR/launcher.lock"
GENERATION_STATUS_SCRIPT="$REPO_ROOT/scripts/sandbox/generation_status.py"
LEGACY_STATE_VOLUME="secai-sandbox_secai-state"
REGISTRY_VOLUME="secai-sandbox_secai-registry"
PROMOTION_VOLUME="secai-sandbox_secai-promotion-staging"
QUARANTINE_VOLUME="secai-sandbox_secai-quarantine"
SCANNER_JOBS_VOLUME="secai-sandbox_secai-quarantine-scanner-jobs"
VAULT_VOLUME="secai-sandbox_secai-vault"
LOGS_VOLUME="secai-sandbox_secai-logs"
AUTH_VOLUME="secai-sandbox_secai-auth"
IMPORT_VOLUME="secai-sandbox_secai-import-staging"
UI_ROOT_VOLUME="secai-sandbox_secai-ui-root"
AGENT_STATE_VOLUME="secai-sandbox_secai-agent-state"
RUN_VOLUME="secai-sandbox_secai-run"
ALPINE_HELPER_IMAGE="docker.io/library/alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40"

WITH_INFERENCE=0
WITH_DIFFUSION=0
WITH_SEARCH=0
WITH_AIRLOCK=0
WITH_GPU=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --with-inference) WITH_INFERENCE=1 ;;
        --with-diffusion) WITH_DIFFUSION=1 ;;
        --with-search) WITH_SEARCH=1 ;;
        --with-airlock) WITH_AIRLOCK=1 ;;
        --with-gpu) WITH_GPU=1 ;;
        *)
            echo "Unknown argument: $1" >&2
            echo "Usage: $0 [--with-inference] [--with-diffusion] [--with-search] [--with-airlock] [--with-gpu]" >&2
            exit 1
            ;;
    esac
    shift
done

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

early_cleanup() {
    exit_code=$?
    trap - EXIT HUP INT TERM
    release_launcher_lock
    exit "$exit_code"
}

trap early_cleanup EXIT
trap 'exit 130' HUP INT TERM
acquire_launcher_lock

PYTHON_BIN=$(command -v python3 || command -v python || true)
if [ -z "$PYTHON_BIN" ]; then
    echo "python3 or python is required to prepare the sandbox configuration." >&2
    exit 1
fi

if ! "$PYTHON_BIN" - "$ENV_EXAMPLE" "$ENV_FILE" <<'PY'; then
import os
import stat
import sys
import secrets
from pathlib import Path

source = Path(sys.argv[1])
target = Path(sys.argv[2])
maximum_size = 1024 * 1024


def real_regular_metadata(path: Path) -> os.stat_result:
    metadata = os.lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum_size:
        raise RuntimeError(f"{path} must be a bounded real regular file")
    return metadata


def read_verified(path: Path) -> bytes:
    metadata = real_regular_metadata(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            raise RuntimeError(f"{path} changed during validation")
        payload = b""
        while len(payload) <= maximum_size:
            chunk = os.read(descriptor, min(65536, maximum_size + 1 - len(payload)))
            if not chunk:
                break
            payload += chunk
        if len(payload) > maximum_size:
            raise RuntimeError(f"{path} exceeds the maximum supported size")
        return payload
    finally:
        os.close(descriptor)


def secure_existing(path: Path) -> None:
    metadata = real_regular_metadata(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            raise RuntimeError(f"{path} changed during validation")
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


parent_metadata = os.lstat(target.parent)
if not stat.S_ISDIR(parent_metadata.st_mode):
    raise RuntimeError("sandbox .env parent must be a real directory")

try:
    secure_existing(target)
except FileNotFoundError:
    payload = read_verified(source)
    temporary = target.with_name(
        f".{target.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("sandbox .env write made no progress")
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(temporary, target)
        except FileExistsError:
            secure_existing(target)
        directory_descriptor = os.open(
            target.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
PY
    echo "Sandbox .env must be an atomically writable real regular file." >&2
    exit 1
fi

if ! CONTROL_TOKEN_STATUS=$(
    "$PYTHON_BIN" "$REPO_ROOT/scripts/sandbox/provision_control_token.py" \
        --runtime-dir "$RUNTIME_DIR" \
        --token-path "$CONTROL_TOKEN_FILE"
); then
    echo "Sandbox control token is malformed. Do not delete runtime metadata while a controller may be active; stop the recorded controller, verify port 8498 is closed, then remove only the token to regenerate it." >&2
    exit 1
fi
case "$CONTROL_TOKEN_STATUS" in
    created)
        echo "Created sandbox control token at $CONTROL_TOKEN_FILE."
        ;;
    existing) ;;
    *)
        echo "Sandbox control-token provisioner returned an invalid result." >&2
        exit 1
        ;;
esac

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
    podman_rootless=$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null) || return 1
    [ "$podman_rootless" = "false" ] || return 1
    podman_version=$(podman version --format '{{.Server.Version}}' 2>/dev/null) || return 1
    version_at_least "$podman_version" 5 3
}

podman_service_container_ids() {
    service_name="$1"
    "$RUNTIME_CMD" ps -aq --no-trunc \
        --filter "label=com.docker.compose.project=secai-sandbox" \
        --filter "label=com.docker.compose.service=$service_name"
}

docker_is_usable() {
    command -v docker >/dev/null 2>&1 || return 1
    docker info >/dev/null 2>&1 || return 1
    docker compose version >/dev/null 2>&1 || return 1
    docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null) || return 1
    version_at_least "$docker_version" 28 0
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

persist_container_runtime() {
    selected_runtime="$1"
    runtime_tmp="$RUNTIME_STATE_FILE.tmp.$$"
    if ! (umask 077 && printf '%s' "$selected_runtime" > "$runtime_tmp"); then
        rm -f "$runtime_tmp"
        return 1
    fi
    chmod 600 "$runtime_tmp"
    if ln "$runtime_tmp" "$RUNTIME_STATE_FILE" 2>/dev/null; then
        rm -f "$runtime_tmp"
        return 0
    fi
    rm -f "$runtime_tmp"
    raced_runtime=$(read_persisted_runtime) || return 1
    if [ "$raced_runtime" != "$selected_runtime" ]; then
        echo "A concurrent launcher pinned the sandbox to $raced_runtime; refusing to continue with $selected_runtime." >&2
        return 1
    fi
}

select_container_runtime() {
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
            echo "The sandbox is pinned to $persisted_runtime; stop it before selecting $requested." >&2
            return 1
        fi
        case "$persisted_runtime" in
            podman)
                if ! podman_is_usable; then
                    echo "The recorded rootful Podman 5.3+ runtime is not ready; refusing to switch engines." >&2
                    return 1
                fi
                ;;
            docker)
                if ! docker_is_usable; then
                    echo "The recorded Docker Server 28+ runtime is not ready; refusing to switch engines." >&2
                    return 1
                fi
                ;;
        esac
        printf '%s\n' "$persisted_runtime"
        return 0
    fi
    case "$requested" in
        podman)
            if ! podman_is_usable; then
                echo "Rootful Podman 5.3+ must be installed and running for SECAI_CONTAINER_RUNTIME=podman; rootless host-loopback routing is unsupported." >&2
                return 1
            fi
            selected_runtime=podman
            ;;
        docker)
            if ! docker_is_usable; then
                echo "Docker Server 28+ must be installed and running for SECAI_CONTAINER_RUNTIME=docker." >&2
                return 1
            fi
            selected_runtime=docker
            ;;
        auto)
            if podman_is_usable; then
                selected_runtime=podman
            elif docker_is_usable; then
                selected_runtime=docker
            else
                echo "No supported runtime is ready; start rootful Podman 5.3+ or Docker Server 28+." >&2
                return 1
            fi
            ;;
    esac
    if ! persist_container_runtime "$selected_runtime"; then
        echo "Could not persist the selected sandbox runtime safely." >&2
        return 1
    fi
    printf '%s\n' "$selected_runtime"
}

RUNTIME_CMD=$(select_container_runtime)
COMPOSE_RUNTIME="$RUNTIME_CMD"
COMPOSE_PROJECT_NAME=secai-sandbox
export COMPOSE_PROJECT_NAME
PODMAN_CONTROL_NETWORK="${COMPOSE_PROJECT_NAME}_ingress"
PODMAN_ANCHOR_SCRIPT="$REPO_ROOT/scripts/sandbox/podman_anchor.py"
PODMAN_ANCHOR_ID=""
PODMAN_ANCHOR_LAUNCH_ID=""
PODMAN_ANCHOR_OWNED=0

# Before mutating readiness or services, preserve only a controller that proves
# the current protocol. Hand every nonzero probe result to the hardened stop
# path, which must confirm both the recorded PID and endpoint are absent.
if [ -e "$RUNTIME_DIR/control-server-host" ] ||
    [ -e "$RUNTIME_DIR/control-server.pid" ]
then
    set +e
    "$PYTHON_BIN" "$REPO_ROOT/scripts/sandbox/control_server.py" \
        --repo-root "$REPO_ROOT" \
        --runtime-dir "$RUNTIME_DIR" \
        --token-path "$CONTROL_TOKEN_FILE" \
        --host auto \
        --runtime "$RUNTIME_CMD" \
        --podman-network "$PODMAN_CONTROL_NETWORK" \
        --port 8498 \
        --probe >/dev/null 2>&1
    early_control_probe_status=$?
    set -e
    if [ "$early_control_probe_status" -ne 0 ]; then
        if ! "$PYTHON_BIN" "$REPO_ROOT/scripts/sandbox/control_server.py" \
            --repo-root "$REPO_ROOT" \
            --runtime-dir "$RUNTIME_DIR" \
            --token-path "$CONTROL_TOKEN_FILE" \
            --host auto \
            --runtime "$RUNTIME_CMD" \
            --podman-network "$PODMAN_CONTROL_NETWORK" \
            --port 8498 \
            --stop >/dev/null 2>&1
        then
            echo "The existing sandbox controller could not be retired safely." >&2
            echo "Readiness and Compose services were left unchanged; stop the controller with its matching launcher and retry." >&2
            exit 1
        fi
    fi
fi

if ! SECAI_RUNTIME_GENERATION=$(
    "$PYTHON_BIN" "$REPO_ROOT/scripts/sandbox/render_runtime.py" \
        --runtime-dir "$RUNTIME_DIR" \
        --read-active 2>/dev/null
); then
    # Parse-only fallback for Compose stop. It is overwritten by the renderer
    # and can never authorize an `up`.
    SECAI_RUNTIME_GENERATION="0000000000000000000000000000000000000000000000000000000000000000"
fi
export SECAI_RUNTIME_GENERATION
if ! "$PYTHON_BIN" "$GENERATION_STATUS_SCRIPT" \
    --runtime-dir "$RUNTIME_DIR" \
    invalidate >/dev/null
then
    echo "The prior sandbox ready-generation marker could not be invalidated safely; existing services were not stopped." >&2
    exit 1
fi
echo "Quiescing existing sandbox services before runtime generation publication."
if ! "$COMPOSE_RUNTIME" compose -f "$SANDBOX_DIR/compose.yaml" \
    --profile search \
    --profile llm \
    --profile diffusion \
    stop
then
    echo "Existing sandbox services could not be quiesced; runtime generation publication was not attempted." >&2
    exit 1
fi
if ! running_project_containers=$(
    "$RUNTIME_CMD" ps -q \
        --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME"
); then
    echo "Container runtime state could not be verified after sandbox quiesce." >&2
    exit 1
fi
if [ -n "$running_project_containers" ]; then
    echo "Sandbox project containers remain running after Compose stop; runtime generation publication was not attempted." >&2
    exit 1
fi

resolve_gpu_backend() {
    configured="${SECAI_DIFFUSION_COMPUTE:-$(read_env_value SECAI_DIFFUSION_COMPUTE)}"
    case "$configured" in
        cuda|rocm) printf '%s\n' "$configured"; return 0 ;;
    esac
    if command -v nvidia-smi >/dev/null 2>&1; then
        printf '%s\n' cuda
        return 0
    fi
    if [ -e /dev/kfd ]; then
        printf '%s\n' rocm
        return 0
    fi
    printf '%s\n' cuda
}

CONFIGURED_CONTROL_PORT=${SECAI_CONTROL_PORT:-$(read_env_value SECAI_CONTROL_PORT)}
if [ -n "$CONFIGURED_CONTROL_PORT" ] && [ "$CONFIGURED_CONTROL_PORT" != "8498" ]; then
    echo "SECAI_CONTROL_PORT is no longer configurable; the fixed relay requires port 8498." >&2
    exit 1
fi
CONTROL_PORT=8498
CONTROL_STARTED=0
CONTROL_PROCESS_PID=0
control_ready=0

cleanup_new_controller() {
    exit_code=$?
    trap - EXIT HUP INT TERM
    if [ "$exit_code" -ne 0 ]; then
        anchor_cleanup_safe=1
        if [ "$CONTROL_STARTED" -eq 1 ]; then
            if "$PYTHON_BIN" "$REPO_ROOT/scripts/sandbox/control_server.py" \
                --repo-root "$REPO_ROOT" \
                --runtime-dir "$RUNTIME_DIR" \
                --token-path "$CONTROL_TOKEN_FILE" \
                --host auto \
                --runtime "$RUNTIME_CMD" \
                --podman-network "$PODMAN_CONTROL_NETWORK" \
                --port "$CONTROL_PORT" \
                --stop >/dev/null 2>&1
            then
                wait "$CONTROL_PROCESS_PID" >/dev/null 2>&1 || true
            else
                anchor_cleanup_safe=0
                echo "Startup failed and the controller could not confirm safe process-tree cleanup; it was left running fail-closed." >&2
            fi
        elif [ "$control_ready" -eq 1 ]; then
            anchor_cleanup_safe=0
        fi
        if [ "$RUNTIME_CMD" = "podman" ] &&
            [ "$PODMAN_ANCHOR_OWNED" -eq 1 ] &&
            [ "$anchor_cleanup_safe" -eq 1 ]
        then
            if ! "$PYTHON_BIN" "$PODMAN_ANCHOR_SCRIPT" \
                --runtime-dir "$RUNTIME_DIR" \
                --network "$PODMAN_CONTROL_NETWORK" \
                remove-owned \
                --container-id "$PODMAN_ANCHOR_ID" \
                --launch-id "$PODMAN_ANCHOR_LAUNCH_ID" >/dev/null 2>&1
            then
                echo "Startup failed and the owned Podman control-network anchor could not be removed safely." >&2
            fi
        fi
    fi
    release_launcher_lock
    exit "$exit_code"
}
trap cleanup_new_controller EXIT
trap 'exit 130' HUP INT TERM

if [ "$RUNTIME_CMD" = "podman" ]; then
    anchor_result=$(
        "$PYTHON_BIN" "$PODMAN_ANCHOR_SCRIPT" \
            --runtime-dir "$RUNTIME_DIR" \
            --network "$PODMAN_CONTROL_NETWORK" \
            prepare \
            --image "$ALPINE_HELPER_IMAGE"
    )
    set -f
    # The helper emits four already-validated, whitespace-free fields.
    # shellcheck disable=SC2086
    set -- $anchor_result
    set +f
    candidate_anchor_id=${2:-}
    candidate_launch_id=${3:-}
    if [ "${4:-}" = 1 ] &&
        [ "${#candidate_anchor_id}" -eq 64 ] &&
        [ "${#candidate_launch_id}" -eq 64 ]
    then
        case "$candidate_anchor_id:$candidate_launch_id" in
            *[!0-9a-f:]*) ;;
            *)
                PODMAN_ANCHOR_ID=$candidate_anchor_id
                PODMAN_ANCHOR_LAUNCH_ID=$candidate_launch_id
                PODMAN_ANCHOR_OWNED=1
                ;;
        esac
    fi
    if [ "$#" -ne 4 ]; then
        echo "Podman control-network anchor returned malformed ownership data." >&2
        exit 1
    fi
    PODMAN_ANCHOR_ID=$2
    PODMAN_ANCHOR_LAUNCH_ID=$3
    PODMAN_ANCHOR_OWNED=$4
    case "$PODMAN_ANCHOR_ID:$PODMAN_ANCHOR_LAUNCH_ID" in
        *[!0-9a-f:]*)
            echo "Podman control-network anchor returned malformed ownership data." >&2
            exit 1
            ;;
    esac
    if [ "${#PODMAN_ANCHOR_ID}" -ne 64 ] ||
        [ "${#PODMAN_ANCHOR_LAUNCH_ID}" -ne 64 ]
    then
        echo "Podman control-network anchor returned malformed ownership data." >&2
        exit 1
    fi
    case "$PODMAN_ANCHOR_OWNED" in
        0|1) ;;
        *)
            echo "Podman control-network anchor returned malformed ownership data." >&2
            exit 1
            ;;
    esac
fi

probe_control_server() {
    "$PYTHON_BIN" "$REPO_ROOT/scripts/sandbox/control_server.py" \
        --repo-root "$REPO_ROOT" \
        --runtime-dir "$RUNTIME_DIR" \
        --token-path "$CONTROL_TOKEN_FILE" \
        --host auto \
        --runtime "$RUNTIME_CMD" \
        --podman-network "$PODMAN_CONTROL_NETWORK" \
        --port "$CONTROL_PORT" \
        --probe >/dev/null 2>&1
}

control_probe_status=0
if probe_control_server; then
    control_ready=1
else
    control_probe_status=$?
    control_ready=0
fi
if [ "$control_ready" -ne 1 ]; then
    if [ "$control_probe_status" -eq 2 ]; then
        echo "An authenticated sandbox controller with an older protocol is running." >&2
        echo "Wait for any active profile change, stop that controller with its matching launcher, then retry." >&2
        exit 1
    fi
    nohup "$PYTHON_BIN" "$REPO_ROOT/scripts/sandbox/control_server.py" \
        --repo-root "$REPO_ROOT" \
        --runtime-dir "$RUNTIME_DIR" \
        --token-path "$CONTROL_TOKEN_FILE" \
        --host auto \
        --runtime "$RUNTIME_CMD" \
        --podman-network "$PODMAN_CONTROL_NETWORK" \
        --port "$CONTROL_PORT" \
        > "$RUNTIME_DIR/control-server.out.log" \
        2> "$RUNTIME_DIR/control-server.err.log" &
    CONTROL_PROCESS_PID=$!
    CONTROL_STARTED=1
    control_attempt=0
    while [ "$control_attempt" -lt 30 ]; do
        if probe_control_server; then
            control_ready=1
            break
        fi
        control_attempt=$((control_attempt + 1))
        sleep 0.1
    done
    if [ "$control_ready" -ne 1 ]; then
        echo "Sandbox control server failed to start; see $RUNTIME_DIR/control-server.err.log." >&2
        exit 1
    fi
    echo "Started sandbox control server on a host-local endpoint at port $CONTROL_PORT."
fi

CONTROL_HOST_ALIAS=$(
    "$PYTHON_BIN" - "$RUNTIME_DIR/control-server-host" <<'PY'
import ipaddress
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    value = path.read_text(encoding="ascii")
    address = ipaddress.ip_address(value)
except (OSError, UnicodeError, ValueError):
    raise SystemExit(1)
private_networks = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
if address.version != 4 or not (
    address.is_loopback or any(address in network for network in private_networks)
):
    raise SystemExit(1)
print("host-gateway" if address.is_loopback else str(address))
PY
) || {
    echo "The recorded sandbox controller address is missing or unsafe." >&2
    exit 1
}
export SECAI_CONTROL_HOST_GATEWAY="$CONTROL_HOST_ALIAS"

set -- "$PYTHON_BIN" "$REPO_ROOT/scripts/sandbox/render_runtime.py" \
    --repo-root "$REPO_ROOT" \
    --runtime-dir "$RUNTIME_DIR"
if [ "$WITH_SEARCH" -eq 1 ] && [ "$WITH_AIRLOCK" -eq 0 ]; then
    WITH_AIRLOCK=1
    echo "Search mode implies the airlock policy in sandbox mode; enabling airlock."
fi
if [ "$WITH_GPU" -eq 1 ] && [ "$WITH_DIFFUSION" -eq 0 ]; then
    WITH_DIFFUSION=1
    echo "GPU acceleration implies the diffusion profile; enabling diffusion."
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
if ! SECAI_RUNTIME_GENERATION=$("$@"); then
    echo "Sandbox runtime generation could not be published safely." >&2
    exit 1
fi
case "$SECAI_RUNTIME_GENERATION" in
    ""|*[!0-9a-f]*)
        echo "Sandbox runtime renderer returned an invalid generation ID." >&2
        exit 1
        ;;
esac
if [ "${#SECAI_RUNTIME_GENERATION}" -ne 64 ]; then
    echo "Sandbox runtime renderer returned an invalid generation ID." >&2
    exit 1
fi
export SECAI_RUNTIME_GENERATION

GPU_COMPOSE_FILE=""
if [ "$WITH_GPU" -eq 1 ]; then
    GPU_BACKEND="$(resolve_gpu_backend)"
    case "$GPU_BACKEND" in
        rocm)
            GPU_COMPOSE_FILE="$SANDBOX_DIR/compose.gpu.rocm.yaml"
            ;;
        *)
            GPU_BACKEND="cuda"
            GPU_COMPOSE_FILE="$SANDBOX_DIR/compose.gpu.nvidia.yaml"
            ;;
    esac
    export SECAI_DIFFUSION_COMPUTE="$GPU_BACKEND"
    export SECAI_DIFFUSION_DEVICE_PREFERENCE="${SECAI_DIFFUSION_DEVICE_PREFERENCE:-auto}"
    export SECAI_DIFFUSION_CPU_OFFLOAD="${SECAI_DIFFUSION_CPU_OFFLOAD:-0}"
    echo "GPU acceleration requested for diffusion ($GPU_BACKEND)."
fi

for volume_name in \
    "$REGISTRY_VOLUME" "$PROMOTION_VOLUME" "$QUARANTINE_VOLUME" "$SCANNER_JOBS_VOLUME" \
    "$VAULT_VOLUME" "$LOGS_VOLUME" "$AUTH_VOLUME" "$IMPORT_VOLUME" \
    "$UI_ROOT_VOLUME" "$AGENT_STATE_VOLUME" "$RUN_VOLUME"
do
    "$RUNTIME_CMD" volume create "$volume_name" >/dev/null
done
"$RUNTIME_CMD" run --rm \
    --network none \
    --read-only \
    --cap-drop ALL \
    --cap-add CHOWN \
    --cap-add DAC_OVERRIDE \
    --cap-add FOWNER \
    --security-opt no-new-privileges \
    --pids-limit 64 \
    --memory 64m \
    --cpus 0.50 \
    -v "$REGISTRY_VOLUME:/volumes/registry" \
    -v "$PROMOTION_VOLUME:/volumes/promotion" \
    -v "$QUARANTINE_VOLUME:/volumes/quarantine" \
    -v "$SCANNER_JOBS_VOLUME:/volumes/scanner-jobs" \
    -v "$VAULT_VOLUME:/volumes/vault" \
    -v "$LOGS_VOLUME:/volumes/logs" \
    -v "$AUTH_VOLUME:/volumes/auth" \
    -v "$IMPORT_VOLUME:/volumes/import-staging" \
    -v "$UI_ROOT_VOLUME:/volumes/ui-root" \
    -v "$AGENT_STATE_VOLUME:/volumes/agent-state" \
    "$ALPINE_HELPER_IMAGE" \
    sh -c "mkdir -p /volumes/registry /volumes/promotion /volumes/quarantine/incoming /volumes/quarantine/processing /volumes/scanner-jobs /volumes/vault/user_docs /volumes/vault/outputs /volumes/logs /volumes/auth /volumes/import-staging/.tmp /volumes/ui-root/state /volumes/ui-root/data /volumes/agent-state && chown -R 65534:65534 /volumes/registry /volumes/promotion /volumes/quarantine /volumes/scanner-jobs /volumes/vault /volumes/logs /volumes/auth /volumes/import-staging /volumes/ui-root /volumes/agent-state && chown -R 65534:65532 /volumes/quarantine/processing && chmod 2750 /volumes/quarantine/processing && chown -R 0:65533 /volumes/scanner-jobs && find /volumes/scanner-jobs -mindepth 1 -maxdepth 1 -type f -exec chmod 0640 {} + && chmod 0700 /volumes/auth /volumes/import-staging /volumes/promotion /volumes/agent-state && chmod 2770 /volumes/scanner-jobs" >/dev/null
if "$RUNTIME_CMD" volume inspect "$LEGACY_STATE_VOLUME" >/dev/null 2>&1; then
    "$RUNTIME_CMD" run --rm \
        --network none \
        --read-only \
        --cap-drop ALL \
        --cap-add CHOWN \
        --cap-add DAC_OVERRIDE \
        --cap-add FOWNER \
        --security-opt no-new-privileges \
        --pids-limit 64 \
        --memory 64m \
        --cpus 0.50 \
        -v "$LEGACY_STATE_VOLUME:/legacy:ro" \
        -v "$REGISTRY_VOLUME:/volumes/registry" \
        -v "$QUARANTINE_VOLUME:/volumes/quarantine" \
        -v "$VAULT_VOLUME:/volumes/vault" \
        -v "$LOGS_VOLUME:/volumes/logs" \
        -v "$AUTH_VOLUME:/volumes/auth" \
        -v "$IMPORT_VOLUME:/volumes/import-staging" \
        -v "$UI_ROOT_VOLUME:/volumes/ui-root" \
        "$ALPINE_HELPER_IMAGE" \
        sh -c "for item in registry quarantine vault logs auth import-staging; do if [ -d \"/legacy/\$item\" ] && [ -z \"\$(ls -A \"/volumes/\$item\" 2>/dev/null)\" ]; then cp -a \"/legacy/\$item/.\" \"/volumes/\$item/\"; fi; done; if [ -d /legacy/state ] && [ -z \"\$(ls -A /volumes/ui-root/state 2>/dev/null)\" ]; then cp -a /legacy/state/. /volumes/ui-root/state/; fi; chown -R 65534:65534 /volumes/registry /volumes/quarantine /volumes/vault /volumes/logs /volumes/auth /volumes/import-staging /volumes/ui-root; chown -R 65534:65532 /volumes/quarantine/processing; chmod 2750 /volumes/quarantine/processing" >/dev/null
    echo "Migrated legacy sandbox state into least-privilege service volumes where empty."
fi
"$RUNTIME_CMD" run --rm \
    --network none \
    --read-only \
    --cap-drop ALL \
    --cap-add CHOWN \
    --cap-add DAC_OVERRIDE \
    --cap-add FOWNER \
    --security-opt no-new-privileges \
    --pids-limit 64 \
    --memory 64m \
    --cpus 0.50 \
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
    set -- "$COMPOSE_RUNTIME" compose -f "$SANDBOX_DIR/compose.yaml"
    if [ -n "$GPU_COMPOSE_FILE" ]; then
        set -- "$@" -f "$GPU_COMPOSE_FILE"
    fi
    set -- "$@" --profile search --profile llm --profile diffusion rm -sf
    # shellcheck disable=SC2086
    "$@" $DISABLED_SERVICES >/dev/null
fi

set -- "$COMPOSE_RUNTIME" compose -f "$SANDBOX_DIR/compose.yaml"
if [ -n "$GPU_COMPOSE_FILE" ]; then
    set -- "$@" -f "$GPU_COMPOSE_FILE"
fi
if [ "$WITH_INFERENCE" -eq 1 ]; then
    set -- "$@" --profile llm
fi
if [ "$WITH_DIFFUSION" -eq 1 ]; then
    set -- "$@" --profile diffusion
fi
if [ "$WITH_SEARCH" -eq 1 ]; then
    set -- "$@" --profile search
fi
set -- "$@" up -d --build --remove-orphans --force-recreate
if [ "$RUNTIME_CMD" = "docker" ]; then
    set -- "$@" --wait
    set -- "$@" --wait-timeout 900
fi

"$@"

if [ "$RUNTIME_CMD" = "podman" ]; then
    set -- "$COMPOSE_RUNTIME" compose -f "$SANDBOX_DIR/compose.yaml"
    if [ -n "$GPU_COMPOSE_FILE" ]; then
        set -- "$@" -f "$GPU_COMPOSE_FILE"
    fi
    if [ "$WITH_INFERENCE" -eq 1 ]; then
        set -- "$@" --profile llm
    fi
    if [ "$WITH_DIFFUSION" -eq 1 ]; then
        set -- "$@" --profile diffusion
    fi
    if [ "$WITH_SEARCH" -eq 1 ]; then
        set -- "$@" --profile search
    fi
    podman_services=$("$@" config --services)
    if [ -z "$podman_services" ]; then
        echo "Podman Compose did not report any enabled sandbox services." >&2
        exit 1
    fi
    health_wait_attempt=0
    stack_health=waiting
    while [ "$health_wait_attempt" -lt 1800 ]; do
        stack_health=healthy
        for service_name in $podman_services; do
            if ! service_containers=$(
                podman_service_container_ids "$service_name" 2>/dev/null
            ); then
                echo "Podman could not enumerate sandbox service $service_name." >&2
                exit 1
            fi
            service_container_count=$(
                printf '%s\n' "$service_containers" |
                    sed '/^$/d' |
                    wc -l |
                    tr -d ' '
            )
            if [ "$service_container_count" -eq 0 ]; then
                stack_health=waiting
                continue
            fi
            if [ "$service_container_count" -ne 1 ]; then
                echo "Podman reported multiple containers for sandbox service $service_name." >&2
                exit 1
            fi
            service_container=$(printf '%s\n' "$service_containers" | sed -n '1p')
            service_state=$(
                "$RUNTIME_CMD" inspect \
                    --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
                    "$service_container" 2>/dev/null || true
            )
            case "$service_state" in
                running\|healthy|running\|none) ;;
                running\|starting|running\|)
                    stack_health=waiting
                    ;;
                running\|unhealthy)
                    echo "Podman reported sandbox service $service_name as unhealthy." >&2
                    exit 1
                    ;;
                "")
                    stack_health=waiting
                    ;;
                *)
                    echo "Podman reported sandbox service $service_name in state $service_state." >&2
                    exit 1
                    ;;
            esac
        done
        if [ "$stack_health" = "healthy" ]; then
            break
        fi
        health_wait_attempt=$((health_wait_attempt + 1))
        sleep 0.5
    done
    if [ "$stack_health" != "healthy" ]; then
        echo "Timed out waiting for Podman sandbox health after 900 seconds." >&2
        exit 1
    fi
    "$PYTHON_BIN" "$PODMAN_ANCHOR_SCRIPT" \
        --runtime-dir "$RUNTIME_DIR" \
        --network "$PODMAN_CONTROL_NETWORK" \
        remove-recorded
    PODMAN_ANCHOR_OWNED=0
fi

if ! "$PYTHON_BIN" "$GENERATION_STATUS_SCRIPT" \
    --runtime-dir "$RUNTIME_DIR" \
    publish \
    --generation "$SECAI_RUNTIME_GENERATION" >/dev/null
then
    echo "Sandbox services passed health checks, but readiness could not be published safely." >&2
    exit 1
fi

CONTROL_STARTED=0
release_launcher_lock
trap - EXIT HUP INT TERM
echo "First-boot setup credential: $RUNTIME_DIR/credentials/ui-setup.token"
echo "SecAI Sandbox is ready. Open http://127.0.0.1:$(awk -F= '/^SECAI_UI_PORT=/{print $2}' "$ENV_FILE" | tail -n1 | tr -d '\r')"
