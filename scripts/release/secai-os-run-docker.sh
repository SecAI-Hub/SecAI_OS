#!/usr/bin/env bash
#
# Download a SecAI OS release source bundle and launch the Docker sandbox.
#
set -euo pipefail

REPO="SecAI-Hub/SecAI_OS"
TAG="latest"
INSTALL_DIR="${HOME}/.local/share/secai-os/sandbox"
PROFILE="offline-private"
WITH_SEARCH=false
WITH_DIFFUSION=false
WITH_INFERENCE=false
WITH_GPU=false
INSTALL_DEPS=true
REFRESH=false
DRY_RUN=false

usage() {
    cat <<'USAGE'
Usage: secai-os-run-docker.sh [options]

Download a SecAI OS release source bundle, build the sandbox containers, and
start the Dockerized evaluation environment.

Options:
  --tag TAG              Release tag to run (default: latest release)
  --repo OWNER/REPO      GitHub repository (default: SecAI-Hub/SecAI_OS)
  --install-dir DIR      Install directory (default: ~/.local/share/secai-os/sandbox)
  --profile PROFILE      offline-private, research, or full-lab
  --with-search          Enable the search/Tor profile
  --with-diffusion       Enable the diffusion worker profile
  --with-inference       Enable the local inference worker profile
  --with-gpu             Enable GPU compose overrides when available
  --install-deps         Install missing distro-packaged dependencies (default)
  --no-install-deps      Fail if dependencies are missing
  --refresh              Replace an existing install directory
  --dry-run              Validate options and print the planned launch
  --help                 Show this help text

Examples:
  bash secai-os-run-docker.sh
  bash secai-os-run-docker.sh --tag v1.0.0 --profile research
  bash secai-os-run-docker.sh --profile full-lab --with-inference
USAGE
}

info() { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
fatal() { printf '[x] %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag)
            TAG="${2:-}"; shift 2 ;;
        --repo)
            REPO="${2:-}"; shift 2 ;;
        --install-dir)
            INSTALL_DIR="${2:-}"; shift 2 ;;
        --profile)
            PROFILE="${2:-}"; shift 2 ;;
        --with-search)
            WITH_SEARCH=true; shift ;;
        --with-diffusion)
            WITH_DIFFUSION=true; shift ;;
        --with-inference)
            WITH_INFERENCE=true; shift ;;
        --with-gpu)
            WITH_GPU=true; shift ;;
        --install-deps)
            INSTALL_DEPS=true; shift ;;
        --no-install-deps)
            INSTALL_DEPS=false; shift ;;
        --refresh)
            REFRESH=true; shift ;;
        --dry-run)
            DRY_RUN=true; shift ;;
        --help|-h)
            usage; exit 0 ;;
        *)
            fatal "Unknown argument: $1" ;;
    esac
done

[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fatal "--repo must look like OWNER/REPO"
[[ "$TAG" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$|^latest$ ]] || fatal "--tag contains unsupported characters"

case "$PROFILE" in
    offline-private|offline_private|offline)
        PROFILE="offline-private" ;;
    research|web|web-assisted)
        PROFILE="research"
        WITH_SEARCH=true ;;
    full-lab|full_lab|lab)
        PROFILE="full-lab"
        WITH_SEARCH=true
        WITH_DIFFUSION=true ;;
    *)
        fatal "Unsupported --profile value: ${PROFILE}" ;;
esac

start_flags=()
[[ "$WITH_SEARCH" == true ]] && start_flags+=(--with-search)
[[ "$WITH_DIFFUSION" == true ]] && start_flags+=(--with-diffusion)
[[ "$WITH_INFERENCE" == true ]] && start_flags+=(--with-inference)
[[ "$WITH_GPU" == true ]] && start_flags+=(--with-gpu)

install_packages() {
    if [[ "$INSTALL_DEPS" != true ]]; then
        return 1
    fi

    local sudo_cmd=()
    if [[ "$(id -u)" -ne 0 ]]; then
        command -v sudo >/dev/null 2>&1 || return 1
        sudo_cmd=(sudo)
    fi

    if command -v apt-get >/dev/null 2>&1; then
        info "Installing missing dependencies with apt-get"
        "${sudo_cmd[@]}" apt-get update
        DEBIAN_FRONTEND=noninteractive "${sudo_cmd[@]}" apt-get install -y "$@"
    elif command -v dnf >/dev/null 2>&1; then
        info "Installing missing dependencies with dnf"
        "${sudo_cmd[@]}" dnf install -y "$@"
    elif command -v pacman >/dev/null 2>&1; then
        info "Installing missing dependencies with pacman"
        "${sudo_cmd[@]}" pacman -Sy --needed --noconfirm "$@"
    else
        return 1
    fi
}

require_commands() {
    local missing=()
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        return 0
    fi

    if install_packages "${missing[@]}"; then
        missing=()
        for cmd in "$@"; do
            command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
        done
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        fatal "Missing required command(s): ${missing[*]}"
    fi
}

resolve_latest_tag() {
    require_commands curl python3
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | \
        python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])'
}

if [[ "$TAG" == "latest" ]]; then
    TAG="$(resolve_latest_tag)"
fi

if [[ "$DRY_RUN" == true ]]; then
    info "Dry run: Docker sandbox launch plan"
    printf '  repo:         %s\n' "$REPO"
    printf '  tag:          %s\n' "$TAG"
    printf '  install dir:  %s\n' "$INSTALL_DIR"
    printf '  profile:      %s\n' "$PROFILE"
    printf '  flags:        %s\n' "${start_flags[*]:-(none)}"
    exit 0
fi

require_commands curl tar docker

if ! docker compose version >/dev/null 2>&1; then
    fatal "Docker Compose v2 is required. Install the docker compose plugin, then rerun this script."
fi

if ! docker info >/dev/null 2>&1; then
    if command -v systemctl >/dev/null 2>&1; then
        warn "Docker daemon is not running; attempting to start docker.service"
        sudo systemctl start docker || true
    fi
fi
docker info >/dev/null 2>&1 || fatal "Docker daemon is not reachable"

if [[ -d "$INSTALL_DIR" && "$REFRESH" == true ]]; then
    rm -rf "$INSTALL_DIR"
fi

if [[ ! -d "$INSTALL_DIR" ]]; then
    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "$tmp_dir"' EXIT
    archive="${tmp_dir}/secai-os-${TAG}.tar.gz"
    url="https://github.com/${REPO}/archive/refs/tags/${TAG}.tar.gz"
    info "Downloading ${url}"
    curl -fsSL "$url" -o "$archive"
    tar -xzf "$archive" -C "$tmp_dir"
    src_dir="$(find "$tmp_dir" -mindepth 1 -maxdepth 1 -type d | head -1)"
    [[ -n "$src_dir" ]] || fatal "Downloaded source archive did not contain a directory"
    mkdir -p "$(dirname "$INSTALL_DIR")"
    mv "$src_dir" "$INSTALL_DIR"
else
    info "Using existing install directory ${INSTALL_DIR}"
fi

[[ -f "${INSTALL_DIR}/scripts/sandbox/start.sh" ]] || fatal "Sandbox launcher not found in ${INSTALL_DIR}"

info "Starting Docker sandbox (${PROFILE})"
(
    cd "$INSTALL_DIR"
    bash scripts/sandbox/start.sh "${start_flags[@]}"
)

info "SecAI OS Docker sandbox is starting at http://127.0.0.1:8480"
