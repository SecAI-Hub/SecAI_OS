#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
SANDBOX_DIR="$REPO_ROOT/deploy/sandbox"

if command -v docker >/dev/null 2>&1; then
    docker compose -f "$SANDBOX_DIR/compose.yaml" down --remove-orphans
elif command -v podman >/dev/null 2>&1; then
    podman compose -f "$SANDBOX_DIR/compose.yaml" down --remove-orphans
else
    echo "Neither docker nor podman was found in PATH." >&2
    exit 1
fi
