#!/usr/bin/env bash
# Compatibility entrypoint for the hardened release USB builder.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "${SCRIPT_DIR}/release/secai-os-build-usb.sh" "$@"
