#!/usr/bin/env bash
# Lint every project-owned Containerfile/Dockerfile with Hadolint.
set -euo pipefail

HADOLINT_BIN="${HADOLINT_BIN:-hadolint}"

if ! command -v "${HADOLINT_BIN}" >/dev/null 2>&1; then
    echo "FATAL: hadolint is required for container linting." >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

mapfile -d '' dockerfiles < <(
    find "${REPO_ROOT}/services" "${REPO_ROOT}/deploy" -type f \
        \( -name 'Containerfile' -o -name 'Containerfile.*' -o -name 'Dockerfile' -o -name 'Dockerfile.*' \) \
        -print0
)

if [ "${#dockerfiles[@]}" -eq 0 ]; then
    echo "FATAL: no Containerfile/Dockerfile files found." >&2
    exit 1
fi

"${HADOLINT_BIN}" "${dockerfiles[@]}"
echo "OK: Hadolint checked ${#dockerfiles[@]} container build file(s)"
