#!/bin/sh
# Run repo-owned Semgrep rules without uploading code or metrics.
set -eu

if ! command -v semgrep >/dev/null 2>&1; then
    echo "FATAL: semgrep is required for application security linting." >&2
    exit 1
fi

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/../.." && pwd)"
cd "${REPO_ROOT}"

exec semgrep scan \
    --config .semgrep.yml \
    --error \
    --metrics=off \
    --disable-version-check \
    --no-git-ignore \
    --oss-only \
    services scripts .github
