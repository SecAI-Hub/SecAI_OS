#!/usr/bin/env bash
# Run repo-owned Semgrep rules without uploading code or metrics.
set -euo pipefail

if ! command -v semgrep >/dev/null 2>&1; then
    echo "FATAL: semgrep is required for application security linting." >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

semgrep scan \
    --config .semgrep.yml \
    --error \
    --metrics=off \
    --disable-version-check \
    --oss-only \
    services scripts .github
