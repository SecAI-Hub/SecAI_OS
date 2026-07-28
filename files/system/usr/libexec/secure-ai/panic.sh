#!/usr/bin/env bash
# Backwards-compatible level-1 panic entrypoint.
set -euo pipefail

exec /usr/libexec/secure-ai/securectl panic 1 --no-countdown
