#!/bin/sh
set -eu

export PYTHONDONTWRITEBYTECODE=1
export PYTHONUNBUFFERED=1
export HOME="${HOME:-/tmp}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-/tmp/.cache}"
export HF_HOME="${HF_HOME:-/tmp/.hf}"
export TORCH_HOME="${TORCH_HOME:-/tmp/.torch}"

mkdir -p "$XDG_CACHE_HOME" "$HF_HOME" "$TORCH_HOME"

exec gunicorn \
    --chdir /app \
    --bind "${BIND_ADDR:-0.0.0.0:8455}" \
    --workers "${GUNICORN_WORKERS:-1}" \
    --threads "${GUNICORN_THREADS:-2}" \
    --timeout "${GUNICORN_TIMEOUT:-1800}" \
    --graceful-timeout "${GUNICORN_GRACEFUL_TIMEOUT:-30}" \
    --worker-tmp-dir /tmp \
    --max-requests "${GUNICORN_MAX_REQUESTS:-500}" \
    --max-requests-jitter "${GUNICORN_MAX_REQUESTS_JITTER:-25}" \
    --access-logfile - \
    --error-logfile - \
    app:app
