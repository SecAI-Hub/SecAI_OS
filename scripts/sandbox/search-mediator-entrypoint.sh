#!/bin/sh
set -eu

export PYTHONDONTWRITEBYTECODE=1
export PYTHONUNBUFFERED=1
export PYTHONPATH="${PYTHONPATH:-/app/services}"

exec gunicorn \
    --chdir /app/services/search-mediator \
    --bind "${BIND_ADDR:-0.0.0.0:8485}" \
    --workers "${GUNICORN_WORKERS:-2}" \
    --threads "${GUNICORN_THREADS:-2}" \
    --timeout "${GUNICORN_TIMEOUT:-30}" \
    --graceful-timeout "${GUNICORN_GRACEFUL_TIMEOUT:-10}" \
    --worker-tmp-dir /tmp \
    --max-requests "${GUNICORN_MAX_REQUESTS:-1000}" \
    --max-requests-jitter "${GUNICORN_MAX_REQUESTS_JITTER:-50}" \
    --access-logfile - \
    --error-logfile - \
    app:app
