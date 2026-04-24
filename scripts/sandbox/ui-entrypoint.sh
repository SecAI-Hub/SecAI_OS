#!/bin/sh
set -eu

export PYTHONDONTWRITEBYTECODE=1
export PYTHONUNBUFFERED=1
export PYTHONPATH="${PYTHONPATH:-/app:/app/services}"
SECURE_AI_TMPDIR="${SECURE_AI_TMPDIR:-/var/lib/secure-ai/import-staging/.tmp}"
mkdir -p "${SECURE_AI_TMPDIR}"
chmod 700 "${SECURE_AI_TMPDIR}"
export TMPDIR="${SECURE_AI_TMPDIR}"
export TMP="${SECURE_AI_TMPDIR}"
export TEMP="${SECURE_AI_TMPDIR}"

UI_WORKERS="${GUNICORN_WORKERS:-1}"
if [ "${UI_WORKERS}" -gt 1 ]; then
    echo "warning: forcing GUNICORN_WORKERS=1 because AuthManager session state is process-local" >&2
    UI_WORKERS=1
fi

exec gunicorn \
    --chdir /app \
    --bind "${BIND_ADDR:-0.0.0.0:8480}" \
    --workers "${UI_WORKERS}" \
    --threads "${GUNICORN_THREADS:-4}" \
    --timeout "${GUNICORN_TIMEOUT:-60}" \
    --graceful-timeout "${GUNICORN_GRACEFUL_TIMEOUT:-15}" \
    --worker-tmp-dir "${SECURE_AI_TMPDIR}" \
    --max-requests "${GUNICORN_MAX_REQUESTS:-1000}" \
    --max-requests-jitter "${GUNICORN_MAX_REQUESTS_JITTER:-50}" \
    --access-logfile - \
    --error-logfile - \
    ui.app:app
