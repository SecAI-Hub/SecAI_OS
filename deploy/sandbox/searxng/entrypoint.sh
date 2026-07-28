#!/bin/sh
set -eu

secret_path=${SECAI_SEARXNG_SECRET_PATH:-/run/secrets/searxng.token}
if [ ! -r "$secret_path" ]; then
    echo "SearXNG secret is missing or unreadable." >&2
    exit 1
fi

SEARXNG_SECRET=$(tr -d '\r\n' < "$secret_path")
if [ -z "$SEARXNG_SECRET" ]; then
    echo "SearXNG secret is empty." >&2
    exit 1
fi
export SEARXNG_SECRET
unset SECAI_SEARXNG_SECRET_PATH

exec /usr/local/searxng/entrypoint.sh "$@"
