#!/bin/sh
# Combine separately delivered client credentials into one private backend key file.
set -eu
umask 077
export LC_ALL=C

fail() {
    echo "ERROR: inference authentication credentials are unavailable or invalid" >&2
    exit 1
}

read_key() {
    credential=$1
    [ -n "$credential" ] && [ -f "$credential" ] && [ ! -L "$credential" ] || fail
    metadata=$(stat -c '%a:%h:%s' -- "$credential") || fail
    case "$metadata" in
        400:1:64|400:1:65|600:1:64|600:1:65) ;;
        444:1:64|444:1:65|644:1:64|644:1:65)
            [ "${SECURE_AI_DEPLOYMENT_MODE:-}" = sandbox ] || fail
            # Sandbox launcher sources are behind an owner-only directory;
            # Compose mounts only these two files, read-only, into the worker.
            ;;
        *) fail ;;
    esac
    case "$metadata" in
        *:65)
            last_byte=$(tail -c 1 -- "$credential" | od -An -tu1 | tr -d ' ')
            [ "$last_byte" = 10 ] || fail
            ;;
    esac
    key=$(head -c 66 -- "$credential") || fail
    [ "${#key}" -eq 64 ] || fail
    case "$key" in *[!0-9a-f]*) fail ;; esac
    # Credential inputs are immutable systemd copies or read-only container mounts.
    [ "$(stat -c '%a:%h:%s' -- "$credential")" = "$metadata" ] || fail
    printf '%s' "$key"
}

ui_key=$(read_key "${INFERENCE_UI_TOKEN_PATH:-}") || fail
agent_key=$(read_key "${INFERENCE_AGENT_TOKEN_PATH:-}") || fail
[ "$ui_key" != "$agent_key" ] || fail
probe_key=""
if [ "${SECURE_AI_DEPLOYMENT_MODE:-native}" != sandbox ]; then
    probe_key=$(read_key "${INFERENCE_PROBE_TOKEN_PATH:-}") || fail
    [ "$probe_key" != "$ui_key" ] && [ "$probe_key" != "$agent_key" ] || fail
fi

directory=${1:-${RUNTIME_DIRECTORY:-${TMPDIR:-/tmp}/secure-ai-inference}}
[ ! -L "$directory" ] || fail
mkdir -p -- "$directory"
[ "$(stat -c '%F:%u:%a' -- "$directory")" = "directory:$(id -u):700" ] || fail
temporary=$(mktemp "$directory/.inference-keys.XXXXXXXX")
trap 'rm -f -- "$temporary"' 0 1 2 15
printf '%s\n%s\n' "$ui_key" "$agent_key" > "$temporary"
if [ -n "$probe_key" ]; then printf '%s\n' "$probe_key" >> "$temporary"; fi
printf '%s\n' "$temporary"
# The enclosing RuntimeDirectory/private tmpfs removes this file at shutdown.
trap - 0 1 2 15
