#!/usr/bin/env bash
#
# Wrapper for llama-server that provides:
#   1. Startup health gate — sends READY=1 once the server responds
#   2. Continuous watchdog — pings health and sends WATCHDOG=1
#   3. Signal forwarding — SIGTERM/SIGINT forwarded to llama-server
#
# Used by secure-ai-inference.service with Type=notify + WatchdogSec.
#
set -euo pipefail

HEALTH_PORT="${PORT:-8465}"
HEALTH_URL="http://127.0.0.1:${HEALTH_PORT}/health"
STARTUP_TIMEOUT="${STARTUP_TIMEOUT:-120}"
# Ping at half the WatchdogSec interval (systemd provides WATCHDOG_USEC in µs)
if [ -n "${WATCHDOG_USEC:-}" ]; then
    WATCHDOG_INTERVAL=$(( WATCHDOG_USEC / 2000000 ))
else
    WATCHDOG_INTERVAL=15
fi
[ "$WATCHDOG_INTERVAL" -lt 5 ] && WATCHDOG_INTERVAL=5

# ---- Signal forwarding ----
LLAMA_PID=""
cleanup() {
    if [ -n "$LLAMA_PID" ] && kill -0 "$LLAMA_PID" 2>/dev/null; then
        kill -TERM "$LLAMA_PID" 2>/dev/null || true
        wait "$LLAMA_PID" 2>/dev/null || true
    fi
}
trap cleanup TERM INT

# ---- Start llama-server ----
/usr/bin/llama-server "$@" &
LLAMA_PID=$!
echo "llama-server started (PID ${LLAMA_PID})"

# ---- Startup health gate ----
echo "Waiting for llama-server health endpoint (timeout ${STARTUP_TIMEOUT}s)..."
ELAPSED=0
while [ "$ELAPSED" -lt "$STARTUP_TIMEOUT" ]; do
    if ! kill -0 "$LLAMA_PID" 2>/dev/null; then
        echo "FATAL: llama-server exited during startup" >&2
        exit 1
    fi
    if curl -sf --max-time 2 "$HEALTH_URL" >/dev/null 2>&1; then
        echo "llama-server healthy after ${ELAPSED}s"
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
done

if [ "$ELAPSED" -ge "$STARTUP_TIMEOUT" ]; then
    echo "FATAL: llama-server did not become healthy within ${STARTUP_TIMEOUT}s" >&2
    kill "$LLAMA_PID" 2>/dev/null || true
    exit 1
fi

# Notify systemd: service is ready
systemd-notify --ready --status="llama-server healthy on port ${HEALTH_PORT}" 2>/dev/null || true

# ---- Watchdog loop ----
while true; do
    sleep "$WATCHDOG_INTERVAL"

    # Check process is alive
    if ! kill -0 "$LLAMA_PID" 2>/dev/null; then
        echo "FATAL: llama-server process died" >&2
        exit 1
    fi

    # Check health endpoint
    if curl -sf --max-time 5 "$HEALTH_URL" >/dev/null 2>&1; then
        systemd-notify WATCHDOG=1 2>/dev/null || true
    else
        echo "WARNING: health check failed — watchdog notification skipped" >&2
        # systemd will kill us after WatchdogSec expires if this persists
    fi
done
