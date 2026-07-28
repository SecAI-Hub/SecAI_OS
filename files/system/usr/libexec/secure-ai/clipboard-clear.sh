#!/usr/bin/env bash
# Clear clipboard and primary selections from the current graphical session.
set -euo pipefail
umask 077

log() {
    echo "[clipboard-clear] $*" >&2
}

clear_wayland() {
    if ! command -v wl-copy >/dev/null 2>&1; then
        log "Wayland session detected but wl-copy is unavailable"
        return 1
    fi
    wl-copy --clear
    wl-copy --primary --clear
}

clear_x11() {
    if command -v xsel >/dev/null 2>&1; then
        xsel --clipboard --clear
        xsel --primary --clear
        return
    fi
    log "X11 session detected but xsel is unavailable"
    return 1
}

if [ -n "${WAYLAND_DISPLAY:-}" ]; then
    clear_wayland
elif [ -n "${DISPLAY:-}" ]; then
    clear_x11
else
    log "no graphical clipboard session is available"
    exit 2
fi

log "clipboard and primary selection cleared"
