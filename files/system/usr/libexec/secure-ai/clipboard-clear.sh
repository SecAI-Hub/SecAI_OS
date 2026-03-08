#!/usr/bin/env bash
#
# Secure AI Appliance — Clipboard Auto-Clear (M21)
#
# Clears the system clipboard after a configurable timeout.
# Prevents sensitive data (model outputs, search results) from persisting
# on the clipboard indefinitely.
#
# Supports: wl-copy/wl-paste (Wayland), xclip/xsel (X11)
#
set -euo pipefail

log() {
    logger -t clipboard-clear "$*" 2>/dev/null || true
}

# Detect display server and clear clipboard
clear_clipboard() {
    local cleared="false"

    # Wayland
    if [ -n "${WAYLAND_DISPLAY:-}" ]; then
        if command -v wl-copy &>/dev/null; then
            echo -n "" | wl-copy 2>/dev/null && cleared="true"
            echo -n "" | wl-copy --primary 2>/dev/null || true
        fi
    fi

    # X11 fallback
    if [ -n "${DISPLAY:-}" ]; then
        if command -v xclip &>/dev/null; then
            echo -n "" | xclip -selection clipboard 2>/dev/null && cleared="true"
            echo -n "" | xclip -selection primary 2>/dev/null || true
        elif command -v xsel &>/dev/null; then
            xsel --clipboard --clear 2>/dev/null && cleared="true"
            xsel --primary --clear 2>/dev/null || true
        fi
    fi

    if [ "$cleared" = "true" ]; then
        log "Clipboard cleared"
    fi
}

clear_clipboard
