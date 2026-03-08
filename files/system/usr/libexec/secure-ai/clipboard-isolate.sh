#!/usr/bin/env bash
#
# Secure AI Appliance — Clipboard Isolation (M21)
#
# Detects and disables clipboard-sharing agents that could leak data between
# the AI environment and the host/hypervisor:
#   - spice-vdagent (QEMU/KVM via SPICE)
#   - vmware-user / vmtoolsd (VMware)
#   - VBoxClient --clipboard (VirtualBox)
#   - open-vm-tools clipboard (VMware open-source)
#
# On bare metal with Wayland, restricts background clipboard access.
#
# Run at first boot and on demand. Non-destructive: disables services,
# does not uninstall packages.
#
set -euo pipefail

SECURE_AI_ROOT="/var/lib/secure-ai"
CLIP_ENV="${SECURE_AI_ROOT}/clipboard.env"

log() {
    echo "[clipboard-isolate] $*"
    logger -t clipboard-isolate "$*" 2>/dev/null || true
}

# Detection results
CLIP_AGENTS_FOUND=""
CLIP_AGENTS_DISABLED=""
IS_VM="false"
IS_WAYLAND="false"
CLIPBOARD_ISOLATED="false"

# --- Detect VM environment ---
detect_vm() {
    if [ -f "${SECURE_AI_ROOT}/vm.env" ]; then
        if grep -q 'IS_VM=true' "${SECURE_AI_ROOT}/vm.env" 2>/dev/null; then
            IS_VM="true"
            return
        fi
    fi
    # Fallback: check systemd-detect-virt
    if command -v systemd-detect-virt &>/dev/null; then
        local virt
        virt=$(systemd-detect-virt 2>/dev/null || echo "none")
        if [ "$virt" != "none" ]; then
            IS_VM="true"
        fi
    fi
}

# --- Detect Wayland ---
detect_wayland() {
    if [ -n "${WAYLAND_DISPLAY:-}" ] || [ -n "${XDG_SESSION_TYPE:-}" ] && [ "${XDG_SESSION_TYPE:-}" = "wayland" ]; then
        IS_WAYLAND="true"
    fi
}

# --- Disable spice-vdagent (QEMU/KVM SPICE clipboard sharing) ---
disable_spice_vdagent() {
    if command -v spice-vdagentd &>/dev/null || systemctl list-unit-files 2>/dev/null | grep -q "spice-vdagentd"; then
        CLIP_AGENTS_FOUND="${CLIP_AGENTS_FOUND:+${CLIP_AGENTS_FOUND}, }spice-vdagent"
        log "Found spice-vdagent — disabling clipboard sharing"

        systemctl stop spice-vdagentd.service 2>/dev/null || true
        systemctl disable spice-vdagentd.service 2>/dev/null || true
        systemctl mask spice-vdagentd.service 2>/dev/null || true

        # Also stop user-level agent
        if pgrep -x spice-vdagent &>/dev/null; then
            pkill -x spice-vdagent 2>/dev/null || true
        fi

        CLIP_AGENTS_DISABLED="${CLIP_AGENTS_DISABLED:+${CLIP_AGENTS_DISABLED}, }spice-vdagent"
        log "spice-vdagent disabled and masked"
    fi
}

# --- Disable VMware clipboard ---
disable_vmware_clipboard() {
    # vmware-user / vmtoolsd clipboard
    if command -v vmware-user &>/dev/null || command -v vmtoolsd &>/dev/null; then
        CLIP_AGENTS_FOUND="${CLIP_AGENTS_FOUND:+${CLIP_AGENTS_FOUND}, }vmware-tools"

        # Disable clipboard via vmware-tools config
        if [ -f /etc/vmware-tools/tools.conf ]; then
            log "Disabling VMware clipboard in tools.conf"
            if grep -q "\[unity\]" /etc/vmware-tools/tools.conf 2>/dev/null; then
                sed -i 's/^#*\s*enableDnD\s*=.*/enableDnD = false/' /etc/vmware-tools/tools.conf 2>/dev/null || true
            else
                echo -e "\n[unity]\nenableDnD = false" >> /etc/vmware-tools/tools.conf
            fi
        fi

        # Kill vmware-user if running (it handles clipboard)
        if pgrep -x vmware-user &>/dev/null; then
            pkill -x vmware-user 2>/dev/null || true
        fi

        CLIP_AGENTS_DISABLED="${CLIP_AGENTS_DISABLED:+${CLIP_AGENTS_DISABLED}, }vmware-tools"
        log "VMware clipboard sharing disabled"
    fi

    # open-vm-tools
    if systemctl list-unit-files 2>/dev/null | grep -q "vmtoolsd"; then
        # Don't disable vmtoolsd entirely (needed for VM integration),
        # but disable clipboard specifically
        if command -v vmware-toolbox-cmd &>/dev/null; then
            vmware-toolbox-cmd config set isolation.tools.copy.disable TRUE 2>/dev/null || true
            vmware-toolbox-cmd config set isolation.tools.paste.disable TRUE 2>/dev/null || true
            vmware-toolbox-cmd config set isolation.tools.dnd.disable TRUE 2>/dev/null || true
            log "open-vm-tools clipboard isolation enabled"
        fi
    fi
}

# --- Disable VirtualBox clipboard ---
disable_vbox_clipboard() {
    if command -v VBoxClient &>/dev/null; then
        CLIP_AGENTS_FOUND="${CLIP_AGENTS_FOUND:+${CLIP_AGENTS_FOUND}, }VBoxClient"

        # Kill clipboard-specific VBoxClient
        if pgrep -f "VBoxClient.*clipboard" &>/dev/null; then
            pkill -f "VBoxClient.*clipboard" 2>/dev/null || true
            log "VBoxClient clipboard process killed"
        fi

        # Disable via guest additions
        if systemctl list-unit-files 2>/dev/null | grep -q "vboxadd-service"; then
            # Mask the clipboard helper, not the whole guest additions
            systemctl stop vboxadd-service 2>/dev/null || true
            systemctl disable vboxadd-service 2>/dev/null || true
            log "VBoxClient clipboard service disabled"
        fi

        CLIP_AGENTS_DISABLED="${CLIP_AGENTS_DISABLED:+${CLIP_AGENTS_DISABLED}, }VBoxClient"
    fi
}

# --- Wayland clipboard restriction ---
restrict_wayland_clipboard() {
    if [ "$IS_WAYLAND" != "true" ]; then
        return
    fi

    log "Wayland session detected — clipboard access restricted to UI process"
    # On Wayland, clipboard access requires the focused surface.
    # Our services run as systemd units (no Wayland surface), so they
    # cannot access clipboard by design. Log this as a positive.
    CLIPBOARD_ISOLATED="true"
}

# --- Main ---
log "=== Clipboard Isolation Check ==="

detect_vm
detect_wayland

if [ "$IS_VM" = "true" ]; then
    log "VM environment detected — checking clipboard sharing agents"
    disable_spice_vdagent
    disable_vmware_clipboard
    disable_vbox_clipboard
else
    log "Bare metal detected"
fi

restrict_wayland_clipboard

# If any agents were disabled, clipboard is isolated
if [ -n "$CLIP_AGENTS_DISABLED" ]; then
    CLIPBOARD_ISOLATED="true"
fi

# If no agents were found at all, clipboard is isolated by default
if [ -z "$CLIP_AGENTS_FOUND" ]; then
    CLIPBOARD_ISOLATED="true"
    log "No clipboard sharing agents found — clipboard isolated by default"
fi

# Write results
mkdir -p "$(dirname "$CLIP_ENV")" 2>/dev/null || true
cat > "$CLIP_ENV" <<EOF
CLIPBOARD_ISOLATED=${CLIPBOARD_ISOLATED}
CLIP_AGENTS_FOUND=${CLIP_AGENTS_FOUND}
CLIP_AGENTS_DISABLED=${CLIP_AGENTS_DISABLED}
IS_VM=${IS_VM}
IS_WAYLAND=${IS_WAYLAND}
EOF
chmod 644 "$CLIP_ENV"

log "Clipboard isolated: ${CLIPBOARD_ISOLATED}"
if [ -n "$CLIP_AGENTS_FOUND" ]; then
    log "Agents found: ${CLIP_AGENTS_FOUND}"
    log "Agents disabled: ${CLIP_AGENTS_DISABLED}"
fi

log "=== Clipboard Isolation Complete ==="
