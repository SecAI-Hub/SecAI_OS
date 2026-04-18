#!/usr/bin/env bash
#
# Secure AI Appliance - hardware-aware boot argument sync
#
# Keeps boot arguments conservative by default and only applies
# hardware-specific tuning when it is actually needed on the current system.
#
set -euo pipefail

STATE_DIR="/var/lib/secure-ai/state"
STATE_FILE="${STATE_DIR}/boot-kargs.status"

log() {
    echo "[secure-ai-boot-kargs] $*"
    logger -t secure-ai-boot-kargs "$*" 2>/dev/null || true
}

if ! command -v rpm-ostree >/dev/null 2>&1; then
    log "rpm-ostree not available; skipping boot argument sync."
    exit 0
fi

mkdir -p "$STATE_DIR"

have_pci_vendor() {
    local vendor="$1"
    local path
    for path in /sys/bus/pci/devices/*/vendor; do
        [ -f "$path" ] || continue
        if grep -q "^${vendor}$" "$path" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

needs_nvidia_kargs=false
if have_pci_vendor "0x10de" || [ -e /proc/driver/nvidia/version ]; then
    needs_nvidia_kargs=true
fi

changed=0
has_karg() {
    rpm-ostree kargs | tr ' ' '\n' | grep -Fxq "$1"
}

append_karg() {
    local arg="$1"
    if ! has_karg "$arg"; then
        rpm-ostree kargs --append-if-missing="$arg" >/dev/null
        changed=1
    fi
}

delete_karg() {
    local arg="$1"
    if has_karg "$arg"; then
        rpm-ostree kargs --delete-if-present="$arg" >/dev/null
        changed=1
    fi
}

# Remove global args that are too risky or no longer universal defaults.
for stale in \
    "iommu=force" \
    "amdgpu.dc=1"; do
    delete_karg "$stale" || true
done

if [ "$needs_nvidia_kargs" = "true" ]; then
    append_karg "rd.driver.blacklist=nouveau" || true
    append_karg "modprobe.blacklist=nouveau" || true
    append_karg "nvidia-drm.modeset=1" || true
    log "NVIDIA GPU detected; ensured NVIDIA-specific boot arguments are present."
else
    for stale in \
        "rd.driver.blacklist=nouveau" \
        "modprobe.blacklist=nouveau" \
        "nvidia-drm.modeset=1"; do
        delete_karg "$stale" || true
    done
fi

{
    echo "nvidia_kargs=${needs_nvidia_kargs}"
    echo "updated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "changed=${changed}"
} > "$STATE_FILE"
chmod 0644 "$STATE_FILE"

if [ "$changed" -eq 1 ]; then
    log "Boot arguments updated. Reboot to apply the new settings."
else
    log "Boot arguments already match the detected hardware."
fi
