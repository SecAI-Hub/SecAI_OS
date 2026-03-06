#!/usr/bin/env bash
#
# Secure AI Appliance — Panic Switch
#
# Emergency lockdown. Immediately:
#   1. Flush nftables to a total-deny policy (loopback only)
#   2. Drop all network routes (kill internet access)
#   3. Stop the airlock service (only service with outbound)
#   4. Stop inference workers
#   5. Write audit record
#
# Usage: systemctl start secure-ai-panic

set -euo pipefail

log() {
    echo "[secure-ai-panic] $*"
    logger -t secure-ai-panic "$*"
}

AUDIT_LOG="/var/lib/secure-ai/logs/panic-audit.jsonl"

log "!!! PANIC SWITCH ACTIVATED !!!"

# 1. Flush nftables to total deny FIRST (fastest network kill)
log "Setting nftables to total deny..."
nft flush ruleset
nft add table inet panic
nft add chain inet panic input '{ type filter hook input priority 0; policy drop; }'
nft add chain inet panic output '{ type filter hook output priority 0; policy drop; }'
nft add chain inet panic forward '{ type filter hook forward priority 0; policy drop; }'
# Allow loopback only so systemd can still function
nft add rule inet panic input iif lo accept
nft add rule inet panic output oif lo accept

# 2. Kill all network routes
log "Dropping all network routes..."
ip route flush table main 2>/dev/null || true
ip -6 route flush table main 2>/dev/null || true

# 3. Stop runtime services
log "Stopping runtime services..."
systemctl stop secure-ai-airlock.service 2>/dev/null || true
systemctl stop secure-ai-ui.service 2>/dev/null || true

# 4. Write audit record
if mkdir -p "$(dirname "$AUDIT_LOG")" 2>/dev/null; then
    echo "{\"timestamp\":\"$(date -Iseconds)\",\"event\":\"panic_activated\",\"user\":\"$(whoami)\"}" >> "$AUDIT_LOG" 2>/dev/null || true
fi

log "Panic lockdown complete. All network access is blocked."
log "Services still running: registry, tool-firewall (localhost only, already isolated)."
log "To restore: reboot the system or run: nft -f /etc/nftables/secure-ai.nft"
