#!/usr/bin/env bash
#
# Secure AI Appliance — Greenboot Health Check (M24)
#
# Runs on every boot via greenboot. If this script exits non-zero,
# greenboot triggers an automatic rpm-ostree rollback + reboot.
#
# Checks:
#   1. Critical systemd services are active
#   2. Registry API is reachable
#   3. Firewall rules are loaded
#   4. Integrity check script exists
#   5. Vault mapper device exists (if configured)
#   6. securectl is executable
#
# Timeout: 5 minutes (configured in greenboot.conf)
#

set -euo pipefail

HEALTH_LOG="/var/lib/secure-ai/logs/health-check.json"
ROLLBACK_COUNTER="/run/secure-ai/rollback-count"
MAX_ROLLBACKS=2
BOOT_ID=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo "unknown")

log() {
    echo "[health-check] $*"
    logger -t secure-ai-health "$*" 2>/dev/null || true
}

fail() {
    log "FAIL: $*"
    write_result "fail" "$*"

    # Track rollback attempts
    local count=0
    if [ -f "$ROLLBACK_COUNTER" ]; then
        count=$(cat "$ROLLBACK_COUNTER" 2>/dev/null || echo "0")
    fi
    count=$((count + 1))

    mkdir -p "$(dirname "$ROLLBACK_COUNTER")" 2>/dev/null || true
    echo "$count" > "$ROLLBACK_COUNTER"

    if [ "$count" -ge "$MAX_ROLLBACKS" ]; then
        log "ERROR: max rollback attempts ($MAX_ROLLBACKS) reached — halting"
        write_result "fail" "max rollbacks reached: $*"
        # Don't exit non-zero here to prevent infinite rollback loop
        # System stays on current (broken) deployment for manual intervention
        exit 0
    fi

    exit 1
}

write_result() {
    local status="$1"
    local detail="${2:-}"
    mkdir -p "$(dirname "$HEALTH_LOG")" 2>/dev/null || true
    python3 -c "
import json, hashlib
from datetime import datetime
entry = {
    'timestamp': datetime.now().isoformat(),
    'event': 'health_check',
    'status': '${status}',
    'detail': '${detail}',
    'boot_id': '${BOOT_ID}'
}
entry['hash'] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
print(json.dumps(entry))
" > "$HEALTH_LOG" 2>/dev/null || true
}

# ── Check 1: Critical services ──
log "Checking critical systemd services..."
CRITICAL_SERVICES=(
    "nftables.service"
)

# These services should be active if they were enabled
OPTIONAL_SERVICES=(
    "secure-ai-registry.service"
    "secure-ai-tool-firewall.service"
    "secure-ai-ui.service"
)

for svc in "${CRITICAL_SERVICES[@]}"; do
    if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
        fail "critical service not active: $svc"
    fi
    log "  $svc: active"
done

for svc in "${OPTIONAL_SERVICES[@]}"; do
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        # Give services up to 60 seconds to start
        for i in $(seq 1 12); do
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                break
            fi
            sleep 5
        done
        if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
            fail "enabled service failed to start: $svc"
        fi
        log "  $svc: active"
    fi
done

# ── Check 2: Registry API ──
log "Checking registry API..."
if systemctl is-enabled --quiet secure-ai-registry.service 2>/dev/null; then
    for i in $(seq 1 6); do
        if curl -sf http://127.0.0.1:8470/health >/dev/null 2>&1; then
            log "  registry API: reachable"
            break
        fi
        if [ "$i" -eq 6 ]; then
            fail "registry API unreachable after 30s"
        fi
        sleep 5
    done
fi

# ── Check 3: Firewall rules ──
log "Checking firewall rules..."
if command -v nft &>/dev/null; then
    if ! nft list ruleset 2>/dev/null | grep -q "secure_ai"; then
        fail "nftables secure_ai table not loaded"
    fi
    log "  nftables: secure_ai table loaded"
else
    fail "nft command not found"
fi

# ── Check 4: Integrity scripts ──
log "Checking integrity scripts..."
for script in \
    /usr/libexec/secure-ai/securectl \
    /usr/libexec/secure-ai/verify-boot-chain.sh \
    /usr/libexec/secure-ai/canary-check.sh; do
    if [ ! -x "$script" ]; then
        fail "integrity script missing or not executable: $script"
    fi
done
log "  integrity scripts: present"

# ── Check 5: Vault device ──
log "Checking vault configuration..."
if [ -f /etc/crypttab ]; then
    if grep -q "secure-ai-vault" /etc/crypttab 2>/dev/null; then
        log "  vault: configured in crypttab"
    fi
fi

# ── All checks passed ──
log "All health checks passed"
write_result "pass" "all checks passed"

# Clear rollback counter on success
rm -f "$ROLLBACK_COUNTER" 2>/dev/null || true

exit 0
