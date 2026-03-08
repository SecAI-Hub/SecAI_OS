#!/usr/bin/env bash
#
# Secure AI Appliance — DNS Leak Detection (M19)
#
# Verifies that DNS queries are NOT leaking outside Tor when the search
# stack is enabled.  Two checks:
#
#   1. Attempt a direct DNS lookup — if it succeeds AND search is enabled,
#      DNS is leaking (nftables should block port 53 except via Tor).
#   2. Verify the Tor SOCKS proxy is reachable.
#
# Run at boot (via firstboot) and periodically (via timer or cron).
# Writes result to /var/lib/secure-ai/logs/dns-leak-check.json
#
set -euo pipefail

RESULT_PATH="/var/lib/secure-ai/logs/dns-leak-check.json"
SEARCH_POLICY="/etc/secure-ai/policy/policy.yaml"

log() {
    echo "[dns-leak-check] $*"
    logger -t dns-leak-check "$*" 2>/dev/null || true
}

# Determine if search stack is enabled
search_enabled() {
    if [ ! -f "$SEARCH_POLICY" ]; then
        echo "false"
        return
    fi
    # Simple YAML parse — look for "enabled: true" under search
    if grep -A2 "^search:" "$SEARCH_POLICY" 2>/dev/null | grep -q "enabled:\s*true"; then
        echo "true"
    else
        echo "false"
    fi
}

SEARCH_ACTIVE=$(search_enabled)
DNS_LEAK="false"
DNS_DETAIL=""
TOR_REACHABLE="false"
NFTABLES_DNS_BLOCKED="unknown"
STATUS="ok"

# --- Check 1: Direct DNS resolution (should fail when search is enabled) ---
log "Testing direct DNS resolution..."
if command -v dig &>/dev/null; then
    # Try resolving a well-known domain directly (not through Tor)
    if dig +short +timeout=5 +tries=1 example.com A 2>/dev/null | grep -qE '^[0-9]+\.'; then
        DNS_DETAIL="direct DNS resolution succeeded"
        if [ "$SEARCH_ACTIVE" = "true" ]; then
            DNS_LEAK="true"
            STATUS="warning"
            log "WARNING: DNS leak detected — direct resolution works while search is enabled"
        else
            DNS_DETAIL="direct DNS works (search disabled, acceptable)"
        fi
    else
        DNS_DETAIL="direct DNS blocked (good)"
    fi
elif command -v nslookup &>/dev/null; then
    if nslookup -timeout=5 example.com 2>/dev/null | grep -q "Address:"; then
        DNS_DETAIL="direct DNS resolution succeeded (nslookup)"
        if [ "$SEARCH_ACTIVE" = "true" ]; then
            DNS_LEAK="true"
            STATUS="warning"
            log "WARNING: DNS leak detected"
        fi
    else
        DNS_DETAIL="direct DNS blocked (good)"
    fi
else
    DNS_DETAIL="no DNS tools available (dig/nslookup)"
fi

# --- Check 2: Tor SOCKS proxy reachability ---
log "Checking Tor SOCKS proxy..."
if command -v curl &>/dev/null; then
    if curl -s --socks5-hostname 127.0.0.1:9050 --max-time 10 \
         -o /dev/null -w "%{http_code}" "https://check.torproject.org/api/ip" 2>/dev/null | grep -q "200"; then
        TOR_REACHABLE="true"
        log "Tor SOCKS proxy is reachable"
    else
        TOR_REACHABLE="false"
        if [ "$SEARCH_ACTIVE" = "true" ]; then
            log "WARNING: Tor SOCKS proxy unreachable but search is enabled"
            STATUS="warning"
        fi
    fi
else
    log "curl not available, skipping Tor check"
fi

# --- Check 3: nftables DNS rules ---
log "Checking nftables DNS blocking rules..."
if command -v nft &>/dev/null; then
    ruleset=$(nft list ruleset 2>/dev/null || echo "")
    if echo "$ruleset" | grep -q "dport 53"; then
        if echo "$ruleset" | grep -q "dport 53.*drop\|dport 53.*reject"; then
            NFTABLES_DNS_BLOCKED="strict"
            log "nftables: DNS port 53 has drop/reject rules (good)"
        else
            NFTABLES_DNS_BLOCKED="rate-limited"
            log "nftables: DNS port 53 is rate-limited"
        fi
    else
        NFTABLES_DNS_BLOCKED="none"
        if [ "$SEARCH_ACTIVE" = "true" ]; then
            log "WARNING: no nftables rules for DNS port 53"
            STATUS="warning"
        fi
    fi
fi

# --- Write results ---
mkdir -p "$(dirname "$RESULT_PATH")" 2>/dev/null || true
cat > "$RESULT_PATH" <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "status": "${STATUS}",
  "search_enabled": ${SEARCH_ACTIVE},
  "dns_leak_detected": ${DNS_LEAK},
  "dns_detail": "${DNS_DETAIL}",
  "tor_reachable": ${TOR_REACHABLE},
  "nftables_dns": "${NFTABLES_DNS_BLOCKED}"
}
EOF
chmod 644 "$RESULT_PATH"

log "DNS leak check complete: status=${STATUS} leak=${DNS_LEAK}"

if [ "$DNS_LEAK" = "true" ]; then
    exit 1
fi
exit 0
