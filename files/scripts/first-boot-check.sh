#!/usr/bin/env bash
# first-boot-check.sh — Validates all Secure AI OS services are running and healthy.
# Run after first boot or after an OS update to verify production readiness.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
ERRORS=0
WARNINGS=0

info()  { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; WARNINGS=$((WARNINGS + 1)); }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; ERRORS=$((ERRORS + 1)); }

echo "=============================================="
echo "  Secure AI OS — First-Boot Health Check"
echo "=============================================="
echo ""

# 1. Core services status
echo "--- Service Status ---"
CORE_SERVICES=(
    secure-ai-policy-engine
    secure-ai-registry
    secure-ai-tool-firewall
    secure-ai-runtime-attestor
    secure-ai-integrity-monitor
    secure-ai-incident-recorder
    secure-ai-mcp-firewall
    secure-ai-gpu-integrity-watch
    secure-ai-agent
    secure-ai-ui
)

for svc in "${CORE_SERVICES[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        info "$svc is running"
    else
        fail "$svc is NOT running"
    fi
done

# Airlock is disabled by default (privacy risk surface)
if systemctl is-active --quiet secure-ai-airlock 2>/dev/null; then
    warn "secure-ai-airlock is running (disabled by default for privacy)"
else
    info "secure-ai-airlock is disabled (expected default)"
fi

echo ""

# 2. Health endpoint checks
echo "--- Health Endpoints ---"
HEALTH_ENDPOINTS=(
    "policy-engine|127.0.0.1:8500|/health"
    "registry|127.0.0.1:8470|/health"
    "tool-firewall|127.0.0.1:8475|/health"
    "runtime-attestor|127.0.0.1:8505|/health"
    "integrity-monitor|127.0.0.1:8510|/health"
    "incident-recorder|127.0.0.1:8515|/health"
)

for entry in "${HEALTH_ENDPOINTS[@]}"; do
    IFS='|' read -r name addr path <<< "$entry"
    if curl -sf "http://${addr}${path}" > /dev/null 2>&1; then
        info "$name health OK"
    else
        fail "$name health check FAILED at ${addr}${path}"
    fi
done

echo ""

# 3. Security posture checks
echo "--- Security Posture ---"

# Check attestation state
ATTEST=$(curl -sf http://127.0.0.1:8505/api/v1/verify 2>/dev/null || echo '{"verified":false}')
if echo "$ATTEST" | grep -q '"verified":true'; then
    info "Runtime attestation: VERIFIED"
else
    warn "Runtime attestation: NOT fully verified (check boot measurements)"
fi

# Check integrity monitor
INTEG=$(curl -sf http://127.0.0.1:8510/api/v1/status 2>/dev/null || echo '{"state":"unknown"}')
if echo "$INTEG" | grep -q '"clean"'; then
    info "Integrity monitor: CLEAN"
elif echo "$INTEG" | grep -q '"state"'; then
    warn "Integrity monitor: state=$(echo "$INTEG" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("state","unknown"))' 2>/dev/null || echo 'unknown')"
else
    fail "Integrity monitor: unreachable"
fi

# Check for open incidents
INC_STATS=$(curl -sf http://127.0.0.1:8515/api/v1/stats 2>/dev/null || echo '{"open_incidents":0}')
OPEN_INC=$(echo "$INC_STATS" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("open_incidents",0))' 2>/dev/null || echo 0)
if [ "$OPEN_INC" -eq 0 ] 2>/dev/null; then
    info "No open incidents"
else
    warn "$OPEN_INC open incident(s) detected"
fi

echo ""

# 4. Filesystem and permission checks
echo "--- Filesystem & Permissions ---"

# Check key directories exist
for dir in /var/lib/secure-ai/logs /var/lib/secure-ai/data /etc/secure-ai/policy; do
    if [ -d "$dir" ]; then
        info "$dir exists"
    else
        warn "$dir missing (will be created on first use)"
    fi
done

# Check service token exists
if [ -f /run/secure-ai/service-token ]; then
    info "Service token present"
else
    warn "Service token missing (/run/secure-ai/service-token) — services running in dev mode"
fi

# Check policy files
if [ -f /etc/secure-ai/policy/policy.yaml ]; then
    info "Policy file present"
else
    warn "Policy file missing (services using built-in defaults)"
fi

echo ""

# 5. Network checks
echo "--- Network ---"

# Verify no unexpected listeners on public interfaces
PUBLIC_LISTENERS=$(ss -tlnp 2>/dev/null | grep -v '127.0.0.1' | grep -v '::1' | grep -v 'LISTEN' | head -5 || true)
if [ -z "$PUBLIC_LISTENERS" ]; then
    info "No services listening on public interfaces"
else
    warn "Services detected on public interfaces (expected: localhost only)"
fi

echo ""
echo "=============================================="
echo "  Results: $ERRORS failure(s), $WARNINGS warning(s)"
echo "=============================================="

if [ $ERRORS -gt 0 ]; then
    echo -e "${RED}FAIL: $ERRORS critical issue(s) found. Review and fix before production use.${NC}"
    exit 1
fi

if [ $WARNINGS -gt 0 ]; then
    echo -e "${YELLOW}PASS with warnings. Review warnings above.${NC}"
    exit 0
fi

echo -e "${GREEN}ALL CHECKS PASSED. System is production-ready.${NC}"
exit 0
