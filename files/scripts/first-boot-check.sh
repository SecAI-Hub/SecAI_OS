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
SERVICE_PROFILE="${SERVICE_PROFILE:-/etc/secure-ai/config/service-profile.json}"

info()  { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; WARNINGS=$((WARNINGS + 1)); }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; ERRORS=$((ERRORS + 1)); }

credential_get() {
    local credential_name="$1"
    local url="$2"
    local credential_path="/var/lib/secure-ai/credentials/${credential_name}"
    local token

    if [ ! -s "$credential_path" ] || [ -L "$credential_path" ]; then
        return 1
    fi
    IFS= read -r token < "$credential_path"
    [[ "$token" =~ ^[0-9a-f]{64}$ ]] || return 1
    printf 'header = "Authorization: Bearer %s"\n' "$token" |
        curl --config - --proto '=http' --proto-redir '=http' --noproxy '*' \
            --fail --silent --show-error --max-time 5 --max-filesize 1048576 "$url"
}

echo "=============================================="
echo "  Secure AI OS — First-Boot Health Check"
echo "=============================================="
echo ""

# 1. Core services status
echo "--- Service Status ---"
if [ ! -s "$SERVICE_PROFILE" ]; then
    fail "Service profile manifest is missing: $SERVICE_PROFILE"
    CORE_SERVICES=()
else
    mapfile -t CORE_SERVICES < <(
        python3 - "$SERVICE_PROFILE" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    profile = json.load(handle)
for service in profile.get("services", []):
    if service.get("required"):
        print(service["unit"])
PY
    )
fi

for svc in "${CORE_SERVICES[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        info "$svc is running"
    else
        fail "$svc is NOT running"
    fi
done

echo ""

# 2. Health endpoint checks
echo "--- Health Endpoints ---"
mapfile -t HEALTH_ENDPOINTS < <(
    python3 - "$SERVICE_PROFILE" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    profile = json.load(handle)
for service in profile.get("services", []):
    url = service.get("health_url", "")
    if service.get("required") and url.startswith(("http://", "https://")):
        print(f'{service["id"]}|{url}')
PY
)

for entry in "${HEALTH_ENDPOINTS[@]}"; do
    IFS='|' read -r name url <<< "$entry"
    if curl -sf "$url" > /dev/null 2>&1; then
        info "$name health OK"
    else
        fail "$name health check FAILED at $url"
    fi
done

echo ""

# 3. Security posture checks
echo "--- Security Posture ---"

# A directory at the vault path is not readiness evidence. Require the exact
# initialized LUKS mapper, filesystem, mount options, marker, and DAC contract.
if [ -x /usr/libexec/secure-ai/verify-vault-mount.py ] && \
   /usr/libexec/secure-ai/verify-vault-mount.py >/dev/null 2>&1; then
    info "Encrypted vault: exact mount contract VERIFIED"
else
    fail "Encrypted vault is unconfigured or failed exact mount verification"
fi

# Check attestation state
ATTEST=$(credential_get runtime-attestor.token \
    http://127.0.0.1:8505/api/v1/verify 2>/dev/null || echo '{"verified":false}')
if echo "$ATTEST" | grep -q '"verified":true'; then
    info "Runtime attestation: VERIFIED"
else
    warn "Runtime attestation: NOT fully verified (check boot measurements)"
fi

# Check integrity monitor
INTEG=$(credential_get integrity-monitor.token \
    http://127.0.0.1:8510/api/v1/status 2>/dev/null || echo '{"state":"unknown"}')
if echo "$INTEG" | grep -q '"state":"trusted"'; then
    info "Integrity monitor: TRUSTED"
elif echo "$INTEG" | grep -q '"state"'; then
    warn "Integrity monitor: state=$(echo "$INTEG" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("state","unknown"))' 2>/dev/null || echo 'unknown')"
else
    fail "Integrity monitor: unreachable"
fi

# Check for open incidents
INC_STATS=$(credential_get incident-read.token \
    http://127.0.0.1:8515/api/v1/stats 2>/dev/null || echo '{"open_incidents":0}')
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

# Root credential sources must exist, be non-empty regular files, and be
# owner-only.  Missing credentials are a readiness failure: services no
# longer have an unauthenticated development fallback.
while IFS= read -r credential; do
    [ -z "$credential" ] && continue
    path="/var/lib/secure-ai/credentials/$credential"
    if [ ! -f "$path" ] || [ -L "$path" ] || [ ! -s "$path" ]; then
        fail "Required service credential is missing or unsafe: $credential"
    elif [ "$(stat -c '%a:%U:%G' "$path" 2>/dev/null || true)" != "600:root:root" ]; then
        fail "Required service credential has unsafe ownership/mode: $credential"
    else
        info "Credential source validated: $credential"
    fi
done < <(
    python3 - "$SERVICE_PROFILE" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    profile = json.load(handle)
credentials = set()
for service in profile.get("services", []):
    if not service.get("required"):
        continue
    credential = service.get("inbound_credential", "")
    if credential:
        credentials.add(credential)
    for credential in service.get("inbound_credentials", []):
        if isinstance(credential, str) and credential:
            credentials.add(credential)
for credential in sorted(credentials):
    if credential:
        print(credential)
PY
)

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
PUBLIC_LISTENERS=$(
    ss -H -tlnp 2>/dev/null |
        awk '$4 !~ /^127\./ && $4 !~ /^\[::1\]:/ && $4 !~ /^::1:/ {print}' |
        head -5 || true
)
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
    echo -e "${YELLOW}NOT READY: $WARNINGS security warning(s) require review or explicit release evidence.${NC}"
    exit 1
fi

echo -e "${GREEN}ALL DECLARED READINESS CHECKS PASSED.${NC}"
exit 0
