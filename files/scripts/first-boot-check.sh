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

security_reply() {
    python3 -c '
import json, sys
def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result
try:
    raw = sys.stdin.read(1048577)
    if len(raw) > 1048576:
        raise ValueError("oversized response")
    data = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(data, dict):
        raise ValueError("expected object")
    kind = sys.argv[1]
    if kind == "attestation":
        valid = (type(data.get("schema_version")) is int and data["schema_version"] == 2
                 and data.get("verification_scope") == "runtime"
                 and data.get("state") == "attested"
                 and data.get("assurance_mode") == "hardware"
                 and data.get("gpu_mode") in ("required", "optional", "no_gpu")
                 and all(data.get(key) is True for key in
                         ("verified", "evidence_verified", "policy_satisfied", "gpu_policy_satisfied")))
    elif kind == "integrity":
        valid = (data.get("state") == "trusted"
                 and type(data.get("scan_count")) is int and data["scan_count"] > 0
                 and type(data.get("violation_count")) is int and data["violation_count"] == 0)
    elif kind == "incidents":
        valid = type(data.get("open_incidents")) is int and data["open_incidents"] >= 0
        if valid:
            print(data["open_incidents"])
    else:
        valid = False
    if not valid:
        raise ValueError("readiness evidence rejected")
except (ValueError, TypeError):
    sys.exit(1)
' "$1"
}

load_service_profile() {
    python3 - "$SERVICE_PROFILE" <<'PY'
import json, re, sys
from urllib.parse import urlsplit

with open(sys.argv[1], encoding="utf-8") as handle:
    raw = handle.read(1048577)
if len(raw) > 1048576:
    raise SystemExit("service profile is too large")
profile = json.loads(raw)
if (not isinstance(profile, dict) or type(profile.get("version")) is not int
        or profile["version"] != 1 or not isinstance(profile.get("services"), list)
        or not profile["services"] or len(profile["services"]) > 128):
    raise SystemExit("invalid service profile")
ids, units = set(), set()
for service in profile["services"]:
    if (not isinstance(service, dict) or type(service.get("required")) is not bool
            or not isinstance(service.get("id"), str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", service["id"])
            or not isinstance(service.get("unit"), str)
            or not re.fullmatch(r"secure-ai-[a-z0-9-]+\.service", service["unit"])
            or service["id"] in ids or service["unit"] in units):
        raise SystemExit("invalid service declaration")
    ids.add(service["id"])
    units.add(service["unit"])
    url = service.get("health_url", "")
    if not isinstance(url, str) or any(char.isspace() for char in url):
        raise SystemExit("invalid health endpoint")
    if url.startswith("unix://"):
        if not re.fullmatch(r"unix:///run/secure-ai/[a-z0-9_/-]+\.sock", url) or "//" in url[7:]:
            raise SystemExit("invalid health socket")
    elif url:
        parsed = urlsplit(url)
        if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
                or parsed.username is not None or parsed.password is not None
                or parsed.port is None or not 1 <= parsed.port <= 65535
                or not re.fullmatch(r"/[a-zA-Z0-9/_-]+", parsed.path)
                or parsed.query or parsed.fragment):
            raise SystemExit("health endpoint must be exact numeric loopback HTTP")
    credentials = service.get("inbound_credentials", [])
    if not isinstance(credentials, list):
        raise SystemExit("invalid credential list")
    for credential in [service.get("inbound_credential", ""), *credentials]:
        if (not isinstance(credential, str) or (credential and
                (not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", credential) or ".." in credential))):
            raise SystemExit("invalid credential name")
if not any(service["required"] for service in profile["services"]):
    raise SystemExit("service profile has no required services")
print(json.dumps(profile, separators=(",", ":")))
PY
}

echo "=============================================="
echo "  Secure AI OS — First-Boot Health Check"
echo "=============================================="
echo ""

# 1. Core services status
echo "--- Service Status ---"
if ! PROFILE_JSON=$(load_service_profile 2>/dev/null); then
    fail "Service profile manifest is missing or invalid: $SERVICE_PROFILE"
    exit 1
fi
mapfile -t CORE_SERVICES < <(
    printf '%s' "$PROFILE_JSON" | python3 -c '
import json, sys
profile = json.load(sys.stdin)
for service in profile.get("services", []):
    if service.get("required"):
        print(service["unit"])
'
)

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
    printf '%s' "$PROFILE_JSON" | python3 -c '
import json, sys
profile = json.load(sys.stdin)
for service in profile.get("services", []):
    url = service.get("health_url", "")
    if service.get("required") and url:
        print("{}|{}".format(service["id"], url))
'
)

for entry in "${HEALTH_ENDPOINTS[@]}"; do
    IFS='|' read -r name url <<< "$entry"
    socket_options=()
    if [[ "$url" == unix://* ]]; then
        socket_options=(--unix-socket "${url#unix://}")
        url=http://localhost/health
    fi
    if curl --proto '=http' --proto-redir '=http' --noproxy '*' \
        --connect-timeout 1 --max-time 5 --max-filesize 1048576 \
        "${socket_options[@]}" -sf "$url" > /dev/null 2>&1; then
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
if ATTEST=$(credential_get runtime-attestor.token \
    http://127.0.0.1:8505/api/v1/verify 2>/dev/null) && \
    printf '%s' "$ATTEST" | security_reply attestation; then
    info "Runtime attestation: VERIFIED"
else
    fail "Runtime attestation: current full hardware and GPU policy is not verified"
fi

# Check integrity monitor
if INTEG=$(credential_get integrity-monitor.token \
    http://127.0.0.1:8510/api/v1/status 2>/dev/null) && \
    printf '%s' "$INTEG" | security_reply integrity; then
    info "Integrity monitor: TRUSTED"
else
    fail "Integrity monitor: no valid trusted completed scan or service unavailable"
fi

# Check for open incidents
if INC_STATS=$(credential_get incident-read.token \
    http://127.0.0.1:8515/api/v1/stats 2>/dev/null) && \
    OPEN_INC=$(printf '%s' "$INC_STATS" | security_reply incidents); then
    if [ "$OPEN_INC" -eq 0 ]; then
        info "No open incidents"
    else
        warn "$OPEN_INC open incident(s) detected"
    fi
else
    fail "Incident recorder: current incident state is unavailable or invalid"
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
    printf '%s' "$PROFILE_JSON" | python3 -c '
import json, sys
profile = json.load(sys.stdin)
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
'
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
