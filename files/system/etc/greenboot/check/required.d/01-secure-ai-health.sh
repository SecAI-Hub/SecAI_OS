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
#   3. Post-upgrade model integrity (SHA256 vs manifest)
#   4. Firewall rules are loaded
#   5. Integrity check script exists
#   6. Vault mapper device exists (if configured)
#
# Timeout: 5 minutes (configured in greenboot.conf)
#

set -euo pipefail

HEALTH_LOG="/var/lib/secure-ai/logs/health-check.json"
ROLLBACK_COUNTER="/var/lib/secure-ai/state/greenboot-failures"
MAX_ROLLBACKS=2
BOOT_ID=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
[[ "$BOOT_ID" =~ ^[0-9a-f-]{36}$ ]] || {
    echo "[health-check] FAIL: kernel boot ID is unavailable or malformed" >&2
    exit 1
}
SERVICE_PROFILE="${SERVICE_PROFILE:-/etc/secure-ai/config/service-profile.json}"
REGISTRY_TOKEN_PATH="${REGISTRY_TOKEN_PATH:-/var/lib/secure-ai/credentials/registry-verify.token}"
INTEGRITY_MONITOR_TOKEN_PATH="${INTEGRITY_MONITOR_TOKEN_PATH:-/var/lib/secure-ai/credentials/integrity-monitor.token}"
INCIDENT_RECORDER_TOKEN_PATH="${INCIDENT_RECORDER_TOKEN_PATH:-/var/lib/secure-ai/credentials/incident-read.token}"
VAULT_VERIFY="/usr/libexec/secure-ai/verify-vault-mount.py"
VAULT_MOUNT="/var/lib/secure-ai/vault"
VAULT_MAPPER="/dev/mapper/secure-ai-vault"

log() {
    echo "[health-check] $*"
    logger -t secure-ai-health "$*" 2>/dev/null || true
}

fail() {
    log "FAIL: $*"
    write_result "fail" "$*"

    # Count failed boots, not repeated checks during one boot. The state must
    # survive reboot; /run would reset and permit an infinite rollback loop.
    local previous_boot="" count=0 temporary
    if [ -f "$ROLLBACK_COUNTER" ]; then
        read -r previous_boot count < "$ROLLBACK_COUNTER" || {
            previous_boot=""
            count=0
        }
    fi
    [[ "$count" =~ ^[0-9]+$ ]] || count=0
    if [ "$previous_boot" != "$BOOT_ID" ]; then
        count=$((count + 1))
    fi

    install -d -m 0750 "$(dirname "$ROLLBACK_COUNTER")"
    temporary=$(mktemp "$(dirname "$ROLLBACK_COUNTER")/.greenboot-failures.XXXXXX")
    printf '%s %s\n' "$BOOT_ID" "$count" > "$temporary"
    chmod 0600 "$temporary"
    mv -f -- "$temporary" "$ROLLBACK_COUNTER"

    if [ "$count" -ge "$MAX_ROLLBACKS" ]; then
        log "ERROR: max failed boots ($MAX_ROLLBACKS) reached — entering emergency recovery"
        write_result "recovery_required" "max failed boots reached: $*"
        systemctl --no-block isolate emergency.target 2>/dev/null || true
    fi

    # Never mark a broken deployment healthy. Greenboot handles rollback;
    # emergency.target stops the loop once both candidate and fallback fail.
    exit 1
}

write_result() {
    local status="$1"
    local detail="${2:-}"
    HEALTH_STATUS="$status" HEALTH_DETAIL="$detail" \
    HEALTH_BOOT_ID="$BOOT_ID" HEALTH_PATH="$HEALTH_LOG" python3 - <<'PY'
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

entry = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "event": "health_check",
    "status": os.environ["HEALTH_STATUS"],
    "detail": os.environ["HEALTH_DETAIL"],
    "boot_id": os.environ["HEALTH_BOOT_ID"],
}
entry["hash"] = hashlib.sha256(
    json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
path = Path(os.environ["HEALTH_PATH"])
path.parent.mkdir(parents=True, exist_ok=True)
fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(entry, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
        os.fchmod(handle.fileno(), 0o640)
    os.replace(temporary, path)
finally:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
PY
}

credential_request() {
    local token_path="$1"
    local method="$2"
    local url="$3"
    local token
    if [ ! -f "$token_path" ] || [ -L "$token_path" ] || [ ! -s "$token_path" ] || \
       [ "$(stat -c '%h' -- "$token_path" 2>/dev/null)" != "1" ]; then
        return 1
    fi
    IFS= read -r token < "$token_path"
    [[ "$token" =~ ^[0-9a-f]{64}$ ]] || return 1
    printf 'header = "Authorization: Bearer %s"\n' "$token" |
        curl --config - --fail --silent --show-error --max-time 30 \
            --max-filesize 1048576 \
            --request "$method" "$url"
}

verify_pristine_setup_vault() {
    python3 - "$VAULT_MOUNT" "$VAULT_MAPPER" <<'PY'
import os
import shlex
import stat
import subprocess
import sys
from pathlib import Path

mount_point = Path(sys.argv[1])
mapper = Path(sys.argv[2])
maximum = 1_048_576


def reject(message: str) -> None:
    print(message)
    raise SystemExit(1)


def read_config(path: Path) -> list[str]:
    if not os.path.lexists(path):
        return []
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        reject(f"{path} is unavailable or unsafe")
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or info.st_size > maximum
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            reject(f"{path} has unsafe ownership, type, size, or mode")
        chunks = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    if len(data) != info.st_size:
        reject(f"{path} changed while it was read")
    try:
        return data.decode("utf-8", "strict").splitlines()
    except UnicodeError:
        reject(f"{path} is not valid UTF-8")


for raw_line in read_config(Path("/etc/crypttab")):
    try:
        fields = shlex.split(raw_line, comments=True, posix=True)
    except ValueError:
        reject("/etc/crypttab contains malformed syntax")
    if fields and fields[0] == "secure-ai-vault":
        reject("vault crypttab configuration exists but the mount did not verify")

for raw_line in read_config(Path("/etc/fstab")):
    try:
        fields = shlex.split(raw_line, comments=True, posix=True)
    except ValueError:
        reject("/etc/fstab contains malformed syntax")
    if fields and (
        fields[0] == str(mapper)
        or (len(fields) > 1 and fields[1] == str(mount_point))
    ):
        reject("vault fstab configuration exists but the mount did not verify")

if os.path.lexists(mapper):
    reject("vault mapper exists but the mount did not verify")

try:
    result = subprocess.run(
        (
            "findmnt",
            "--json",
            "--mountpoint",
            str(mount_point),
            "--output",
            "SOURCE,FSTYPE,OPTIONS",
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
except (OSError, subprocess.SubprocessError):
    reject("the vault mount state cannot be inspected")
if result.returncode == 0:
    reject("the unconfigured vault path is unexpectedly mounted")
if result.returncode != 1:
    reject("findmnt could not establish that the vault path is unmounted")

try:
    info = mount_point.lstat()
except OSError:
    reject("the unconfigured vault mount point is missing")
if (
    not stat.S_ISDIR(info.st_mode)
    or info.st_uid != 0
    or info.st_gid != 0
    or stat.S_IMODE(info.st_mode) != 0o711
):
    reject("the unconfigured vault mount point has unsafe ownership or mode")
try:
    if any(mount_point.iterdir()):
        reject("plaintext or unexpected data exists beneath the unmounted vault path")
except OSError:
    reject("the unconfigured vault path cannot be inspected")

print("pristine")
PY
}

# A fresh appliance is allowed one explicitly identified setup-required state.
# Any partial configuration, unexpected mount, mapper, or plaintext data is a
# health failure rather than a reason to bless the deployment.
log "Establishing encrypted vault state..."
if [ ! -x "$VAULT_VERIFY" ]; then
    fail "exact vault mount verifier is missing or not executable"
fi
if "$VAULT_VERIFY" >/dev/null 2>&1; then
    VAULT_MODE="configured"
    log "  vault: configured encrypted mount verified"
else
    setup_detail=$(verify_pristine_setup_vault) || \
        fail "${setup_detail:-vault state is neither verified nor safely unconfigured}"
    [ "$setup_detail" = "pristine" ] || \
        fail "vault setup-state verifier returned an invalid result"
    VAULT_MODE="setup_required"
    log "  vault: pristine and unconfigured (local-console setup required)"
fi

# ── Check 1: Critical services ──
log "Checking critical systemd services..."
if [ ! -s "$SERVICE_PROFILE" ] || [ -L "$SERVICE_PROFILE" ]; then
    fail "service profile is missing or unsafe"
fi
critical_service_output=$(python3 - "$SERVICE_PROFILE" "$VAULT_MODE" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    profile = json.load(handle)
if profile.get("version") != 1:
    raise SystemExit("unsupported service profile")
mode = sys.argv[2]
expected_vault_services = {
    "agent",
    "diffusion",
    "inference",
    "integrity-monitor",
    "mcp-firewall",
    "registry",
    "tool-firewall",
}
services = profile.get("services", [])
if not isinstance(services, list):
    raise SystemExit("service profile has no service list")
by_id = {}
for service in services:
    if not isinstance(service, dict):
        raise SystemExit("invalid service entry")
    service_id = service.get("id")
    if not isinstance(service_id, str) or service_id in by_id:
        raise SystemExit("invalid or duplicate service ID")
    by_id[service_id] = service
for service_id in expected_vault_services:
    if by_id.get(service_id, {}).get("requires_vault") is not True:
        raise SystemExit(f"missing vault dependency declaration: {service_id}")
for service in profile.get("services", []):
    requires_vault = service.get("requires_vault", False)
    if not isinstance(requires_vault, bool):
        raise SystemExit("invalid requires_vault value")
    if (
        service.get("required") is True
        and (mode == "configured" or not requires_vault)
    ):
        unit = service.get("unit")
        if not isinstance(unit, str) or not unit.startswith("secure-ai-"):
            raise SystemExit("invalid required service unit")
        print(unit)
PY
) || fail "service profile validation failed"
mapfile -t CRITICAL_SERVICES <<< "$critical_service_output"
[ -n "$critical_service_output" ] || fail "service profile has no required services"
CRITICAL_SERVICES+=("nftables.service")

if [ "$VAULT_MODE" = "setup_required" ]; then
    mapfile -t VAULT_CONSUMERS < <(
        python3 - "$SERVICE_PROFILE" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    profile = json.load(handle)
for service in profile.get("services", []):
    if service.get("requires_vault") is True:
        print(service["unit"])
PY
    )
    VAULT_CONSUMERS+=(
        "secure-ai-vault-mounted.service"
        "secure-ai-quarantine-watcher.service"
        "secure-ai-integrity.service"
    )
    for svc in "${VAULT_CONSUMERS[@]}"; do
        active_state=$(systemctl show --property ActiveState --value "$svc" 2>/dev/null) || \
            fail "cannot establish setup-mode state for $svc"
        [ "$active_state" = "inactive" ] || \
            fail "vault consumer must be inactive before setup: $svc ($active_state)"
    done
fi

for svc in "${CRITICAL_SERVICES[@]}"; do
    for _attempt in $(seq 1 12); do
        systemctl is-active --quiet "$svc" 2>/dev/null && break
        sleep 5
    done
    systemctl is-active --quiet "$svc" 2>/dev/null || \
        fail "critical service not active: $svc"
    log "  $svc: active"
done

# ── Check 2: Registry and model integrity ──
if [ "$VAULT_MODE" = "configured" ]; then
    log "Checking registry API..."
    for i in $(seq 1 6); do
        if curl -sf --max-time 5 http://127.0.0.1:8470/health >/dev/null 2>&1; then
            log "  registry API: reachable"
            break
        fi
        [ "$i" -ne 6 ] || fail "registry API unreachable after 30s"
        sleep 5
    done

    # Ask both independent integrity authorities to re-hash current state from
    # the registry's authoritative manifest and the signed runtime baseline.
    log "Checking model integrity..."
    credential_request "$REGISTRY_TOKEN_PATH" POST \
        "http://127.0.0.1:8470/v1/models/verify-all" >/dev/null || \
        fail "registry model verification failed"
    credential_request "$INTEGRITY_MONITOR_TOKEN_PATH" POST \
        "http://127.0.0.1:8510/api/v1/scan" >/dev/null || \
        fail "continuous integrity scan failed"
    credential_request "$INTEGRITY_MONITOR_TOKEN_PATH" GET \
        "http://127.0.0.1:8510/api/v1/verify" >/dev/null || \
        fail "continuous integrity state is not trusted"
    log "  registry and continuous integrity: verified"
fi

log "Checking incident recorder state..."
incident_stats=$(credential_request "$INCIDENT_RECORDER_TOKEN_PATH" GET \
    "http://127.0.0.1:8515/api/v1/stats") || \
    fail "incident recorder status is unavailable"
open_incidents=$(printf '%s' "$incident_stats" | python3 -c '
import json, sys
value = json.load(sys.stdin).get("open_incidents")
if type(value) is not int or value < 0:
    raise SystemExit(1)
print(value)
') || fail "incident recorder returned an invalid status"
[ "$open_incidents" -eq 0 ] || fail "$open_incidents incident(s) remain open"
log "  incident recorder: reachable with no open incidents"

# ── Check 3: Firewall rules ──
log "Checking firewall rules..."
if command -v nft &>/dev/null; then
    if ! nft list ruleset 2>/dev/null | grep -F "table inet secure_ai" >/dev/null; then
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

# ── All checks passed ──
if [ "$VAULT_MODE" = "setup_required" ]; then
    log "Base appliance controls passed; encrypted vault setup is still required"
    write_result "setup_required" \
        "run sudo /usr/libexec/secure-ai/secai-setup-wizard.sh from the local console"
    rm -f -- "$ROLLBACK_COUNTER"
    exit 0
fi

log "All health checks passed"
write_result "pass" "all checks passed"

# Clear rollback counter on success
rm -f -- "$ROLLBACK_COUNTER"

exit 0
