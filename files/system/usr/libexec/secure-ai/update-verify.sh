#!/usr/bin/env bash
#
# Secure AI Appliance — signed, digest-bound rpm-ostree updates (M24)
#
# Usage:
#   update-verify.sh check
#   update-verify.sh stage
#   update-verify.sh apply
#   update-verify.sh rollback
#   update-verify.sh status
#
set -euo pipefail
umask 077

SECURE_AI_ROOT="${SECURE_AI_ROOT:-/var/lib/secure-ai}"
UPDATE_STATE="${UPDATE_STATE:-/run/secure-ai/update-state.json}"
AUDIT_LOG="${AUDIT_LOG:-${SECURE_AI_ROOT}/logs/update-audit.jsonl}"
COSIGN_PUB_KEY="${COSIGN_PUB_KEY:-/etc/pki/containers/secai-cosign.pub}"
CANDIDATE_DIR="${CANDIDATE_DIR:-${SECURE_AI_ROOT}/updates}"
CANDIDATE_RECORD="${CANDIDATE_RECORD:-${CANDIDATE_DIR}/verified-candidate.json}"
HIGH_WATER_RECORD="${HIGH_WATER_RECORD:-${CANDIDATE_DIR}/accepted-release.json}"
EXPECTED_IMAGE_REPOSITORY="${EXPECTED_IMAGE_REPOSITORY:-ghcr.io/secai-hub/secai_os}"

log() {
    printf '[update-verify] %s\n' "$*" >&2
    logger -t secure-ai-update -- "$*" 2>/dev/null || true
}

validate_configuration() {
    if [[ ! "$EXPECTED_IMAGE_REPOSITORY" =~ ^[a-z0-9.-]+/[a-z0-9._/-]+$ ]]; then
        log "ERROR: EXPECTED_IMAGE_REPOSITORY is invalid"
        return 1
    fi
    case "$UPDATE_STATE $AUDIT_LOG $CANDIDATE_RECORD $HIGH_WATER_RECORD" in
        *$'\n'*|*$'\r'*)
            log "ERROR: configured state paths contain control characters"
            return 1
            ;;
    esac
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log "ERROR: this action requires root privileges"
        return 1
    fi
}

require_verification_tools() {
    local tool
    for tool in rpm-ostree python3 skopeo cosign; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log "ERROR: required update-verification tool was not found: $tool"
            return 1
        fi
    done
    if [ ! -f "$COSIGN_PUB_KEY" ] || [ -L "$COSIGN_PUB_KEY" ] || [ ! -s "$COSIGN_PUB_KEY" ]; then
        log "ERROR: trusted cosign key must be a nonempty regular file"
        return 1
    fi
    local key_mode
    key_mode=$(stat -c '%a' "$COSIGN_PUB_KEY" 2>/dev/null) || return 1
    if (( (8#$key_mode & 8#022) != 0 )); then
        log "ERROR: trusted cosign key is group/world writable"
        return 1
    fi
}

audit_update() {
    local action="$1"
    local detail="${2:-}"
    local timestamp
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    python3 - "$AUDIT_LOG" "$timestamp" "$action" "$detail" <<'PY' || {
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

path = Path(sys.argv[1])
timestamp, action, detail = sys.argv[2:5]
path.parent.mkdir(parents=True, exist_ok=True)
if path.is_symlink():
    raise SystemExit("audit log must not be a symlink")
if path.exists() and not stat.S_ISREG(path.stat().st_mode):
    raise SystemExit("audit log must be a regular file")

previous_hash = "0" * 64
if path.exists() and path.stat().st_size:
    with path.open("rb") as handle:
        try:
            last = handle.readlines()[-1]
            previous = json.loads(last)
            candidate = previous.get("hash", "")
            if isinstance(candidate, str) and len(candidate) == 64:
                previous_hash = candidate
        except (IndexError, json.JSONDecodeError, OSError):
            raise SystemExit("audit log tail is invalid")

entry = {
    "timestamp": timestamp,
    "event": "update_action",
    "action": action,
    "detail": detail,
    "previous_hash": previous_hash,
}
canonical = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
entry["hash"] = hashlib.sha256(canonical).hexdigest()
encoded = (json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n").encode()

flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
fd = os.open(path, flags, 0o600)
try:
    os.fchmod(fd, 0o600)
    os.write(fd, encoded)
    os.fsync(fd)
finally:
    os.close(fd)
PY
        log "WARNING: unable to append update audit event"
        return 0
    }
}

write_json_file() {
    local destination="$1"
    local mode="$2"
    local payload="$3"
    python3 - "$destination" "$mode" "$payload" <<'PY'
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

destination = Path(sys.argv[1])
mode = int(sys.argv[2], 8)
payload = json.loads(sys.argv[3])
destination.parent.mkdir(parents=True, exist_ok=True)
if destination.is_symlink():
    raise SystemExit(f"refusing symlink destination: {destination}")
if destination.exists() and not stat.S_ISREG(destination.stat().st_mode):
    raise SystemExit(f"refusing non-regular destination: {destination}")

fd, temporary_name = tempfile.mkstemp(
    prefix=f".{destination.name}.", dir=destination.parent
)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
        os.fchmod(handle.fileno(), mode)
    os.replace(temporary_name, destination)
    parent_fd = os.open(destination.parent, os.O_RDONLY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
finally:
    try:
        os.unlink(temporary_name)
    except FileNotFoundError:
        pass
PY
}

write_state() {
    local status="$1"
    local detail="${2:-}"
    local version="${3:-}"
    local payload
    payload=$(python3 - "$status" "$detail" "$version" <<'PY'
import datetime as dt
import json
import sys

print(json.dumps({
    "status": sys.argv[1],
    "detail": sys.argv[2],
    "version": sys.argv[3],
    "timestamp": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
}))
PY
)
    write_json_file "$UPDATE_STATE" 0644 "$payload"
}

emit_json() {
    python3 - "$@" <<'PY'
import json
import sys

if len(sys.argv[1:]) % 2:
    raise SystemExit("emit_json requires key/value pairs")
result = {}
for index in range(1, len(sys.argv), 2):
    value = sys.argv[index + 1]
    if value == "true":
        value = True
    elif value == "false":
        value = False
    result[sys.argv[index]] = value
print(json.dumps(result, sort_keys=True))
PY
}

booted_deployment_json() {
    rpm-ostree status --json | python3 -c '
import json
import sys

data = json.load(sys.stdin)
booted = [item for item in data.get("deployments", []) if item.get("booted") is True]
if len(booted) != 1:
    raise SystemExit("expected exactly one booted deployment")
print(json.dumps(booted[0], sort_keys=True))
'
}

normalize_image_reference() {
    python3 - "$1" <<'PY'
import sys

ref = sys.argv[1]
for prefix in (
    "ostree-image-signed:docker://",
    "ostree-unverified-registry:",
    "ostree-unverified-image:docker://",
    "docker://",
):
    if ref.startswith(prefix):
        ref = ref[len(prefix):]
        break
if not ref or any(char.isspace() for char in ref):
    raise SystemExit("invalid image reference")
print(ref)
PY
}

tracking_reference() {
    local deployment raw_ref
    deployment=$(booted_deployment_json) || {
        log "ERROR: cannot identify the booted rpm-ostree deployment"
        return 1
    }
    raw_ref=$(python3 - "$deployment" <<'PY'
import json
import sys

deployment = json.loads(sys.argv[1])
ref = deployment.get("container-image-reference") or deployment.get("origin") or ""
if not isinstance(ref, str) or not ref:
    raise SystemExit("booted deployment has no image reference")
print(ref)
PY
)
    normalize_image_reference "$raw_ref"
}

validate_exact_reference() {
    local ref="$1"
    if [[ ! "$ref" =~ ^${EXPECTED_IMAGE_REPOSITORY//./\\.}(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[0-9a-f]{64}$ ]]; then
        return 1
    fi
}

current_exact_reference() {
    local ref
    ref=$(tracking_reference) || return 1
    if ! validate_exact_reference "$ref"; then
        log "ERROR: booted deployment is not bound to an approved exact image digest"
        return 1
    fi
    printf '%s\n' "$ref"
}

resolve_candidate() {
    require_verification_tools

    local tracking channel digest
    tracking=$(tracking_reference) || return 1
    channel="${tracking%@*}"
    if [[ ! "$channel" =~ ^${EXPECTED_IMAGE_REPOSITORY//./\\.}:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]]; then
        log "ERROR: booted deployment lacks an approved tagged update channel"
        return 1
    fi

    digest=$(skopeo inspect --format '{{.Digest}}' "docker://${channel}") || {
        log "ERROR: cannot resolve candidate digest for $channel"
        return 1
    }
    if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        log "ERROR: registry returned an invalid candidate digest"
        return 1
    fi
    printf '%s@%s\n' "$channel" "$digest"
}

verify_signature() {
    local registry_ref="${1:-}"
    if ! validate_exact_reference "$registry_ref"; then
        log "ERROR: signature verification requires an approved exact digest reference"
        return 1
    fi
    require_verification_tools
    log "Verifying signature for exact candidate: $registry_ref"
    if ! cosign verify --key "$COSIGN_PUB_KEY" "$registry_ref" >/dev/null; then
        log "ERROR: signature verification FAILED for $registry_ref"
        audit_update "verify_signature" "FAILED: $registry_ref"
        return 1
    fi
    audit_update "verify_signature" "passed: $registry_ref"
}

inspect_release_metadata() {
    local ref="$1"
    local inspect_json
    validate_exact_reference "$ref" || return 1
    inspect_json=$(skopeo inspect "docker://${ref}") || return 1
    python3 - "$ref" "$inspect_json" <<'PY'
import datetime as dt
import json
import re
import sys

expected_ref = sys.argv[1]
data = json.loads(sys.argv[2])
expected_digest = expected_ref.rsplit("@", 1)[1]
if data.get("Digest") != expected_digest:
    raise SystemExit("registry metadata digest does not match the requested image")
labels = data.get("Labels") or {}
created = labels.get("org.opencontainers.image.created") or data.get("Created")
revision = labels.get("org.opencontainers.image.revision")
if not isinstance(created, str):
    raise SystemExit("image has no creation timestamp")
try:
    parsed = dt.datetime.fromisoformat(created.replace("Z", "+00:00"))
except ValueError as exc:
    raise SystemExit(f"invalid image creation timestamp: {exc}")
if parsed.tzinfo is None:
    raise SystemExit("image creation timestamp must include a timezone")
if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
    raise SystemExit("image has no valid source revision label")
print(json.dumps({
    "image_ref": expected_ref,
    "digest": expected_digest,
    "created": parsed.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "source_commit": revision,
}, sort_keys=True, separators=(",", ":")))
PY
}

enforce_anti_rollback() {
    local current_ref="$1"
    local candidate_ref="$2"
    local current_metadata candidate_metadata
    current_metadata=$(inspect_release_metadata "$current_ref") || {
        log "ERROR: cannot validate current release metadata"
        return 1
    }
    candidate_metadata=$(inspect_release_metadata "$candidate_ref") || {
        log "ERROR: candidate lacks valid release metadata"
        return 1
    }

    python3 - "$current_metadata" "$candidate_metadata" "$HIGH_WATER_RECORD" <<'PY'
import datetime as dt
import json
import stat
import sys
from pathlib import Path

current = json.loads(sys.argv[1])
candidate = json.loads(sys.argv[2])
high_water_path = Path(sys.argv[3])

def timestamp(record):
    return dt.datetime.fromisoformat(record["created"].replace("Z", "+00:00"))

if candidate["digest"] == current["digest"]:
    raise SystemExit("candidate digest is already booted")
if timestamp(candidate) <= timestamp(current):
    raise SystemExit("candidate is not newer than the booted release")

if high_water_path.exists() or high_water_path.is_symlink():
    if high_water_path.is_symlink() or not stat.S_ISREG(high_water_path.stat().st_mode):
        raise SystemExit("anti-rollback high-water state is not a regular file")
    high_water = json.loads(high_water_path.read_text(encoding="utf-8"))
    if timestamp(candidate) < timestamp(high_water):
        raise SystemExit("candidate predates the accepted-release high-water mark")

print(json.dumps(candidate, sort_keys=True, separators=(",", ":")))
PY
}

check_updates() {
    log "Checking the signed update channel..."
    write_state "checking" "resolving exact update candidate"

    local current_ref candidate candidate_metadata
    current_ref=$(current_exact_reference) || {
        write_state "verification_failed" "booted deployment is not digest-bound"
        return 1
    }
    candidate=$(resolve_candidate) || {
        write_state "verification_failed" "candidate resolution failed"
        return 1
    }

    # A digest-bound origin must not use `rpm-ostree upgrade --check` to select
    # an artifact: channel discovery is separated from exact-digest approval.
    if [ "${current_ref##*@}" = "${candidate##*@}" ]; then
        write_state "up_to_date" "no newer signed digest is available" "$current_ref"
        emit_json update_available false current "$current_ref"
        return 0
    fi
    verify_signature "$candidate" || {
        write_state "signature_failed" "available update failed verification"
        return 1
    }
    candidate_metadata=$(enforce_anti_rollback "$current_ref" "$candidate") || {
        write_state "rollback_rejected" "candidate violates anti-rollback policy"
        audit_update "check" "rejected candidate: $candidate"
        return 1
    }
    write_state "update_available" "signed, newer exact digest available" "$candidate"
    audit_update "check" "verified update available: $candidate"
    emit_json update_available true current "$current_ref" candidate "$candidate" metadata "$candidate_metadata"
}

stage_update() {
    require_root
    log "Staging a signed exact-digest update without rebooting..."
    write_state "staging" "resolving and validating update"
    audit_update "stage" "beginning staged download"

    local current_ref candidate candidate_metadata
    current_ref=$(current_exact_reference) || return 1
    candidate=$(resolve_candidate) || {
        write_state "verification_failed" "candidate resolution failed"
        return 1
    }
    verify_signature "$candidate" || {
        write_state "signature_failed" "update rejected: bad signature"
        return 1
    }
    candidate_metadata=$(enforce_anti_rollback "$current_ref" "$candidate") || {
        write_state "rollback_rejected" "candidate violates anti-rollback policy"
        return 1
    }

    if rpm-ostree rebase --experimental --download-only \
        "ostree-image-signed:docker://${candidate}" 2>&1; then
        install -d -m 0700 "$CANDIDATE_DIR"
        write_json_file "$CANDIDATE_RECORD" 0600 "$candidate_metadata"
        write_state "staged" "verified update downloaded, ready to apply" "$candidate"
        audit_update "stage" "verified candidate staged: $candidate"
        emit_json status staged candidate "$candidate" message "Update downloaded; apply will re-verify it before reboot."
    else
        write_state "stage_failed" "rpm-ostree rebase download failed"
        audit_update "stage" "staging failed"
        return 1
    fi
}

read_candidate_record() {
    python3 - "$CANDIDATE_RECORD" <<'PY'
import json
import os
import stat
import sys
from pathlib import Path

path = Path(sys.argv[1])
if path.is_symlink() or not path.is_file():
    raise SystemExit("verified candidate record is missing or unsafe")
info = path.stat()
if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
    raise SystemExit("verified candidate record ownership/mode/link count is unsafe")
record = json.loads(path.read_text(encoding="utf-8"))
required = {"image_ref", "digest", "created", "source_commit"}
if set(record) != required:
    raise SystemExit("verified candidate record has unexpected fields")
print(json.dumps(record, sort_keys=True, separators=(",", ":")))
PY
}

apply_update() {
    require_root
    log "Applying the staged exact-digest update..."
    write_state "applying" "re-verifying staged update"
    audit_update "apply" "applying staged update"

    local record candidate current_ref candidate_metadata
    record=$(read_candidate_record) || {
        write_state "verification_failed" "verified candidate state is missing or unsafe"
        return 1
    }
    candidate=$(python3 - "$record" <<'PY'
import json
import sys
print(json.loads(sys.argv[1])["image_ref"])
PY
)
    validate_exact_reference "$candidate" || {
        write_state "verification_failed" "staged candidate reference is invalid"
        return 1
    }
    verify_signature "$candidate" || {
        write_state "signature_failed" "apply rejected: bad signature"
        return 1
    }
    current_ref=$(current_exact_reference) || return 1
    candidate_metadata=$(enforce_anti_rollback "$current_ref" "$candidate") || {
        write_state "rollback_rejected" "staged candidate violates anti-rollback policy"
        return 1
    }
    if [ "$candidate_metadata" != "$record" ]; then
        log "ERROR: staged candidate metadata changed or was tampered with"
        write_state "verification_failed" "staged candidate metadata mismatch"
        return 1
    fi

    if rpm-ostree rebase --experimental \
        "ostree-image-signed:docker://${candidate}" 2>&1; then
        install -d -m 0700 "$CANDIDATE_DIR"
        write_json_file "$HIGH_WATER_RECORD" 0600 "$candidate_metadata"
        write_state "applied" "update applied, reboot required" "$candidate"
        audit_update "apply" "update applied, reboot pending: $candidate"
        emit_json status applied candidate "$candidate" message "Update applied; rebooting."
        systemctl reboot
    else
        write_state "apply_failed" "rpm-ostree rebase failed"
        audit_update "apply" "apply failed"
        return 1
    fi
}

previous_deployment_reference() {
    rpm-ostree status --json | python3 -c '
import json
import sys

data = json.load(sys.stdin)
previous = [
    item for item in data.get("deployments", [])
    if not item.get("booted") and not item.get("staged")
]
if not previous:
    raise SystemExit("no previous deployment")
ref = previous[0].get("container-image-reference") or previous[0].get("origin") or ""
print(ref)
'
}

do_rollback() {
    require_root
    local previous_raw previous
    previous_raw=$(previous_deployment_reference) || {
        log "ERROR: no previous deployment is available"
        return 1
    }
    previous=$(normalize_image_reference "$previous_raw") || return 1
    if ! validate_exact_reference "$previous"; then
        log "ERROR: previous deployment is not an approved exact image digest"
        return 1
    fi
    verify_signature "$previous" || {
        write_state "signature_failed" "rollback target signature is invalid"
        return 1
    }

    audit_update "rollback" "user-approved rollback target: $previous"
    write_state "rolling_back" "reverting to verified previous deployment" "$previous"
    if rpm-ostree rollback 2>&1; then
        write_state "rolled_back" "rollback applied, rebooting" "$previous"
        audit_update "rollback" "rollback applied: $previous"
        emit_json status rolled_back target "$previous" message "Rollback applied; rebooting."
        systemctl reboot
    else
        write_state "rollback_failed" "rpm-ostree rollback failed"
        audit_update "rollback" "rollback failed"
        return 1
    fi
}

show_status() {
    local deployments
    deployments=$(rpm-ostree status --json 2>/dev/null || printf '{"deployments":[]}')
    python3 - "$UPDATE_STATE" "$deployments" <<'PY'
import json
import stat
import sys
from pathlib import Path

state_path = Path(sys.argv[1])
if state_path.is_symlink():
    raise SystemExit("update state must not be a symlink")
if state_path.exists() and not stat.S_ISREG(state_path.stat().st_mode):
    raise SystemExit("update state must be a regular file")
state = (
    json.loads(state_path.read_text(encoding="utf-8"))
    if state_path.exists()
    else {"status": "unknown", "detail": "no update check has run"}
)
rpm_state = json.loads(sys.argv[2])
state["deployments"] = [
    {
        "checksum": item.get("checksum", "")[:12],
        "version": item.get("version", ""),
        "booted": bool(item.get("booted")),
        "staged": bool(item.get("staged")),
        "origin": item.get("container-image-reference") or item.get("origin", ""),
    }
    for item in rpm_state.get("deployments", [])
]
print(json.dumps(state, indent=2, sort_keys=True))
PY
}

validate_configuration

cmd="${1:-help}"
case "$cmd" in
    check)
        check_updates
        ;;
    stage)
        stage_update
        ;;
    apply)
        apply_update
        ;;
    rollback)
        do_rollback
        ;;
    status)
        show_status
        ;;
    help|--help|-h)
        cat <<'EOF'
update-verify.sh — Secure AI Update Verification (M24)

Commands:
  check     Resolve, verify, and anti-rollback-check the update channel
  stage     Download a verified exact-digest update (root)
  apply     Re-verify and apply the staged exact digest, then reboot (root)
  rollback  Verify and boot the previous deployment (root)
  status    Show update state and rpm-ostree deployments
EOF
        ;;
    *)
        echo "Unknown command: $cmd" >&2
        exit 1
        ;;
esac
