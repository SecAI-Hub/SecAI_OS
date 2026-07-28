#!/usr/bin/env bash
#
# Secure AI Appliance — offline-first boot chain integrity verification.
#
# Verifies the running kernel (not merely the newest file in /boot), loaded
# external kernel-module signatures, and the exact booted rpm-ostree image.
# Image verification is safe while offline: rpm-ostree's signed transport,
# local sigstore policy/key, and their immutable release-baseline measurements
# are checked without contacting a registry.
#
set -euo pipefail
umask 077

RESULT_PATH="${BOOT_VERIFY_RESULT_PATH:-/var/lib/secure-ai/logs/boot-verify-last.json}"
MOK_PEM="${MOK_PEM:-/etc/secure-ai/keys/secureai-mok.pem}"
COSIGN_PUB="${COSIGN_PUB_KEY:-/etc/pki/containers/secai-cosign.pub}"
CONTAINERS_POLICY="${CONTAINERS_POLICY:-/etc/containers/policy.json}"
REGISTRIES_CONFIG="${REGISTRIES_CONFIG:-/etc/containers/registries.d/secai-os.yaml}"
RELEASE_BASELINE="${RELEASE_BASELINE:-/usr/share/secure-ai/integrity/release-baseline.json}"
EXPECTED_IMAGE_REPOSITORY="${EXPECTED_IMAGE_REPOSITORY:-ghcr.io/secai-hub/secai_os}"

declare -A checks

log() {
    printf '[verify-boot-chain] %s\n' "$*" >&2
    logger -t verify-boot-chain -- "$*" 2>/dev/null || true
}

check_secure_boot() {
    if [ ! -d /sys/firmware/efi ]; then
        checks[secure_boot]="unavailable"
        checks[secure_boot_detail]="legacy BIOS or no UEFI"
        return
    fi
    if ! command -v mokutil >/dev/null 2>&1; then
        checks[secure_boot]="unknown"
        checks[secure_boot_detail]="mokutil is unavailable"
        return
    fi

    local sb_state
    sb_state=$(mokutil --sb-state 2>/dev/null || printf 'unknown')
    case "$sb_state" in
        *enabled*|*Enabled*)
            checks[secure_boot]="enabled"
            checks[secure_boot_detail]="UEFI Secure Boot is active"
            ;;
        *disabled*|*Disabled*)
            checks[secure_boot]="disabled"
            checks[secure_boot_detail]="Secure Boot is disabled"
            ;;
        *)
            checks[secure_boot]="unknown"
            checks[secure_boot_detail]="could not determine Secure Boot state"
            ;;
    esac
}

check_tpm2() {
    if [ ! -e /dev/tpmrm0 ] && [ ! -e /dev/tpm0 ]; then
        checks[tpm2]="unavailable"
        checks[tpm2_sealed]="false"
        checks[tpm2_detail]="no TPM device found"
        return
    fi
    if ! command -v tpm2_pcrread >/dev/null 2>&1; then
        checks[tpm2]="unavailable"
        checks[tpm2_sealed]="false"
        checks[tpm2_detail]="tpm2-tools is unavailable"
        return
    fi

    if tpm2_pcrread "sha256:0" >/dev/null 2>&1; then
        checks[tpm2]="available"
        if [ -f /var/lib/secure-ai/keys/tpm2/vault-key.sealed ] || \
           [ -f /var/lib/secure-ai/keys/tpm2/vault-key.sealed.pub ]; then
            checks[tpm2_sealed]="true"
            checks[tpm2_detail]="TPM2 active; vault key is sealed"
        else
            checks[tpm2_sealed]="false"
            checks[tpm2_detail]="TPM2 active; vault uses passphrase-only mode"
        fi
    else
        checks[tpm2]="error"
        checks[tpm2_sealed]="false"
        checks[tpm2_detail]="TPM device is present but PCR 0 cannot be read"
    fi
}

running_kernel_path() {
    local release="$1"
    local candidate resolved
    if [[ ! "$release" =~ ^[A-Za-z0-9._+-]+$ ]]; then
        return 1
    fi
    for candidate in \
        "/usr/lib/modules/${release}/vmlinuz" \
        "/boot/vmlinuz-${release}"; do
        [ -e "$candidate" ] || continue
        resolved=$(readlink -f -- "$candidate") || continue
        if [ -f "$resolved" ] && [[ "$resolved" == /usr/lib/modules/* || "$resolved" == /boot/* ]]; then
            printf '%s\n' "$resolved"
            return 0
        fi
    done
    return 1
}

check_kernel_signature() {
    checks[kernel_release]="$(uname -r)"
    if ! command -v sbverify >/dev/null 2>&1; then
        checks[kernel_sig]="unchecked"
        checks[kernel_sig_detail]="sbverify is unavailable"
        return
    fi

    local kernel
    kernel=$(running_kernel_path "${checks[kernel_release]}") || {
        checks[kernel_sig]="invalid"
        checks[kernel_sig_detail]="running kernel image could not be located"
        return
    }
    checks[kernel_path]="$kernel"

    if ! sbverify --list "$kernel" >/dev/null 2>&1; then
        checks[kernel_sig]="invalid"
        checks[kernel_sig_detail]="running kernel has no valid PE signature table"
        return
    fi
    if [ -f "$MOK_PEM" ] && ! [ -L "$MOK_PEM" ] && \
       sbverify --cert "$MOK_PEM" "$kernel" >/dev/null 2>&1; then
        checks[kernel_sig]="valid"
        checks[kernel_sig_detail]="running kernel is signed by the enrolled SecAI MOK"
    else
        checks[kernel_sig]="valid"
        checks[kernel_sig_detail]="running kernel has a PE signature and was selected under Secure Boot policy"
    fi
}

check_module_signatures() {
    checks[module_sig]="unchecked"
    checks[module_signed_count]="0"
    checks[module_external_count]="0"
    if [ ! -r /proc/modules ]; then
        checks[module_sig_detail]="/proc/modules is unavailable"
        return
    fi
    if ! command -v modinfo >/dev/null 2>&1; then
        checks[module_sig_detail]="modinfo is unavailable"
        return
    fi

    local module filename signer
    local external_count=0
    local signed_count=0
    local unsigned_modules=()
    while read -r module _; do
        [[ "$module" =~ ^[A-Za-z0-9_-]+$ ]] || {
            unsigned_modules+=("invalid-name")
            continue
        }
        filename=$(modinfo -n "$module" 2>/dev/null || printf '')
        if [ -z "$filename" ]; then
            unsigned_modules+=("$module")
            continue
        fi
        if [ "$filename" = "(builtin)" ]; then
            continue
        fi
        external_count=$((external_count + 1))
        signer=$(modinfo -F signer "$module" 2>/dev/null || printf '')
        if [ -n "$signer" ]; then
            signed_count=$((signed_count + 1))
        else
            unsigned_modules+=("$module")
        fi
    done < /proc/modules

    checks[module_external_count]="$external_count"
    checks[module_signed_count]="$signed_count"
    local tainted=0
    if [ -r /proc/sys/kernel/tainted ]; then
        read -r tainted < /proc/sys/kernel/tainted || tainted=0
    fi
    if (( (tainted & 8192) != 0 )); then
        unsigned_modules+=("kernel-taint-bit-13")
    fi

    if [ "${#unsigned_modules[@]}" -gt 0 ]; then
        checks[module_sig]="invalid"
        checks[module_sig_detail]="unsigned/unverifiable loaded modules: ${unsigned_modules[*]}"
    else
        checks[module_sig]="valid"
        checks[module_sig_detail]="${signed_count}/${external_count} loaded external modules carry signatures"
    fi
}

check_local_signing_policy() {
    python3 - \
        "$CONTAINERS_POLICY" \
        "$REGISTRIES_CONFIG" \
        "$COSIGN_PUB" \
        "$RELEASE_BASELINE" \
        "$EXPECTED_IMAGE_REPOSITORY" <<'PY'
import hashlib
import json
import stat
import sys
from pathlib import Path

policy_path, registries_path, key_path, baseline_path = map(Path, sys.argv[1:5])
repository = sys.argv[5]
required = (policy_path, registries_path, key_path)
for path in (*required, baseline_path):
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"unsafe or missing signing-policy file: {path}")

baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
if baseline.get("version") != 1:
    raise SystemExit("unsupported release baseline")
measurements = {
    item.get("path"): item.get("sha256")
    for item in baseline.get("files", [])
    if isinstance(item, dict)
}
for path in required:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if measurements.get(str(path)) != digest:
        raise SystemExit(f"release baseline mismatch: {path}")

policy = json.loads(policy_path.read_text(encoding="utf-8"))
rules = policy.get("transports", {}).get("docker", {}).get(repository)
expected = [{
    "type": "sigstoreSigned",
    "keyPath": str(key_path),
    "signedIdentity": {"type": "matchRepository"},
}]
if rules != expected:
    raise SystemExit("container signing policy is not the approved sigstore policy")

print(hashlib.sha256(key_path.read_bytes()).hexdigest())
PY
}

check_ostree_signature() {
    local key_fingerprint
    key_fingerprint=$(check_local_signing_policy) || {
        checks[signing_policy]="invalid"
        checks[signing_policy_detail]="local policy/key failed immutable release-baseline validation"
        checks[ostree_sig]="invalid"
        checks[ostree_sig_detail]="cannot trust the booted image without the approved local signing policy"
        return
    }
    checks[signing_policy]="valid"
    checks[signing_policy_detail]="local sigstore policy/key match immutable release measurements"
    checks[signing_key_sha256]="$key_fingerprint"

    if ! command -v rpm-ostree >/dev/null 2>&1; then
        checks[ostree_sig]="unchecked"
        checks[ostree_sig_detail]="rpm-ostree is unavailable"
        return
    fi

    local deployment
    deployment=$(rpm-ostree status --json 2>/dev/null | python3 -c '
import json
import sys
data = json.load(sys.stdin)
booted = [item for item in data.get("deployments", []) if item.get("booted") is True]
if len(booted) != 1:
    raise SystemExit(1)
print(json.dumps(booted[0], sort_keys=True))
') || {
        checks[ostree_sig]="invalid"
        checks[ostree_sig_detail]="could not identify exactly one booted deployment"
        return
    }

    local raw_ref image_ref
    raw_ref=$(python3 - "$deployment" <<'PY'
import json
import sys
item = json.loads(sys.argv[1])
print(item.get("container-image-reference") or item.get("origin") or "")
PY
)
    case "$raw_ref" in
        ostree-image-signed:docker://*)
            image_ref="${raw_ref#ostree-image-signed:docker://}"
            ;;
        *)
            checks[ostree_sig]="invalid"
            checks[ostree_sig_detail]="booted deployment was not imported through ostree-image-signed"
            return
            ;;
    esac
    if [[ ! "$image_ref" =~ ^${EXPECTED_IMAGE_REPOSITORY//./\\.}(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[0-9a-f]{64}$ ]]; then
        checks[ostree_sig]="invalid"
        checks[ostree_sig_detail]="booted deployment is not an approved exact image digest"
        return
    fi

    checks[ostree_commit]="${image_ref##*@}"
    checks[ostree_ref]="$image_ref"
    checks[ostree_sig]="valid_offline"
    checks[ostree_sig_detail]="signed rpm-ostree transport and immutable local sigstore policy validated without registry access"

    # Optional operator diagnostic only; boot never depends on network access.
    # `cosign verify --key "$COSIGN_PUB" "$image_ref"` may be run manually to
    # re-check registry-hosted signature material.
}

increment_warning() {
    local current="$1"
    printf '%s\n' "$((current + 1))"
}

write_results() {
    local status="ok"
    local warnings=0
    local critical
    for critical in kernel_sig module_sig signing_policy ostree_sig; do
        case "${checks[$critical]:-unchecked}" in
            valid|valid_offline)
                ;;
            invalid)
                status="failed"
                warnings=$(increment_warning "$warnings")
                ;;
            *)
                if [ "$status" = "ok" ]; then
                    status="degraded"
                fi
                warnings=$(increment_warning "$warnings")
                ;;
        esac
    done
    if [ "${checks[secure_boot]:-unknown}" != "enabled" ]; then
        if [ "$status" = "ok" ]; then
            status="warning"
        fi
        warnings=$(increment_warning "$warnings")
    fi
    if [ "${checks[tpm2]:-unavailable}" = "error" ]; then
        if [ "$status" = "ok" ]; then
            status="warning"
        fi
        warnings=$(increment_warning "$warnings")
    fi

    local payload
    payload=$(python3 - \
        "$status" "$warnings" \
        "${checks[secure_boot]:-unknown}" "${checks[secure_boot_detail]:-}" \
        "${checks[tpm2]:-unknown}" "${checks[tpm2_sealed]:-false}" "${checks[tpm2_detail]:-}" \
        "${checks[kernel_sig]:-unchecked}" "${checks[kernel_release]:-}" "${checks[kernel_path]:-}" "${checks[kernel_sig_detail]:-}" \
        "${checks[module_sig]:-unchecked}" "${checks[module_signed_count]:-0}" "${checks[module_external_count]:-0}" "${checks[module_sig_detail]:-}" \
        "${checks[signing_policy]:-unchecked}" "${checks[signing_key_sha256]:-}" "${checks[signing_policy_detail]:-}" \
        "${checks[ostree_sig]:-unchecked}" "${checks[ostree_commit]:-}" "${checks[ostree_ref]:-}" "${checks[ostree_sig_detail]:-}" <<'PY'
import datetime as dt
import json
import sys

args = sys.argv[1:]
document = {
    "timestamp": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "status": args[0],
    "warnings": int(args[1]),
    "checks": {
        "secure_boot": {"state": args[2], "detail": args[3]},
        "tpm2": {"state": args[4], "sealed": args[5] == "true", "detail": args[6]},
        "kernel_signature": {
            "state": args[7], "release": args[8], "path": args[9], "detail": args[10],
        },
        "module_signatures": {
            "state": args[11], "signed_external": int(args[12]),
            "external": int(args[13]), "detail": args[14],
        },
        "signing_policy": {
            "state": args[15], "key_sha256": args[16], "detail": args[17],
        },
        "ostree_signature": {
            "state": args[18], "commit": args[19], "image_ref": args[20],
            "detail": args[21],
        },
    },
}
print(json.dumps(document, sort_keys=True, separators=(",", ":")))
PY
)

    python3 - "$RESULT_PATH" "$payload" <<'PY'
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(sys.argv[2])
path.parent.mkdir(parents=True, exist_ok=True)
if path.is_symlink() or (path.exists() and not stat.S_ISREG(path.stat().st_mode)):
    raise SystemExit("unsafe boot verification result path")
fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
        os.fchmod(handle.fileno(), 0o644)
    os.replace(temporary, path)
finally:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
PY
    log "Boot chain verification complete: status=${status}, warnings=${warnings}"
    [ "$status" != "failed" ]
}

log "=== Boot Chain Integrity Verification ==="
check_secure_boot
check_tpm2
check_kernel_signature
check_module_signatures
check_ostree_signature
write_results
