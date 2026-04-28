#!/usr/bin/env bash
#
# Enable the diffusion worker on SecAI OS.
#
# The base image ships with secure-ai-diffusion.service DISABLED because
# the GPU runtime (PyTorch, diffusers, etc.) is not included in the
# immutable OS image. This script acquires the runtime on demand, verifies
# every artifact, installs into an isolated venv, and enables the service.
#
# Primary path (default, triggered by systemd path unit or operator):
#   sudo secai-enable-diffusion.sh
#   sudo secai-enable-diffusion.sh --progress-file /run/secure-ai/diffusion-progress.json
#
# Secondary path (air-gapped / admin):
#   sudo secai-enable-diffusion.sh --from-local /path/to/wheels
#
# Supply-chain controls:
#   - Backend-specific lockfile + wheel manifest as trust anchor
#   - Source allowlist + redirect verification (HTTPS only)
#   - Wheel-only policy (reject sdists/tarballs)
#   - Exact filename + SHA256 verification before promotion
#   - Wheel tag/ABI/platform check against running environment
#   - Metadata inspection (package name + version from .dist-info)
#   - Offline install from local verified cache (pip --no-index --require-hashes)
#   - Smoke test (import, device check, tensor op) before promotion
#   - Atomic venv swap + systemd override
#
# Fail-closed: on ANY error, the script removes partial state, keeps the
# unit disabled, and exits non-zero.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
VENV_DIR="/var/lib/secure-ai/diffusion-venv"
VENV_TMP="/var/lib/secure-ai/diffusion-venv.tmp"
CACHE_DIR="/var/lib/secure-ai/diffusion-cache"
INCOMING_DIR="${CACHE_DIR}/incoming"
VERIFIED_DIR="${CACHE_DIR}/verified"
READY_MARKER="/var/lib/secure-ai/.diffusion-ready"
FAILED_MARKER="/var/lib/secure-ai/.diffusion-failed"
OVERRIDE_DIR="/etc/systemd/system/secure-ai-diffusion.service.d"
OVERRIDE_FILE="${OVERRIDE_DIR}/venv.conf"
MANIFEST="/usr/libexec/secure-ai/diffusion-runtime-manifest.yaml"
LOCKFILE_DIR="/usr/libexec/secure-ai"
AUDIT_LOG="/var/lib/secure-ai/logs/diffusion-setup.json"
LOCK_FILE="/var/lib/secure-ai/.diffusion-install.lock"
REQUEST_MARKER="/run/secure-ai-ui/diffusion-request"

# Defaults
MODE="online"            # primary: on-demand download
LOCAL_WHEEL_DIR=""
FORCE=false
DRY_RUN=false
PROGRESS_FILE=""
BACKEND_OVERRIDE=""

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --from-local)
            MODE="local"
            LOCAL_WHEEL_DIR="$2"
            shift 2
            ;;
        --backend)
            case "$2" in
                cpu|cuda|rocm) BACKEND_OVERRIDE="$2" ;;
                *) echo "ERROR: --backend must be cpu, cuda, or rocm (got: $2)" >&2; exit 1 ;;
            esac
            shift 2
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --progress-file)
            PROGRESS_FILE="$2"
            shift 2
            ;;
        *)
            echo "Usage: $0 [--from-local /path] [--backend cpu|cuda|rocm] [--force] [--dry-run] [--progress-file /path]" >&2
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Pre-checks
# ---------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root" >&2
    exit 1
fi

if [ -f "$READY_MARKER" ] && [ "$FORCE" = false ]; then
    echo "Diffusion worker already configured. Use --force to reconfigure."
    exit 0
fi

if [ -f "$FAILED_MARKER" ] && [ "$FORCE" = false ]; then
    echo "ERROR: Previous installation failed. Fix the issue and re-run with --force."
    echo "Failure detail: $(cat "$FAILED_MARKER")"
    exit 1
fi

# ---------------------------------------------------------------------------
# Progress reporting
# ---------------------------------------------------------------------------
_progress() {
    local phase="$1"
    local percent="$2"
    local detail="${3:-}"
    if [ -n "$PROGRESS_FILE" ]; then
        _PROG_PHASE="$phase" _PROG_PERCENT="$percent" \
        _PROG_BACKEND="${GPU_BACKEND:-unknown}" _PROG_DETAIL="$detail" \
        _PROG_FILE="$PROGRESS_FILE" \
        python3 -c '
import json, os
progress = {
    "phase": os.environ["_PROG_PHASE"],
    "percent": int(os.environ["_PROG_PERCENT"]),
    "backend": os.environ["_PROG_BACKEND"],
    "detail": os.environ["_PROG_DETAIL"],
    "error": None,
}
fd = os.open(os.environ["_PROG_FILE"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
with os.fdopen(fd, "w") as f:
    json.dump(progress, f)
' 2>/dev/null || true
    fi
}

_progress_error() {
    local reason="$1"
    if [ -n "$PROGRESS_FILE" ]; then
        _PROG_BACKEND="${GPU_BACKEND:-unknown}" _PROG_REASON="$reason" \
        _PROG_FILE="$PROGRESS_FILE" \
        python3 -c '
import json, os
reason = os.environ["_PROG_REASON"]
progress = {
    "phase": "failed",
    "percent": 0,
    "backend": os.environ["_PROG_BACKEND"],
    "detail": reason,
    "error": reason,
}
fd = os.open(os.environ["_PROG_FILE"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
with os.fdopen(fd, "w") as f:
    json.dump(progress, f)
' 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------------------
# Fail-closed rollback
# ---------------------------------------------------------------------------
rollback() {
    local reason="${1:-unknown error}"
    echo "ROLLBACK: ${reason}" >&2

    # 1. Remove temp venv
    rm -rf "$VENV_TMP" 2>/dev/null || true

    # 2. Remove partial systemd override
    rm -f "$OVERRIDE_FILE" 2>/dev/null
    rmdir "$OVERRIDE_DIR" 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true

    # 3. Ensure unit stays disabled
    systemctl disable secure-ai-diffusion.service 2>/dev/null || true

    # 4. Remove ready marker if present
    rm -f "$READY_MARKER" 2>/dev/null

    # 5. Mark as failed
    mkdir -p "$(dirname "$FAILED_MARKER")"
    echo "${reason}" > "$FAILED_MARKER"
    chmod 0644 "$FAILED_MARKER"

    # 6. Clean up request marker (trap handler for path-unit flow)
    rm -f "$REQUEST_MARKER" 2>/dev/null || true

    # 7. Audit log
    _audit "setup_failed" "{\"reason\": \"${reason}\"}"

    # 8. Progress file
    _progress_error "${reason}"

    echo ""
    echo "FAILED: Diffusion worker installation rolled back."
    echo "Detail: ${reason}"
    echo "The unit remains disabled. Fix the issue and re-run with --force."
    exit 1
}

trap 'rollback "unexpected error on line $LINENO"' ERR
trap 'rollback "interrupted by signal"' INT TERM

# ---------------------------------------------------------------------------
# Audit helper
# ---------------------------------------------------------------------------
_audit() {
    local event="$1"
    local detail="${2:-{}}"
    mkdir -p "$(dirname "$AUDIT_LOG")"
    _AUDIT_EVENT="$event" _AUDIT_DETAIL="$detail" _AUDIT_LOG="$AUDIT_LOG" \
    python3 -c '
import json, hashlib, os
from datetime import datetime, timezone
entry = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "event": "diffusion_" + os.environ["_AUDIT_EVENT"],
    "detail": json.loads(os.environ["_AUDIT_DETAIL"]),
}
entry["hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
with open(os.environ["_AUDIT_LOG"], "a") as f:
    f.write(json.dumps(entry) + "\n")
' 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Acquire flock (prevents concurrent installs)
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo "ERROR: Another diffusion install is already in progress" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Validate platform against manifest
# ---------------------------------------------------------------------------
_progress "detecting" 0 "Checking platform compatibility"
echo "=== Checking platform compatibility ==="

if [ ! -f "$MANIFEST" ]; then
    rollback "Manifest not found: ${MANIFEST}"
fi

# Read all manifest metadata in a single safe Python call (no shell interpolation)
CURRENT_PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
CURRENT_ARCH=$(uname -m)

eval "$(_SECAI_MANIFEST="$MANIFEST" python3 -c '
import os, sys, yaml
with open(os.environ["_SECAI_MANIFEST"]) as f:
    m = yaml.safe_load(f)
print(f"MANIFEST_POPULATED={\"yes\" if m.get(\"populated\", False) else \"no\"}")
print(f"REQUIRED_PYTHON_VERSION={m.get(\"python_version\", \"\")}")
arches = m.get("supported_architectures", [])
print(f"SUPPORTED_ARCHES={\" \".join(arches)}")
')"

if [ "$MANIFEST_POPULATED" != "yes" ]; then
    rollback "Diffusion runtime manifest is not yet populated with real package hashes. Run scripts/refresh-diffusion-locks.sh on a Linux machine with the target Python version to generate the manifest, then commit the result."
fi

if [ -n "$REQUIRED_PYTHON_VERSION" ] && [ "$CURRENT_PYTHON_VERSION" != "$REQUIRED_PYTHON_VERSION" ]; then
    rollback "Python version mismatch: have ${CURRENT_PYTHON_VERSION}, need ${REQUIRED_PYTHON_VERSION}"
fi

ARCH_OK=false
for arch in $SUPPORTED_ARCHES; do
    if [ "$CURRENT_ARCH" = "$arch" ]; then
        ARCH_OK=true
        break
    fi
done
if [ "$ARCH_OK" = false ]; then
    rollback "Unsupported architecture: ${CURRENT_ARCH} (supported: ${SUPPORTED_ARCHES})"
fi

echo "  Python: ${CURRENT_PYTHON_VERSION} (required: ${REQUIRED_PYTHON_VERSION})"
echo "  Arch:   ${CURRENT_ARCH}"

# ---------------------------------------------------------------------------
# Step 2: Detect GPU backend
# ---------------------------------------------------------------------------
_progress "detecting" 5 "Detecting GPU backend"
echo "=== Detecting GPU backend ==="

if [ -n "$BACKEND_OVERRIDE" ]; then
    GPU_BACKEND="$BACKEND_OVERRIDE"
    echo "  Override: ${GPU_BACKEND}"
else
    GPU_BACKEND="cpu"
    if [ -d /proc/driver/nvidia ] || lspci 2>/dev/null | grep -qi nvidia; then
        GPU_BACKEND="cuda"
    elif [ -e /dev/kfd ]; then
        GPU_BACKEND="rocm"
    fi
    echo "  Detected: ${GPU_BACKEND}"
fi

# Validate backend exists in manifest and read config (single safe Python call)
eval "$(
    _SECAI_MANIFEST="$MANIFEST" _SECAI_BACKEND="$GPU_BACKEND" \
    python3 -c '
import os, sys, yaml
with open(os.environ["_SECAI_MANIFEST"]) as f:
    m = yaml.safe_load(f)
backend = os.environ["_SECAI_BACKEND"]
if backend not in m.get("backends", {}):
    print(f"BACKEND_EXISTS=no")
    sys.exit(0)
cfg = m["backends"][backend]
print(f"BACKEND_EXISTS=yes")
print(f"BACKEND_LOCKFILE={cfg[\"lockfile\"]}")
print(f"BACKEND_TORCH_INDEX={cfg[\"torch_index\"]}")
'
)"

if [ "$BACKEND_EXISTS" != "yes" ]; then
    rollback "Backend '${GPU_BACKEND}' not defined in manifest"
fi

LOCKFILE="${LOCKFILE_DIR}/${BACKEND_LOCKFILE}"
if [ ! -f "$LOCKFILE" ]; then
    rollback "Lockfile not found: ${LOCKFILE}"
fi

echo "  Lockfile: ${BACKEND_LOCKFILE}"
echo "  Index:    ${BACKEND_TORCH_INDEX}"

_progress "detecting" 10 "Backend: ${GPU_BACKEND}"

# ---------------------------------------------------------------------------
# Step 3: Download phase (skip for --from-local)
# ---------------------------------------------------------------------------
if [ "$MODE" = "local" ]; then
    echo "=== Using local wheels from ${LOCAL_WHEEL_DIR} ==="
    if [ -z "$LOCAL_WHEEL_DIR" ]; then
        LOCAL_WHEEL_DIR="/var/lib/secure-ai/diffusion-wheels"
    fi
    if [ ! -d "$LOCAL_WHEEL_DIR" ]; then
        rollback "Local wheel directory not found: ${LOCAL_WHEEL_DIR}"
    fi
    INSTALL_SOURCE="$LOCAL_WHEEL_DIR"
else
    echo "=== Downloading wheels (backend: ${GPU_BACKEND}) ==="
    mkdir -p "$INCOMING_DIR" "$VERIFIED_DIR"

    # Export env vars BEFORE the heredoc so the Python script can read them
    export _MANIFEST="$MANIFEST"
    export _BACKEND="$GPU_BACKEND"
    export _INCOMING="$INCOMING_DIR"
    export _VERIFIED="$VERIFIED_DIR"
    export _TORCH_INDEX="$BACKEND_TORCH_INDEX"
    export _DRY_RUN="$DRY_RUN"
    export _PROGRESS_FILE="$PROGRESS_FILE"
    export _CURRENT_ARCH="$CURRENT_ARCH"

    # Read wheel manifest entries and download/verify each one
    python3 << 'DOWNLOAD_SCRIPT'
import hashlib
import json
import os
import re
import sys
import urllib.request
import zipfile
from fnmatch import fnmatch
from pathlib import Path

import yaml

manifest_path = os.environ.get("_MANIFEST", "")
backend = os.environ.get("_BACKEND", "")
incoming = os.environ.get("_INCOMING", "")
verified = os.environ.get("_VERIFIED", "")
torch_index = os.environ.get("_TORCH_INDEX", "")
dry_run = os.environ.get("_DRY_RUN", "false") == "true"
progress_file = os.environ.get("_PROGRESS_FILE", "")
current_arch = os.environ.get("_CURRENT_ARCH", "")

with open(manifest_path) as f:
    manifest = yaml.safe_load(f)

allowed_sources = manifest.get("allowed_sources", [])
backend_cfg = manifest["backends"][backend]
wheels = backend_cfg.get("wheels", [])
schema_version = manifest.get("schema_version", 0)
python_version = manifest.get("python_version", "")

# Cache validation metadata
cache_meta_path = Path(verified) / ".cache-meta.json"
cache_meta = {}
if cache_meta_path.exists():
    try:
        cache_meta = json.loads(cache_meta_path.read_text())
    except Exception:
        pass


def cache_valid(filename, expected_sha256):
    """Check if a cached wheel is still valid."""
    cached = Path(verified) / filename
    if not cached.exists():
        return False
    # Verify cache metadata matches current context
    if cache_meta.get("schema_version") != schema_version:
        return False
    if cache_meta.get("backend") != backend:
        return False
    if cache_meta.get("python_version") != python_version:
        return False
    if cache_meta.get("arch") != current_arch:
        return False
    # Verify filename is in the expected set from this manifest version
    expected_files = cache_meta.get("expected_files", [])
    if expected_files and filename not in expected_files:
        return False
    # Verify hash
    h = hashlib.sha256()
    with open(cached, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest() == expected_sha256


def url_matches_allowlist(url, sources):
    """Check if URL matches any allowed source pattern."""
    for pattern in sources:
        if fnmatch(url, pattern):
            return True
    return False


def verify_wheel_tags(filename):
    """Parse wheel filename and verify Python/ABI/platform compatibility."""
    # PEP 427 wheel filename: {name}-{version}(-{build})?-{python}-{abi}-{platform}.whl
    parts = filename.rstrip(".whl").split("-")
    if len(parts) < 5:
        # Pure-Python wheel: name-version-pytag-abi-platform
        # Some have fewer parts (e.g. py3-none-any)
        pass
    platform_tag = parts[-1] if len(parts) >= 5 else "any"
    python_tag = parts[-3] if len(parts) >= 5 else parts[-3] if len(parts) >= 3 else ""
    abi_tag = parts[-2] if len(parts) >= 5 else "none"

    import platform as _platform
    machine = _platform.machine()

    # Check platform compatibility
    if platform_tag not in ("any", f"linux_{machine}", f"manylinux2014_{machine}",
                             f"manylinux_2_17_{machine}"):
        # Allow broader manylinux patterns
        if not (platform_tag.startswith("manylinux") and machine in platform_tag):
            return False, f"platform tag '{platform_tag}' incompatible with {machine}"

    # Check Python compatibility
    if python_tag and python_tag not in ("py3", "py2.py3", f"cp3{sys.version_info[1]}",
                                          f"cp{sys.version_info[0]}{sys.version_info[1]}"):
        # Allow broader patterns
        if not python_tag.startswith("cp3") and python_tag != "py3":
            return False, f"python tag '{python_tag}' incompatible with Python {sys.version_info[0]}.{sys.version_info[1]}"

    return True, ""


def verify_wheel_metadata(wheel_path, expected_name, expected_version):
    """Inspect .dist-info/METADATA inside the wheel."""
    try:
        with zipfile.ZipFile(wheel_path, "r") as zf:
            metadata_files = [n for n in zf.namelist() if n.endswith("/METADATA")]
            if not metadata_files:
                return False, "no METADATA found in wheel"
            content = zf.read(metadata_files[0]).decode("utf-8", errors="replace")
            meta_name = None
            meta_version = None
            for line in content.splitlines():
                if line.startswith("Name: "):
                    meta_name = line[6:].strip().lower().replace("-", "_")
                elif line.startswith("Version: "):
                    meta_version = line[9:].strip()
            if meta_name != expected_name.lower().replace("-", "_"):
                return False, f"metadata name '{meta_name}' != expected '{expected_name}'"
            if meta_version and expected_version and not meta_version.startswith(expected_version.split("+")[0]):
                return False, f"metadata version '{meta_version}' != expected '{expected_version}'"
    except Exception as e:
        return False, f"metadata inspection failed: {e}"
    return True, ""


def write_progress(phase, percent, detail=""):
    if not progress_file:
        return
    try:
        with open(progress_file, "w") as f:
            json.dump({
                "phase": phase,
                "percent": percent,
                "backend": backend,
                "total_packages": len(wheels),
                "detail": detail,
                "error": None,
            }, f)
    except Exception:
        pass


total = len(wheels)
cached_hits = 0
downloaded = 0
errors = []

for i, entry in enumerate(wheels):
    filename = entry["filename"]
    expected_sha256 = entry["sha256"]
    source_pattern = entry["source"]
    percent = 10 + int(60 * i / max(total, 1))

    # Extract package name/version from filename for metadata check
    name_parts = filename.split("-")
    pkg_name = name_parts[0] if name_parts else ""
    pkg_version = name_parts[1] if len(name_parts) > 1 else ""

    # Format gate: must be .whl
    if not filename.endswith(".whl"):
        errors.append(f"REJECT {filename}: not a wheel file")
        break

    # Check wheel tags
    tag_ok, tag_reason = verify_wheel_tags(filename)
    if not tag_ok:
        errors.append(f"REJECT {filename}: {tag_reason}")
        break

    # Cache check
    if cache_valid(filename, expected_sha256):
        cached_hits += 1
        write_progress("downloading", percent, f"Cached: {filename}")
        print(f"  CACHED: {filename}")
        continue

    if dry_run:
        print(f"  WOULD DOWNLOAD: {filename}")
        continue

    write_progress("downloading", percent, f"Downloading: {filename}")
    print(f"  DOWNLOADING: {filename}")

    # Determine download URL
    if "pytorch.org" in source_pattern:
        download_url = f"{torch_index}/{filename}"
    else:
        # PyPI: use simple index to find the actual URL
        # For now, construct the expected URL pattern
        download_url = f"https://files.pythonhosted.org/packages/py3/{pkg_name[0]}/{pkg_name}/{filename}"

    # Source policy: initial URL
    if not download_url.startswith("https://"):
        errors.append(f"REJECT {filename}: non-HTTPS URL: {download_url}")
        break

    if not url_matches_allowlist(download_url, allowed_sources):
        errors.append(f"REJECT {filename}: URL not in allowed sources: {download_url}")
        break

    # Download with redirect verification
    dest = os.path.join(incoming, filename)
    try:
        req = urllib.request.Request(download_url)
        response = urllib.request.urlopen(req, timeout=300)

        # Verify final URL after redirects
        final_url = response.url
        if not final_url.startswith("https://"):
            errors.append(f"REJECT {filename}: final URL not HTTPS: {final_url}")
            break
        if not url_matches_allowlist(final_url, allowed_sources):
            errors.append(f"REJECT {filename}: final URL not in allowed sources: {final_url}")
            break

        with open(dest, "wb") as out:
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                out.write(chunk)
    except Exception as e:
        errors.append(f"DOWNLOAD FAILED {filename}: {e}")
        # Clean up partial download
        try:
            os.unlink(dest)
        except OSError:
            pass
        break

    # Hash verification
    h = hashlib.sha256()
    with open(dest, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    actual_sha256 = h.hexdigest()

    if actual_sha256 != expected_sha256:
        errors.append(f"REJECT {filename}: hash mismatch (got {actual_sha256[:16]}..., expected {expected_sha256[:16]}...)")
        os.unlink(dest)
        break

    # Metadata inspection
    meta_ok, meta_reason = verify_wheel_metadata(dest, pkg_name, pkg_version)
    if not meta_ok:
        errors.append(f"REJECT {filename}: {meta_reason}")
        os.unlink(dest)
        break

    # Promote to verified
    verified_path = os.path.join(verified, filename)
    os.rename(dest, verified_path)
    downloaded += 1
    print(f"  VERIFIED: {filename}")

if errors:
    for err in errors:
        print(f"ERROR: {err}", file=sys.stderr)
    sys.exit(1)

if not dry_run:
    # Write cache metadata
    cache_meta_path.write_text(json.dumps({
        "schema_version": schema_version,
        "backend": backend,
        "python_version": python_version,
        "arch": current_arch,
        "expected_files": [e["filename"] for e in wheels],
    }))

print(f"\nDownload complete: {downloaded} downloaded, {cached_hits} cached, {total} total")
DOWNLOAD_SCRIPT

    if [ "$DRY_RUN" = true ]; then
        echo "=== Dry run complete ==="
        exit 0
    fi

    INSTALL_SOURCE="$VERIFIED_DIR"
fi

# ---------------------------------------------------------------------------
# Step 4: Verify all wheels present (for --from-local path, also verify)
# ---------------------------------------------------------------------------
_progress "verifying" 70 "Verifying wheel cache"
echo "=== Verifying wheel cache ==="

_SECAI_MANIFEST="$MANIFEST" _SECAI_BACKEND="$GPU_BACKEND" _SECAI_SOURCE="$INSTALL_SOURCE" \
python3 - <<'VERIFY_WHEELS' || rollback "wheel cache verification failed"
import hashlib, os, platform, sys, zipfile
import yaml

with open(os.environ["_SECAI_MANIFEST"]) as f:
    m = yaml.safe_load(f)
wheels = m["backends"][os.environ["_SECAI_BACKEND"]].get("wheels", [])
source = os.environ["_SECAI_SOURCE"]
machine = platform.machine()
py_ver = f'{sys.version_info.major}{sys.version_info.minor}'
errors = []

for entry in wheels:
    fn = entry['filename']
    path = os.path.join(source, fn)

    # Existence check
    if not os.path.exists(path):
        errors.append(f'MISSING: {fn}')
        continue

    # Format gate: must be .whl
    if not fn.endswith('.whl'):
        errors.append(f'NOT A WHEEL: {fn}')
        continue

    # Hash verification
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    if h.hexdigest() != entry['sha256']:
        errors.append(f'HASH MISMATCH: {fn}')
        continue

    # Wheel tag check (Python/ABI/platform compatibility)
    parts = fn.rstrip('.whl').split('-')
    if len(parts) >= 5:
        plat_tag = parts[-1]
        py_tag = parts[-3]
        if plat_tag != 'any' and machine not in plat_tag:
            errors.append(f'PLATFORM MISMATCH: {fn} (tag={plat_tag}, machine={machine})')
            continue
        if py_tag not in ('py3', 'py2.py3', f'cp{py_ver}'):
            if not py_tag.startswith('cp3') and py_tag != 'py3':
                errors.append(f'PYTHON TAG MISMATCH: {fn} (tag={py_tag}, python=cp{py_ver})')
                continue

    # Metadata inspection
    try:
        with zipfile.ZipFile(path, 'r') as zf:
            meta_files = [n for n in zf.namelist() if n.endswith('/METADATA')]
            if meta_files:
                content = zf.read(meta_files[0]).decode('utf-8', errors='replace')
                meta_name = None
                for line in content.splitlines():
                    if line.startswith('Name: '):
                        meta_name = line[6:].strip().lower().replace('-', '_')
                        break
                expected_name = parts[0].lower().replace('-', '_') if parts else ''
                if meta_name and expected_name and meta_name != expected_name:
                    errors.append(f'METADATA NAME MISMATCH: {fn} (got={meta_name}, expected={expected_name})')
                    continue
    except Exception as e:
        errors.append(f'METADATA INSPECT FAILED: {fn}: {e}')
        continue

    print(f'  VERIFIED: {fn}')

if errors:
    for err in errors:
        print(f'ERROR: {err}', file=sys.stderr)
    sys.exit(1)
print(f"All {len(wheels)} wheels verified")
VERIFY_WHEELS

# ---------------------------------------------------------------------------
# Step 5: Install into temporary venv
# ---------------------------------------------------------------------------
_progress "installing" 75 "Creating temporary venv"
echo "=== Creating temporary venv ==="

rm -rf "$VENV_TMP"
python3 -m venv "$VENV_TMP"

echo "=== Installing from verified cache ==="
_progress "installing" 80 "Installing packages"

"${VENV_TMP}/bin/pip" install \
    --no-index \
    --require-hashes \
    --no-cache-dir \
    --find-links "$INSTALL_SOURCE" \
    -r "$LOCKFILE" || rollback "pip install failed"

# ---------------------------------------------------------------------------
# Step 6: Smoke test
# ---------------------------------------------------------------------------
_progress "smoke_testing" 85 "Running smoke test"
echo "=== Running smoke test ==="

_SECAI_BACKEND="$GPU_BACKEND" "${VENV_TMP}/bin/python3" -c '
import os, sys
print(f"Python {sys.version}")

# Core imports
import torch
print(f"PyTorch {torch.__version__}")
import diffusers
print(f"Diffusers {diffusers.__version__}")
import transformers
print(f"Transformers {transformers.__version__}")
import safetensors
print(f"Safetensors {safetensors.__version__}")
import accelerate
print(f"Accelerate {accelerate.__version__}")

# Backend/device detection
backend = os.environ["_SECAI_BACKEND"]
if backend == "cuda":
    assert torch.cuda.is_available(), "CUDA not available but backend is cuda"
    print(f"CUDA devices: {torch.cuda.device_count()}")
    t = torch.randn(8, 8, device="cuda")
    assert t.device.type == "cuda"
    result = torch.matmul(t, t.T)
    print(f"CUDA tensor op OK: {result.shape}")
elif backend == "rocm":
    assert torch.cuda.is_available(), "ROCm/HIP not available but backend is rocm"
    print(f"ROCm devices: {torch.cuda.device_count()}")
    t = torch.randn(8, 8, device="cuda")
    result = torch.matmul(t, t.T)
    print(f"ROCm tensor op OK: {result.shape}")
else:
    t = torch.randn(8, 8)
    result = torch.matmul(t, t.T)
    print(f"CPU tensor op OK: {result.shape}")

print("Smoke test PASSED")
' || rollback "smoke test failed"

# ---------------------------------------------------------------------------
# Step 7: Promote venv (atomic swap)
# ---------------------------------------------------------------------------
_progress "enabling" 90 "Promoting venv"
echo "=== Promoting venv ==="

if [ -d "$VENV_DIR" ]; then
    rm -rf "${VENV_DIR}.old"
    mv "$VENV_DIR" "${VENV_DIR}.old"
fi
mv "$VENV_TMP" "$VENV_DIR"
rm -rf "${VENV_DIR}.old" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Step 8: Write systemd override
# ---------------------------------------------------------------------------
_progress "enabling" 92 "Configuring systemd"
echo "=== Configuring systemd service ==="

mkdir -p "$OVERRIDE_DIR"
cat > "$OVERRIDE_FILE" <<EOF
[Service]
ExecStart=
ExecStart=${VENV_DIR}/bin/gunicorn \\
    --chdir /opt/secure-ai/services/diffusion-worker \\
    --bind \${BIND_ADDR:-127.0.0.1:8455} \\
    --workers 1 \\
    --threads 2 \\
    --timeout \${GUNICORN_TIMEOUT:-1800} \\
    --graceful-timeout 30 \\
    --max-requests 500 \\
    --access-logfile - \\
    --error-logfile - \\
    app:app
Environment=VIRTUAL_ENV=${VENV_DIR}
Environment=PATH=${VENV_DIR}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
EOF

# ---------------------------------------------------------------------------
# Step 9: Enable and start
# ---------------------------------------------------------------------------
_progress "enabling" 95 "Starting service"
echo "=== Enabling diffusion service ==="

systemctl daemon-reload
systemctl enable --now secure-ai-diffusion.service

# Verify it started
sleep 2
if systemctl is-active --quiet secure-ai-diffusion.service; then
    echo "OK: secure-ai-diffusion.service is active"
else
    rollback "service failed to start after enable"
fi

# ---------------------------------------------------------------------------
# Step 10: Write ready marker + clean up
# ---------------------------------------------------------------------------
rm -f "$FAILED_MARKER"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) backend=${GPU_BACKEND} python=${CURRENT_PYTHON_VERSION} arch=${CURRENT_ARCH}" > "$READY_MARKER"
chmod 0644 "$READY_MARKER"

# Clean up request marker (from path-unit trigger)
rm -f "$REQUEST_MARKER" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Step 11: Audit log + final progress
# ---------------------------------------------------------------------------
_audit "setup_complete" "{\"backend\": \"${GPU_BACKEND}\", \"mode\": \"${MODE}\", \"python\": \"${CURRENT_PYTHON_VERSION}\", \"arch\": \"${CURRENT_ARCH}\"}"
_progress "complete" 100 "Diffusion runtime installed"

echo ""
echo "=== Diffusion worker enabled ==="
echo "  Backend:  ${GPU_BACKEND}"
echo "  Python:   ${CURRENT_PYTHON_VERSION}"
echo "  Arch:     ${CURRENT_ARCH}"
echo "  Venv:     ${VENV_DIR}"
echo "  Service:  secure-ai-diffusion.service (active)"
echo ""
echo "Test: curl http://127.0.0.1:8455/health"
