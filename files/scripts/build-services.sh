#!/usr/bin/env bash
#
# Build and install Secure AI services into the OS image.
# This runs during the BlueBuild image build process.
#
# FAIL-CLOSED: Required services that fail to build abort the entire image build.
# Only truly optional components (scanner tools, pip packages) use soft warnings.
#
# HERMETIC BUILD: When HERMETIC_BUILD=true (set by CI stage 2), all network
# access is blocked. Source comes from vendored subtrees (upstreams/), Go vendor
# dirs (services/*/vendor/), the committed Python wheelhouse (vendor/wheels/),
# and the pre-staged llama.cpp tarball. The shell-function overrides below are
# human-readable diagnostics — the real proof of hermeticity is the
# network-disabled container/namespace that stage 2 runs in.
#
set -euo pipefail

INSTALL_DIR="/usr/libexec/secure-ai"
SRC_DIR="/tmp/secure-ai-build"
SOURCE_DIR=""  # Set by locate_source

echo "=== Building Secure AI services ==="

# ---------------------------------------------------------------------------
# Hermetic build enforcement (stage 2)
# ---------------------------------------------------------------------------
if [ "${HERMETIC_BUILD:-}" = "true" ]; then
    echo "HERMETIC BUILD MODE — all network access is blocked"

    # Verify SOURCE_PREP_MANIFEST.json if present
    if [ -f "/tmp/SOURCE_PREP_MANIFEST.json" ]; then
        echo "Verifying source-prep manifest..."
        python3 -c "
import json, hashlib, sys

with open('/tmp/SOURCE_PREP_MANIFEST.json') as f:
    manifest = json.load(f)

# Verify wheelhouse digest
if 'wheelhouse_sha256sums_digest' in manifest:
    with open('vendor/wheels/SHA256SUMS', 'rb') as f:
        actual = hashlib.sha256(f.read()).hexdigest()
    expected = manifest['wheelhouse_sha256sums_digest']
    if actual != expected:
        print(f'FATAL: wheelhouse SHA256SUMS digest mismatch: {actual} != {expected}')
        sys.exit(1)
    print('OK: wheelhouse SHA256SUMS digest verified')

# Verify lock manifest digest
if 'upstreams_lock_digest' in manifest:
    with open('.upstreams.lock.yaml', 'rb') as f:
        actual = hashlib.sha256(f.read()).hexdigest()
    expected = manifest['upstreams_lock_digest']
    if actual != expected:
        print(f'FATAL: .upstreams.lock.yaml digest mismatch: {actual} != {expected}')
        sys.exit(1)
    print('OK: .upstreams.lock.yaml digest verified')

print('Source-prep manifest verification passed')
" || fail_build "SOURCE_PREP_MANIFEST.json verification failed"
    fi

    # Override network commands to fail with clear diagnostics
    git() {
        if [ "$1" = "clone" ]; then
            fail_build "network clone attempted in hermetic build: $*"
        fi
        command git "$@"
    }
    curl() { fail_build "curl attempted in hermetic build: $*"; }
    wget() { fail_build "wget attempted in hermetic build: $*"; }

    # Go: vendor-only, no network proxy, no sum DB, no VCS
    export GOFLAGS="-mod=vendor"
    export GOPROXY=off
    export GOSUMDB=off
    export GOVCS=off

    # Python: local wheelhouse only
    export PIP_NO_INDEX=1
    export PIP_DISABLE_PIP_VERSION_CHECK=1
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Fatal error — abort the build
fail_build() {
    echo "FATAL: $1" >&2
    exit 1
}

# Locate service source from local paths only.
# Usage: locate_source <name> <local-path...>
# Sets SOURCE_DIR on success. Returns 1 if not found (does NOT exit).
locate_source() {
    local name="$1"; shift
    local paths=()

    while [ $# -gt 0 ]; do
        paths+=("$1"); shift
    done

    for p in "${paths[@]}"; do
        if [ -d "$p" ]; then
            cp -r "$p" "${SRC_DIR}/${name}"
            SOURCE_DIR="${SRC_DIR}/${name}"
            return 0
        fi
    done

    echo "WARNING: ${name} source not available — checked: ${paths[*]}" >&2
    SOURCE_DIR=""
    return 1
}

# Track a built binary
track_binary() {
    echo "  -> $1"
}

# ---------------------------------------------------------------------------
# Build dependencies — all come from recipe rpm-ostree, not ad hoc installs.
# If a build-time package is missing, fix recipes/recipe.yml.
# ---------------------------------------------------------------------------
mkdir -p "$INSTALL_DIR" "$SRC_DIR"

# ===========================================================================
# Go Services — skip gracefully if upstream source not yet available.
# Once upstreams are populated (PENDING → pinned), missing source becomes fatal.
# ===========================================================================
GO_SKIPPED=0

# --- Airlock (egress control gateway, disabled at runtime by default) ---
echo "Building: airlock"
if locate_source airlock /tmp/services/airlock /tmp/files/services/airlock; then
    cd "$SOURCE_DIR"
    CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/airlock" .
    track_binary "${INSTALL_DIR}/airlock"
else GO_SKIPPED=$((GO_SKIPPED + 1)); fi

# --- ai-model-registry (security-first artifact registry) ---
echo "Building: ai-model-registry"
if locate_source ai-model-registry \
    /tmp/upstreams/ai-model-registry /tmp/ai-model-registry /tmp/services/registry; then
    cd "$SOURCE_DIR"
    CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/registry" .
    CGO_ENABLED=0 go build -ldflags="-s -w" -o /usr/local/bin/securectl ./cmd/securectl/
    track_binary "${INSTALL_DIR}/registry"
    track_binary "/usr/local/bin/securectl"
else GO_SKIPPED=$((GO_SKIPPED + 1)); fi

# --- agent-tool-firewall (policy gateway for LLM tool calls) ---
echo "Building: agent-tool-firewall"
if locate_source agent-tool-firewall \
    /tmp/upstreams/agent-tool-firewall /tmp/agent-tool-firewall /tmp/services/tool-firewall; then
    cd "$SOURCE_DIR"
    CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/tool-firewall" .
    track_binary "${INSTALL_DIR}/tool-firewall"
else GO_SKIPPED=$((GO_SKIPPED + 1)); fi

# --- gpu-integrity-watch (continuous GPU runtime verification) ---
echo "Building: gpu-integrity-watch"
if locate_source gpu-integrity-watch \
    /tmp/upstreams/gpu-integrity-watch /tmp/services/gpu-integrity-watch /tmp/gpu-integrity-watch; then
    cd "$SOURCE_DIR"
    CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/gpu-integrity-watch" .
    track_binary "${INSTALL_DIR}/gpu-integrity-watch"
    # Default profile (optional — runtime uses built-in defaults if missing)
    mkdir -p /etc/secure-ai/gpu-integrity
    cp profiles/default-profile.yaml /etc/secure-ai/gpu-integrity/ 2>/dev/null || true
else GO_SKIPPED=$((GO_SKIPPED + 1)); fi

# --- mcp-firewall (Model Context Protocol policy gateway) ---
echo "Building: mcp-firewall"
if locate_source mcp-firewall \
    /tmp/upstreams/mcp-firewall /tmp/services/mcp-firewall /tmp/mcp-firewall; then
    cd "$SOURCE_DIR"
    CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/mcp-firewall" .
    track_binary "${INSTALL_DIR}/mcp-firewall"
    # Default policy (optional — runtime uses built-in defaults if missing)
    mkdir -p /etc/secure-ai/mcp-firewall
    cp policies/default-policy.yaml /etc/secure-ai/mcp-firewall/ 2>/dev/null || true
else GO_SKIPPED=$((GO_SKIPPED + 1)); fi

# --- policy-engine (unified OPA-style decision point) ---
echo "Building: policy-engine"
if locate_source policy-engine \
    /tmp/upstreams/policy-engine /tmp/services/policy-engine /tmp/policy-engine; then
    cd "$SOURCE_DIR"
    CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/policy-engine" .
    track_binary "${INSTALL_DIR}/policy-engine"
else GO_SKIPPED=$((GO_SKIPPED + 1)); fi

# --- runtime-attestor (TPM2 quote verification + startup gating) ---
echo "Building: runtime-attestor"
if locate_source runtime-attestor \
    /tmp/upstreams/runtime-attestor /tmp/services/runtime-attestor /tmp/runtime-attestor; then
    cd "$SOURCE_DIR"
    CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/runtime-attestor" .
    track_binary "${INSTALL_DIR}/runtime-attestor"
else GO_SKIPPED=$((GO_SKIPPED + 1)); fi

# --- integrity-monitor (continuous baseline-verified file watcher) ---
echo "Building: integrity-monitor"
if locate_source integrity-monitor \
    /tmp/upstreams/integrity-monitor /tmp/services/integrity-monitor /tmp/integrity-monitor; then
    cd "$SOURCE_DIR"
    CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/integrity-monitor" .
    track_binary "${INSTALL_DIR}/integrity-monitor"
else GO_SKIPPED=$((GO_SKIPPED + 1)); fi

# --- incident-recorder (security event capture and containment) ---
echo "Building: incident-recorder"
if locate_source incident-recorder \
    /tmp/upstreams/incident-recorder /tmp/services/incident-recorder /tmp/incident-recorder; then
    cd "$SOURCE_DIR"
    CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/incident-recorder" .
    track_binary "${INSTALL_DIR}/incident-recorder"
else GO_SKIPPED=$((GO_SKIPPED + 1)); fi

# --- gguf-guard (GGUF model integrity scanner) ---
echo "Building: gguf-guard"
if locate_source gguf-guard \
    /tmp/upstreams/gguf-guard /tmp/gguf-guard; then
    cd "$SOURCE_DIR"
    CGO_ENABLED=0 go build -ldflags="-s -w" -o /usr/local/bin/gguf-guard ./cmd/gguf-guard/
    track_binary "/usr/local/bin/gguf-guard"
else GO_SKIPPED=$((GO_SKIPPED + 1)); fi

if [ "$GO_SKIPPED" -gt 0 ]; then
    echo "WARNING: ${GO_SKIPPED} Go service(s) skipped — upstream source not available"
    echo "  This is expected while upstreams are PENDING. Pin upstreams to fix."
fi

# ===========================================================================
# llama.cpp (required — inference engine)
#
# Checksum verification provides integrity.
# TODO: For full hermeticity, vendor the tarball into vendor/llama-cpp/
# or produce a pinned source artifact in release CI.
# ===========================================================================
echo "Building: llama-server"
LLAMA_CPP_VERSION="${LLAMA_CPP_VERSION:-b5200}"
# SHA256 of the release tarball — update when bumping LLAMA_CPP_VERSION
LLAMA_CPP_SHA256="${LLAMA_CPP_SHA256:-d823b3a8976743a83eaaf25451b6b3ed99d113d7c61f04d61dbe2aa9e46f1eec}"

cd "$SRC_DIR"

# In hermetic mode, the tarball must be pre-staged by the source-prep job
LLAMA_TARBALL="/tmp/llama-cpp-${LLAMA_CPP_VERSION}.tar.gz"
if [ "${HERMETIC_BUILD:-}" = "true" ]; then
    if [ ! -f "$LLAMA_TARBALL" ]; then
        fail_build "llama.cpp tarball not pre-staged at ${LLAMA_TARBALL} (required in hermetic mode)"
    fi
else
    # Non-hermetic (dev) mode: download with checksum verification
    curl -fsSL -o "$LLAMA_TARBALL" \
        "https://github.com/ggml-org/llama.cpp/archive/refs/tags/${LLAMA_CPP_VERSION}.tar.gz"
fi

# Verify checksum
echo "${LLAMA_CPP_SHA256}  ${LLAMA_TARBALL}" | sha256sum -c || \
    fail_build "llama.cpp tarball checksum mismatch (expected ${LLAMA_CPP_SHA256})"

tar xzf "$LLAMA_TARBALL"
cd "llama.cpp-${LLAMA_CPP_VERSION}"

# GPU backend detection — best-effort fallback chain: CUDA → Vulkan → CPU
# This is intentionally soft: the build must succeed even without GPU headers.
GPU_BACKEND="cpu"
if cmake -B build -DGGML_CUDA=ON -DGGML_VULKAN=ON -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_BUILD_TYPE=Release 2>/dev/null; then
    GPU_BACKEND="cuda"
elif { rm -rf build && cmake -B build -DGGML_VULKAN=ON -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_BUILD_TYPE=Release 2>/dev/null; }; then
    GPU_BACKEND="vulkan"
else
    rm -rf build && cmake -B build -DBUILD_SHARED_LIBS=OFF \
        -DLLAMA_CURL=OFF -DCMAKE_BUILD_TYPE=Release
    GPU_BACKEND="cpu"
fi
cmake --build build --target llama-server -j"$(nproc)"
install -m 755 build/bin/llama-server /usr/bin/llama-server
track_binary "/usr/bin/llama-server"

# Record GPU backend metadata for runtime verification
mkdir -p /etc/secure-ai
cat > /etc/secure-ai/gpu-backend.json <<GPUMETA
{
    "backend": "${GPU_BACKEND}",
    "build_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "llama_cpp_version": "${LLAMA_CPP_VERSION}"
}
GPUMETA
echo "  -> /etc/secure-ai/gpu-backend.json (backend: ${GPU_BACKEND})"

# ===========================================================================
# Python Services (required — build failures are fatal)
# ===========================================================================

# --- ai-quarantine (seven-stage artifact admission-control) ---
echo "Building: quarantine-watcher"
if locate_source ai-quarantine \
    /tmp/upstreams/ai-quarantine /tmp/ai-quarantine /tmp/services/quarantine; then
    pip3 install --prefix=/usr --no-cache-dir "${SOURCE_DIR}" 2>/dev/null || \
        pip3 install --prefix=/usr --break-system-packages --no-cache-dir "${SOURCE_DIR}"
    cat > "${INSTALL_DIR}/quarantine-watcher" <<'WRAPPER'
#!/usr/bin/env python3
from quarantine.watcher import main
main()
WRAPPER
    chmod +x "${INSTALL_DIR}/quarantine-watcher"
    track_binary "${INSTALL_DIR}/quarantine-watcher"
else
    echo "WARNING: quarantine source not available, skipping"
fi

# Quarantine scanning tools (optional — individual tool failures are non-fatal)
echo "Installing: quarantine scanning tools"
for scanner in modelscan fickling garak modelaudit; do
    echo "  Installing: ${scanner}"
    pip3 install --prefix=/usr --no-cache-dir "${scanner}" 2>/dev/null || \
        pip3 install --prefix=/usr --break-system-packages --no-cache-dir "${scanner}" 2>/dev/null || \
        echo "  WARNING: ${scanner} install failed — scanner will be skipped at runtime"
done

# --- Agent service (policy-bound local autopilot) ---
echo "Building: agent"
if [ -d "/tmp/services/agent" ]; then
    pip3 install --prefix=/usr --no-cache-dir /tmp/services/agent 2>/dev/null || \
        pip3 install --prefix=/usr --break-system-packages --no-cache-dir /tmp/services/agent
    cat > "${INSTALL_DIR}/agent" <<'WRAPPER'
#!/usr/bin/env python3
from agent.app import main
main()
WRAPPER
    chmod +x "${INSTALL_DIR}/agent"
    track_binary "${INSTALL_DIR}/agent"
else
    fail_build "agent source not found at /tmp/services/agent"
fi

# --- Web UI (production: gunicorn via wrapper; dev: Flask built-in) ---
echo "Building: ui"
if [ -d "/tmp/services/ui" ]; then
    pip3 install --prefix=/usr --no-cache-dir /tmp/services/ui 2>/dev/null || \
        pip3 install --prefix=/usr --break-system-packages --no-cache-dir /tmp/services/ui
    cat > "${INSTALL_DIR}/ui" <<'WRAPPER'
#!/usr/bin/env bash
# Production wrapper — Gunicorn with env-driven config.
# The appliance runtime gets Gunicorn from the OS image (python3-gunicorn).
export PYTHONPATH="${PYTHONPATH:-/usr/lib/python3/site-packages}"
exec gunicorn \
    --bind "${BIND_ADDR:-127.0.0.1:8480}" \
    --workers "${GUNICORN_WORKERS:-1}" \
    --threads "${GUNICORN_THREADS:-4}" \
    --timeout "${GUNICORN_TIMEOUT:-60}" \
    --graceful-timeout 15 \
    --max-requests 1000 \
    --max-requests-jitter 50 \
    --access-logfile - \
    --error-logfile - \
    ui.app:app
WRAPPER
    chmod +x "${INSTALL_DIR}/ui"
    track_binary "${INSTALL_DIR}/ui"
else
    fail_build "UI source not found at /tmp/services/ui"
fi

# ===========================================================================
# Optional Services (warnings are acceptable — not core security)
# ===========================================================================

# Diffusion worker (optional — disabled by default, opt-in via secai-enable-diffusion.sh)
echo "Installing: diffusion-worker"
DIFFUSION_DIR="/opt/secure-ai/services/diffusion-worker"
mkdir -p "$DIFFUSION_DIR"
if [ -f "/tmp/services/diffusion-worker/app.py" ]; then
    cp /tmp/services/diffusion-worker/app.py "$DIFFUSION_DIR/app.py"
    echo "  -> ${DIFFUSION_DIR}/app.py"
    # Wrapper for when diffusion is enabled via opt-in installer
    cat > "${INSTALL_DIR}/diffusion-worker" <<'WRAPPER'
#!/usr/bin/env bash
# Diffusion worker — requires opt-in via secai-enable-diffusion.sh.
# This wrapper is only used after the installer writes a systemd override
# pointing to the venv's gunicorn. If called directly without the venv,
# it fails with a helpful message.
if [ ! -f /var/lib/secure-ai/.diffusion-ready ]; then
    echo "ERROR: Diffusion worker not configured. Run: sudo secai-enable-diffusion.sh" >&2
    exit 1
fi
source /var/lib/secure-ai/diffusion-venv/bin/activate
export LANG="${LANG:-C.UTF-8}"
export LC_ALL="${LC_ALL:-C.UTF-8}"
export PYTHONPATH="/opt/secure-ai/services/diffusion-worker:${PYTHONPATH:-}"
exec gunicorn \
    --chdir /opt/secure-ai/services/diffusion-worker \
    --bind "${BIND_ADDR:-127.0.0.1:8455}" \
    --workers 1 \
    --threads 2 \
    --timeout "${GUNICORN_TIMEOUT:-1800}" \
    --graceful-timeout 30 \
    --max-requests 500 \
    --access-logfile - \
    --error-logfile - \
    app:app
WRAPPER
    chmod +x "${INSTALL_DIR}/diffusion-worker"
else
    echo "WARNING: diffusion-worker source not found — diffusion worker will not be available"
fi

# --- llm-search-mediator (optional — privacy-preserving search bridge) ---
echo "Installing: llm-search-mediator"
SEARCH_DIR="/opt/secure-ai/services/search-mediator"
mkdir -p "$SEARCH_DIR"
if [ -d "/tmp/upstreams/llm-search-mediator" ]; then
    cp -r /tmp/upstreams/llm-search-mediator "${SRC_DIR}/llm-search-mediator"
elif [ -d "/tmp/llm-search-mediator" ]; then
    cp -r /tmp/llm-search-mediator "${SRC_DIR}/llm-search-mediator"
elif [ -d "/tmp/services/search-mediator" ]; then
    cp -r /tmp/services/search-mediator "${SRC_DIR}/llm-search-mediator"
else
    echo "WARNING: llm-search-mediator not available — search mediator will not be installed"
fi
if [ -d "${SRC_DIR}/llm-search-mediator" ]; then
    # Copy source to runtime location
    if [ -d "${SRC_DIR}/llm-search-mediator/search_mediator" ]; then
        cp -r "${SRC_DIR}/llm-search-mediator/search_mediator" "$SEARCH_DIR/"
    elif [ -f "${SRC_DIR}/llm-search-mediator/app.py" ]; then
        cp "${SRC_DIR}/llm-search-mediator/app.py" "$SEARCH_DIR/app.py"
    fi
    # Install requirements if present
    if [ -f "${SRC_DIR}/llm-search-mediator/requirements.txt" ]; then
        pip3 install --prefix=/usr --no-cache-dir \
            -r "${SRC_DIR}/llm-search-mediator/requirements.txt" 2>/dev/null || \
            pip3 install --prefix=/usr --break-system-packages --no-cache-dir \
                -r "${SRC_DIR}/llm-search-mediator/requirements.txt" 2>/dev/null || \
            echo "WARNING: search-mediator requirements install failed"
    fi
    cat > "${INSTALL_DIR}/search-mediator" <<'WRAPPER'
#!/usr/bin/env bash
# Production wrapper — Gunicorn for search mediator.
export PYTHONPATH="/opt/secure-ai/services/search-mediator:${PYTHONPATH:-}"
exec gunicorn \
    --bind "${BIND_ADDR:-127.0.0.1:8485}" \
    --workers "${GUNICORN_WORKERS:-2}" \
    --threads "${GUNICORN_THREADS:-4}" \
    --timeout "${GUNICORN_TIMEOUT:-30}" \
    --graceful-timeout 10 \
    --access-logfile - \
    --error-logfile - \
    search_mediator.app:app
WRAPPER
    chmod +x "${INSTALL_DIR}/search-mediator"
    echo "  -> ${INSTALL_DIR}/search-mediator"
fi

# HuggingFace CLI (optional — for model downloads)
echo "Installing: huggingface-hub"
pip3 install --prefix=/usr --no-cache-dir huggingface-hub 2>/dev/null || \
    pip3 install --prefix=/usr --break-system-packages --no-cache-dir huggingface-hub 2>/dev/null || \
    echo "WARNING: huggingface-hub install failed — model downloads will use git clone fallback"

# SearXNG (optional — privacy search engine)
echo "Installing: searxng"
pip3 install --prefix=/usr --no-cache-dir searxng 2>/dev/null || \
    pip3 install --prefix=/usr --break-system-packages --no-cache-dir searxng 2>/dev/null || \
    echo "WARNING: searxng pip install failed — SearXNG search will not be available"

# ===========================================================================
# Staging directory for local model imports (M54 hardening)
# ===========================================================================
echo "Creating import staging directory..."
mkdir -p /var/lib/secure-ai/import-staging
chmod 0700 /var/lib/secure-ai/import-staging

# ===========================================================================
# Final Verification — confirm all required binaries exist
# ===========================================================================
echo ""
echo "=== Build Verification ==="

REQUIRED_BINARIES=(
    "${INSTALL_DIR}/airlock"
    "${INSTALL_DIR}/registry"
    "${INSTALL_DIR}/tool-firewall"
    "${INSTALL_DIR}/gpu-integrity-watch"
    "${INSTALL_DIR}/mcp-firewall"
    "${INSTALL_DIR}/policy-engine"
    "${INSTALL_DIR}/runtime-attestor"
    "${INSTALL_DIR}/integrity-monitor"
    "${INSTALL_DIR}/incident-recorder"
    "${INSTALL_DIR}/quarantine-watcher"
    "${INSTALL_DIR}/agent"
    "${INSTALL_DIR}/ui"
    "/usr/local/bin/securectl"
    "/usr/bin/llama-server"
)

# Optional binaries — built from external upstreams, may be skipped
OPTIONAL_BINARIES=(
    "/usr/local/bin/gguf-guard"
)

MISSING=0
for bin in "${REQUIRED_BINARIES[@]}"; do
    if [ -f "$bin" ]; then
        SIZE=$(stat -c%s "$bin" 2>/dev/null || stat -f%z "$bin" 2>/dev/null || echo "?")
        printf "  %-50s %s bytes\n" "$bin" "$SIZE"
    else
        printf "  MISSING: %s\n" "$bin"
        MISSING=$((MISSING + 1))
    fi
done

echo ""
if [ "$MISSING" -gt 0 ]; then
    fail_build "${MISSING} required binaries missing — image build aborted"
fi
echo "All ${#REQUIRED_BINARIES[@]} required binaries verified."

# Check optional binaries (warn but don't fail)
for bin in "${OPTIONAL_BINARIES[@]}"; do
    if [ -f "$bin" ]; then
        SIZE=$(stat -c%s "$bin" 2>/dev/null || stat -f%z "$bin" 2>/dev/null || echo "?")
        printf "  OPTIONAL: %-45s %s bytes\n" "$bin" "$SIZE"
    else
        printf "  OPTIONAL MISSING: %s (upstream not pinned)\n" "$bin"
    fi
done

# ---------------------------------------------------------------------------
# Configure container signing policy for cosign-verified SecAI images.
# ---------------------------------------------------------------------------
echo ""
echo "=== Configuring container signing policy ==="

POLICY_JSON="/etc/containers/policy.json"
COSIGN_PUB="/etc/pki/containers/secai-cosign.pub"
REGISTRIES_D="/etc/containers/registries.d/secai-os.yaml"

if [ -f "$COSIGN_PUB" ] && [ -f "$REGISTRIES_D" ]; then
    if [ -f "$POLICY_JSON" ]; then
        python3 -c "
import json, sys

with open('${POLICY_JSON}') as f:
    policy = json.load(f)

policy.setdefault('transports', {})
policy['transports'].setdefault('docker', {})

policy['transports']['docker']['ghcr.io/secai-hub/secai_os'] = [{
    'type': 'sigstoreSigned',
    'keyPath': '${COSIGN_PUB}',
    'signedIdentity': {'type': 'matchRepository'}
}]

with open('${POLICY_JSON}', 'w') as f:
    json.dump(policy, f, indent=2)
    f.write('\n')

print('  -> policy.json updated: sigstoreSigned entry for ghcr.io/secai-hub/secai_os')
" || fail_build "Failed to update container signing policy"
    else
        echo "WARNING: ${POLICY_JSON} not found — signing policy not configured"
    fi
    echo "  -> ${COSIGN_PUB}: installed"
    echo "  -> ${REGISTRIES_D}: installed"
else
    echo "WARNING: signing policy files missing from image — cosign verification may not work"
fi

# Cleanup build artifacts (but not build tools — they come from the recipe)
rm -rf "$SRC_DIR"
# Remove service source copied by containerfile COPY step (not needed at runtime)
rm -rf /tmp/services

echo ""
echo "=== Secure AI services installed ==="
ls -la "$INSTALL_DIR"/
