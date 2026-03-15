#!/usr/bin/env bash
#
# Build and install Secure AI services into the OS image.
# This runs during the BlueBuild image build process.
#
# FAIL-CLOSED: Required services that fail to build abort the entire image build.
# Only truly optional components (scanner tools, pip packages) use soft warnings.
#
set -euo pipefail

INSTALL_DIR="/usr/libexec/secure-ai"
SRC_DIR="/tmp/secure-ai-build"
SOURCE_DIR=""  # Set by locate_source

echo "=== Building Secure AI services ==="

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Fatal error — abort the build
fail_build() {
    echo "FATAL: $1" >&2
    exit 1
}

# Locate service source: checks local paths, then clones. Exits on failure.
# Usage: locate_source <name> <local-path...> [--clone <url>]
# Sets SOURCE_DIR on success.
locate_source() {
    local name="$1"; shift
    local clone_url=""
    local paths=()

    while [ $# -gt 0 ]; do
        case "$1" in
            --clone) clone_url="$2"; shift 2 ;;
            *) paths+=("$1"); shift ;;
        esac
    done

    for p in "${paths[@]}"; do
        if [ -d "$p" ]; then
            cp -r "$p" "${SRC_DIR}/${name}"
            SOURCE_DIR="${SRC_DIR}/${name}"
            return 0
        fi
    done

    if [ -n "$clone_url" ]; then
        if git clone --depth 1 "$clone_url" "${SRC_DIR}/${name}" 2>/dev/null; then
            SOURCE_DIR="${SRC_DIR}/${name}"
            return 0
        fi
    fi

    fail_build "${name} source not available — checked: ${paths[*]}${clone_url:+ clone: ${clone_url}}"
}

# Track a built binary
track_binary() {
    echo "  -> $1"
}

# ---------------------------------------------------------------------------
# Build dependencies
# ---------------------------------------------------------------------------
dnf install -y golang python3 python3-pip cmake gcc gcc-c++ libcurl-devel 2>/dev/null || true

mkdir -p "$INSTALL_DIR" "$SRC_DIR"

# ===========================================================================
# Go Services (required — build failures are fatal)
# ===========================================================================

# --- Airlock (egress control gateway, disabled at runtime by default) ---
echo "Building: airlock"
locate_source airlock /tmp/services/airlock /tmp/files/services/airlock
cd "$SOURCE_DIR"
CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/airlock" .
track_binary "${INSTALL_DIR}/airlock"

# --- ai-model-registry (security-first artifact registry) ---
echo "Building: ai-model-registry"
locate_source ai-model-registry /tmp/ai-model-registry \
    --clone https://github.com/SecAI-Hub/ai-model-registry.git
cd "$SOURCE_DIR"
CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/registry" .
CGO_ENABLED=0 go build -ldflags="-s -w" -o /usr/local/bin/securectl ./cmd/securectl/
track_binary "${INSTALL_DIR}/registry"
track_binary "/usr/local/bin/securectl"

# --- agent-tool-firewall (policy gateway for LLM tool calls) ---
echo "Building: agent-tool-firewall"
locate_source agent-tool-firewall /tmp/agent-tool-firewall \
    --clone https://github.com/SecAI-Hub/agent-tool-firewall.git
cd "$SOURCE_DIR"
CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/tool-firewall" .
track_binary "${INSTALL_DIR}/tool-firewall"

# --- gpu-integrity-watch (continuous GPU runtime verification) ---
echo "Building: gpu-integrity-watch"
locate_source gpu-integrity-watch \
    /tmp/services/gpu-integrity-watch /tmp/gpu-integrity-watch \
    --clone https://github.com/SecAI-Hub/gpu-integrity-watch.git
cd "$SOURCE_DIR"
CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/gpu-integrity-watch" .
track_binary "${INSTALL_DIR}/gpu-integrity-watch"
# Default profile (optional — runtime uses built-in defaults if missing)
mkdir -p /etc/secure-ai/gpu-integrity
cp profiles/default-profile.yaml /etc/secure-ai/gpu-integrity/ 2>/dev/null || true

# --- mcp-firewall (Model Context Protocol policy gateway) ---
echo "Building: mcp-firewall"
locate_source mcp-firewall \
    /tmp/services/mcp-firewall /tmp/mcp-firewall \
    --clone https://github.com/SecAI-Hub/mcp-firewall.git
cd "$SOURCE_DIR"
CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/mcp-firewall" .
track_binary "${INSTALL_DIR}/mcp-firewall"
# Default policy (optional — runtime uses built-in defaults if missing)
mkdir -p /etc/secure-ai/mcp-firewall
cp policies/default-policy.yaml /etc/secure-ai/mcp-firewall/ 2>/dev/null || true

# --- policy-engine (unified OPA-style decision point) ---
echo "Building: policy-engine"
locate_source policy-engine \
    /tmp/services/policy-engine /tmp/policy-engine \
    --clone https://github.com/SecAI-Hub/policy-engine.git
cd "$SOURCE_DIR"
CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/policy-engine" .
track_binary "${INSTALL_DIR}/policy-engine"

# --- runtime-attestor (TPM2 quote verification + startup gating) ---
echo "Building: runtime-attestor"
locate_source runtime-attestor \
    /tmp/services/runtime-attestor /tmp/runtime-attestor \
    --clone https://github.com/SecAI-Hub/runtime-attestor.git
cd "$SOURCE_DIR"
CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/runtime-attestor" .
track_binary "${INSTALL_DIR}/runtime-attestor"

# --- integrity-monitor (continuous baseline-verified file watcher) ---
echo "Building: integrity-monitor"
locate_source integrity-monitor \
    /tmp/services/integrity-monitor /tmp/integrity-monitor \
    --clone https://github.com/SecAI-Hub/integrity-monitor.git
cd "$SOURCE_DIR"
CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/integrity-monitor" .
track_binary "${INSTALL_DIR}/integrity-monitor"

# --- incident-recorder (security event capture and containment) ---
echo "Building: incident-recorder"
locate_source incident-recorder \
    /tmp/services/incident-recorder /tmp/incident-recorder \
    --clone https://github.com/SecAI-Hub/incident-recorder.git
cd "$SOURCE_DIR"
CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/incident-recorder" .
track_binary "${INSTALL_DIR}/incident-recorder"

# --- gguf-guard (GGUF model integrity scanner) ---
echo "Building: gguf-guard"
locate_source gguf-guard /tmp/gguf-guard \
    --clone https://github.com/SecAI-Hub/gguf-guard.git
cd "$SOURCE_DIR"
CGO_ENABLED=0 go build -ldflags="-s -w" -o /usr/local/bin/gguf-guard ./cmd/gguf-guard/
track_binary "/usr/local/bin/gguf-guard"

# ===========================================================================
# llama.cpp (required — inference engine)
# ===========================================================================
echo "Building: llama-server"
LLAMA_CPP_VERSION="${LLAMA_CPP_VERSION:-b5200}"
cd "$SRC_DIR"
curl -fsSL "https://github.com/ggml-org/llama.cpp/archive/refs/tags/${LLAMA_CPP_VERSION}.tar.gz" \
    | tar xz
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

# Record GPU backend metadata for runtime verification (Step 3: GPU backend recording)
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
locate_source ai-quarantine /tmp/ai-quarantine \
    --clone https://github.com/SecAI-Hub/ai-quarantine.git
pip3 install --prefix=/usr --no-cache-dir "${SOURCE_DIR}" 2>/dev/null || \
    pip3 install --prefix=/usr --break-system-packages --no-cache-dir "${SOURCE_DIR}"
cat > "${INSTALL_DIR}/quarantine-watcher" <<'WRAPPER'
#!/usr/bin/env python3
from quarantine.watcher import main
main()
WRAPPER
chmod +x "${INSTALL_DIR}/quarantine-watcher"
track_binary "${INSTALL_DIR}/quarantine-watcher"

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

# --- Web UI ---
echo "Building: ui"
if [ -d "/tmp/services/ui" ]; then
    pip3 install --prefix=/usr --no-cache-dir /tmp/services/ui 2>/dev/null || \
        pip3 install --prefix=/usr --break-system-packages --no-cache-dir /tmp/services/ui
    cat > "${INSTALL_DIR}/ui" <<'WRAPPER'
#!/usr/bin/env python3
from ui.app import main
main()
WRAPPER
    chmod +x "${INSTALL_DIR}/ui"
    track_binary "${INSTALL_DIR}/ui"
else
    fail_build "UI source not found at /tmp/services/ui"
fi

# ===========================================================================
# Optional Services (warnings are acceptable — not core security)
# ===========================================================================

# Diffusion worker (optional — image generation)
echo "Installing: diffusion-worker"
DIFFUSION_DIR="/opt/secure-ai/services/diffusion-worker"
mkdir -p "$DIFFUSION_DIR"
if [ -f "/tmp/services/diffusion-worker/app.py" ]; then
    cp /tmp/services/diffusion-worker/app.py "$DIFFUSION_DIR/app.py"
    echo "  -> ${DIFFUSION_DIR}/app.py"
else
    echo "WARNING: diffusion-worker source not found — diffusion worker will not be available"
fi

# --- llm-search-mediator (optional — privacy-preserving search bridge) ---
echo "Installing: llm-search-mediator"
SEARCH_DIR="/opt/secure-ai/services/search-mediator"
mkdir -p "$SEARCH_DIR"
if [ -d "/tmp/llm-search-mediator" ]; then
    cp -r /tmp/llm-search-mediator "${SRC_DIR}/llm-search-mediator"
elif git clone --depth 1 https://github.com/SecAI-Hub/llm-search-mediator.git \
    "${SRC_DIR}/llm-search-mediator" 2>/dev/null; then
    true  # clone succeeded
else
    echo "WARNING: llm-search-mediator not available — search mediator will not be installed"
fi
if [ -d "${SRC_DIR}/llm-search-mediator" ]; then
    cp -r "${SRC_DIR}/llm-search-mediator/search_mediator" "$SEARCH_DIR/"
    pip3 install --prefix=/usr --no-cache-dir \
        -r "${SRC_DIR}/llm-search-mediator/requirements.txt" 2>/dev/null || \
        pip3 install --prefix=/usr --break-system-packages --no-cache-dir \
            -r "${SRC_DIR}/llm-search-mediator/requirements.txt"
    cat > "${INSTALL_DIR}/search-mediator" <<'WRAPPER'
#!/usr/bin/env python3
import sys
sys.path.insert(0, "/opt/secure-ai/services/search-mediator")
from search_mediator.app import main
main()
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
    "/usr/local/bin/gguf-guard"
    "/usr/bin/llama-server"
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

# ---------------------------------------------------------------------------
# Configure container signing policy for cosign-verified SecAI images.
# This ensures rpm-ostree verifies cosign signatures on all future upgrades
# when using the ostree-image-signed: transport.
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

policy['transports']['docker']['ghcr.io/sec_ai/secai_os'] = [{
    'type': 'sigstoreSigned',
    'keyPath': '${COSIGN_PUB}',
    'signedIdentity': {'type': 'matchRepository'}
}]

with open('${POLICY_JSON}', 'w') as f:
    json.dump(policy, f, indent=2)
    f.write('\n')

print('  -> policy.json updated: sigstoreSigned entry for ghcr.io/sec_ai/secai_os')
" || fail_build "Failed to update container signing policy"
    else
        echo "WARNING: ${POLICY_JSON} not found — signing policy not configured"
    fi
    echo "  -> ${COSIGN_PUB}: installed"
    echo "  -> ${REGISTRIES_D}: installed"
else
    echo "WARNING: signing policy files missing from image — cosign verification may not work"
fi

# Cleanup build artifacts
rm -rf "$SRC_DIR"
dnf remove -y golang cmake gcc gcc-c++ 2>/dev/null || true
dnf clean all 2>/dev/null || true

echo ""
echo "=== Secure AI services installed ==="
ls -la "$INSTALL_DIR"/
