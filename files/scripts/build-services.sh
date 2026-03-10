#!/usr/bin/env bash
#
# Build and install Secure AI services into the OS image.
# This runs during the BlueBuild image build process.
#
set -oue pipefail

INSTALL_DIR="/usr/libexec/secure-ai"
SRC_DIR="/tmp/secure-ai-build"

echo "=== Building Secure AI services ==="

# Install build dependencies
dnf install -y golang python3 python3-pip cmake gcc gcc-c++ 2>/dev/null || true

mkdir -p "$INSTALL_DIR" "$SRC_DIR"

# --- Airlock (disabled by default — last monorepo service) ---
echo "Building: airlock"
if [ -d "/tmp/services/airlock" ]; then
    cp -r /tmp/services/airlock "${SRC_DIR}/airlock"
elif [ -d "/tmp/files/services/airlock" ]; then
    cp -r /tmp/files/services/airlock "${SRC_DIR}/airlock"
else
    echo "WARNING: airlock source not found — airlock will not be available (disabled by default)"
fi
if [ -d "${SRC_DIR}/airlock" ]; then
    cd "${SRC_DIR}/airlock"
    CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/airlock" .
    echo "  -> ${INSTALL_DIR}/airlock"
fi

# --- ai-model-registry (standalone: security-first artifact registry) ---
echo "Building: ai-model-registry"
if [ -d "/tmp/ai-model-registry" ]; then
    cp -r /tmp/ai-model-registry "${SRC_DIR}/ai-model-registry"
else
    git clone --depth 1 https://github.com/SecAI-Hub/ai-model-registry.git "${SRC_DIR}/ai-model-registry" 2>/dev/null || \
        echo "WARNING: ai-model-registry clone failed — registry will not be available"
fi
if [ -d "${SRC_DIR}/ai-model-registry" ]; then
    cd "${SRC_DIR}/ai-model-registry"
    CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/registry" .
    CGO_ENABLED=0 go build -ldflags="-s -w" -o /usr/local/bin/securectl ./cmd/securectl/
    echo "  -> ${INSTALL_DIR}/registry"
    echo "  -> /usr/local/bin/securectl"
fi

# --- agent-tool-firewall (standalone: policy gateway for LLM tool calls) ---
echo "Building: agent-tool-firewall"
if [ -d "/tmp/agent-tool-firewall" ]; then
    cp -r /tmp/agent-tool-firewall "${SRC_DIR}/agent-tool-firewall"
else
    git clone --depth 1 https://github.com/SecAI-Hub/agent-tool-firewall.git "${SRC_DIR}/agent-tool-firewall" 2>/dev/null || \
        echo "WARNING: agent-tool-firewall clone failed — tool firewall will not be available"
fi
if [ -d "${SRC_DIR}/agent-tool-firewall" ]; then
    cd "${SRC_DIR}/agent-tool-firewall"
    CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/tool-firewall" .
    echo "  -> ${INSTALL_DIR}/tool-firewall"
fi

# --- gguf-guard (GGUF model integrity scanner) ---
echo "Building: gguf-guard"
if [ -d "/tmp/gguf-guard" ]; then
    cp -r /tmp/gguf-guard "${SRC_DIR}/gguf-guard"
else
    git clone --depth 1 https://github.com/SecAI-Hub/gguf-guard.git "${SRC_DIR}/gguf-guard" 2>/dev/null || \
        echo "WARNING: gguf-guard clone failed — GGUF integrity scanner will not be available"
fi
if [ -d "${SRC_DIR}/gguf-guard" ]; then
    cd "${SRC_DIR}/gguf-guard"
    CGO_ENABLED=0 go build -ldflags="-s -w" -o /usr/local/bin/gguf-guard ./cmd/gguf-guard/
    echo "  -> /usr/local/bin/gguf-guard"
fi

# --- llama.cpp (inference engine) ---
echo "Building: llama-server"
LLAMA_CPP_VERSION="${LLAMA_CPP_VERSION:-b5200}"
cd "$SRC_DIR"
curl -fsSL "https://github.com/ggml-org/llama.cpp/archive/refs/tags/${LLAMA_CPP_VERSION}.tar.gz" \
    | tar xz
cd "llama.cpp-${LLAMA_CPP_VERSION}"
cmake -B build -DGGML_CUDA=ON -DGGML_VULKAN=ON -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_BUILD_TYPE=Release 2>/dev/null || \
    cmake -B build -DGGML_VULKAN=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Release 2>/dev/null || \
    cmake -B build -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build build --target llama-server -j"$(nproc)"
install -m 755 build/bin/llama-server /usr/bin/llama-server
echo "  -> /usr/bin/llama-server"

# --- Python services (installed as wrapper scripts) ---

# --- ai-quarantine (standalone: seven-stage artifact admission-control) ---
echo "Building: quarantine-watcher"
if [ -d "/tmp/ai-quarantine" ]; then
    cp -r /tmp/ai-quarantine "${SRC_DIR}/ai-quarantine"
else
    git clone --depth 1 https://github.com/SecAI-Hub/ai-quarantine.git "${SRC_DIR}/ai-quarantine" 2>/dev/null || \
        echo "WARNING: ai-quarantine clone failed — quarantine pipeline will not be available"
fi
if [ -d "${SRC_DIR}/ai-quarantine" ]; then
    pip3 install --prefix=/usr --no-cache-dir "${SRC_DIR}/ai-quarantine" 2>/dev/null || \
        pip3 install --prefix=/usr --break-system-packages --no-cache-dir "${SRC_DIR}/ai-quarantine"
    cat > "${INSTALL_DIR}/quarantine-watcher" <<'WRAPPER'
#!/usr/bin/env python3
from quarantine.watcher import main
main()
WRAPPER
    chmod +x "${INSTALL_DIR}/quarantine-watcher"
    echo "  -> ${INSTALL_DIR}/quarantine-watcher"
fi

# Quarantine scanning tools (installed independently so one failure doesn't block others)
echo "Installing: quarantine scanning tools"
for scanner in modelscan fickling garak modelaudit; do
    echo "  Installing: ${scanner}"
    pip3 install --prefix=/usr --no-cache-dir "${scanner}" 2>/dev/null || \
        pip3 install --prefix=/usr --break-system-packages --no-cache-dir "${scanner}" 2>/dev/null || \
        echo "  WARNING: ${scanner} install failed — scanner will be skipped at runtime"
done

# --- Agent service (policy-bound local autopilot) ---
echo "Building: agent"
pip3 install --prefix=/usr --no-cache-dir /tmp/services/agent 2>/dev/null || \
    pip3 install --prefix=/usr --break-system-packages --no-cache-dir /tmp/services/agent
cat > "${INSTALL_DIR}/agent" <<'WRAPPER'
#!/usr/bin/env python3
from agent.app import main
main()
WRAPPER
chmod +x "${INSTALL_DIR}/agent"
echo "  -> ${INSTALL_DIR}/agent"

# Web UI
echo "Building: ui"
pip3 install --prefix=/usr --no-cache-dir /tmp/services/ui 2>/dev/null || \
    pip3 install --prefix=/usr --break-system-packages --no-cache-dir /tmp/services/ui
cat > "${INSTALL_DIR}/ui" <<'WRAPPER'
#!/usr/bin/env python3
from ui.app import main
main()
WRAPPER
chmod +x "${INSTALL_DIR}/ui"
echo "  -> ${INSTALL_DIR}/ui"

# Diffusion worker
echo "Installing: diffusion-worker"
DIFFUSION_DIR="/opt/secure-ai/services/diffusion-worker"
mkdir -p "$DIFFUSION_DIR"
cp /tmp/services/diffusion-worker/app.py "$DIFFUSION_DIR/app.py"
echo "  -> ${DIFFUSION_DIR}/app.py"

# --- llm-search-mediator (standalone: privacy-preserving search bridge) ---
echo "Installing: llm-search-mediator"
SEARCH_DIR="/opt/secure-ai/services/search-mediator"
mkdir -p "$SEARCH_DIR"
if [ -d "/tmp/llm-search-mediator" ]; then
    cp -r /tmp/llm-search-mediator "${SRC_DIR}/llm-search-mediator"
else
    git clone --depth 1 https://github.com/SecAI-Hub/llm-search-mediator.git "${SRC_DIR}/llm-search-mediator" 2>/dev/null || \
        echo "WARNING: llm-search-mediator clone failed — search mediator will not be available"
fi
if [ -d "${SRC_DIR}/llm-search-mediator" ]; then
    cp -r "${SRC_DIR}/llm-search-mediator/search_mediator" "$SEARCH_DIR/"
    pip3 install --prefix=/usr --no-cache-dir -r "${SRC_DIR}/llm-search-mediator/requirements.txt" 2>/dev/null || \
        pip3 install --prefix=/usr --break-system-packages --no-cache-dir -r "${SRC_DIR}/llm-search-mediator/requirements.txt"
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

# HuggingFace CLI (for model downloads)
echo "Installing: huggingface-hub"
pip3 install --prefix=/usr --no-cache-dir huggingface-hub 2>/dev/null || \
    pip3 install --prefix=/usr --break-system-packages --no-cache-dir huggingface-hub 2>/dev/null || \
    echo "WARNING: huggingface-hub install failed — model downloads will use git clone fallback"

# Install SearXNG via pip if not available as RPM
echo "Installing: searxng"
pip3 install --prefix=/usr --no-cache-dir searxng 2>/dev/null || \
    pip3 install --prefix=/usr --break-system-packages --no-cache-dir searxng 2>/dev/null || \
    echo "WARNING: searxng pip install failed — SearXNG search will not be available"

# Cleanup build artifacts
rm -rf "$SRC_DIR"
dnf remove -y golang cmake gcc gcc-c++ 2>/dev/null || true
dnf clean all 2>/dev/null || true

echo "=== Secure AI services installed ==="
ls -la "$INSTALL_DIR"/
