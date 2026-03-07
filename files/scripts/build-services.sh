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
dnf install -y golang python3 python3-pip 2>/dev/null || true

mkdir -p "$INSTALL_DIR" "$SRC_DIR"

# --- Go services ---
for svc in registry tool-firewall airlock; do
    echo "Building: $svc"
    cp -r /tmp/services/${svc} "${SRC_DIR}/${svc}"
    cd "${SRC_DIR}/${svc}"
    CGO_ENABLED=0 go build -ldflags="-s -w" -o "${INSTALL_DIR}/${svc}" .
    echo "  -> ${INSTALL_DIR}/${svc}"
done

# Build securectl CLI
echo "Building: securectl"
cd "${SRC_DIR}/registry"
CGO_ENABLED=0 go build -ldflags="-s -w" -o /usr/local/bin/securectl ./cmd/securectl/
echo "  -> /usr/local/bin/securectl"

# --- Python services (installed as wrapper scripts) ---

# Quarantine watcher
echo "Building: quarantine-watcher"
pip3 install --prefix=/usr --no-cache-dir /tmp/services/quarantine 2>/dev/null || \
    pip3 install --prefix=/usr --break-system-packages --no-cache-dir /tmp/services/quarantine
cat > "${INSTALL_DIR}/quarantine-watcher" <<'WRAPPER'
#!/usr/bin/env python3
from quarantine.watcher import main
main()
WRAPPER
chmod +x "${INSTALL_DIR}/quarantine-watcher"
echo "  -> ${INSTALL_DIR}/quarantine-watcher"

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

# Cleanup build artifacts
rm -rf "$SRC_DIR"
dnf remove -y golang 2>/dev/null || true
dnf clean all 2>/dev/null || true

echo "=== Secure AI services installed ==="
ls -la "$INSTALL_DIR"/
