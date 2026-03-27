#!/usr/bin/env bash
#
# Generate real diffusion lockfiles and populate the runtime manifest.
#
# This script must run on Linux with Python 3.12 and network access.
# It creates backend-specific pip lockfiles with --generate-hashes and
# fills in the wheel manifest entries with real filenames and SHA256 hashes.
#
# Usage:
#   bash scripts/generate-diffusion-locks.sh
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPTS_DIR="${REPO_ROOT}/files/scripts"
MANIFEST="${SCRIPTS_DIR}/diffusion-runtime-manifest.yaml"
WORK="/tmp/secai-diffusion-locks"

echo "=== SecAI Diffusion Lockfile Generator ==="
echo "  Repo:    ${REPO_ROOT}"
echo "  Python:  $(python3 --version)"
echo "  Arch:    $(uname -m)"

# Create isolated venv for pip-compile
rm -rf "${WORK}"
python3 -m venv "${WORK}/venv"
# shellcheck disable=SC1091
source "${WORK}/venv/bin/activate"
pip install --quiet pip-tools pyyaml

# Write the input requirements file (the packages we need)
cat > "${WORK}/diffusion-in.txt" <<'EOF'
torch
diffusers
transformers
safetensors
accelerate
EOF

# Generate lockfiles for each backend
declare -A TORCH_INDEXES=(
    ["cpu"]="https://download.pytorch.org/whl/cpu"
    ["cuda"]="https://download.pytorch.org/whl/cu121"
    ["rocm"]="https://download.pytorch.org/whl/rocm6.0"
)

for backend in cpu cuda rocm; do
    echo ""
    echo "=== Generating lockfile: diffusion-${backend}.lock ==="
    LOCKFILE="${SCRIPTS_DIR}/diffusion-${backend}.lock"
    INDEX="${TORCH_INDEXES[$backend]}"

    pip-compile \
        --allow-unsafe \
        --generate-hashes \
        --extra-index-url "${INDEX}" \
        --output-file "${LOCKFILE}" \
        "${WORK}/diffusion-in.txt" \
    || {
        echo "ERROR: pip-compile failed for ${backend}" >&2
        echo "  This may be a network issue or a missing compatible wheel."
        echo "  Continuing with other backends..."
        continue
    }

    echo "  -> ${LOCKFILE} ($(wc -l < "${LOCKFILE}") lines)"
done

# Now generate the wheel manifest entries from the lockfiles
echo ""
echo "=== Generating wheel manifest entries ==="

python3 << 'MANIFEST_SCRIPT'
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

SCRIPTS_DIR = os.environ.get("SCRIPTS_DIR", "files/scripts")
MANIFEST_PATH = os.path.join(SCRIPTS_DIR, "diffusion-runtime-manifest.yaml")

with open(MANIFEST_PATH) as f:
    manifest = yaml.safe_load(f)

backends = manifest.get("backends", {})
all_populated = True

for backend_name, cfg in backends.items():
    lockfile_path = os.path.join(SCRIPTS_DIR, cfg["lockfile"])
    if not os.path.exists(lockfile_path):
        print(f"  SKIP {backend_name}: lockfile not found at {lockfile_path}")
        all_populated = False
        continue

    content = Path(lockfile_path).read_text()

    # Check if lockfile is actually populated (has package entries)
    pkg_pattern = re.compile(r"^(\S+)==(\S+)\s*\\", re.MULTILINE)
    packages = pkg_pattern.findall(content)
    if not packages:
        print(f"  SKIP {backend_name}: lockfile is empty (pip-compile may have failed)")
        all_populated = False
        continue

    # Download all wheels to a temp directory to get filenames and hashes
    print(f"  Downloading wheels for {backend_name} ({len(packages)} packages)...")
    tmpdir = tempfile.mkdtemp(prefix=f"secai-{backend_name}-")
    torch_index = cfg["torch_index"]

    result = subprocess.run(
        [
            sys.executable, "-m", "pip", "download",
            "--no-deps",
            "--only-binary=:all:",
            "--require-hashes",
            "--dest", tmpdir,
            "--extra-index-url", torch_index,
            "-r", lockfile_path,
        ],
        capture_output=True, text=True,
    )

    if result.returncode != 0:
        print(f"  ERROR downloading wheels for {backend_name}:")
        print(result.stderr[-500:] if len(result.stderr) > 500 else result.stderr)
        all_populated = False
        continue

    # Build wheel entries from downloaded files
    wheels = []
    for whl_file in sorted(Path(tmpdir).glob("*.whl")):
        sha256 = hashlib.sha256(whl_file.read_bytes()).hexdigest()
        # Determine source pattern based on filename
        if "torch" in whl_file.name.lower() and ("cpu" in whl_file.name or "cu1" in whl_file.name or "rocm" in whl_file.name):
            source = f"{torch_index}/*"
        else:
            source = "https://files.pythonhosted.org/packages/*"
        wheels.append({
            "filename": whl_file.name,
            "sha256": sha256,
            "source": source,
        })

    cfg["wheels"] = wheels
    print(f"  {backend_name}: {len(wheels)} wheels")

# Update populated flag
manifest["populated"] = all_populated
manifest["backends"] = backends

# Write back the manifest
with open(MANIFEST_PATH, "w") as f:
    yaml.dump(manifest, f, default_flow_style=False, sort_keys=False, width=120)

if all_populated:
    print(f"\n=== SUCCESS: manifest populated with real hashes ===")
else:
    print(f"\n=== PARTIAL: some backends failed — manifest NOT marked as populated ===")

sys.exit(0 if all_populated else 1)
MANIFEST_SCRIPT

echo ""
echo "=== Done ==="
echo "  Lockfiles:  ${SCRIPTS_DIR}/diffusion-{cpu,cuda,rocm}.lock"
echo "  Manifest:   ${MANIFEST}"
echo ""
echo "Next steps:"
echo "  1. Review the generated files"
echo "  2. git add files/scripts/diffusion-*.lock files/scripts/diffusion-runtime-manifest.yaml"
echo "  3. git commit -m 'Populate diffusion runtime manifests with real hashes'"
