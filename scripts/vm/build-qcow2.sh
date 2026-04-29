#!/bin/bash
#
# Build a SecAI OS QCOW2 virtual disk image for KVM/QEMU/Proxmox.
#
# Prerequisites:
#   - virt-install, qemu-img, libvirt (dnf install virt-install qemu-img libvirt)
#   - The SecAI OS container image built and available
#
# Usage:
#   ./build-qcow2.sh [output-dir]
#
# Output:
#   secai-os.qcow2 — bootable QCOW2 disk image (root + vault partitions)
#
set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)
COSIGN_PUB_SRC="${REPO_ROOT}/cosign.pub"
COSIGN_PUB_SHA256="de6a17ed1cd444a2671798f14d6bf98c1658259dc443a130eba9f40855a7d310"

# Parse flags
CI_MODE=false
CUSTOM_IMAGE_REF=""
POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ci) CI_MODE=true; shift ;;
        --image-ref) CUSTOM_IMAGE_REF="$2"; shift 2 ;;
        --image-ref=*) CUSTOM_IMAGE_REF="${1#*=}"; shift ;;
        *) POSITIONAL_ARGS+=("$1"); shift ;;
    esac
done

OUTPUT_DIR="${POSITIONAL_ARGS[0]:-./output}"
IMAGE_NAME="secai-os"
DISK_SIZE="64G"

# SecAI OS container image (override with --image-ref for CI)
CONTAINER_IMAGE="${CUSTOM_IMAGE_REF:-ghcr.io/secai-hub/secai_os:latest}"
case "$CONTAINER_IMAGE" in
    *[!A-Za-z0-9._:/@+-]*)
        echo "ERROR: image ref contains unsupported characters: $CONTAINER_IMAGE" >&2
        exit 1
        ;;
esac

for tool in awk openssl qemu-img sha256sum tr; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "ERROR: required tool not found: $tool" >&2
        exit 2
    }
done

if [ "$CI_MODE" = true ]; then
    for tool in virt-install virsh; do
        command -v "$tool" >/dev/null 2>&1 || {
            echo "ERROR: --ci requires $tool on the KVM build runner" >&2
            exit 2
        }
    done
fi

if [ ! -f "$COSIGN_PUB_SRC" ]; then
    echo "ERROR: missing signing key at ${COSIGN_PUB_SRC}" >&2
    exit 1
fi
COSIGN_PUB_CONTENT=$(tr -d '\r' < "$COSIGN_PUB_SRC")
ACTUAL_COSIGN_SHA256=$(printf '%s\n' "$COSIGN_PUB_CONTENT" | sha256sum | awk '{print $1}')
if [ "$ACTUAL_COSIGN_SHA256" != "$COSIGN_PUB_SHA256" ]; then
    echo "ERROR: cosign.pub fingerprint mismatch" >&2
    echo "  expected: ${COSIGN_PUB_SHA256}" >&2
    echo "  got:      ${ACTUAL_COSIGN_SHA256}" >&2
    exit 1
fi

# Generate random passwords for VM build (never hardcoded)
SECAI_VM_PASSWORD="${SECAI_VM_PASSWORD:-$(openssl rand -base64 18)}"
SECAI_VAULT_PASSWORD="${SECAI_VAULT_PASSWORD:-$(openssl rand -base64 18)}"
export SECAI_VM_PASSWORD SECAI_VAULT_PASSWORD

VM_BUILD_NAME="${SECAI_VM_BUILD_NAME:-secai-os-build}"
if [ "$CI_MODE" = true ] && [ -z "${SECAI_VM_BUILD_NAME:-}" ]; then
    VM_BUILD_NAME="secai-os-build-${GITHUB_RUN_ID:-$$}"
fi

echo "=========================================="
echo " SecAI OS — QCOW2 Image Builder"
echo "=========================================="
echo ""
echo "  WARNING: This image is for VIRTUAL MACHINES."
echo "  The host OS can inspect VM memory, including"
echo "  decrypted vault contents and inference data."
echo "  For maximum security, use bare-metal install."
echo ""
if [ "$CI_MODE" = true ]; then
    echo "  CI mode: running unattended virt-install on the KVM runner."
    echo ""
fi
echo "=========================================="

mkdir -p "$OUTPUT_DIR"

# Step 1: Create the disk image
echo "[1/4] Creating QCOW2 disk image (${DISK_SIZE})..."
qemu-img create -f qcow2 "${OUTPUT_DIR}/${IMAGE_NAME}.qcow2" "$DISK_SIZE"

# Step 2: Install using virt-install (unattended Fedora Silverblue + signed rebase)
echo "[2/4] Creating installation kickstart..."
cat > "${OUTPUT_DIR}/secai-ks.cfg" <<KICKSTART
# SecAI OS VM Kickstart — automated install
lang en_US.UTF-8
keyboard us
timezone UTC --utc
rootpw --lock
user --name=secai --groups=wheel --plaintext --password=${SECAI_VM_PASSWORD}

# Partitioning — root + vault
zerombr
clearpart --all --initlabel
part /boot/efi --fstype=efi --size=512
part /boot --fstype=ext4 --size=1024
part / --fstype=btrfs --size=30720
part /var/lib/secure-ai --fstype=ext4 --grow --encrypted --passphrase=${SECAI_VAULT_PASSWORD}

# Network
network --bootproto=dhcp --activate

# Post-install: rebase to SecAI OS
%post --log=/root/secai-post.log
install -d -m 0755 /etc/pki/containers /etc/containers/registries.d
cat > /etc/pki/containers/secai-cosign.pub <<'COSIGNPUB'
${COSIGN_PUB_CONTENT}
COSIGNPUB
chmod 0644 /etc/pki/containers/secai-cosign.pub

cat > /etc/containers/registries.d/secai-os.yaml <<'YAML'
docker:
  ghcr.io/secai-hub/secai_os:
    use-sigstore-attachments: true
YAML
chmod 0644 /etc/containers/registries.d/secai-os.yaml

python3 - <<'PY'
import json
import os
import shutil

policy_path = "/etc/containers/policy.json"
key_path = "/etc/pki/containers/secai-cosign.pub"

if os.path.exists(policy_path):
    shutil.copy2(policy_path, policy_path + ".pre-secai")
    with open(policy_path, encoding="utf-8") as f:
        policy = json.load(f)
else:
    policy = {"default": [{"type": "reject"}], "transports": {}}

policy.setdefault("transports", {})
policy["transports"].setdefault("docker", {})
policy["transports"]["docker"]["ghcr.io/secai-hub/secai_os"] = [{
    "type": "sigstoreSigned",
    "keyPath": key_path,
    "signedIdentity": {"type": "matchRepository"},
}]
policy["transports"].setdefault("docker-daemon", {})
policy["transports"]["docker-daemon"].setdefault("", [{"type": "insecureAcceptAnything"}])

with open(policy_path, "w", encoding="utf-8") as f:
    json.dump(policy, f, indent=2)
    f.write("\n")
PY

# Rebase to SecAI OS through the signed container policy from the first pull.
rpm-ostree rebase "ostree-image-signed:docker://${CONTAINER_IMAGE}"

# Write a flag so firstboot knows this is a VM install
mkdir -p /var/lib/secure-ai
echo "vm-kickstart" > /var/lib/secure-ai/.vm-install

# Remind user to change passwords
echo "============================================" > /etc/motd
echo " SecAI OS — Virtual Machine Installation"  >> /etc/motd
echo ""                                           >> /etc/motd
echo " IMPORTANT: Change your passwords!"         >> /etc/motd
echo "   sudo passwd secai"                       >> /etc/motd
echo "   sudo cryptsetup luksChangeKey /dev/sda4" >> /etc/motd
echo ""                                           >> /etc/motd
echo " The signed SecAI OS image is already staged." >> /etc/motd
echo " Reboot if rpm-ostree reports a pending deployment." >> /etc/motd
echo "============================================" >> /etc/motd
%end

reboot
KICKSTART
chmod 0600 "${OUTPUT_DIR}/secai-ks.cfg"

VIRT_INSTALL_ARGS=(
    --name "$VM_BUILD_NAME"
    --ram 4096
    --vcpus 2
    --disk "path=${OUTPUT_DIR}/${IMAGE_NAME}.qcow2,format=qcow2"
    --location "https://download.fedoraproject.org/pub/fedora/linux/releases/42/Silverblue/x86_64/os/"
    --initrd-inject "${OUTPUT_DIR}/secai-ks.cfg"
    --extra-args "inst.ks=file:/secai-ks.cfg"
    --os-variant fedora42
    --graphics none
    --console "pty,target_type=serial"
    --wait -1
    --noreboot
)

if [ "$CI_MODE" = true ]; then
    echo "[3/4] Running unattended virt-install..."
    if virsh dominfo "$VM_BUILD_NAME" >/dev/null 2>&1; then
        echo "ERROR: libvirt domain already exists: ${VM_BUILD_NAME}" >&2
        echo "Set SECAI_VM_BUILD_NAME to an unused name or remove the stale domain." >&2
        exit 1
    fi
    virt-install "${VIRT_INSTALL_ARGS[@]}"
    virsh undefine "$VM_BUILD_NAME" --nvram >/dev/null 2>&1 || true
else
    echo "[3/4] Building VM image..."
    echo "  To complete the build, run:"
    echo ""
    printf "  virt-install"
    for arg in "${VIRT_INSTALL_ARGS[@]}"; do
        printf " %q" "$arg"
    done
    echo ""
    echo ""
fi

echo "[4/4] Post-build instructions:"
echo ""
echo "  After installation completes:"
echo "    1. Boot the VM"
echo "    2. Log in as 'secai' (password: ${SECAI_VM_PASSWORD})"
echo "    3. CHANGE BOTH PASSWORDS IMMEDIATELY:"
echo "       sudo passwd secai"
echo "       sudo cryptsetup luksChangeKey /dev/sda4  (current: ${SECAI_VAULT_PASSWORD})"
echo "    4. Confirm the signed SecAI OS deployment: rpm-ostree status"
echo "    5. Reboot if a deployment is staged: sudo systemctl reboot"
echo ""
echo "  The QCOW2 image is at: ${OUTPUT_DIR}/${IMAGE_NAME}.qcow2"
echo "  Kickstart file is at: ${OUTPUT_DIR}/secai-ks.cfg (mode 0600; contains temporary passwords)"
