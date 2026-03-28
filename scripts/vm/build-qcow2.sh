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

OUTPUT_DIR="${1:-./output}"
IMAGE_NAME="secai-os"
DISK_SIZE="64G"
VAULT_SIZE="32G"

# SecAI OS container image
CONTAINER_IMAGE="ghcr.io/sec_ai/secai_os:latest"

# Generate random passwords for VM build (never hardcoded)
SECAI_VM_PASSWORD="${SECAI_VM_PASSWORD:-$(openssl rand -base64 18)}"
SECAI_VAULT_PASSWORD="${SECAI_VAULT_PASSWORD:-$(openssl rand -base64 18)}"
export SECAI_VM_PASSWORD SECAI_VAULT_PASSWORD

echo "=========================================="
echo " SecAI OS — QCOW2 Image Builder"
echo "=========================================="
echo ""
echo "  WARNING: This image is for VIRTUAL MACHINES."
echo "  The host OS can inspect VM memory, including"
echo "  decrypted vault contents and inference data."
echo "  For maximum security, use bare-metal install."
echo ""
echo "=========================================="

mkdir -p "$OUTPUT_DIR"

# Step 1: Create the disk image
echo "[1/4] Creating QCOW2 disk image (${DISK_SIZE})..."
qemu-img create -f qcow2 "${OUTPUT_DIR}/${IMAGE_NAME}.qcow2" "$DISK_SIZE"

# Step 2: Install using virt-install (unattended Fedora Silverblue + rebase)
echo "[2/4] Creating installation kickstart..."
cat > "${OUTPUT_DIR}/secai-ks.cfg" <<'KICKSTART'
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
# Rebase to SecAI OS (unsigned first, then signed after reboot)
rpm-ostree rebase ostree-unverified-registry:ghcr.io/sec_ai/secai_os:latest || true

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
echo " Then reboot to complete SecAI OS setup:"   >> /etc/motd
echo "   sudo rpm-ostree rebase ostree-image-signed:docker://ghcr.io/sec_ai/secai_os:latest" >> /etc/motd
echo "   sudo systemctl reboot"                   >> /etc/motd
echo "============================================" >> /etc/motd
%end

reboot
KICKSTART

echo "[3/4] Building VM image..."
echo "  To complete the build, run:"
echo ""
echo "  virt-install \\"
echo "    --name secai-os-build \\"
echo "    --ram 4096 --vcpus 2 \\"
echo "    --disk path=${OUTPUT_DIR}/${IMAGE_NAME}.qcow2,format=qcow2 \\"
echo "    --location https://download.fedoraproject.org/pub/fedora/linux/releases/42/Silverblue/x86_64/os/ \\"
echo "    --initrd-inject ${OUTPUT_DIR}/secai-ks.cfg \\"
echo "    --extra-args 'inst.ks=file:/secai-ks.cfg' \\"
echo "    --os-variant fedora42 \\"
echo "    --graphics none --console pty,target_type=serial \\"
echo "    --noreboot"
echo ""

echo "[4/4] Post-build instructions:"
echo ""
echo "  After installation completes:"
echo "    1. Boot the VM"
echo "    2. Log in as 'secai' (password: ${SECAI_VM_PASSWORD})"
echo "    3. CHANGE BOTH PASSWORDS IMMEDIATELY:"
echo "       sudo passwd secai"
echo "       sudo cryptsetup luksChangeKey /dev/sda4  (current: ${SECAI_VAULT_PASSWORD})"
echo "    4. Complete rebase: sudo rpm-ostree rebase ostree-image-signed:docker://ghcr.io/sec_ai/secai_os:latest"
echo "    5. Reboot: sudo systemctl reboot"
echo ""
echo "  The QCOW2 image is at: ${OUTPUT_DIR}/${IMAGE_NAME}.qcow2"
echo "  Kickstart file is at: ${OUTPUT_DIR}/secai-ks.cfg"
