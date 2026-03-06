#!/usr/bin/env bash
#
# Secure AI Appliance — Encrypted Vault Setup
#
# This script sets up the LUKS2 encrypted persistent partition.
# Run during initial installation or from a live environment.
#
# Usage: sudo setup-vault.sh /dev/sdX3
#   where /dev/sdX3 is the partition to use for the encrypted vault.
#
# The vault will be mounted at /var/lib/secure-ai on every boot
# after the user provides the passphrase.

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root."
    exit 1
fi

if [ $# -ne 1 ]; then
    echo "Usage: $0 <partition>"
    echo "Example: $0 /dev/sda3"
    exit 1
fi

PARTITION="$1"
MAPPER_NAME="secure-ai-vault"
MOUNT_POINT="/var/lib/secure-ai"

if [ ! -b "$PARTITION" ]; then
    echo "ERROR: $PARTITION is not a block device."
    exit 1
fi

echo "=== Secure AI Vault Setup ==="
echo ""
echo "This will ERASE all data on $PARTITION and create an encrypted vault."
echo ""
read -rp "Type YES to continue: " CONFIRM
if [ "$CONFIRM" != "YES" ]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "Setting up LUKS2 encryption on $PARTITION..."
echo "You will be asked to set a passphrase."
echo ""
cryptsetup luksFormat --type luks2 \
    --cipher aes-xts-plain64 \
    --key-size 512 \
    --hash sha512 \
    --iter-time 5000 \
    --pbkdf argon2id \
    "$PARTITION"

echo ""
echo "Opening encrypted partition..."
cryptsetup open "$PARTITION" "$MAPPER_NAME"

echo "Creating ext4 filesystem..."
mkfs.ext4 -L secure-ai-vault "/dev/mapper/$MAPPER_NAME"

echo "Mounting at $MOUNT_POINT..."
mkdir -p "$MOUNT_POINT"
mount "/dev/mapper/$MAPPER_NAME" "$MOUNT_POINT"

echo ""
echo "=== Vault Setup Complete ==="
echo "Partition: $PARTITION"
echo "Mapped to: /dev/mapper/$MAPPER_NAME"
echo "Mounted at: $MOUNT_POINT"
echo ""
echo "To auto-prompt for passphrase on boot, add to /etc/crypttab:"
echo "  $MAPPER_NAME  UUID=$(blkid -s UUID -o value "$PARTITION")  none  luks,discard"
echo ""
echo "And add to /etc/fstab:"
echo "  /dev/mapper/$MAPPER_NAME  $MOUNT_POINT  ext4  defaults,nodev,nosuid  0  2"
