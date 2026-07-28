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
# The vault will be mounted at /var/lib/secure-ai/vault on every boot
# after the user provides the passphrase.

set -euo pipefail
umask 077

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
MOUNT_POINT="/var/lib/secure-ai/vault"
MAPPER_PATH="/dev/mapper/$MAPPER_NAME"

# Older images created empty vault subdirectories before the encrypted mount
# existed. Remove only those known, empty compatibility directories; any file
# or unknown entry is treated as possible plaintext data and blocks setup.
if [ -L "$MOUNT_POINT" ] || [ ! -d "$MOUNT_POINT" ]; then
    echo "ERROR: Vault mountpoint must be an existing real directory: $MOUNT_POINT"
    exit 1
fi
if findmnt -rn --mountpoint "$MOUNT_POINT" >/dev/null 2>&1; then
    echo "ERROR: Refusing setup because $MOUNT_POINT is already mounted."
    exit 1
fi
for legacy_dir in models contained-models user_docs outputs; do
    rmdir "${MOUNT_POINT}/${legacy_dir}" 2>/dev/null || true
done
if find "$MOUNT_POINT" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
    echo "ERROR: $MOUNT_POINT contains data while the vault is unmounted."
    echo "Move and securely review that data before configuring the encrypted vault."
    exit 1
fi

if [ ! -b "$PARTITION" ]; then
    echo "ERROR: $PARTITION is not a block device."
    exit 1
fi
PARTITION=$(readlink -f -- "$PARTITION")
if [[ "$PARTITION" != /dev/* ]]; then
    echo "ERROR: Resolved partition path is outside /dev."
    exit 1
fi
DEVICE_TYPE=$(lsblk -dnro TYPE "$PARTITION")
if [ "$DEVICE_TYPE" != "part" ] && [ "$DEVICE_TYPE" != "lvm" ]; then
    echo "ERROR: Vault target must be a dedicated partition or logical volume."
    exit 1
fi
if [ "$(blockdev --getro "$PARTITION")" != "0" ]; then
    echo "ERROR: $PARTITION is read-only."
    exit 1
fi
if lsblk -nrpo NAME,MOUNTPOINTS "$PARTITION" | grep -Eq '[[:space:]]+/'; then
    echo "ERROR: $PARTITION or one of its children is mounted."
    exit 1
fi
while IFS= read -r candidate; do
    [ -n "$candidate" ] || continue
    if swapon --noheadings --show=NAME 2>/dev/null \
        | while IFS= read -r swap_device; do
            [ "$(readlink -f -- "$swap_device")" != "$candidate" ] || exit 1
        done
    then
        :
    else
        echo "ERROR: $candidate is active swap."
        exit 1
    fi
    block_name="${candidate##*/}"
    if [ -d "/sys/class/block/${block_name}/holders" ] \
        && find "/sys/class/block/${block_name}/holders" -mindepth 1 -maxdepth 1 \
            -print -quit | grep -q .; then
        echo "ERROR: $candidate has active device-mapper holders."
        exit 1
    fi
done < <(lsblk -nrpo NAME "$PARTITION")
if cryptsetup status "$MAPPER_NAME" >/dev/null 2>&1; then
    echo "ERROR: $MAPPER_NAME is already active."
    exit 1
fi
DEVICE_ID=$(lsblk -dnro MAJ:MIN "$PARTITION")
if [[ ! "$DEVICE_ID" =~ ^[0-9]+:[0-9]+$ ]]; then
    echo "ERROR: Could not bind confirmation to a stable block-device identity."
    exit 1
fi

MAPPED=false
MOUNTED=false
COMPLETE=false
cleanup() {
    if [ "$COMPLETE" != true ]; then
        if [ "$MOUNTED" = true ]; then
            umount "$MOUNT_POINT" >/dev/null 2>&1 || true
        fi
        if [ "$MAPPED" = true ]; then
            cryptsetup close "$MAPPER_NAME" >/dev/null 2>&1 || true
        fi
    fi
}
trap cleanup EXIT INT TERM

echo "=== Secure AI Vault Setup ==="
echo ""
echo "This will ERASE all data on $PARTITION and create an encrypted vault."
echo ""
read -rp "Type ERASE $PARTITION to continue: " CONFIRM
if [ "$CONFIRM" != "ERASE $PARTITION" ]; then
    echo "Aborted."
    exit 1
fi
if [ "$(lsblk -dnro MAJ:MIN "$PARTITION")" != "$DEVICE_ID" ]; then
    echo "ERROR: Block device identity changed after confirmation."
    exit 1
fi

echo ""
echo "Setting up LUKS2 encryption on $PARTITION..."
echo "You will be asked to set a passphrase."
echo ""
cryptsetup luksFormat --type luks2 \
    --batch-mode \
    --cipher aes-xts-plain64 \
    --key-size 512 \
    --hash sha512 \
    --iter-time 5000 \
    --pbkdf argon2id \
    "$PARTITION"

echo ""
echo "Opening encrypted partition..."
cryptsetup open "$PARTITION" "$MAPPER_NAME"
MAPPED=true

echo "Creating ext4 filesystem..."
mkfs.ext4 -L secure-ai-vault "$MAPPER_PATH"

echo "Mounting at $MOUNT_POINT..."
mkdir -p "$MOUNT_POINT"
mount -o nodev,nosuid,noexec "$MAPPER_PATH" "$MOUNT_POINT"
MOUNTED=true
chown root:root "$MOUNT_POINT"
chmod 0711 "$MOUNT_POINT"
install -d -m 2770 -o root -g secure-ai-registry \
    "$MOUNT_POINT/models"
install -d -m 2770 -o root -g secure-ai-registry-containment \
    "$MOUNT_POINT/contained-models"
install -d -m 2750 -o root -g secure-ai-vault-read \
    "$MOUNT_POINT/user_docs"
install -d -m 2770 -o root -g secure-ai-vault-write \
    "$MOUNT_POINT/outputs"

PARTITION_UUID=$(cryptsetup luksUUID "$PARTITION")
if [[ ! "$PARTITION_UUID" =~ ^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$ ]]; then
    echo "ERROR: Could not determine a valid LUKS UUID."
    exit 1
fi

python3 - "$PARTITION_UUID" "$MAPPER_NAME" "$MOUNT_POINT" <<'PY'
import os
import stat
import sys
import tempfile
from pathlib import Path

luks_uuid, mapper_name, mount_point = sys.argv[1:4]

def update_config(
    path: Path,
    mode: int,
    replacement: str,
    remove_entry,
) -> None:
    if path.is_symlink():
        raise SystemExit(f"refusing symlink configuration: {path}")
    original = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    retained = []
    for line in original:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            retained.append(line)
            continue
        fields = stripped.split()
        if not remove_entry(fields):
            retained.append(line)
    retained.append(replacement)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(retained).rstrip() + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            os.fchmod(handle.fileno(), mode)
        os.replace(temporary, path)
        parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass

update_config(
    Path("/etc/crypttab"),
    0o600,
    f"{mapper_name} UUID={luks_uuid} none luks",
    lambda fields: fields[0] == mapper_name,
)
update_config(
    Path("/etc/fstab"),
    0o644,
    f"/dev/mapper/{mapper_name} {mount_point} ext4 defaults,nodev,nosuid,noexec 0 2",
    lambda fields: fields[0] == f"/dev/mapper/{mapper_name}"
    or (len(fields) > 1 and fields[1] == mount_point),
)
PY

python3 - "$MOUNT_POINT/.initialized" "$PARTITION_UUID" <<'PY'
import datetime as dt
import json
import os
import sys

path = sys.argv[1]
payload = {
    "initialized_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "luks_uuid": sys.argv[2],
    "mapper": "secure-ai-vault",
    "mount_point": "/var/lib/secure-ai/vault",
    "schema_version": 1,
}
with open(path, "x", encoding="utf-8") as handle:
    json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
os.chmod(path, 0o600)
directory_fd = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY
systemctl daemon-reload

echo "Enrolling the mounted vault canary..."
if ! /usr/libexec/secure-ai/canary-place.sh; then
    echo "ERROR: Vault setup succeeded, but canary enrollment failed."
    echo "The new vault will be unmounted and closed; inspect local logs before retrying."
    exit 1
fi

echo "Verifying the exact encrypted mount contract..."
if ! /usr/libexec/secure-ai/verify-vault-mount.py; then
    echo "ERROR: Vault setup completed, but exact mount verification failed."
    echo "The new vault will be unmounted and closed."
    exit 1
fi

# Consumers that failed closed during an unconfigured first boot can now
# start. Disabled optional units (notably diffusion) remain disabled.
systemctl reset-failed secure-ai-vault-mounted.service \
    secure-ai-registry.service secure-ai-integrity-monitor.service \
    secure-ai-quarantine-watcher.service secure-ai-inference.service \
    secure-ai-agent.service secure-ai-tool-firewall.service \
    secure-ai-mcp-firewall.service >/dev/null 2>&1 || true
systemctl start secure-ai-vault-mounted.service
COMPLETE=true
for service in \
    secure-ai-registry.service \
    secure-ai-integrity-monitor.service \
    secure-ai-quarantine-watcher.service \
    secure-ai-inference.service \
    secure-ai-agent.service \
    secure-ai-tool-firewall.service \
    secure-ai-mcp-firewall.service
do
    if systemctl is-enabled --quiet "$service"; then
        systemctl start "$service"
    fi
done

echo ""
echo "=== Vault Setup Complete ==="
echo "Partition: $PARTITION"
echo "Mapped to: /dev/mapper/$MAPPER_NAME"
echo "Mounted at: $MOUNT_POINT"
echo "Persistent mappings: /etc/crypttab and /etc/fstab updated atomically"
