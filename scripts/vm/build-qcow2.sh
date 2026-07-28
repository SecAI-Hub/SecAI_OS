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
#   secai-os.qcow2 — bootable QCOW2 image with encrypted host state and an
#                    unused partition for the local-console vault ceremony
#
set -euo pipefail
export LC_ALL=C
umask 077

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)
COSIGN_PUB_SRC="${REPO_ROOT}/cosign.pub"
COSIGN_PUB_SHA256="de6a17ed1cd444a2671798f14d6bf98c1658259dc443a130eba9f40855a7d310"

# Parse flags
CI_MODE=false
CUSTOM_IMAGE_REF=""
QUALIFICATION_SSH_KEY=""
POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ci) CI_MODE=true; shift ;;
        --image-ref)
            [ "$#" -ge 2 ] || {
                echo "ERROR: --image-ref requires a value" >&2
                exit 2
            }
            CUSTOM_IMAGE_REF="$2"
            shift 2
            ;;
        --image-ref=*) CUSTOM_IMAGE_REF="${1#*=}"; shift ;;
        --cosign-key)
            [ "$#" -ge 2 ] || {
                echo "ERROR: --cosign-key requires a value" >&2
                exit 2
            }
            COSIGN_PUB_SRC="$2"
            shift 2
            ;;
        --cosign-key=*) COSIGN_PUB_SRC="${1#*=}"; shift ;;
        --qualification-ssh-key)
            [ "$#" -ge 2 ] || {
                echo "ERROR: --qualification-ssh-key requires a value" >&2
                exit 2
            }
            QUALIFICATION_SSH_KEY="$2"
            shift 2
            ;;
        --qualification-ssh-key=*)
            QUALIFICATION_SSH_KEY="${1#*=}"
            shift
            ;;
        -*) echo "ERROR: unknown option: $1" >&2; exit 2 ;;
        *) POSITIONAL_ARGS+=("$1"); shift ;;
    esac
done

[ "${#POSITIONAL_ARGS[@]}" -le 1 ] || {
    echo "ERROR: at most one output directory may be supplied" >&2
    exit 2
}

OUTPUT_DIR="${POSITIONAL_ARGS[0]:-./output}"
IMAGE_NAME="secai-os"
DISK_SIZE="64G"

if [ -L "$OUTPUT_DIR" ]; then
    echo "ERROR: output directory must not be a symlink: ${OUTPUT_DIR}" >&2
    exit 1
fi
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR=$(CDPATH='' cd -- "$OUTPUT_DIR" && pwd -P)
QCOW2_PATH="${OUTPUT_DIR}/${IMAGE_NAME}.qcow2"
KICKSTART_PATH="${OUTPUT_DIR}/secai-ks.cfg"
SECRETS_FILE="${OUTPUT_DIR}/secai-first-boot-secrets.txt"

for output_path in "$QCOW2_PATH" "$KICKSTART_PATH"; do
    if [ -e "$output_path" ] || [ -L "$output_path" ]; then
        echo "ERROR: refusing to overwrite existing output: ${output_path}" >&2
        exit 1
    fi
done
if [ "$CI_MODE" != true ] &&
    { [ -e "$SECRETS_FILE" ] || [ -L "$SECRETS_FILE" ]; }; then
    echo "ERROR: refusing to overwrite existing secrets file: ${SECRETS_FILE}" >&2
    exit 1
fi

# Media must always be tied to an explicitly reviewed immutable deployment.
if [ -z "$CUSTOM_IMAGE_REF" ]; then
    echo "ERROR: --image-ref repository@sha256:<64 lowercase hex> is required" >&2
    exit 1
fi
CONTAINER_IMAGE="$CUSTOM_IMAGE_REF"
case "$CONTAINER_IMAGE" in
    *[!A-Za-z0-9._:/@+-]*)
        echo "ERROR: image ref contains unsupported characters: $CONTAINER_IMAGE" >&2
        exit 1
        ;;
esac
if [[ ! "$CONTAINER_IMAGE" =~ ^[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]]; then
    echo "ERROR: --image-ref must be an exact repository@sha256:<64 lowercase hex> reference" >&2
    exit 1
fi

for tool in awk cosign openssl qemu-img sha256sum tr; do
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

SSH_KEY_DIRECTIVE=""
if [ -n "$QUALIFICATION_SSH_KEY" ]; then
    if [ "$CI_MODE" != true ]; then
        echo "ERROR: --qualification-ssh-key is restricted to --ci builds" >&2
        exit 2
    fi
    command -v ssh-keygen >/dev/null 2>&1 || {
        echo "ERROR: --qualification-ssh-key requires ssh-keygen" >&2
        exit 2
    }
    if [ -L "$QUALIFICATION_SSH_KEY" ] || [ ! -f "$QUALIFICATION_SSH_KEY" ]; then
        echo "ERROR: qualification SSH key must be a regular, non-symlink file" >&2
        exit 2
    fi
    mapfile -t SSH_KEY_LINES < "$QUALIFICATION_SSH_KEY"
    if [ "${#SSH_KEY_LINES[@]}" -ne 1 ]; then
        echo "ERROR: qualification SSH public key must contain exactly one line" >&2
        exit 2
    fi
    read -r SSH_KEY_TYPE SSH_KEY_BODY _ <<<"${SSH_KEY_LINES[0]}"
    if [ "$SSH_KEY_TYPE" != "ssh-ed25519" ] ||
        [[ ! "$SSH_KEY_BODY" =~ ^[A-Za-z0-9+/]+={0,3}$ ]] ||
        ! ssh-keygen -l -f "$QUALIFICATION_SSH_KEY" >/dev/null 2>&1; then
        echo "ERROR: qualification SSH key must be a valid Ed25519 public key" >&2
        exit 2
    fi
    SSH_KEY_DIRECTIVE="sshkey --username=root \"ssh-ed25519 ${SSH_KEY_BODY}\""
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

echo "Verifying signed immutable source image ${CONTAINER_IMAGE}..."
cosign verify --key "$COSIGN_PUB_SRC" "$CONTAINER_IMAGE" >/dev/null

# Local builds generate user-specific first-boot credentials. CI qualification
# callers must provide ephemeral values explicitly so an unrecoverable or
# accidentally distributable image is never produced.
if [ "$CI_MODE" = true ]; then
    if [ -z "${SECAI_VM_PASSWORD:-}" ] ||
        [ -z "${SECAI_HOST_STATE_PASSWORD:-}" ]; then
        echo "ERROR: --ci requires caller-provided SECAI_VM_PASSWORD and" >&2
        echo "       SECAI_HOST_STATE_PASSWORD for an ephemeral qualification build" >&2
        exit 2
    fi
else
    SECAI_VM_PASSWORD="${SECAI_VM_PASSWORD:-$(openssl rand -hex 24)}"
    SECAI_HOST_STATE_PASSWORD="${SECAI_HOST_STATE_PASSWORD:-$(openssl rand -hex 24)}"
fi

for credential_name in SECAI_VM_PASSWORD SECAI_HOST_STATE_PASSWORD; do
    credential_value="${!credential_name}"
    if [ "${#credential_value}" -lt 24 ] ||
        [ "${#credential_value}" -gt 128 ] ||
        [[ ! "$credential_value" =~ ^[A-Za-z0-9._~+/=-]+$ ]]; then
        echo "ERROR: ${credential_name} must be 24-128 safe ASCII characters" >&2
        exit 2
    fi
done

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

# Step 1: Create the disk image
echo "[1/4] Creating QCOW2 disk image (${DISK_SIZE})..."
qemu-img create -f qcow2 "$QCOW2_PATH" "$DISK_SIZE"
chmod 0600 "$QCOW2_PATH"

# Step 2: Install using virt-install (unattended Fedora Silverblue + signed rebase)
echo "[2/4] Creating installation kickstart..."
KICKSTART_TMP=$(mktemp "${OUTPUT_DIR}/.secai-ks.XXXXXX")
cat > "$KICKSTART_TMP" <<KICKSTART
# SecAI OS VM Kickstart — automated install
lang en_US.UTF-8
keyboard us
timezone UTC --utc
rootpw --lock
user --name=secai --groups=wheel --plaintext --password=${SECAI_VM_PASSWORD}
${SSH_KEY_DIRECTIVE}
services --enabled=sshd

# Partitioning — immutable root, encrypted service state, and a dedicated
# unused partition that the local-console wizard converts to the data vault.
zerombr
clearpart --all --initlabel
part /boot/efi --fstype=efi --size=512
part /boot --fstype=ext4 --size=1024
part / --fstype=btrfs --size=24576
part /var/lib/secure-ai --fstype=ext4 --size=8192 --encrypted --passphrase=${SECAI_HOST_STATE_PASSWORD}
part /var/tmp/secai-vault-staging --fstype=ext4 --grow

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

# The final partition is intentionally unused at first boot. Remove only its
# exact temporary installer mount from fstab; the console vault ceremony will
# reformat /dev/sda5 as LUKS2 after explicit destructive confirmation.
python3 - <<'PY'
from pathlib import Path

path = Path("/etc/fstab")
lines = path.read_text(encoding="utf-8").splitlines()
retained = []
removed = 0
for line in lines:
    fields = line.split()
    if len(fields) >= 2 and fields[1] == "/var/tmp/secai-vault-staging":
        removed += 1
        continue
    retained.append(line)
if removed != 1:
    raise SystemExit("expected exactly one temporary vault-staging fstab entry")
path.write_text("\n".join(retained).rstrip() + "\n", encoding="utf-8")
PY

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
echo "   sudo /usr/libexec/secure-ai/secai-setup-wizard.sh --vault-device /dev/sda5" >> /etc/motd
echo ""                                           >> /etc/motd
echo " The signed SecAI OS image is already staged." >> /etc/motd
echo " Reboot if rpm-ostree reports a pending deployment." >> /etc/motd
echo "============================================" >> /etc/motd
%end

reboot
KICKSTART
chmod 0600 "$KICKSTART_TMP"
if ! ln "$KICKSTART_TMP" "$KICKSTART_PATH"; then
    rm -f -- "$KICKSTART_TMP"
    echo "ERROR: could not atomically publish ${KICKSTART_PATH}" >&2
    exit 1
fi
rm -f -- "$KICKSTART_TMP"

if [ "$CI_MODE" != true ]; then
    SECRETS_TMP=$(mktemp "${OUTPUT_DIR}/.secai-first-boot-secrets.XXXXXX")
    {
        printf 'Temporary VM user password: %s\n' "$SECAI_VM_PASSWORD"
        printf 'Temporary encrypted host-state passphrase: %s\n' \
            "$SECAI_HOST_STATE_PASSWORD"
    } > "$SECRETS_TMP"
    chmod 0600 "$SECRETS_TMP"
    if ! ln "$SECRETS_TMP" "$SECRETS_FILE"; then
        rm -f -- "$SECRETS_TMP"
        echo "ERROR: could not atomically publish ${SECRETS_FILE}" >&2
        exit 1
    fi
    rm -f -- "$SECRETS_TMP"
fi

VIRT_INSTALL_ARGS=(
    --name "$VM_BUILD_NAME"
    --ram 4096
    --vcpus 2
    --disk "path=${OUTPUT_DIR}/${IMAGE_NAME}.qcow2,format=qcow2"
    --location "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Silverblue/x86_64/os/"
    --initrd-inject "$KICKSTART_PATH"
    --extra-args "inst.ks=file:/secai-ks.cfg"
    --os-variant fedora44
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
    rm -f -- "$KICKSTART_PATH"
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
echo "    2. Unlock encrypted host state, then log in as 'secai'."
if [ "$CI_MODE" != true ]; then
    echo "       Temporary credentials are in: ${SECRETS_FILE} (mode 0600)"
fi
echo "    3. CHANGE BOTH TEMPORARY CREDENTIALS IMMEDIATELY:"
echo "       sudo passwd secai"
echo "       sudo cryptsetup luksChangeKey /dev/sda4"
echo "       rm -f -- ${KICKSTART_PATH}"
echo "    4. Create the separate encrypted data vault:"
echo "       sudo /usr/libexec/secure-ai/secai-setup-wizard.sh --vault-device /dev/sda5"
echo "    5. Confirm the signed SecAI OS deployment: rpm-ostree status"
echo "    6. Reboot if a deployment is staged: sudo systemctl reboot"
echo ""
echo "  The QCOW2 image is at: ${OUTPUT_DIR}/${IMAGE_NAME}.qcow2"
if [ "$CI_MODE" != true ]; then
    echo "  Kickstart file is at: ${KICKSTART_PATH} (mode 0600; contains temporary credentials)"
else
    echo "  This CI output is qualification-only and must not be distributed."
fi
