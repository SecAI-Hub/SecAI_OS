#!/bin/bash
#
# Build a SecAI OS OVA virtual appliance for VirtualBox / VMware.
#
# Prerequisites:
#   - A completed QCOW2 image (run build-qcow2.sh first)
#   - qemu-img (for format conversion)
#   - python3 (for strict qemu-img metadata parsing)
#   - tar (for OVA packaging)
#
# Usage:
#   ./build-ova.sh [qcow2-path] [output-dir]
#
# Output:
#   secai-os.ova — importable in VirtualBox, VMware Workstation/Fusion, Proxmox
#
set -euo pipefail
export LC_ALL=C
umask 077

QCOW2_PATH="${1:-./output/secai-os.qcow2}"
OUTPUT_DIR="${2:-./output}"
OVA_NAME="secai-os"
VM_NAME="SecAI-OS"

for tool in cut du mktemp python3 qemu-img stat tar; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "ERROR: required tool not found: $tool" >&2
        exit 2
    }
done

echo "=========================================="
echo " SecAI OS — OVA Appliance Builder"
echo "=========================================="
echo ""
echo "  WARNING: This appliance is for VIRTUAL MACHINES."
echo "  See README for security implications."
echo ""
echo "=========================================="

if [ -L "$QCOW2_PATH" ] || [ ! -f "$QCOW2_PATH" ]; then
    echo "ERROR: QCOW2 image not found at: ${QCOW2_PATH}"
    echo "Run build-qcow2.sh first."
    exit 1
fi
if [ "$(qemu-img info --output=json "$QCOW2_PATH" | python3 -c \
    'import json,sys; print(json.load(sys.stdin).get("format", ""))')" != "qcow2" ]; then
    echo "ERROR: input is not a QCOW2 image: ${QCOW2_PATH}" >&2
    exit 1
fi

if [ -L "$OUTPUT_DIR" ]; then
    echo "ERROR: output directory must not be a symlink: ${OUTPUT_DIR}" >&2
    exit 1
fi
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR=$(CDPATH='' cd -- "$OUTPUT_DIR" && pwd -P)
OVA_PATH="${OUTPUT_DIR}/${OVA_NAME}.ova"
if [ -e "$OVA_PATH" ] || [ -L "$OVA_PATH" ]; then
    echo "ERROR: refusing to overwrite existing OVA: ${OVA_PATH}" >&2
    exit 1
fi
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

# Step 1: Convert QCOW2 to VMDK (compatible with VirtualBox + VMware)
echo "[1/3] Converting QCOW2 to VMDK..."
qemu-img convert -f qcow2 -O vmdk -o subformat=streamOptimized \
    "$QCOW2_PATH" "${WORK_DIR}/${OVA_NAME}-disk1.vmdk"

VMDK_SIZE=$(stat -f%z "${WORK_DIR}/${OVA_NAME}-disk1.vmdk" 2>/dev/null || stat -c%s "${WORK_DIR}/${OVA_NAME}-disk1.vmdk")

# Step 2: Generate OVF descriptor
echo "[2/3] Generating OVF descriptor..."
cat > "${WORK_DIR}/${OVA_NAME}.ovf" <<OVFEOF
<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1"
          xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
          xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
          xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xmlns:vbox="http://www.virtualbox.org/ovf/machine">

  <References>
    <File ovf:href="${OVA_NAME}-disk1.vmdk" ovf:id="file1" ovf:size="${VMDK_SIZE}"/>
  </References>

  <DiskSection>
    <Info>Virtual disk information</Info>
    <Disk ovf:capacity="68719476736" ovf:diskId="vmdisk1" ovf:fileRef="file1"
          ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>

  <NetworkSection>
    <Info>Network configuration</Info>
    <Network ovf:name="NAT">
      <Description>NAT network for controlled internet access</Description>
    </Network>
  </NetworkSection>

  <VirtualSystem ovf:id="${VM_NAME}">
    <Info>SecAI OS - Secure AI Appliance (VM Edition)</Info>
    <Name>${VM_NAME}</Name>

    <AnnotationSection>
      <Info>Description</Info>
      <Annotation>SecAI OS: Local-first AI appliance with defense-in-depth security.

SECURITY WARNING: Running in a VM means the host OS can inspect VM memory,
including decrypted vault contents and inference data. For maximum security,
use the bare-metal installation method instead.

GPU passthrough is disabled by default. Enable it in the UI under
Settings if you have a dedicated GPU passed through to the VM.

Default user: secai (temporary credential is set during local QCOW2 generation)
Encrypted host state: temporary credential is set during local generation
Separate data vault: initialize /dev/sda5 from the trusted local console
Rotate both temporary credentials before handling sensitive data.

Web UI: http://127.0.0.1:8480 (port-forward or access from within VM)</Annotation>
    </AnnotationSection>

    <OperatingSystemSection ovf:id="96">
      <Info>Fedora 64-bit</Info>
    </OperatingSystemSection>

    <VirtualHardwareSection>
      <Info>Virtual hardware requirements</Info>

      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemIdentifier>${VM_NAME}</vssd:VirtualSystemIdentifier>
        <vssd:VirtualSystemType>vmx-14 virtualbox-2.2</vssd:VirtualSystemType>
      </System>

      <!-- 4 CPUs -->
      <Item>
        <rasd:Caption>4 virtual CPUs</rasd:Caption>
        <rasd:Description>Number of virtual CPUs</rasd:Description>
        <rasd:ElementName>4 virtual CPUs</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>4</rasd:VirtualQuantity>
      </Item>

      <!-- 16 GB RAM -->
      <Item>
        <rasd:Caption>16384 MB of memory</rasd:Caption>
        <rasd:Description>Memory Size</rasd:Description>
        <rasd:ElementName>16384 MB of memory</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>16384</rasd:VirtualQuantity>
      </Item>

      <!-- IDE Controller -->
      <Item>
        <rasd:Caption>ideController0</rasd:Caption>
        <rasd:ElementName>ideController0</rasd:ElementName>
        <rasd:InstanceID>3</rasd:InstanceID>
        <rasd:ResourceSubType>PIIX4</rasd:ResourceSubType>
        <rasd:ResourceType>5</rasd:ResourceType>
      </Item>

      <!-- SATA Controller -->
      <Item>
        <rasd:Caption>sataController0</rasd:Caption>
        <rasd:ElementName>sataController0</rasd:ElementName>
        <rasd:InstanceID>4</rasd:InstanceID>
        <rasd:ResourceSubType>AHCI</rasd:ResourceSubType>
        <rasd:ResourceType>20</rasd:ResourceType>
      </Item>

      <!-- Disk -->
      <Item>
        <rasd:Caption>disk1</rasd:Caption>
        <rasd:ElementName>disk1</rasd:ElementName>
        <rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource>
        <rasd:InstanceID>5</rasd:InstanceID>
        <rasd:Parent>4</rasd:Parent>
        <rasd:ResourceType>17</rasd:ResourceType>
      </Item>

      <!-- NAT Network -->
      <Item>
        <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
        <rasd:Caption>NAT</rasd:Caption>
        <rasd:Connection>NAT</rasd:Connection>
        <rasd:ElementName>NAT</rasd:ElementName>
        <rasd:InstanceID>6</rasd:InstanceID>
        <rasd:ResourceSubType>E1000</rasd:ResourceSubType>
        <rasd:ResourceType>10</rasd:ResourceType>
      </Item>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
OVFEOF

# Step 3: Package as OVA (tar with OVF first, then VMDK)
echo "[3/3] Packaging OVA..."
cd "$WORK_DIR"
# OVA is just a tar with OVF descriptor first
OVA_TMP=$(mktemp "${OUTPUT_DIR}/.secai-os.ova.XXXXXX")
tar -cf "$OVA_TMP" "${OVA_NAME}.ovf" "${OVA_NAME}-disk1.vmdk"
chmod 0600 "$OVA_TMP"
if ! ln "$OVA_TMP" "$OVA_PATH"; then
    rm -f -- "$OVA_TMP"
    echo "ERROR: could not atomically publish ${OVA_PATH}" >&2
    exit 1
fi
rm -f -- "$OVA_TMP"
cd - >/dev/null

OVA_SIZE=$(du -h "$OVA_PATH" | cut -f1)
echo ""
echo "=========================================="
echo " OVA built successfully!"
echo "  File: ${OVA_PATH}"
echo "  Size: ${OVA_SIZE}"
echo ""
echo " Import in VirtualBox:"
echo "   File -> Import Appliance -> ${OVA_NAME}.ova"
echo ""
echo " Import in VMware:"
echo "   File -> Open -> ${OVA_NAME}.ova"
echo ""
echo " IMPORTANT: Change temporary passwords after first boot!"
echo "   sudo passwd secai"
echo "   sudo cryptsetup luksChangeKey /dev/sda4"
echo "   sudo /usr/libexec/secure-ai/secai-setup-wizard.sh --vault-device /dev/sda5"
echo " This is a user-specific local image; do not publish it as a generic appliance."
echo "=========================================="
