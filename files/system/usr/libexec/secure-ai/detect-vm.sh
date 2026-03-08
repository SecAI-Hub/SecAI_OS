#!/bin/bash
#
# Detect if running inside a virtual machine and identify the hypervisor.
# Writes results to /var/lib/secure-ai/vm.env
# Called by secure-ai-firstboot.service.
#
set -euo pipefail

ENV_FILE="/var/lib/secure-ai/vm.env"
IS_VM="false"
HYPERVISOR="none"
GPU_PASSTHROUGH="false"
VM_WARNINGS=""

echo "=== SecAI VM Detection ==="

# --- Method 1: systemd-detect-virt ---
if command -v systemd-detect-virt &>/dev/null; then
    VIRT=$(systemd-detect-virt 2>/dev/null || echo "none")
    if [ "$VIRT" != "none" ]; then
        IS_VM="true"
        HYPERVISOR="$VIRT"
        echo "Detected virtualization: ${VIRT} (via systemd-detect-virt)"
    fi
fi

# --- Method 2: DMI/SMBIOS strings ---
if [ "$IS_VM" = "false" ]; then
    DMI_PRODUCT=$(cat /sys/class/dmi/id/product_name 2>/dev/null || echo "")
    DMI_VENDOR=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || echo "")
    DMI_BOARD=$(cat /sys/class/dmi/id/board_name 2>/dev/null || echo "")

    case "${DMI_PRODUCT}${DMI_VENDOR}${DMI_BOARD}" in
        *VirtualBox*)   IS_VM="true"; HYPERVISOR="virtualbox" ;;
        *VMware*)       IS_VM="true"; HYPERVISOR="vmware" ;;
        *QEMU*|*KVM*)   IS_VM="true"; HYPERVISOR="kvm" ;;
        *Hyper-V*)      IS_VM="true"; HYPERVISOR="hyperv" ;;
        *Parallels*)    IS_VM="true"; HYPERVISOR="parallels" ;;
        *Xen*)          IS_VM="true"; HYPERVISOR="xen" ;;
    esac

    if [ "$IS_VM" = "true" ]; then
        echo "Detected virtualization: ${HYPERVISOR} (via DMI/SMBIOS)"
    fi
fi

# --- Method 3: cpuid hypervisor bit ---
if [ "$IS_VM" = "false" ] && [ -e /proc/cpuinfo ]; then
    if grep -q "hypervisor" /proc/cpuinfo 2>/dev/null; then
        IS_VM="true"
        HYPERVISOR="unknown"
        echo "Detected virtualization: unknown (via cpuid hypervisor flag)"
    fi
fi

# --- Check for GPU passthrough ---
if [ "$IS_VM" = "true" ]; then
    # Check if a real GPU is passed through (not virtual VGA)
    if command -v lspci &>/dev/null; then
        # Look for NVIDIA, AMD, or Intel discrete GPU on PCI bus
        if lspci 2>/dev/null | grep -iE "VGA|3D|Display" | grep -ivE "virtio|vmware|virtualbox|qxl|bochs|cirrus|vga compatible" | grep -iqE "nvidia|amd|radeon|intel.*arc"; then
            GPU_PASSTHROUGH="true"
            echo "GPU passthrough detected: physical GPU visible on PCI bus"
        fi
    fi

    # Also check for NVIDIA device nodes
    if [ -e /dev/nvidia0 ] || [ -e /dev/kfd ]; then
        GPU_PASSTHROUGH="true"
        echo "GPU passthrough detected: GPU device nodes present"
    fi
fi

# --- Build warnings ---
if [ "$IS_VM" = "true" ]; then
    VM_WARNINGS="RUNNING IN VIRTUAL MACHINE (${HYPERVISOR})"
    VM_WARNINGS="${VM_WARNINGS}|HOST_CAN_INSPECT_VM_MEMORY: The host OS and hypervisor can read all VM memory including decrypted vault contents and inference data"
    VM_WARNINGS="${VM_WARNINGS}|VM_SNAPSHOTS_CAPTURE_STATE: Snapshots may preserve decrypted secrets, model weights in GPU memory, and active session data"
    VM_WARNINGS="${VM_WARNINGS}|SHARED_CLIPBOARD_RISK: If clipboard sharing is enabled, data can leak between VM and host"
    VM_WARNINGS="${VM_WARNINGS}|TIMING_SIDE_CHANNELS: Co-located VMs may observe inference timing patterns"

    if [ "$GPU_PASSTHROUGH" = "true" ]; then
        VM_WARNINGS="${VM_WARNINGS}|GPU_PASSTHROUGH_ACTIVE: GPU memory is accessible to the host via the hypervisor"
        VM_WARNINGS="${VM_WARNINGS}|GPU_DMA_RISK: GPU has DMA access that bypasses some VM memory isolation"
        VM_WARNINGS="${VM_WARNINGS}|DRIVER_ATTACK_SURFACE: GPU drivers in the VM increase the attack surface"
    fi
fi

echo "Result: is_vm=${IS_VM} hypervisor=${HYPERVISOR} gpu_passthrough=${GPU_PASSTHROUGH}"

# Write environment file
mkdir -p "$(dirname "$ENV_FILE")"
cat > "$ENV_FILE" <<EOF
# Auto-detected by detect-vm.sh — re-run to update
IS_VM=${IS_VM}
HYPERVISOR=${HYPERVISOR}
GPU_PASSTHROUGH=${GPU_PASSTHROUGH}
VM_WARNINGS=${VM_WARNINGS}
# GPU passthrough for inference: disabled by default in VMs for safety.
# Set to "true" to enable GPU acceleration in the VM (see security warnings above).
VM_GPU_ENABLED=false
EOF

echo "Written to ${ENV_FILE}"
echo "=== VM Detection Complete ==="
