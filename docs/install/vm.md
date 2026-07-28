# Virtual Machine Installation

This guide covers running SecAI OS in a virtual machine. VM mode is suitable for evaluation, development, and environments where bare metal installation is not practical.

---

## Security Limitations of VM Mode

Running SecAI OS in a VM introduces limitations that do not apply to bare metal:

- **No hardware-rooted TPM assurance:** A hypervisor may expose a virtual TPM,
  but the host controls its state. SecAI OS treats vTPM attestation as
  evaluation-only. Vault sealing requires an explicit degraded-lab
  `--allow-vtpm` acknowledgement and retains a passphrase recovery keyslot.
- **No Secure Boot chain:** VM Secure Boot (when available) does not provide the same guarantees as hardware Secure Boot with MOK enrollment.
- **Host visibility:** The hypervisor host can inspect VM memory, potentially exposing decrypted model data and inference content.
- **Shared resources:** Side-channel attacks from other VMs or the host are possible.
- **Reduced GPU performance:** GPU passthrough adds latency; virtual GPUs (vGPU) may not support all CUDA features.

For production use with sensitive models, bare metal installation is recommended.

---

## VirtualBox

### Requirements

- VirtualBox 7.0 or newer
- 16 GB RAM allocated to the VM (32 GB recommended)
- 100 GB virtual disk
- EFI mode enabled

### OVA Import

After creating a user-specific OVA with the local builder:

1. Open VirtualBox and select File > Import Appliance.
2. Select the SecAI OS OVA file.
3. Review and adjust resource allocation (CPU, RAM).
4. Click Import.
5. After import, go to Settings > System and ensure EFI is enabled.
6. Start the VM.
7. Treat the image as evaluation-only until you rotate its temporary login and
   encrypted host-state credentials and create the separate data vault from
   the local console.

The UI binds only to guest loopback. Forward it over SSH rather than publishing
port 8480:

```bash
ssh -L 8480:127.0.0.1:8480 secai@<guest-ip>
# Browse to http://127.0.0.1:8480 on the host.
```

### Manual Setup

1. Create a new VM: Type "Linux", Version "Fedora (64-bit)".
2. Allocate at least 4 CPUs and 16 GB RAM.
3. Create a 100 GB dynamically allocated VDI disk.
4. In Settings > System, enable EFI.
5. In Settings > Storage, attach the Fedora Silverblue 44 ISO.
6. Start the VM and follow the standard Fedora Silverblue installation.
7. After installation, rebase to SecAI OS using the [bootstrap script](bare-metal.md#production-install-recommended).

### GPU Passthrough (VirtualBox)

VirtualBox has limited GPU passthrough support. For GPU-accelerated inference:

- Use VBoxManage to configure PCI passthrough (Linux hosts only).
- Requires IOMMU enabled in BIOS and host kernel.
- Not all GPUs are compatible.

For reliable GPU passthrough, use KVM/QEMU instead.

---

## VMware (Workstation / Fusion)

### Requirements

- VMware Workstation 17+ (Linux/Windows) or Fusion 13+ (macOS)
- 16 GB RAM allocated to the VM
- 100 GB virtual disk
- EFI firmware selected

### Setup

1. Create a new VM and select the Fedora Silverblue 44 ISO.
2. Choose "Linux" > "Fedora 64-bit" as the guest OS.
3. Allocate at least 4 CPUs and 16 GB RAM.
4. Set disk size to 100 GB.
5. In VM Settings > Options > Advanced, select "UEFI" firmware.
6. Install Fedora Silverblue, then rebase to SecAI OS using the [bootstrap script](bare-metal.md#production-install-recommended).

### GPU Passthrough (VMware)

VMware Workstation supports GPU passthrough on Linux hosts:

1. Ensure IOMMU is enabled in BIOS (Intel VT-d or AMD-Vi).
2. Add the GPU as a PCI passthrough device in VM settings.
3. The host GPU must not be in use by the host display.

VMware Fusion on macOS does not support GPU passthrough for NVIDIA GPUs.

---

## KVM/QEMU (Recommended for Linux Hosts)

KVM with QEMU and libvirt provides the best VM experience for SecAI OS, including reliable GPU passthrough.

### Requirements

- Linux host with KVM support (check with `lsmod | grep kvm`)
- IOMMU enabled for GPU passthrough
- virt-manager or virsh for VM management
- 16 GB RAM allocated to the VM
- 100 GB disk image

### Setup with virt-manager

1. Open virt-manager and create a new VM.
2. Select the Fedora Silverblue 44 ISO as installation media.
3. Allocate at least 4 CPUs and 16 GB RAM.
4. Create a 100 GB qcow2 disk.
5. Before starting, go to Overview > Firmware and select UEFI (OVMF).
6. Install Fedora Silverblue, then rebase to SecAI OS using the [bootstrap script](bare-metal.md#production-install-recommended).

### Setup with virsh/command line

```bash
# Create disk image
qemu-img create -f qcow2 /var/lib/libvirt/images/secai-os.qcow2 100G

# Start installation
virt-install \
  --name secai-os \
  --ram 16384 \
  --vcpus 4 \
  --disk path=/var/lib/libvirt/images/secai-os.qcow2,format=qcow2 \
  --cdrom /path/to/Fedora-Silverblue-44-x86_64.iso \
  --os-variant fedora44 \
  --boot uefi \
  --network bridge=virbr0
```

### Automated QCOW2/OVA Builders

The repository includes helper scripts for local KVM builders:

```bash
bash scripts/vm/build-qcow2.sh --image-ref ghcr.io/secai-hub/secai_os@sha256:<digest>
bash scripts/vm/build-ova.sh output/secai-os.qcow2 output
```

The QCOW2 builder installs the SecAI signing policy in the kickstart and
rebases with `ostree-image-signed:docker://` on the first pull. It does not
perform an unsigned bootstrap pull. It creates encrypted host state and leaves
`/dev/sda5` unused for the separate vault ceremony. Local-build temporary
credentials are written to a mode-`0600` file instead of build logs; the
kickstart is also mode `0600` and is removed after unattended CI builds.
For a local build, delete both files after rotating the VM login and encrypted
host-state credentials.

CI uses `build-qcow2.sh --ci` only for ephemeral builder and boot qualification.
That mode requires caller-provided random credentials, and the workflow destroys
the resulting images. SecAI OS does not publish a generic QCOW2 or OVA because
doing so would require either sharing an encrypted-boot secret or publishing an
image that its recipient cannot unlock.

### GPU Passthrough (KVM/QEMU)

This is the most reliable GPU passthrough option.

1. Enable IOMMU in BIOS (Intel VT-d or AMD-Vi).

2. Enable IOMMU in the host kernel. Add to `/etc/default/grub`:
   ```
   GRUB_CMDLINE_LINUX="intel_iommu=on iommu=pt"
   ```
   Or for AMD:
   ```
   GRUB_CMDLINE_LINUX="amd_iommu=on iommu=pt"
   ```

3. Regenerate GRUB and reboot:
   ```bash
   sudo grub2-mkconfig -o /boot/grub2/grub.cfg
   sudo reboot
   ```

4. Identify the GPU's IOMMU group:
   ```bash
   for d in /sys/kernel/iommu_groups/*/devices/*; do
     n=${d#*/iommu_groups/*}; n=${n%%/*}
     printf 'IOMMU Group %s: ' "$n"
     lspci -nns "${d##*/}"
   done | grep -i nvidia
   ```

5. Bind the GPU to vfio-pci (replace IDs with your GPU's values):
   ```bash
   echo "options vfio-pci ids=10de:2684,10de:22bc" | sudo tee /etc/modprobe.d/vfio.conf
   sudo dracut -f
   sudo reboot
   ```

6. Add the GPU to the VM using virt-manager (Add Hardware > PCI Host Device) or virsh XML.

---

## VM-Specific Recommendations

- **Snapshots:** Take a VM snapshot after initial setup and before importing models. This provides a clean rollback point.
- **Networking:** Use NAT networking by default. The VM's nftables rules provide defense-in-depth, but host-level isolation adds another layer.
- **Clipboard:** Disable both shared clipboard and drag-and-drop in the
  hypervisor configuration. SecAI OS records guest-side control status in
  `/var/lib/secure-ai/state/clipboard.json`, but a guest cannot attest or
  override every host policy. Treat
  `requires_hypervisor_verification` as a deployment blocker.
- **Shared folders:** Do not use shared folders between host and guest. Transfer models via the UI import feature instead.
- **Resource monitoring:** Monitor VM resource usage. LLM inference is resource-intensive; under-provisioned VMs will produce slow responses.
- **Nested virtualization:** Not recommended. SecAI OS does not use containers or VMs internally, but nested virtualization adds latency and complexity.
