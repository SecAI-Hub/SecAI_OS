# VM vs. Bare Metal

The Secure AI Appliance can run on bare metal or in a virtual machine.
This guide explains the security tradeoffs, GPU passthrough considerations,
and when to use which.

---

## Security Tradeoffs

### Bare Metal

| Aspect               | Status                                                   |
|----------------------|----------------------------------------------------------|
| Memory isolation     | Full hardware isolation. No hypervisor can read RAM.      |
| GPU memory           | Only accessible by the appliance. No host snooping.       |
| Disk encryption      | LUKS + TPM2 sealing is fully effective.                   |
| Boot chain           | Secure Boot + measured boot works as designed.            |
| Clipboard isolation  | No VM clipboard agents to worry about.                   |
| Side-channel attacks | No co-located VMs to observe timing patterns.            |
| Physical access      | Main risk. Mitigated by TPM2 sealing and LUKS encryption.|

Bare metal provides the strongest security guarantees. All defense-in-depth
features work as designed without caveats.

### Virtual Machine

| Aspect               | Status                                                   |
|----------------------|----------------------------------------------------------|
| Memory isolation     | The host hypervisor can read ALL VM memory.               |
| GPU memory           | With passthrough, GPU memory is visible to the host.      |
| Disk encryption      | LUKS works, but the host can read decrypted data in RAM.  |
| Boot chain           | TPM2 may be emulated (vTPM). Less trustworthy.           |
| Clipboard isolation  | VM clipboard agents may share data with the host.        |
| Side-channel attacks | Co-located VMs may observe timing from inference workloads.|
| Snapshots            | VM snapshots capture decrypted secrets if vault is open.  |

Running in a VM means you must trust the host machine, hypervisor,
and any other VMs on the same host.

---

## GPU Passthrough

### What It Is

GPU passthrough (VFIO/PCI passthrough) assigns a physical GPU directly
to the VM, bypassing the hypervisor's graphics virtualization. This gives
the VM near-native GPU performance for inference and diffusion.

### Security Implications

When GPU passthrough is enabled:

1. **GPU memory is visible to the host** -- The hypervisor can read GPU
   memory via DMA (Direct Memory Access), which may contain model weights,
   intermediate computations, and generated outputs.

2. **DMA bypass** -- GPU DMA can bypass some VM memory isolation boundaries.
   This is a hardware-level concern that no software can fully mitigate.

3. **Driver vulnerabilities** -- GPU driver bugs in the host kernel could
   be exploited through the passthrough device.

### Configuration

GPU passthrough is **disabled by default** in VMs for security. The
appliance auto-detects VM status at first boot.

Check VM status:

```bash
curl http://127.0.0.1:8480/api/vm/status
```

Example response (VM with passthrough available but disabled):

```json
{
  "is_vm": true,
  "hypervisor": "kvm",
  "gpu_passthrough": true,
  "vm_gpu_enabled": false,
  "security_notice": {
    "level": "warning",
    "title": "Running in a Virtual Machine (kvm)",
    "details": [
      "The host OS and hypervisor can read all VM memory...",
      "VM snapshots may capture decrypted secrets...",
      "Disable clipboard sharing...",
      "Co-located VMs may observe timing patterns..."
    ]
  }
}
```

To enable GPU passthrough (accepting the security tradeoff):

```bash
curl -X POST http://127.0.0.1:8480/api/vm/gpu \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -H "X-CSRF-Token: <csrf>" \
  -d '{"enabled": true}'
```

Or edit `appliance.yaml`:

```yaml
vm:
  gpu_passthrough: true
```

When disabled, inference and diffusion run on CPU only. This is slower
but safer.

---

## Resource Allocation

### CPU

- **Bare metal**: All cores available. No overhead.
- **VM**: Allocate at least 4 vCPUs. 8+ recommended for concurrent
  inference and diffusion. Avoid overcommitting CPU on the host.

### RAM

- **Bare metal**: All RAM available. GGUF models are memory-mapped.
- **VM**: Allocate at least 16 GB. For 7B models, 24 GB is comfortable.
  For 13B+ models, 32 GB or more. Remember that mlock pins sensitive
  buffers in physical RAM, so overcommitting host memory is risky.

### GPU VRAM

- **Bare metal**: Full VRAM available.
- **VM with passthrough**: Full VRAM available (same as bare metal).
- **VM without passthrough**: No GPU acceleration. CPU-only inference.

### Disk

- **Bare metal**: Use a fast NVMe SSD for the vault partition. Model
  loading speed is I/O-bound.
- **VM**: Use virtio-blk or virtio-scsi for best I/O performance.
  Avoid QCOW2 with heavy fragmentation. Raw disk images or LVM
  thin provisioning are preferred.

---

## When to Use Which

### Use Bare Metal When

- You need the strongest security guarantees.
- You are handling sensitive data (medical, legal, financial).
- You want TPM2 sealing to work with hardware-backed trust.
- You need maximum inference performance.
- The machine is physically secure.

### Use a VM When

- You are testing or evaluating the appliance.
- You want to run it alongside other workloads on the same machine.
- You trust the host OS and hypervisor operator.
- You accept that the host can read VM memory.
- Physical security of the host is already handled.
- You want snapshot/restore for testing (but never snapshot with
  the vault unlocked in production).

### Use a VM with GPU Passthrough When

- You need GPU acceleration but are running in a VM.
- You trust the host machine and its operator.
- The performance difference between CPU and GPU is significant
  for your workload (always the case for diffusion, often the case
  for large LLMs).
- You accept that GPU memory is visible to the host.

---

## VM-Specific Hardening

If you must run in a VM, apply these additional precautions:

1. **Disable clipboard sharing** -- The appliance does this automatically
   by detecting and disabling VM clipboard agents (spice-vdagent,
   vmware-user, VBoxClient). Verify with:

```bash
systemctl status spice-vdagentd.service
# Should be "inactive" or "not found"
```

2. **Disable VM snapshots** -- Or ensure you never snapshot while the
   vault is unlocked. Snapshots capture the full memory state, including
   decrypted vault contents.

3. **Isolate the VM** -- Run the appliance VM on a dedicated host if
   possible. Co-located VMs can observe timing patterns from inference
   workloads.

4. **Use virtio** -- Use virtio drivers for disk and network. They are
   well-audited and performant.

5. **Disable shared folders** -- Do not mount host directories into the VM.

6. **Use UEFI boot with vTPM** -- If your hypervisor supports it (QEMU 6.0+,
   VMware Workstation 16+), enable UEFI boot and vTPM for measured boot.
   Note that vTPM is backed by the host, so the trust model is weaker
   than hardware TPM2.
