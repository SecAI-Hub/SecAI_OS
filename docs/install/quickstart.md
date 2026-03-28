# Quickstart

Get SecAI OS running in the fewest steps possible. Choose the path that fits your hardware.

## Choose Your Install Path

| Method | Time | Difficulty | Best For |
|--------|------|-----------|----------|
| **ISO** (Recommended) | ~30 min | Easy | Real PC, full security |
| **VM Import (OVA)** | ~15 min | Easy | Try it first (VirtualBox/VMware) |
| **VM Import (QCOW2)** | ~15 min | Easy | KVM / Proxmox / QEMU |
| **Rebase** (Advanced) | ~45 min | Moderate | Existing Fedora Silverblue |

---

## Path A: Install from ISO (Real PC)

This gives you the full security stack including Secure Boot, TPM2, and hardware isolation.

**1. Download the ISO**

Go to the [latest release](https://github.com/SecAI-Hub/SecAI_OS/releases/latest) and download `secai-os-<version>-x86_64.iso`.

**2. Write to USB**

Linux/macOS:
```bash
sudo dd if=secai-os-*.iso of=/dev/sdX bs=4M status=progress
sync
```

Windows: Use [Rufus](https://rufus.ie) — select the ISO, choose your USB drive, and click Start.

**3. Boot from USB**

Restart your computer. Enter the boot menu (usually F12, F2, or Esc) and select the USB drive. Follow the installer prompts.

**4. First boot**

After installation completes and the system reboots, open a browser to:
```
http://127.0.0.1:8480
```

**What you should see:** The SecAI OS setup wizard. It will ask you to choose a privacy profile, verify system health, and import your first AI model.

---

## Path B: Import VM — VirtualBox / VMware (OVA)

For evaluation. Note: VM installs cannot use TPM2 sealing or Secure Boot chain verification.

**1. Download the OVA**

Go to the [latest release](https://github.com/SecAI-Hub/SecAI_OS/releases/latest) and download `secai-os-<version>.ova`.

> OVA may not be available in every release. If absent, use Path C (QCOW2) or Path A (ISO).

**2. Import**

- **VirtualBox:** File → Import Appliance → select the OVA → Import
- **VMware:** File → Open → select the OVA → Import

**3. Start the VM and open the UI**

Start the VM. After boot, open a browser to the VM's IP on port 8480:
```
http://<vm-ip>:8480
```

If using NAT networking, forward port 8480 from the VM to your host, then use `http://127.0.0.1:8480`.

**What you should see:** The setup wizard with profile selection, system check, and model import.

---

## Path C: Import VM — KVM / Proxmox / QEMU (QCOW2)

**1. Download the QCOW2**

Go to the [latest release](https://github.com/SecAI-Hub/SecAI_OS/releases/latest) and download `secai-os-<version>.qcow2`.

> QCOW2 may not be available in every release. If absent, use Path A (ISO).

**2. Create a VM**

```bash
# Example: create and start a KVM VM using the downloaded disk
virt-install \
  --name secai-os \
  --memory 16384 \
  --vcpus 4 \
  --disk path=secai-os-*.qcow2,format=qcow2 \
  --import \
  --os-variant fedora42 \
  --network default \
  --noautoconsole
```

**3. Access the UI**

```bash
# Find the VM's IP
virsh domifaddr secai-os
# Open in browser
xdg-open http://<vm-ip>:8480
```

**What you should see:** The setup wizard.

---

## Path D: Advanced — Rebase from Existing Fedora

If you already have Fedora Silverblue (F42+), you can rebase directly. This is the operator path.

See [bare-metal.md](bare-metal.md) for the full bootstrap flow with digest pinning and signing policy configuration.

```bash
# Quick version (evaluation only — use --digest for production)
curl -sSfL https://raw.githubusercontent.com/SecAI-Hub/SecAI_OS/main/files/scripts/secai-bootstrap.sh \
  -o /tmp/secai-bootstrap.sh
less /tmp/secai-bootstrap.sh   # Review first
sudo bash /tmp/secai-bootstrap.sh
sudo systemctl reboot
```

After reboot, open `http://127.0.0.1:8480` and run the setup wizard.

---

## After Boot: First-Time Setup

Regardless of install path, the setup wizard guides you through:

1. **Choose your privacy level** — Maximum Privacy (default), Web-Assisted Research, or Full Lab
2. **System check** — verifies core services are running
3. **Import a model** — upload a `.gguf` model file (it goes through the 7-stage quarantine pipeline automatically)
4. **Start chatting** — once the model is promoted, you're ready

---

## Verify Your Install (Optional)

After downloading any release artifact, you can verify its integrity.

**Linux / macOS:**
```bash
curl -sSfL https://github.com/SecAI-Hub/SecAI_OS/releases/latest/download/SHA256SUMS -o SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

**Windows (PowerShell):**
```powershell
Invoke-WebRequest -Uri "https://github.com/SecAI-Hub/SecAI_OS/releases/latest/download/SHA256SUMS" -OutFile SHA256SUMS
$expected = (Get-Content SHA256SUMS | Select-String "secai-os").Line.Split()[0]
$actual = (Get-FileHash "secai-os-*.iso" -Algorithm SHA256).Hash.ToLower()
if ($expected -eq $actual) { "OK: checksum matches" } else { "FAIL: checksum mismatch" }
```

For advanced verification (cosign signatures, SLSA3 provenance), see [sample-release-bundle.md](../docs/sample-release-bundle.md) or run:
```bash
make verify-release
```

---

## Next Steps

- [Import a GGUF Model](../examples/import-gguf-model.md)
- [Enable Web Search](../examples/enable-web-search.md)
- [Vault Management](../examples/lock-unlock-vault.md)
- [Security Dashboard](http://127.0.0.1:8480/security) — verify your appliance health
- [Why is this safe?](../docs/why-is-this-safe.md) — plain-language security explanation
