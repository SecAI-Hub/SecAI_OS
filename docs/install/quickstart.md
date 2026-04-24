# Quickstart

Get SecAI OS running in the fewest steps possible. Choose the path that fits your situation.

## Choose Your Install Path

| Method | Time | Difficulty | Best For |
|--------|------|-----------|----------|
| **Bootstrap** (Recommended) | ~30 min | Easy | Real PC or VM, full security |
| **Portable USB** | ~10 min | Easy | Run directly from removable media without installing first |
| **VM Build** | ~45 min | Moderate | Local evaluation in VirtualBox/VMware/KVM |
| **Sandbox Stack** | ~10 min | Easy | Evaluate the control plane on an existing workstation |
| **Development** | ~10 min | Easy | Service development only (no OS features) |

> **Note on release media:** The release pipeline builds both an installer ISO and a portable USB image (`*-usb.raw.xz`). Pre-built VM images (OVA/QCOW2) still require build infrastructure not yet provisioned. The bootstrap path remains the recommended production install, but the portable USB artifact is the right choice when you want to boot and evaluate directly from removable media. See [Artifact Availability](#artifact-availability) for details.

---

## Path A: Bootstrap Install (Real PC or VM)

This is the recommended path. It installs Fedora Silverblue, then rebases to SecAI OS with full signature verification. You get the complete security stack: Secure Boot, TPM2, encrypted vault, and all 25+ defense layers.

**1. Install Fedora Silverblue**

Download [Fedora Silverblue 42](https://fedoraproject.org/silverblue/) and install it on your hardware or in a VM. A minimal install is fine — SecAI OS replaces the desktop.

**2. Run the bootstrap script**

The bootstrap script configures cosign signature verification **before** the first image pull — no unverified data is ever fetched.

```bash
# Download and review the script (always review before running as root)
curl -sSfL https://raw.githubusercontent.com/SecAI-Hub/SecAI_OS/main/files/scripts/secai-bootstrap.sh \
  -o /tmp/secai-bootstrap.sh
less /tmp/secai-bootstrap.sh

# Run the bootstrap
sudo bash /tmp/secai-bootstrap.sh
```

For production, pin to an exact image digest from the [latest release](https://github.com/SecAI-Hub/SecAI_OS/releases/latest):

```bash
sudo bash /tmp/secai-bootstrap.sh --digest sha256:RELEASE_DIGEST
```

**3. Reboot**

```bash
sudo systemctl reboot
```

**4. Open the UI**

After reboot, open a browser to:
```
http://127.0.0.1:8480
```

**What you should see:** The SecAI OS setup wizard. It asks you to choose a privacy profile, verifies system health, and walks you through importing your first AI model.

---

## Path B: Run From a Portable USB

This path is for evaluation directly from removable media without first installing to the internal disk.

**1. Download the portable USB image**

Get the latest `secai-os-*-usb.raw.xz` workflow artifact from the
[Release workflow](https://github.com/SecAI-Hub/SecAI_OS/actions/workflows/release.yml).

**2. Verify the checksum**

Download `SHA256SUMS` from the matching release bundle or workflow output and
confirm that the hash for `secai-os-*-usb.raw.xz` matches your download.

**3. Write it to the USB drive**

**Windows (recommended):**

- Prefer **USBImager**. It can write `*.raw.xz` images directly.
- Select the downloaded `secai-os-*-usb.raw.xz` file.
- Select the USB drive.
- Click `Write`.

**Windows (Rufus fallback):**

- Set **Boot selection** to `Disk or ISO image`.
- Click `SELECT` and choose the portable USB image.
- If Rufus does not accept `*.raw.xz`, extract it to `*.raw` first with 7-Zip and select the extracted file.
- Do **not** choose `MS-DOS`, `FreeDOS`, or `Non bootable`.
- If Rufus offers `DD` vs `ISO` write modes, choose `DD`.

**Linux / macOS:**

```bash
# Linux
xz -dk secai-os-<version>-x86_64-usb.raw.xz
sudo dd if=secai-os-<version>-x86_64-usb.raw of=/dev/sdX bs=16M status=progress oflag=sync

# macOS
xz -dk secai-os-<version>-x86_64-usb.raw.xz
sudo dd if=secai-os-<version>-x86_64-usb.raw of=/dev/rdiskN bs=16m
sync
```

Replace `/dev/sdX` or `/dev/rdiskN` with the actual removable device.

**4. Boot from the USB**

- Use the firmware's explicit **UEFI USB** boot entry.
- Disable **Legacy/CSM** mode.
- If the USB still does not appear bootable, try one test with **Secure Boot temporarily disabled** to distinguish firmware policy issues from a bad write.

**What you should see:** The system should boot directly from the USB image rather than showing the installer-only ISO menu.

---

## Path C: Build a VM Image Locally

If you want a self-contained VM image without installing Fedora first, you can build one from the OCI image using the included scripts. This requires a Linux host with KVM/QEMU.

**1. Clone the repo and build**

```bash
git clone https://github.com/SecAI-Hub/SecAI_OS.git
cd SecAI_OS

# Build QCOW2 (requires: virt-install, qemu-img, libvirt)
bash scripts/vm/build-qcow2.sh

# Optionally convert to OVA for VirtualBox/VMware
bash scripts/vm/build-ova.sh
```

The build scripts pull the signed OCI image and create a bootable disk with root + encrypted vault partitions. Credentials are randomly generated and printed at build time.

**2. Start the VM**

```bash
# KVM/QEMU
virt-install \
  --name secai-os \
  --memory 16384 \
  --vcpus 4 \
  --disk path=output/secai-os.qcow2,format=qcow2 \
  --import \
  --os-variant fedora42 \
  --network default \
  --noautoconsole

# Or import the OVA into VirtualBox/VMware
```

**3. Access the UI**

```bash
virsh domifaddr secai-os
# Open http://<vm-ip>:8480 in your browser
```

> **Security note:** VM installs cannot use TPM2 vault key sealing and the host hypervisor has visibility into guest memory. VMs are suitable for evaluation, not sensitive workloads. See [support-lifecycle.md](../support-lifecycle.md) for the full support matrix.

---

## Path D: Sandbox Stack

Run the compose-based sandbox bundle when you want the SecAI UI, registry, quarantine pipeline, tool firewall, airlock, policy engine, and agent on an existing workstation without rebasing the host OS.

See [sandbox.md](sandbox.md) for the full instructions.

Common flags:

- `--with-search` / `-WithSearch` enables the Tor + SearXNG search sidecars and turns on `search.enabled` in the sandbox runtime policy.
- `--with-airlock` / `-WithAirlock` turns on airlock-mediated outbound downloads in the sandbox runtime policy.
- `--with-inference` / `-WithInference` and `--with-diffusion` / `-WithDiffusion` enable the heavier model-serving profiles.

> **Security note:** This is a lower-assurance path than the full OS or VM image. The host kernel and container runtime can inspect container memory, mounted files, and network activity. Use it for evaluation and workflow testing, not sensitive workloads.

---

## Path E: Development Mode

Run individual services locally for development without rebasing your OS. No security features (sandboxing, firewall, vault) are active.

See [dev.md](dev.md) for setup instructions.

---

## After Boot: First-Time Setup

Regardless of install path, the setup wizard guides you through:

1. **Choose your privacy level** — Maximum Privacy (default), Web-Assisted Research, or Full Lab
2. **System check** — verifies core services are running
3. **Import a model** — upload a `.gguf` model file (it passes through the 7-stage quarantine pipeline automatically)
4. **Start chatting** — once the model is promoted, you're ready

---

## Verify Your Install (Optional)

After running the bootstrap, you can verify the image signature:

```bash
cosign verify --key cosign.pub ghcr.io/secai-hub/secai_os:latest
```

To verify release artifacts (Go binaries, SBOMs, checksums):

**Linux / macOS:**
```bash
curl -sSfL https://github.com/SecAI-Hub/SecAI_OS/releases/latest/download/SHA256SUMS -o SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

**Windows (PowerShell):**
```powershell
Invoke-WebRequest -Uri "https://github.com/SecAI-Hub/SecAI_OS/releases/latest/download/SHA256SUMS" -OutFile SHA256SUMS
Get-Content SHA256SUMS
```

For advanced verification (cosign detached signatures, SLSA3 provenance attestation), see [sample-release-bundle.md](../sample-release-bundle.md) or run:
```bash
make verify-release
```

---

## Artifact Availability

| Artifact | Where | Status |
|----------|-------|--------|
| **OCI image** | `ghcr.io/secai-hub/secai_os:latest` | Always available, cosign-signed |
| **Go binaries + SBOMs** | [GitHub Releases](https://github.com/SecAI-Hub/SecAI_OS/releases/latest) | Always available |
| **Installer ISO** | Release workflow artifact (90-day retention) | Built in CI; intended for install-to-disk |
| **ISO signature** | [GitHub Releases](https://github.com/SecAI-Hub/SecAI_OS/releases/latest) | `.iso.sig` file for verification |
| **Portable USB image** | Release workflow artifact (90-day retention) | Built in CI as `secai-os-*-usb.raw.xz`; flash directly to removable media |
| **Portable USB signature** | [GitHub Releases](https://github.com/SecAI-Hub/SecAI_OS/releases/latest) | `.raw.xz.sig` file for verification |
| **QCOW2 / OVA** | `scripts/vm/build-qcow2.sh` / `build-ova.sh` | Build locally; CI build requires self-hosted KVM runner |

The installer ISO and portable USB image are produced by every tagged release and are available as [workflow artifacts](https://github.com/SecAI-Hub/SecAI_OS/actions/workflows/release.yml) with 90-day retention. Their cosign signatures are published to GitHub Releases for verification. For permanent hosting, an external storage solution is still needed.

---

## Next Steps

- [Import a GGUF Model](../examples/import-gguf-model.md)
- [Enable Web Search](../examples/enable-web-search.md)
- [Vault Management](../examples/lock-unlock-vault.md)
- [Security Dashboard](http://127.0.0.1:8480/security) — verify your appliance health
- [Why is this safe?](../why-is-this-safe.md) — plain-language security explanation
