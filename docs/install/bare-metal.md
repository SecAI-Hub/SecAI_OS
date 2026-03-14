# Bare Metal Installation

This guide covers installing SecAI OS on physical hardware.

---

## Prerequisites

- **CPU:** x86_64 processor with virtualization extensions (VT-x/AMD-V)
- **RAM:** 16 GB minimum, 32 GB recommended
- **Storage:** 100 GB SSD minimum (NVMe recommended)
- **GPU:** NVIDIA GPU with CUDA support (RTX 3000 series or newer recommended) or Apple Silicon (M1 or newer, for Metal via llama.cpp)
- **Network:** Ethernet or WiFi (only needed for initial setup if downloading models)
- **USB drive:** 8 GB or larger for installation media
- **UEFI firmware:** Secure Boot supported (optional but recommended)

---

## Step 1: Download the ISO

Download the latest Fedora Silverblue 42 ISO from the official Fedora website:

```
https://fedoraproject.org/silverblue/download
```

SecAI OS rebases on top of Fedora Silverblue, so the base installation uses the standard Silverblue installer.

---

## Step 2: Write to USB

Write the ISO to a USB drive using one of these tools:

**Linux:**
```bash
sudo dd if=Fedora-Silverblue-42-x86_64.iso of=/dev/sdX bs=4M status=progress
sync
```

**macOS:**
```bash
sudo dd if=Fedora-Silverblue-42-x86_64.iso of=/dev/rdiskN bs=4m
sync
```

**Windows:** Use Rufus or Fedora Media Writer.

Replace `/dev/sdX` or `/dev/rdiskN` with your actual USB device. Double-check the device name to avoid overwriting the wrong disk.

---

## Step 3: Install Fedora Silverblue

1. Boot from the USB drive (enter BIOS/UEFI and select USB as the boot device).
2. Select "Install Fedora" from the boot menu.
3. Follow the Anaconda installer:
   - Set language and keyboard layout.
   - Select the installation destination (use the full disk; automatic partitioning is fine).
   - Enable disk encryption (LUKS) when prompted. Choose a strong passphrase.
   - Create a user account.
4. Complete the installation and reboot. Remove the USB drive when prompted.

---

## Step 4: Rebase to SecAI OS

After booting into the fresh Fedora Silverblue installation, open a terminal.

### 4a. Verify image signature (before rebasing)

Before installing the image, verify its authenticity using cosign:

```bash
# Install cosign (if not already present)
sudo dnf install -y cosign

# Fetch the project's public key
curl -sSfL https://raw.githubusercontent.com/SecAI-Hub/SecAI_OS/main/cosign.pub -o /tmp/cosign.pub

# Verify the image signature
cosign verify --key /tmp/cosign.pub ghcr.io/sec_ai/secai_os:latest
```

You should see `The following checks were performed on each of these signatures: ...`
with a successful verification result. **Do not proceed if verification fails.**

### 4b. Bootstrap rebase

> **Note on the bootstrap trust gap:** The first rebase must use
> `ostree-unverified-registry:` because the local ostree store does not yet
> have the SecAI signing policy configured. This is a one-time bootstrapping
> step — the cosign verification above provides out-of-band attestation
> before the unverified pull. After the first boot, all subsequent updates
> use `ostree-image-signed:` and are verified automatically.

```bash
# Initial rebase (signature verified out-of-band above)
sudo rpm-ostree rebase ostree-unverified-registry:ghcr.io/sec_ai/secai_os:latest
sudo systemctl reboot
```

### 4c. Switch to signed updates

After the first reboot, switch to the signed image transport so that all
future updates are cryptographically verified by rpm-ostree:

```bash
# Switch to the signed transport (all future updates verified automatically)
sudo rpm-ostree rebase ostree-image-signed:docker://ghcr.io/sec_ai/secai_os:latest
sudo systemctl reboot
```

After this reboot, the system is running SecAI OS with full signature verification enabled.

---

## Step 5: Set Up the Encrypted Vault

On first boot after rebasing, the firstboot script runs automatically. It will:

1. Create the encrypted vault partition at `/var/lib/secure-ai/vault` (if not already present).
2. Initialize the registry manifest.
3. Set up systemd service dependencies.
4. Configure nftables firewall rules.
5. Run Greenboot health checks.

You will be prompted to set a vault passphrase. This passphrase encrypts the LUKS volume that stores your models and configuration. Store it securely -- there is no recovery mechanism.

---

## Step 6: First Boot Verification

After firstboot completes, run the automated health check:

```bash
# Comprehensive health check (validates all services, endpoints, security posture)
sudo /usr/libexec/secure-ai/first-boot-check.sh
```

This validates all core services are running, health endpoints respond, attestation
state is verified, no open incidents exist, and no services are exposed on public
interfaces. See [docs/production-operations.md](../production-operations.md) for details.

You can also verify manually:

```bash
# Check that all services are running
systemctl status secure-ai-registry
systemctl status secure-ai-tool-firewall
systemctl status secure-ai-ui

# Check firewall rules
sudo nft list ruleset

# Check vault status
curl http://localhost:8480/api/vault/status

# Open the UI
xdg-open http://localhost:8480
```

---

## Post-Installation

- The UI is accessible at `http://localhost:8480`.
- No models are installed by default. Import a model through the UI or CLI.
- The Airlock and Search Mediator are disabled by default.
- Review `/etc/secure-ai/policy/policy.yaml` to customize security policy.
- If you have a TPM2 module, the vault passphrase can be sealed to the TPM for automatic unlock on trusted boots.

---

## Secure Boot (Optional)

If your hardware supports Secure Boot:

1. The SecAI OS image includes a MOK (Machine Owner Key) for signing.
2. On first boot with Secure Boot enabled, you will be prompted to enroll the MOK.
3. After enrollment, the full Secure Boot chain is verified: UEFI firmware, bootloader, kernel, and initramfs.
4. TPM2 measured boot records extend PCR values at each stage for tamper detection.

---

## Troubleshooting

**Boot fails after rebase:** Roll back to the previous deployment:
```bash
rpm-ostree rollback
systemctl reboot
```

**GPU not detected:** Ensure NVIDIA drivers are loaded:
```bash
nvidia-smi
```

**Vault fails to mount:** Check LUKS status:
```bash
sudo cryptsetup status secure-ai-vault
```
