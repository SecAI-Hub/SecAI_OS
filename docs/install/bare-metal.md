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

### Production Install (Recommended)

The bootstrap script configures the container signing policy **before** pulling the image, so the very first rebase uses the signed transport. No unverified pull is ever performed.

```bash
# 1. Download the bootstrap script
curl -sSfL https://raw.githubusercontent.com/SecAI-Hub/SecAI_OS/main/files/scripts/secai-bootstrap.sh \
  -o /tmp/secai-bootstrap.sh

# 2. Review the script before running (ALWAYS review downloaded scripts)
less /tmp/secai-bootstrap.sh

# 3. Run the bootstrap (use the digest from the latest release for production)
sudo bash /tmp/secai-bootstrap.sh --digest sha256:RELEASE_DIGEST
```

> **Where do I find the digest?** Check the
> [latest release](https://github.com/SecAI-Hub/SecAI_OS/releases/latest)
> for the `IMAGE_DIGEST` asset, or the build workflow summary.
> For evaluation, you can omit `--digest` to use `:latest`.

The script will:

1. Install cosign (if needed) and fetch the SecAI public signing key
2. Verify the key's SHA256 fingerprint against a hardcoded value
3. Configure the signing policy on your system (`policy.json` + `registries.d`)
4. Verify the image signature using cosign
5. Rebase using the **signed** transport (`ostree-image-signed:docker://`)
6. Prompt you to reboot

After the script completes:

```bash
sudo systemctl reboot
```

### Returning Users / Existing SecAI OS Installs

If you are upgrading an existing SecAI OS installation (already on the
signed transport), simply run:

```bash
sudo rpm-ostree upgrade
sudo systemctl reboot
```

All upgrades are automatically verified against the cosign signing key
baked into the image.

### Recovery / Development Install

> **WARNING**: The recovery path uses an unverified container transport.
> Use it **only** when the signing policy is broken or for development/CI.
> See [Recovery Bootstrap](recovery-bootstrap.md) for instructions.

---

## Step 5: First-Boot Setup Wizard

After rebooting into SecAI OS, run the interactive setup wizard:

```bash
sudo /usr/libexec/secure-ai/secai-setup-wizard.sh
```

The wizard walks you through:

1. **System identity** — OS version, deployment origin, Secure Boot + TPM2 status
2. **Image integrity** — Cosign signature verification of the running image
3. **Transport check** — Confirms you are on signed transport (offers to switch if not)
4. **Vault setup** — Creates the encrypted LUKS volume for models and secrets
5. **TPM2 sealing** (optional) — Seals the vault key to TPM2 PCRs for auto-unlock on trusted boots
6. **Health check** — Validates all services are running and endpoints are reachable
7. **Summary** — Security posture card and next steps

You can also run the health check independently at any time:

```bash
sudo /usr/libexec/secure-ai/first-boot-check.sh
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

**Bootstrap script fails:** See [Recovery Bootstrap](recovery-bootstrap.md) for the manual fallback procedure.
