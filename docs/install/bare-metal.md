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

After booting into the fresh Fedora Silverblue installation, open a terminal and rebase to the SecAI OS image:

```bash
rpm-ostree rebase ostree-unverified-registry:ghcr.io/sec_ai/secai_os:latest
```

Wait for the rebase to complete, then reboot:

```bash
systemctl reboot
```

After reboot, the system will be running SecAI OS.

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

After firstboot completes, verify the installation:

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
