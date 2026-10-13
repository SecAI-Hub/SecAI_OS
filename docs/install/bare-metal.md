# Bare Metal Installation

This guide covers installing SecAI OS on physical hardware.

---

## Prerequisites

- **CPU:** x86_64 processor with virtualization extensions (VT-x/AMD-V)
- **RAM:** 16 GB minimum, 32 GB recommended
- **Storage:** 100 GB SSD minimum (NVMe recommended), with either a second
  dedicated data device or space reserved for an unused vault partition
- **GPU:** NVIDIA RTX 5080 is the first qualification target; other GPUs require release-specific qualification
- **Network:** Ethernet or WiFi (only needed for initial setup if downloading models)
- **USB drive:** 8 GB or larger for installation media
- **UEFI firmware:** Secure Boot enabled, with shim signature validation active
- **TPM:** Physical TPM2 available for enrollment and fresh boot attestation

The first production target is a bare-metal GPU appliance. Its required GPU
policy must contain reviewed profile and baseline approvals for the release's
qualified hardware. The source defaults contain empty approval pins and cannot
pass appliance readiness until that enrollment is supplied. Hardware detection
alone does not approve a GPU.

---

## Step 1: Download the ISO

Download the latest Fedora Silverblue 44 ISO from the official Fedora website:

```
https://fedoraproject.org/silverblue/download
```

SecAI OS rebases on top of Fedora Silverblue, so the base installation uses the standard Silverblue installer.

---

## Step 2: Write to USB

Write the ISO to a USB drive using one of these tools:

**Linux:**
```bash
sudo dd if=Fedora-Silverblue-44-x86_64.iso of=/dev/sdX bs=4M status=progress
sync
```

**macOS:**
```bash
sudo dd if=Fedora-Silverblue-44-x86_64.iso of=/dev/rdiskN bs=4m
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
   - Select the installation destination. Use custom partitioning unless a
     second dedicated data device is available.
   - Enable disk encryption (LUKS) when prompted. This is mandatory: service
     credentials and UI authentication state must remain encrypted even while
     the independently lockable model/data vault is closed.
   - Leave a dedicated partition or logical volume unmounted for the SecAI
     data vault. Record its exact `/dev/...` path; the setup ceremony will
     erase and reformat it only after exact confirmation.
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

# 3. Run the bootstrap with the release channel and its exact signed digest
sudo bash /tmp/secai-bootstrap.sh \
  --tag release-vMAJOR.MINOR.PATCH \
  --digest sha256:RELEASE_DIGEST
```

> **Where do I find the digest?** Check the
> [latest release](https://github.com/SecAI-Hub/SecAI_OS/releases/latest)
> for the signed `IMAGE_DIGEST` asset. A digest is mandatory; mutable
> tag-only installation is intentionally unsupported.

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

If you are upgrading an existing SecAI OS installation, use the appliance
update gate. It verifies the candidate signature, binds the staged deployment
to an exact digest, and enforces anti-rollback state:

```bash
sudo /usr/libexec/secure-ai/update-verify.sh check
sudo /usr/libexec/secure-ai/update-verify.sh stage
sudo /usr/libexec/secure-ai/update-verify.sh apply
```

Do not bypass this gate with `rpm-ostree upgrade`.

### Recovery Install

The recovery path remains digest-pinned and signature-verified even when the
local policy needs repair. See [Recovery Bootstrap](recovery-bootstrap.md).

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
4. **Vault setup** — Creates the independently lockable LUKS volume for models, user documents, and outputs
5. **Vault TPM2 enrollment** (optional) — Checks the current LUKS2 token and configured PCR policy; offers enrollment for TPM unlock
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

Vault TPM unlock is separate from required appliance TPM attestation. An
enrollment status check verifies metadata and current boot prerequisites; it
does not prove automatic unlock or recovery. Verify both through a cold boot
and recovery passphrase test before depending on automatic unlock.

---

## Secure Boot and TPM Qualification

Secure Boot and physical TPM evidence are required for the production hardware
profile. Enable firmware Secure Boot and retain shim signature validation.
Use signed kernel and GPU driver components appropriate to the qualified
release. The repository does not ship a private MOK signing key, and a
signature table alone does not prove that a component is trusted.

Inspect enrollment from a local console:

```bash
sudo /usr/libexec/secure-ai/enroll-secureboot.sh --check-only
sudo /usr/libexec/secure-ai/tpm2-seal-vault.sh status
sudo /usr/libexec/secure-ai/first-boot-check.sh
```

If the release supplies a MOK certificate that needs enrollment, use the
actual module-signing certificate and its independently reviewed release SHA256:

```bash
sudo /usr/libexec/secure-ai/enroll-secureboot.sh --enroll \
  --certificate /path/to/REVIEWED_MODULE_SIGNER.der \
  --sha256 RELEASE_CERTIFICATE_SHA256
```

The certificate must be a protected root-owned DER file. The utility verifies
its exact bytes and stages a private copy before importing it. Rerun with
`--check-only` and the same certificate/SHA256 options after firmware
confirmation. Generating a new key does not sign the prebuilt NVIDIA modules.
If a reviewed certificate is provisioned at the utility's default path, the
certificate options may be omitted.

Complete firmware
confirmation after reboot. A pending request is not completed enrollment,
and MOK enrollment does not turn on Secure Boot. Fresh TPM quote verification
and approved GPU bootstrap/runtime evidence must also pass; do not waive these
gates to complete setup.

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
