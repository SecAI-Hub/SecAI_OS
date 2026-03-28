# Recovery Bootstrap (Unverified Transport)

> **WARNING**: This procedure uses an **unverified** container transport.
> It does NOT verify image signatures during the pull. Use this **only** when:
>
> - The container signing policy is broken or misconfigured
> - You are in a development or CI environment
> - The bootstrap script (`secai-bootstrap.sh`) fails and you need a manual fallback
>
> For production installs, use the [signed bootstrap script](bare-metal.md#production-install-recommended).

---

## When to Use This Path

| Scenario | Recommended Path |
|----------|-----------------|
| Fresh production install | `secai-bootstrap.sh` (signed) |
| Existing install upgrade | `rpm-ostree upgrade` (auto-verified) |
| Broken signing policy | **This page** (recovery) |
| Development / CI testing | **This page** (recovery) |
| Evaluating without digest | `secai-bootstrap.sh` without `--digest` |

---

## Procedure

### 1. Verify Image Signature Out-of-Band (Mandatory)

Before performing the unverified pull, verify the image signature using
cosign. **Do not skip this step** — it is the only integrity guarantee
when using the unverified transport.

```bash
# Install cosign (if not already present)
sudo dnf install -y cosign

# Fetch the project's public key
curl -sSfL https://raw.githubusercontent.com/SecAI-Hub/SecAI_OS/main/cosign.pub \
  -o /tmp/cosign.pub

# Verify the image signature — STOP if this fails
cosign verify --key /tmp/cosign.pub ghcr.io/secai-hub/secai_os:latest
```

You must see a successful verification result. **Do not proceed if verification fails.**

### 2. Perform the Unverified Rebase

```bash
# One-time unverified pull (safe ONLY because you verified the signature above)
sudo rpm-ostree rebase ostree-unverified-registry:ghcr.io/secai-hub/secai_os:latest
sudo systemctl reboot
```

> **Why unverified?** The system's `/etc/containers/policy.json` does not
> have a sigstore verification entry for SecAI images. Normally, the
> bootstrap script installs this policy before the rebase. If that script
> failed or is unavailable, this unverified pull bypasses the policy check.
> The out-of-band cosign verification in step 1 provides equivalent
> assurance for this single pull.

### 3. Lock to Signed Transport (Mandatory)

**Immediately after rebooting**, switch to the signed transport. This step
is not optional — it ensures all future updates are cryptographically
verified by rpm-ostree.

```bash
# Lock to signed transport — all future updates verified automatically
sudo rpm-ostree rebase ostree-image-signed:docker://ghcr.io/secai-hub/secai_os:latest
sudo systemctl reboot
```

After this reboot, the system is running SecAI OS with full signature
verification enabled. The signing policy files are baked into the OS
image, so the `ostree-image-signed:` transport works without additional
configuration.

### 4. Run the Setup Wizard

```bash
sudo /usr/libexec/secure-ai/secai-setup-wizard.sh
```

---

## Returning to Signed Transport

If your system is currently on the unverified transport (check with
`rpm-ostree status`), switch to signed transport:

```bash
sudo rpm-ostree rebase ostree-image-signed:docker://ghcr.io/secai-hub/secai_os:latest
sudo systemctl reboot
```

After rebooting, verify the transport:

```bash
rpm-ostree status | grep -i "image-signed"
```

---

## Fixing a Broken Signing Policy

If `rpm-ostree upgrade` fails with a signature verification error:

1. Check that the signing policy is intact:
   ```bash
   cat /etc/containers/policy.json | python3 -m json.tool
   # Should contain a "sigstoreSigned" entry for ghcr.io/secai-hub/secai_os
   ```

2. Check the registries config:
   ```bash
   cat /etc/containers/registries.d/secai-os.yaml
   # Should contain use-sigstore-attachments: true
   ```

3. Check the public key:
   ```bash
   ls -la /etc/pki/containers/secai-cosign.pub
   ```

4. If any of these are missing or corrupted, re-run the bootstrap script:
   ```bash
   curl -sSfL https://raw.githubusercontent.com/SecAI-Hub/SecAI_OS/main/files/scripts/secai-bootstrap.sh \
     -o /tmp/secai-bootstrap.sh
   sudo bash /tmp/secai-bootstrap.sh --dry-run  # verify first
   sudo bash /tmp/secai-bootstrap.sh             # apply
   ```
