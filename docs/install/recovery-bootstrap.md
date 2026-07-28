# Recovery Bootstrap (Verified, Immutable Image)

This recovery path never permits an unverified container transport. If the
local signing policy is missing or damaged, restore it and rebase only to the
exact digest published in a signed SecAI OS release.

## Before You Start

Obtain these files from the same GitHub release:

- `IMAGE_DIGEST`
- `SHA256SUMS` and `SHA256SUMS.sig`
- `secai-os-build-*.sh` only if you are rebuilding media

Obtain `cosign.pub` through a trusted channel and confirm its SHA-256
fingerprint is:

```text
de6a17ed1cd444a2671798f14d6bf98c1658259dc443a130eba9f40855a7d310
```

Stop if the fingerprint, checksum signature, image signature, or digest format
does not verify.

## 1. Verify Release Metadata

```bash
sha256sum cosign.pub
cosign verify-blob --key cosign.pub \
  --signature SHA256SUMS.sig SHA256SUMS
sha256sum --check --strict SHA256SUMS

IMAGE_DIGEST="$(tr -d '\r\n' < IMAGE_DIGEST)"
printf '%s\n' "$IMAGE_DIGEST" |
  grep -Eq '^sha256:[0-9a-f]{64}$' ||
  { echo "Invalid release digest" >&2; exit 1; }
IMAGE_REF="ghcr.io/secai-hub/secai_os@${IMAGE_DIGEST}"
cosign verify --key cosign.pub "$IMAGE_REF" >/dev/null
```

The format guard prevents ambiguous references; `cosign verify` is the
authoritative signature and digest check.

## 2. Restore Policy and Rebase Through Signed Transport

Use a locally reviewed copy of `secai-bootstrap.sh` from the same source
revision as the release. Bind the deployment to both the immutable digest and
the reviewed release channel:

```bash
sudo bash ./secai-bootstrap.sh \
  --tag "release-vMAJOR.MINOR.PATCH" \
  --digest "$IMAGE_DIGEST"
sudo systemctl reboot
```

The bootstrap script verifies the pinned public-key fingerprint, verifies the
exact `repository:tag@sha256` image with cosign, installs a fail-closed
container policy, and uses only:

```text
ostree-image-signed:docker://
```

There is no `ostree-unverified-registry:` fallback. If signed transport still
fails, remain on the prior deployment and repair the trust configuration
instead of bypassing it.

## 3. Verify the Booted Deployment

```bash
rpm-ostree status
sudo /usr/libexec/secure-ai/update-verify.sh status
sudo /usr/libexec/secure-ai/verify-boot-chain.sh
```

The booted origin must contain the expected repository, release channel, and
exact `@sha256:` digest.

## Future Updates

Never use `rpm-ostree upgrade` directly for SecAI OS. The appliance update
gate resolves the configured channel, verifies the candidate signature,
enforces anti-rollback state, and stages the exact digest:

```bash
sudo /usr/libexec/secure-ai/update-verify.sh check
sudo /usr/libexec/secure-ai/update-verify.sh stage
sudo /usr/libexec/secure-ai/update-verify.sh apply
```

For an approved rollback:

```bash
sudo /usr/libexec/secure-ai/update-verify.sh rollback
```
