# Supply Chain & Provenance Architecture

This document describes which workflow is the source of truth for each stage of the SecAI OS supply chain: image builds, release artifacts, SBOM generation, provenance attestation, and verification before install/update.

Last updated: 2026-03-14

## Workflow Responsibilities

| Stage | Source of Truth | Workflow File | Trigger |
|-------|----------------|---------------|---------|
| **OS Image Builds** | `build.yml` | `.github/workflows/build.yml` | Push to main, daily schedule (06:00), manual dispatch |
| **Release Artifacts** | `release.yml` | `.github/workflows/release.yml` | Tag push (`v*`), manual dispatch |
| **CI Tests** | `ci.yml` | `.github/workflows/ci.yml` | Push to main, PRs, manual dispatch |
| **Image SBOM** | `build.yml` | `.github/workflows/build.yml` | After image build (non-PR only) |
| **Service SBOMs** | `release.yml` | `.github/workflows/release.yml` | At release time |
| **Provenance Attestation** | `build.yml` + `release.yml` | Both | After image builds and at release time |
| **Signing** | `build.yml` + `release.yml` | Both | cosign with `SIGNING_SECRET` |
| **Verification** | `ci.yml` (supply-chain-verify job) | `.github/workflows/ci.yml` | Every CI run |

## Provenance Pipeline

```
build → attest → sign → verify → promote
```

### 1. Build (build.yml)
- BlueBuild action builds the OS image from `recipes/recipe.yml`
- Image published to `ghcr.io/secai-hub/secai_os`
- cosign signs the image using `SIGNING_SECRET`

### 2. Attest (build.yml + release.yml)
- **Image SBOM:** pinned Syft scans the squashed final-image root and generates a CycloneDX JSON SBOM
- **SBOM Attestation:** `cosign attest --type cyclonedx` creates a signed attestation binding the SBOM to the image
- **Service SBOMs:** Syft generates per-service CycloneDX SBOMs at release time
- **SLSA v1 Provenance:** Cosign creates signed SLSA v1 image provenance, and `actions/attest-build-provenance` creates an independent GitHub-native SLSA v1 attestation

### 3. Sign (build.yml + release.yml)
- All images signed with cosign + `SIGNING_SECRET`
- Release checksums (SHA256SUMS) signed with cosign
- SBOM attestations signed with cosign private key

### 4. Verify (ci.yml)
The `supply-chain-verify` CI job validates:
- Syft can generate SBOMs for all Go and Python services
- cosign is available and functional
- `release.yml` contains required provenance keywords: `sbom-action`, `attest-build-provenance`, `cosign`, `cyclonedx`, `SHA256SUMS`
- `build.yml` contains required SBOM keywords: `sbom-action`, `cosign attest`, `cyclonedx`

### 5. Promote (runtime)
- At boot, the Runtime Attestor (:8505) verifies the measured boot chain
- rpm-ostree atomic updates ensure image integrity
- Greenboot health checks verify post-boot system state

## Key Material

| Key | Purpose | Storage | Rotation |
|-----|---------|---------|----------|
| `SIGNING_SECRET` | cosign image + SBOM signing | GitHub encrypted secret | Manual rotation |
| HMAC signing key | Capability token + audit chain signing | Keystore (software/TPM2/HSM) | Auto-rotation via keystore |
| TPM2 sealed keys | Vault encryption, attestation | TPM2 PCR-sealed | PCR policy change triggers re-seal |

## SBOM Coverage

| Component | Generator | Format | When |
|-----------|-----------|--------|------|
| OS image | Syft against the squashed image root | CycloneDX JSON | build.yml (non-PR) |
| Go services (9) | Syft | CycloneDX JSON | release.yml + ci.yml verification |
| Python services (6) | Syft | CycloneDX JSON | release.yml + ci.yml verification |

### Go Services
airlock, registry, tool-firewall, gpu-integrity-watch, mcp-firewall, policy-engine, runtime-attestor, integrity-monitor, incident-recorder

### Python Services
agent, ui, quarantine, common, diffusion-worker, search-mediator
