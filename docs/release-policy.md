# Release Policy

Defines release channels, versioning strategy, and upgrade paths for SecAI OS.

Last updated: 2026-03-14

---

## Versioning

SecAI OS follows [Semantic Versioning 2.0.0](https://semver.org/):

```
vMAJOR.MINOR.PATCH
```

| Component | Bumped When | Examples |
|-----------|-------------|---------|
| **MAJOR** | Breaking changes to policy schema, API contracts, or upgrade path | Policy YAML schema change requiring manual migration |
| **MINOR** | New features, new services, non-breaking policy additions | New quarantine stage, new incident class, new API endpoint |
| **PATCH** | Bug fixes, security patches, dependency updates | CVE fix, crash fix, typo in policy |

---

## Release Channels

### `stable` (Production)

- **Tag format:** `v1.2.3`
- **Image tag:** `ghcr.io/secai-hub/secai_os:latest`, `ghcr.io/secai-hub/secai_os:v1.2.3`
- **Cadence:** As needed (security patches within 72 hours, features monthly)
- **Quality gate:** Full [production-readiness checklist](production-readiness-checklist.md) must pass; all CI jobs green including `release-gate` (zero-tolerance vuln scanning, CVE-ID govulncheck waivers, M5 acceptance re-verification)
- **Supply chain:** Cosign-signed, SBOM-attested, SLSA3 provenance
- **Rollback:** Automatic via Greenboot; manual via `rpm-ostree rollback`

This is the only channel recommended for production use.

### `candidate` (Pre-Release)

- **Tag format:** `v1.2.3-rc.1`
- **Image tag:** `ghcr.io/secai-hub/secai_os:candidate`
- **Cadence:** Before each stable release
- **Quality gate:** CI must pass including `release-gate` hardened checks (zero-tolerance bandit, CVE-ID govulncheck); first-boot-check must pass; manual smoke testing required
- **Purpose:** Final validation before stable promotion
- **Not for production use**

### `dev` (Development)

- **Tag format:** None (built from `main` branch on every push)
- **Image tag:** `ghcr.io/secai-hub/secai_os:dev`
- **Cadence:** Continuous (every merged PR)
- **Quality gate:** CI must pass
- **Purpose:** Development and integration testing
- **Not for production or candidate use**

---

## Release Process

### 1. Prepare Release

```bash
# Ensure main is clean
git checkout main && git pull

# Verify CI is green (all 18 jobs must pass, including enforced vulnerability scans)
gh run list --workflow=ci.yml --limit=1

# Check for unexpired vulnerability waivers that may need review
cat .github/vuln-waivers.json

# Update version references (if any hardcoded)
# Update CHANGELOG.md with release notes
```

### 2. Create Release Candidate

```bash
# Tag release candidate
git tag -s v1.2.3-rc.1 -m "Release candidate for v1.2.3"
git push origin v1.2.3-rc.1

# This triggers the release workflow which:
# - Builds all Go binaries (linux/amd64 + linux/arm64)
# - Generates per-service SBOMs
# - Creates SHA256SUMS and signs with cosign
# - Creates SLSA3 provenance attestation
# - Publishes GitHub Release (pre-release)
```

### 3. Validate Candidate

- [ ] Install on test hardware or VM
- [ ] Run `first-boot-check.sh`
- [ ] Complete [production-readiness checklist](production-readiness-checklist.md)
- [ ] Verify supply chain: `files/scripts/verify-release.sh ghcr.io/secai-hub/secai_os:v1.2.3-rc.1`

### 4. Promote to Stable

```bash
# Tag stable release (same commit as the validated RC)
git tag -s v1.2.3 -m "Release v1.2.3"
git push origin v1.2.3

# Update :latest tag
# (Handled automatically by the build workflow)
```

### 5. Post-Release

- [ ] Verify GitHub Release is published with all artifacts
- [ ] Verify image is available: `cosign verify --key cosign.pub ghcr.io/secai-hub/secai_os:v1.2.3`
- [ ] Update any external references
- [ ] Announce release

---

## Upgrade Paths

### Patch Upgrades (v1.2.2 → v1.2.3)

- **Method:** `rpm-ostree upgrade`
- **Downtime:** Single reboot (~30 seconds)
- **Risk:** Low (bug fixes only)
- **Rollback:** `rpm-ostree rollback` (automatic via Greenboot on health failure)
- **Data migration:** None required

### Minor Upgrades (v1.2.x → v1.3.0)

- **Method:** `rpm-ostree upgrade`
- **Downtime:** Single reboot
- **Risk:** Low-medium (new features, but backward compatible)
- **Rollback:** `rpm-ostree rollback`
- **Data migration:** None required (new features use new config keys with defaults)

### Major Upgrades (v1.x → v2.0.0)

- **Method:** `rpm-ostree rebase` to new image reference (if needed) + `rpm-ostree upgrade`
- **Downtime:** Single reboot + potential post-upgrade steps
- **Risk:** Medium (breaking changes possible)
- **Rollback:** `rpm-ostree rollback` (pre-upgrade snapshot recommended)
- **Data migration:** Release notes will include explicit migration steps
- **Pre-upgrade:** Backup incident store and audit logs (see [production-operations.md](production-operations.md))

---

## Install Artifacts

Each tagged release may include bootable install artifacts in addition to the OCI image and Go binaries:

| Artifact | Format | Produced By | Required |
|----------|--------|-------------|----------|
| OCI image | Container | BlueBuild (build.yml) | Always |
| ISO | Bootable installer | isogenerator (release.yml) | Always |
| Portable USB | Direct-flash raw.xz | bootc-image-builder raw + xz (release.yml) | Always |
| QCOW2 | KVM/QEMU disk image | build-qcow2.sh on KVM runner | When `vars.HAS_KVM_RUNNER` is set |
| OVA | VirtualBox/VMware appliance | build-ova.sh on KVM runner | When `vars.HAS_KVM_RUNNER` is set |

All install artifacts are built from the same OCI image. After installation, the upgrade path is identical regardless of install method: `rpm-ostree upgrade`.

QCOW2 and OVA may be absent in releases if the repository does not have a self-hosted KVM runner configured. The installer ISO and portable USB image are produced on standard GitHub runners.

See [release-artifacts.json](release-artifacts.json) for the machine-readable specification of expected artifacts.

---

## Security Patch Policy

| Severity | Target Response Time | Target Release Time |
|----------|---------------------|-------------------|
| Critical (actively exploited) | < 4 hours (acknowledgment) | < 24 hours |
| High (CVE, no known exploit) | < 24 hours (acknowledgment) | < 72 hours |
| Medium | < 1 week | Next scheduled release |
| Low | Next scheduled release | Next scheduled release |

Security patches are always released as patch versions (e.g., v1.2.3 → v1.2.4) to minimize upgrade risk.

---

## Dependency Update Policy

| Dependency Type | Update Frequency | Breaking Changes | Enforcement |
|----------------|-----------------|------------------|-------------|
| Go standard library | With Go version updates (semi-annual) | Major version only | govulncheck fails CI on unwaived vulns |
| Go third-party | Monthly or on CVE | Patch/minor: auto; major: manual review | govulncheck fails CI on unwaived vulns |
| Python packages | Monthly or on CVE | Pinned in `requirements-ci.txt` | pip-audit fails CI on unwaived vulns |
| System packages (rpm-ostree) | With Fedora rebases | Follow Fedora release cycle | -- |
| GitHub Actions | Via Dependabot (auto-PR) | Review + CI must pass | check-pins verifies SHA pinning |
| Container base image | With Fedora Atomic updates | Follow uBlue release cycle | cosign signature verification |

Vulnerability waivers for reviewed/accepted findings are tracked in [`.github/vuln-waivers.json`](../.github/vuln-waivers.json) with mandatory expiry dates. Expired waivers automatically re-fail CI.

---

## Image Retention

| Channel | Retention | Notes |
|---------|-----------|-------|
| `stable` tags | Indefinite | All stable releases preserved |
| `candidate` tags | 90 days | Cleaned up after stable promotion |
| `dev` builds | 30 days | Rolling; only latest 30 days kept |
| `:latest` | Always points to latest stable | Updated on each stable release |
