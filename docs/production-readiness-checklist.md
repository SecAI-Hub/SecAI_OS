# Production Readiness Checklist

Formal release gate checklist for SecAI OS deployments. Every item must be verified before a release is tagged as production-ready. This checklist is separate from the [production operations guide](production-operations.md), which covers day-to-day operational procedures.

Last updated: 2026-08-02

This file is a template, not evidence that any release passed. A completed
checklist must identify the immutable source commit and image digest, link every
machine-produced result, name the required deployment profile and hardware, and
be signed by the developer, independent security reviewer, and release manager.
Unchecked, waived without expiry, or unavailable mandatory evidence blocks a
production designation.

---

## Pre-Release Verification

### Build & CI

- [ ] All CI jobs pass on the release commit (green badge on `main`)
- [ ] Go build succeeds for all 10 tested modules: 9 native release services and the sandbox UI ingress (`CGO_ENABLED=0`, `-race` tests pass)
- [ ] Python test suite passes (unit, integration, adversarial, M5 acceptance)
- [ ] Ruff lint clean (no `E`, `F`, `W` errors)
- [ ] Bandit security scan shows no high-severity findings
- [ ] Semgrep project security rules pass
- [ ] ShellCheck passes for all shell scripts
- [ ] Hadolint passes for all Containerfiles and Dockerfiles
- [ ] YAML policy validation passes
- [ ] Test count drift check passes (no regression below [test-counts.json](test-counts.json))
- [ ] Dependency vulnerability audit reviewed (govulncheck + pip-audit)
- [ ] Action pins verified (all GitHub Actions pinned to commit SHAs)
- [ ] Container base image pins verified for service, sandbox, and deploy images (`check-container-pins.sh`)
- [ ] Runtime Python dependency audit reviewed for CI and service requirement files
- [ ] Quarantine scanner package pins and Python compatibility reviewed before changing the quarantine base image
- [ ] YARA rules compile and quarantine import scanning blocks suspicious payload signatures
- [ ] Line-ending check passes for shell, workflow, config, and docs files
- [ ] Release-gate job passes if on release branch (zero-tolerance bandit + CVE-ID govulncheck)
- [ ] Branch protection rules configured per `.github/branch-protection.md`

### Supply Chain

- [ ] Container image signed with cosign (`cosign verify --key cosign.pub`)
- [ ] Per-release-service CycloneDX SBOMs generated (9 native Go + 6 Python), and the sandbox UI ingress container has a generated image SBOM
- [ ] SLSA3 provenance attestation attached to image
- [ ] SHA256SUMS file generated and signed
- [ ] `verify-release.sh` runs clean against the release artifacts
- [ ] Release workflow (`release.yml`) executed without errors

### Security Posture

- [ ] Security regression tests pass (adversarial Python, MCP firewall, policy engine, incident recovery)
- [ ] No open critical or high incidents in issue tracker
- [ ] Threat model reviewed and up-to-date (`docs/threat-model.md`)
- [ ] Security status document current (`docs/security-status.md`)
- [ ] All systemd units have production hardening (TimeoutStartSec, StartLimitInterval, etc.)
- [ ] Seccomp profiles present for all Go services
- [ ] Landlock entries configured for all services
- [ ] SELinux is `Enforcing` with the approved policy, fixed SecAI OS paths have
      reviewed labels, and locally reviewed AVC/USER_AVC denials contain no
      unexplained SecAI OS events
- [ ] Podman qualification evidence reports SELinux and seccomp enabled for the
      target runtime; any bind-mount relabeling is limited to the documented
      shared `:z` paths
- [ ] No services listening on public interfaces (localhost-only by default)

---

## Image Validation

### First Boot

Record the deployment profile being certified and derive its required services
from the service manifest. Do not use a hard-coded service count.

- [ ] `first-boot-check.sh` passes with zero failures
- [ ] Every required service in the selected deployment profile starts and reports healthy
- [ ] Health endpoints respond for all HTTP services
- [ ] Runtime attestation reports `assurance_mode=hardware`,
      `evidence_verified=true`, `verified=true`, and
      `policy_satisfied=true` after a fresh nonce-bound quote
- [ ] `/var/lib/secure-ai/tpm-attestation/profile.json` is root-owned mode
      `0600`, pins AK handle `0x81010020`, and contains the approved PCR
      0/2/4/7 baseline
- [ ] Integrity monitor state is `clean`
- [ ] No open incidents after first boot
- [ ] Service token is present and valid
- [ ] Reboot recreates/loads every per-service credential and unauthorized requests remain denied
- [ ] Firewall rules loaded (nftables default-deny egress)

### Functional Smoke Tests

- [ ] Web UI accessible at `http://localhost:8480`
- [ ] Model import via UI works (quarantine pipeline triggers)
- [ ] Quarantine pipeline completes (all 7 stages)
- [ ] Local-console vault lock/unlock works; HTTP unlock rejects passphrases
- [ ] Persistent credentials are on dm-crypt/LUKS-backed host state
- [ ] Tool firewall denies unauthorized tool calls
- [ ] Airlock is disabled by default (no public egress)
- [ ] Direct workload egress is blocked; only the authenticated Airlock fetch proxy can reach approved destinations
- [ ] Quarantine workers have no service credential, network, or trusted-state write access
- [ ] Agent mode responds to basic prompts
- [ ] Emergency panic level 1 (lock) works and is reversible

### Resilience Tests

- [ ] Graceful shutdown: `SIGTERM` to each Go service completes within 15s
- [ ] Incident persistence: restart incident-recorder, incidents survive
- [ ] Greenboot: simulated boot failure triggers auto-rollback
- [ ] Log rotation: `logrotate -f` runs without errors
- [ ] Service restart: each service recovers from `systemctl restart`
- [ ] Start limit: rapid restart hits StartLimitBurst and stops cycling
- [ ] Disk-full and interrupted-write tests preserve registry, audit, and incident-store consistency
- [ ] Encrypted backup restore meets the release RPO/RTO and is independently verified

---

## Documentation

- [ ] README current (milestone count, test counts, architecture table)
- [ ] Install guides accurate (bare-metal, VM, dev)
- [ ] API docs cover all endpoints (`docs/api.md`)
- [ ] SLOs documented (`docs/slos.md`)
- [ ] Release policy documented (`docs/release-policy.md`)
- [ ] Support lifecycle documented (`docs/support-lifecycle.md`)
- [ ] Recovery runbook tested (`docs/recovery-runbook.md`)
- [ ] CHANGELOG updated with release notes

---

## Release Process

### Tagging

- [ ] Version follows semantic versioning (`vMAJOR.MINOR.PATCH`)
- [ ] Git tag is signed (`git tag -s`)
- [ ] Tag pushed triggers release workflow

### Post-Release

- [ ] GitHub Release created with all artifacts
- [ ] Release notes include: summary, breaking changes, upgrade notes, known issues
- [ ] Container image published to `ghcr.io/secai-hub/secai_os`
- [ ] Image signature and attestations attached
- [ ] Announce in appropriate channels

---

## Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Developer | | | |
| Security Reviewer | | | |
| Release Manager | | | |

> **Note:** This checklist can be verified automatically using the CI pipeline
> and `first-boot-check.sh`. Manual review is required for documentation
> currency, threat model review, and release notes quality.
