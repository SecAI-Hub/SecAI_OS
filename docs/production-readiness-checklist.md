# Production Readiness Checklist

Formal release gate checklist for SecAI OS deployments. Every item must be verified before a release is tagged as production-ready. This checklist is separate from the [production operations guide](production-operations.md), which covers day-to-day operational procedures.

Last updated: 2026-03-14

---

## Pre-Release Verification

### Build & CI

- [ ] All CI jobs pass on the release commit (green badge on `main`)
- [ ] Go build succeeds for all 9 services (`CGO_ENABLED=0`, `-race` tests pass)
- [ ] Python test suite passes (unit, integration, adversarial, M5 acceptance)
- [ ] Ruff lint clean (no `E`, `F`, `W` errors)
- [ ] Bandit security scan shows no high-severity findings
- [ ] ShellCheck passes for all shell scripts
- [ ] YAML policy validation passes
- [ ] Test count drift check passes (no regression below [test-counts.json](test-counts.json))
- [ ] Dependency vulnerability audit reviewed (govulncheck + pip-audit)
- [ ] Action pins verified (all GitHub Actions pinned to commit SHAs)
- [ ] Container base image pins verified (`check-container-pins.sh`)
- [ ] Release-gate job passes if on release branch (zero-tolerance bandit + CVE-ID govulncheck)
- [ ] Branch protection rules configured per `.github/branch-protection.md`

### Supply Chain

- [ ] Container image signed with cosign (`cosign verify --key cosign.pub`)
- [ ] Per-service CycloneDX SBOMs generated (9 Go + 6 Python)
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
- [ ] No services listening on public interfaces (localhost-only by default)

---

## Image Validation

### First Boot

- [ ] `first-boot-check.sh` passes with zero failures
- [ ] All 10 core services start and report healthy
- [ ] Health endpoints respond for all HTTP services
- [ ] Runtime attestation state is `verified`
- [ ] Integrity monitor state is `clean`
- [ ] No open incidents after first boot
- [ ] Service token is present and valid
- [ ] Firewall rules loaded (nftables default-deny egress)

### Functional Smoke Tests

- [ ] Web UI accessible at `http://localhost:8480`
- [ ] Model import via UI works (quarantine pipeline triggers)
- [ ] Quarantine pipeline completes (all 7 stages)
- [ ] Vault lock/unlock works
- [ ] Tool firewall denies unauthorized tool calls
- [ ] Airlock is disabled by default (no public egress)
- [ ] Agent mode responds to basic prompts
- [ ] Emergency panic level 1 (lock) works and is reversible

### Resilience Tests

- [ ] Graceful shutdown: `SIGTERM` to each Go service completes within 15s
- [ ] Incident persistence: restart incident-recorder, incidents survive
- [ ] Greenboot: simulated boot failure triggers auto-rollback
- [ ] Log rotation: `logrotate -f` runs without errors
- [ ] Service restart: each service recovers from `systemctl restart`
- [ ] Start limit: rapid restart hits StartLimitBurst and stops cycling

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
