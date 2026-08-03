# Test Coverage Matrix

This document summarizes the test coverage for SecAI_OS across all languages and test categories.

Last updated: 2026-08-02

> **Canonical source of truth for test counts:** [`docs/test-counts.json`](test-counts.json).
> CI enforces that actual counts never drift below documented values.

## Summary

| Language | Test Count | Runner |
|----------|-----------|--------|
| Go | 506 | `go test -race ./...` |
| Python | 1598 | `pytest` |
| Shell | CI-scoped scripts plus Makefile target for all repo shell scripts | `shellcheck` |

## Go Tests (506 total)

| Service | Location | Tests | Description |
|---------|----------|-------|-------------|
| Registry | services/registry/ | 36 | Trusted model registry, hash pinning, cosign verification |
| Tool Firewall | services/tool-firewall/ | 32 | Default-deny typed-argument policy, nested constraint enforcement, audit redaction and file-identity checks, and fail-closed request handling |
| Airlock | services/airlock/ | 27 | Online airlock, request sanitization, policy enforcement |
| GPU Integrity Watch | services/gpu-integrity-watch/ | 63 | GPU probe scoring, baseline comparison, action triggers, daemon mode, driver fingerprint, device allowlist, attestor/incident integration |
| MCP Firewall | services/mcp-firewall/ | 71 | MCP tool call policy enforcement, input redaction, taint tracking, audit, adversarial tests (M43), trust tier isolation, session binding |
| Policy Engine | services/policy-engine/ | 45 | Unified policy decisions across 6 domains, evidence generation, auth, adversarial tests (M43) |
| Runtime Attestor | services/runtime-attestor/ | 64 | TPM2 quote verification, HMAC bundles, state machine, startup gating, service digests, incident-recorder integration |
| Integrity Monitor | services/integrity-monitor/ | 54 | Baseline computation, continuous scanning, violation detection, state machine, HMAC baselines, incident-recorder integration |
| Incident Recorder | services/incident-recorder/ | 108 | Incident creation, auto-containment, lifecycle management, severity ranking, policy loading, containment execution, enforcement chain integration, recovery ceremony, severity escalation, forensic bundle export (M43), persistence durability (fsync) |
| UI Ingress | services/ui-ingress/ | 6 | Uncredentialed fixed-route TCP relay, bounded connections, dual UI/controller health validation, protocol identity, and failure behavior |

## Python Tests (1598 total)

| Test File | Location | Tests | Description |
|-----------|----------|-------|-------------|
| test_adversarial.py | tests/ | 28 | Prompt injection, policy bypass, step signature tampering, containment determinism, GPU runtime tamper, blocked paths (M43) |
| test_agent.py | tests/ | 191 | Agent policy engine, task store, capabilities, fail-closed tool-firewall execution, authentication, and service isolation |
| test_audit_chain.py | tests/ | 23 | Hash-chained audit logging and tamper detection |
| test_audit_verifier.py | tests/ | 5 | Audit-chain verifier command behavior |
| test_auth.py | tests/ | 25 | Authentication, session handling, and API authorization |
| test_backup_restore_security.py | tests/ | 14 | Encrypted backup/restore validation and unsafe archive rejection |
| test_build_hermetic.py | tests/ | 16 | Hermetic build inputs, version-bound Python runtime, shared-package assembly, vendoring, and network-denial checks |
| test_canary_security.py | tests/ | 7 | Canary ownership, confidentiality, and fail-closed behavior |
| test_canary_tripwire.py | tests/ | 49 | Canary token placement, tripwire monitoring, alerts |
| test_capability_claims.py | tests/ | 8 | Capability metadata and implementation claim consistency |
| test_circuit_breaker.py | tests/ | 15 | Circuit breaker state machine (closed/open/half-open), reset, error propagation |
| test_clipboard_isolation.py | tests/ | 19 | Clipboard access controls and content sanitization |
| test_custom_python_vex.py | tests/ | 5 | Custom Python OpenVEX generation |
| test_differential_privacy.py | tests/ | 37 | Query obfuscation, decoy queries, k-anonymity, timing randomization |
| test_diffusion_entrypoint.py | tests/ | 2 | Diffusion worker entrypoint behavior |
| test_diffusion_installer.py | tests/ | 65 | Diffusion opt-in installer, dependency selection, manifests, and service wiring |
| test_diffusion_installer_integration.py | tests/ | 19 | Diffusion installer integration paths |
| test_diffusion_runtime_manifest.py | tests/ | 53 | Diffusion runtime manifest and interpreter-specific lock validation |
| test_diffusion_worker.py | tests/ | 14 | Diffusion worker routes and request handling |
| test_emergency_wipe.py | tests/ | 20 | Three-level panic containment and recovery behavior |
| test_forensic_verify.py | tests/ | 8 | Forensic archive authenticity and tamper detection |
| test_govulncheck_stream.py | tests/ | 2 | Streaming govulncheck result normalization |
| test_gunicorn_config.py | tests/ | 16 | Gunicorn wrapper and runtime configuration |
| test_hardware_qualification.py | tests/ | 6 | Redacted hardware qualification evidence generation, including scoped SELinux and Podman security state |
| test_hardware_state_security.py | tests/ | 11 | Hardware-state persistence and trust boundaries |
| test_host_state_encryption.py | tests/ | 8 | Encrypted host-state verification |
| test_image_ref_consistency.py | tests/ | 10 | Canonical image reference consistency |
| test_landlock_integration.py | tests/ | 7 | Landlock policy application and fail-closed integration |
| test_m5_acceptance.py | tests/ | 32 | M5 acceptance certification across attestation, integrity, policy, recovery, and workspace isolation |
| test_memory_protection.py | tests/ | 33 | Swap encryption, zswap, core dumps, mlock, TEE detection |
| test_native_scoped_credentials.py | tests/ | 7 | Per-service native credential scope |
| test_profile_plan_security.py | tests/ | 11 | Profile plan validation and safe application |
| test_profile_system.py | tests/ | 34 | Profile loading, validation, default-deny typed tool policy, and policy behavior |
| test_python_dependency_audit.py | tests/ | 3 | Strict Python dependency-audit integration |
| test_quarantine_pipeline.py | tests/ | 51 | Quarantine pipeline stages, provenance, scanning, and promotion gates |
| test_quarantine_scanner_broker.py | tests/ | 7 | Scanner broker isolation and result validation |
| test_quarantine_scanner_stage.py | tests/ | 3 | Scanner-stage fail-closed sequencing |
| test_quarantine_scanner_worker.py | tests/ | 10 | Native scanner subprocess containment |
| test_quarantine_watcher.py | tests/ | 18 | Quarantine watcher startup and filesystem behavior |
| test_recipe_validation.py | tests/ | 32 | Fedora recipe, module ordering, and packaged-file validation |
| test_release_artifacts.py | tests/ | 72 | Release workflow, artifact manifest, and verification consistency |
| test_runtime_attestation_hardware.py | tests/ | 8 | Nonce-bound TPM evidence and vTPM degradation |
| test_sandbox.py | tests/ | 46 | Sandbox policy, runtime constraints, and network isolation |
| test_sandbox_bundle.py | tests/ | 61 | Sandbox bundle, immutable candidate/readiness publication, session-bound generation state, atomic credential/control-token recovery, launcher quiescing, helper hardening, loopback ingress, and artifact checks |
| test_sandbox_control_server.py | tests/ | 70 | Exact control keys, signed request/restart-persistent replay protection, session/profile-bound challenge proofs, token-nondisclosing protocol probes, bounded HTTP handling, manifest-backed generation/profile reads, safe runtime/host-bind selection, and verified cross-platform process-tree cancellation |
| test_podman_anchor.py | tests/ | 5 | Project-scoped Podman gateway anchor hardening, stopped/orphan recovery, ownership validation, and owner-only state |
| test_search.py | tests/ | 37 | Search mediator, PII stripping, injection detection |
| test_secure_boot.py | tests/ | 18 | Secure Boot, measured boot, and enrollment behavior |
| test_searxng_credentials.py | tests/ | 6 | Owner-only ephemeral SearXNG settings, credential injection, and pinned schema |
| test_slo_tracker.py | tests/ | 3 | Service-level objective tracker persistence |
| test_source_prep_archive.py | tests/ | 7 | Cross-job source-prep archive validation and deterministic SearXNG metadata |
| test_systemd_units.py | tests/ | 12 | Unit hardening, dependencies, and packaged execution paths |
| test_traffic_analysis.py | tests/ | 41 | Padding, timing jitter, dummy traffic generation |
| test_ui.py | tests/ | 110 | Flask UI routes, setup, agent controls, authentication, exact sandbox-control credentials, manifest/session-bound sandbox readiness, fail-closed profile recovery, and model catalog loading |
| test_ui_cookies.py | tests/ | 11 | UI cookie security attributes |
| test_ui_file_handling.py | tests/ | 18 | UI file upload and path handling |
| test_ui_runtime_ipc.py | tests/ | 3 | UI-to-agent Unix-socket IPC |
| test_update_rollback.py | tests/ | 80 | Signed update verification, rollback triggers, recovery |
| test_vault_mount_verifier.py | tests/ | 18 | Exact LUKS mapper, mount, marker, and directory contract |
| test_vault_setup_security.py | tests/ | 8 | Destructive setup confirmation and fail-closed LUKS provisioning |
| test_vault_watchdog.py | tests/ | 32 | Vault auto-lock, exact identity, and local-console unlock controls |

## Shell Checks

CI validates the production shell entrypoints that directly affect boot, service build, first-boot validation, MOK generation, and release verification. The repo-root `make shellcheck` target covers the broader repo-owned script set, including `.github/scripts/*.sh`, `files/scripts/*.sh`, and `files/system/usr/libexec/secure-ai/*.sh`.

## CI Pipeline

CI is defined in `.github/workflows/ci.yml` and runs on every push and pull request.

Steps:
1. Build and test all 10 Go modules (`go test -race ./...`)
2. Lint Python (py_compile for all service modules including agent)
3. Run Python tests (`pytest tests/`) split into unit/integration and adversarial/acceptance gates
4. Run Ruff, Bandit, mypy, dependency audits, and vulnerability waiver checks
5. Lint shell scripts with ShellCheck
6. Lint container build files with Hadolint and repo-owned app-security rules with Semgrep
7. Validate YAML configs (policy, agent, recipes)
8. Verify action pins, container image pins, docs consistency, line endings, and image references
9. Supply chain verification: SBOM generation via pinned Anchore action, cosign availability, and release/build provenance validation

## Test Categories

| Category | Description | Examples |
|----------|-------------|---------|
| Unit | Isolated function/method tests | Hash verification, policy rule parsing |
| Integration | Multi-component interaction tests | Pipeline stage sequencing, service auth flow |
| Security | Validates security invariants hold | Injection detection, PII stripping, fail-closed behavior |

## Running Tests Locally

### Go tests

```bash
cd services/registry && go test ./...
cd services/tool-firewall && go test ./...
cd services/airlock && go test ./...
cd services/gpu-integrity-watch && go test ./...
cd services/mcp-firewall && go test ./...
cd services/policy-engine && go test ./...
cd services/runtime-attestor && go test ./...
cd services/integrity-monitor && go test ./...
cd services/incident-recorder && go test ./...
cd services/ui-ingress && go test ./...
```

### Python tests

```bash
python -m pip install --require-hashes -r requirements-ci.lock
PYTHONPATH=services python -m pytest tests/ -v
```

To run a specific test file:

```bash
PYTHONPATH=services python -m pytest tests/test_release_artifacts.py -v
PYTHONPATH=services python -m pytest tests/test_search.py -v
PYTHONPATH=services python -m pytest tests/test_agent.py -v
```

### Shell checks

```bash
make shellcheck
```
