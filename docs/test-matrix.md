# Test Coverage Matrix

This document summarizes the test coverage for SecAI_OS across all languages and test categories.

Last updated: 2026-04-29

> **Canonical source of truth for test counts:** [`docs/test-counts.json`](test-counts.json).
> CI enforces that actual counts never drift below documented values.

## Summary

| Language | Test Count | Runner |
|----------|-----------|--------|
| Go | 428 | `go test -race ./...` |
| Python | 1133 | `pytest` |
| Shell | CI-scoped scripts plus Makefile target for all repo shell scripts | `shellcheck` |

## Go Tests (428 total)

| Service | Location | Tests | Description |
|---------|----------|-------|-------------|
| Registry | services/registry/ | 22 | Trusted model registry, hash pinning, cosign verification |
| Tool Firewall | services/tool-firewall/ | 15 | Default-deny egress policy, rule evaluation |
| Airlock | services/airlock/ | 11 | Online airlock, request sanitization, policy enforcement |
| GPU Integrity Watch | services/gpu-integrity-watch/ | 62 | GPU probe scoring, baseline comparison, action triggers, daemon mode, driver fingerprint, device allowlist, attestor/incident integration |
| MCP Firewall | services/mcp-firewall/ | 71 | MCP tool call policy enforcement, input redaction, taint tracking, audit, adversarial tests (M43), trust tier isolation, session binding |
| Policy Engine | services/policy-engine/ | 45 | Unified policy decisions across 6 domains, evidence generation, auth, adversarial tests (M43) |
| Runtime Attestor | services/runtime-attestor/ | 55 | TPM2 quote verification, HMAC bundles, state machine, startup gating, service digests, incident-recorder integration |
| Integrity Monitor | services/integrity-monitor/ | 50 | Baseline computation, continuous scanning, violation detection, state machine, HMAC baselines, incident-recorder integration |
| Incident Recorder | services/incident-recorder/ | 97 | Incident creation, auto-containment, lifecycle management, severity ranking, policy loading, containment execution, enforcement chain integration, recovery ceremony, severity escalation, forensic bundle export (M43), persistence durability (fsync) |

## Python Tests (1133 total)

| Test File | Location | Tests | Description |
|-----------|----------|-------|-------------|
| test_adversarial.py | tests/ | 28 | Prompt injection, policy bypass, step signature tampering, containment determinism, GPU runtime tamper, blocked paths (M43) |
| test_agent.py | tests/ | 172 | Agent policy engine, capability tokens, storage gateway, budgets, planner, executor, API, workspace validation, security invariants, two-phase approval, policy evidence, keystore abstraction |
| test_audit_chain.py | tests/ | 16 | Hash-chained audit logging and tamper detection |
| test_auth.py | tests/ | 25 | Authentication, session handling, and API authorization |
| test_build_hermetic.py | tests/ | 11 | Hermetic build inputs, vendoring, and network-denial checks |
| test_canary_tripwire.py | tests/ | 49 | Canary token placement, tripwire monitoring, alerts |
| test_circuit_breaker.py | tests/ | 15 | Circuit breaker state machine (closed/open/half-open), reset, error propagation |
| test_clipboard_isolation.py | tests/ | 30 | Clipboard access controls and content sanitization |
| test_custom_python_vex.py | tests/ | 5 | Custom Python OpenVEX generation |
| test_differential_privacy.py | tests/ | 37 | Query obfuscation, decoy queries, k-anonymity, timing randomization |
| test_diffusion_entrypoint.py | tests/ | 2 | Diffusion worker entrypoint behavior |
| test_diffusion_installer.py | tests/ | 63 | Diffusion opt-in installer, dependency selection, manifests, and service wiring |
| test_diffusion_installer_integration.py | tests/ | 18 | Diffusion installer integration paths |
| test_diffusion_runtime_manifest.py | tests/ | 40 | Diffusion runtime manifest validation |
| test_diffusion_worker.py | tests/ | 9 | Diffusion worker routes and request handling |
| test_emergency_wipe.py | tests/ | 65 | 3-level panic wipe, secure deletion, escalation |
| test_gunicorn_config.py | tests/ | 13 | Gunicorn wrapper and runtime configuration |
| test_image_ref_consistency.py | tests/ | 10 | Canonical image reference consistency |
| test_m5_acceptance.py | tests/ | 32 | M5 acceptance certification across attestation, integrity, policy, recovery, and workspace isolation |
| test_memory_protection.py | tests/ | 37 | Swap encryption, zswap, core dumps, mlock, TEE detection |
| test_profile_system.py | tests/ | 32 | Profile loading, validation, and policy behavior |
| test_quarantine_pipeline.py | tests/ | 13 | Quarantine pipeline stages, scanning, pass/fail logic, YARA rule handling |
| test_quarantine_watcher.py | tests/ | 5 | Quarantine watcher startup and filesystem behavior |
| test_recipe_validation.py | tests/ | 26 | Recipe and packaged-file validation |
| test_release_artifacts.py | tests/ | 52 | Release workflow, artifact manifest, and verification UX consistency |
| test_sandbox.py | tests/ | 31 | Sandbox compose, policy, and runtime constraints |
| test_sandbox_bundle.py | tests/ | 8 | Sandbox bundle and artifact checks |
| test_search.py | tests/ | 36 | Search mediator, PII stripping, injection detection |
| test_secure_boot.py | tests/ | 38 | Secure boot and measured boot behavior |
| test_traffic_analysis.py | tests/ | 41 | Padding, timing jitter, dummy traffic generation |
| test_ui.py | tests/ | 56 | Flask web UI routes, rendering, input handling, model catalog loading |
| test_ui_cookies.py | tests/ | 11 | UI cookie security attributes |
| test_ui_file_handling.py | tests/ | 12 | UI file upload and path handling |
| test_update_rollback.py | tests/ | 74 | Signed update verification, rollback triggers, recovery |
| test_vault_watchdog.py | tests/ | 21 | Vault auto-lock, idle detection, timer controls |

### Agent test breakdown (test_agent.py)

| Class | Tests | Category | Description |
|-------|-------|----------|-------------|
| TestClassifyRisk | 3 | Unit | Risk-level classification for agent actions |
| TestPolicyEngine | 15 | Unit / Security | Deny-by-default evaluation, always-deny invariants, hard-approval gates |
| TestCapabilityTokens | 8 | Unit | Token creation, workspace scoping, mode-specific capabilities |
| TestBudgets | 7 | Unit | Budget enforcement, limit checking, sensitive-mode tighter limits |
| TestStorageGateway | 14 | Unit / Security | Path scope validation, sensitive file blocking, sensitivity ceiling, file size limits |
| TestPlannerHeuristic | 8 | Unit | Heuristic plan decomposition, keyword-to-action mapping |
| TestPlannerLLMParsing | 8 | Unit | LLM response parsing, malformed plan rejection |
| TestExecutor | 7 | Integration | Step execution dispatch, tool firewall calls, budget tracking |
| TestAgentAPI | 22 | Integration | HTTP endpoint contracts, input validation, task CRUD lifecycle, workspace ID resolution |
| TestSecurityInvariants | 9 | Security | Fail-closed behavior, airlock/firewall bypass prevention, service-down handling |
| TestDataModels | 4 | Unit | Task/step serialisation, status enum coverage |
| TestTokenSigning | 10 | Security | HMAC-SHA256 token signing, tamper detection, replay protection, expiry enforcement |
| TestTokenBinding | 8 | Security | Intent hashing, policy digest, task context binding, token-to-dict serialisation |
| TestTwoPhaseApproval | 6 | Security | Two-phase approval for high-risk actions (trust change, export, widen scope) |
| TestPolicyEvidence | 8 | Security | Per-step PolicyDecision evidence, risk classification, token validity tracking |
| TestVerifiedSupervisorAPI | 3 | Integration | Signed tokens in API responses, policy decisions in step params |
| TestSoftwareKeyProvider | 13 | Unit / Security | Software key provider: sign/verify, key rotation, file persistence, key derivation |
| TestTPM2KeyProvider | 5 | Unit | TPM2 provider: graceful degradation, PCR config, missing file handling |
| TestPKCS11KeyProvider | 6 | Unit | PKCS#11 stub: NotImplementedError for all operations, status reporting |
| TestKeystoreFactory | 7 | Integration | Provider factory, config loading, auto-detection, fallback chain |
| TestUnixSocketServer | 1 | Integration | Unix socket server wiring |

## Shell Checks

CI validates the production shell entrypoints that directly affect boot, service build, first-boot validation, MOK generation, and release verification. The repo-root `make shellcheck` target covers the broader repo-owned script set, including `.github/scripts/*.sh`, `files/scripts/*.sh`, and `files/system/usr/libexec/secure-ai/*.sh`.

## CI Pipeline

CI is defined in `.github/workflows/ci.yml` and runs on every push and pull request.

Steps:
1. Build and test all 9 Go services (`go test -race ./...`)
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
```

### Python tests

```bash
python -m pip install -r requirements-ci.txt
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
