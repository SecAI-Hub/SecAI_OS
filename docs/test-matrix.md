# Test Coverage Matrix

This document summarizes the test coverage for SecAI_OS across all languages and test categories.

Last updated: 2026-03-13

## Summary

| Language | Test Count | Runner |
|----------|-----------|--------|
| Go | 288+ | `go test ./...` |
| Python | 743+ | `pytest` |
| Shell | All .sh files | `shellcheck` |

## Go Tests (288+ total)

| Service | Location | Tests | Description |
|---------|----------|-------|-------------|
| Registry | services/registry/ | 6 | Trusted model registry, hash pinning, cosign verification |
| Tool Firewall | services/tool-firewall/ | 10 | Default-deny egress policy, rule evaluation |
| Airlock | services/airlock/ | 10 | Online airlock, request sanitization, policy enforcement |
| GPU Integrity Watch | services/gpu-integrity-watch/ | 81 | GPU probe scoring, baseline comparison, action triggers, daemon mode, driver fingerprint, device allowlist, attestor/incident integration |
| MCP Firewall | services/mcp-firewall/ | 30+ | MCP tool call policy enforcement, input redaction, taint tracking, audit |
| Policy Engine | services/policy-engine/ | 37 | Unified policy decisions across 6 domains, evidence generation, auth |
| Runtime Attestor | services/runtime-attestor/ | 46 | TPM2 quote verification, HMAC bundles, state machine, startup gating, service digests |
| Integrity Monitor | services/integrity-monitor/ | 42 | Baseline computation, continuous scanning, violation detection, state machine, HMAC baselines |
| Incident Recorder | services/incident-recorder/ | 47 | Incident creation, auto-containment, lifecycle management, severity ranking, policy loading |

## Python Tests (677+ total)

| Test File | Location | Approx. Tests | Description |
|-----------|----------|---------------|-------------|
| test_pipeline.py | tests/ | ~96 | Quarantine pipeline stages, scanning, pass/fail logic |
| test_search.py | tests/ | ~27 | Search mediator, PII stripping, injection detection |
| test_ui.py | tests/ | ~11 | Flask web UI routes, rendering, input handling |
| test_vault_watchdog.py | tests/ | ~18 | Vault auto-lock, idle detection, timer controls |
| test_memory_protection.py | tests/ | ~37 | Swap encryption, zswap, core dumps, mlock, TEE detection |
| test_traffic_analysis.py | tests/ | ~41 | Padding, timing jitter, dummy traffic generation |
| test_differential_privacy.py | tests/ | ~37 | Privacy-preserving query obfuscation: decoy queries, k-anonymity, timing randomization |
| test_clipboard_isolation.py | tests/ | ~30 | Clipboard access controls, content sanitization |
| test_canary_tripwire.py | tests/ | ~49 | Canary token placement, tripwire monitoring, alerts |
| test_emergency_wipe.py | tests/ | ~65 | 3-level panic wipe, secure deletion, escalation |
| test_update_rollback.py | tests/ | ~74 | Signed update verification, rollback triggers, recovery |
| test_agent.py | tests/ | 159 | Agent policy engine, capability tokens (HMAC signing, nonce replay, expiry), storage gateway, budgets, planner, executor, API, workspace validation, security invariants, two-phase approval, policy evidence, keystore abstraction (software/TPM2/PKCS#11) |

### Agent test breakdown (test_agent.py)

| Class | Tests | Category | Description |
|-------|-------|----------|-------------|
| TestClassifyRisk | 3 | Unit | Risk-level classification for agent actions |
| TestPolicyEngine | 15 | Unit / Security | Deny-by-default evaluation, always-deny invariants, hard-approval gates |
| TestCapabilityTokens | 8 | Unit | Token creation, workspace scoping, mode-specific capabilities |
| TestBudgets | 7 | Unit | Budget enforcement, limit checking, sensitive-mode tighter limits |
| TestStorageGateway | 14 | Unit / Security | Path scope validation, sensitive file blocking, sensitivity ceiling, file size limits |
| TestPlannerHeuristic | 8 | Unit | Heuristic plan decomposition, keyword-to-action mapping |
| TestPlannerLLMParsing | 4 | Unit | LLM response parsing, malformed plan rejection |
| TestExecutor | 6 | Integration | Step execution dispatch, tool firewall calls, budget tracking |
| TestAgentAPI | 17 | Integration | HTTP endpoint contracts, input validation, task CRUD lifecycle, workspace ID resolution |
| TestSecurityInvariants | 7 | Security | Fail-closed behavior, airlock/firewall bypass prevention, service-down handling |
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

## Shell Checks

All shell scripts under `files/system/` are validated with `shellcheck`. This is enforced in CI.

## CI Pipeline

CI is defined in `.github/workflows/ci.yml` and runs on every push and pull request.

Steps:
1. Lint shell scripts with shellcheck
2. Run Go tests (`go test ./...`)
3. Lint Python (py_compile for all service modules including agent)
4. Run Python tests (`pytest tests/`) — includes agent tests
5. Validate YAML configs (policy, agent, recipes)

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
pip install pytest flask requests pyyaml
pytest tests/
```

To run a specific test file:

```bash
pytest tests/test_pipeline.py
pytest tests/test_search.py
pytest tests/test_agent.py
```

### Shell checks

```bash
shellcheck files/system/usr/libexec/secure-ai/*.sh
```
