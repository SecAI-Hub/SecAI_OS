# Test Coverage Matrix

This document summarizes the test coverage for SecAI_OS across all languages and test categories.

Last updated: 2026-03-10

## Summary

| Language | Test Count | Runner |
|----------|-----------|--------|
| Go | 26 | `go test ./...` |
| Python | 677+ | `pytest` |
| Shell | All .sh files | `shellcheck` |

## Go Tests (26 total)

| Service | Location | Tests | Description |
|---------|----------|-------|-------------|
| Registry | services/registry/ | 6 | Trusted model registry, hash pinning, cosign verification |
| Tool Firewall | services/tool-firewall/ | 10 | Default-deny egress policy, rule evaluation |
| Airlock | services/airlock/ | 10 | Online airlock, request sanitization, policy enforcement |

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
| test_agent.py | tests/ | ~93 | Agent policy engine, capability tokens, storage gateway, budgets, planner, executor, API, workspace validation, security invariants |

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
