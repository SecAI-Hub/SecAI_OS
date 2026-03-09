# Security Test Matrix

This document maps each security feature to its corresponding test files, test counts, and coverage areas.

Last updated: 2026-03-08

## Security Feature to Test Mapping

| Security Feature | Test File | Language | Approx. Tests | Key Areas Covered |
|-----------------|-----------|----------|---------------|-------------------|
| Quarantine pipeline | tests/test_pipeline.py | Python | ~96 | 7-stage scanning, pass/fail logic, malformed input handling |
| PII stripping | tests/test_search.py | Python | ~27 | Email, phone, SSN, address redaction from search queries |
| Injection detection | tests/test_search.py | Python | ~27 | Prompt injection, command injection, query sanitization |
| Memory protection | tests/test_memory_protection.py | Python | ~37 | Swap encryption, zswap disabling, core dump prevention, mlock enforcement, TEE detection |
| Traffic analysis resistance | tests/test_traffic_analysis.py | Python | ~41 | Packet padding, timing jitter, dummy traffic, traffic shaping |
| Differential privacy | tests/test_differential_privacy.py | Python | ~37 | Noise injection, epsilon/delta budgets, query indistinguishability |
| Clipboard isolation | tests/test_clipboard_isolation.py | Python | ~30 | Clipboard access controls, paste sanitization, cross-context isolation |
| Canary/tripwire system | tests/test_canary_tripwire.py | Python | ~49 | Token placement, filesystem tripwires, tamper detection, alerting |
| Emergency wipe | tests/test_emergency_wipe.py | Python | ~65 | 3-level panic escalation, secure deletion, vault destruction, recovery prevention |
| Update verification | tests/test_update_rollback.py | Python | ~74 | Signature verification, rollback triggers, version pinning, recovery |
| Vault auto-lock | tests/test_vault_watchdog.py | Python | ~18 | Idle detection, lock timer, UI lock/unlock controls |
| Web UI security | tests/test_ui.py | Python | ~11 | Route protection, input validation, CSP headers |
| Tool firewall | services/tool-firewall/*_test.go | Go | 10 | Default-deny policy, rule evaluation, egress filtering |
| Airlock | services/airlock/*_test.go | Go | 10 | Request sanitization, policy enforcement, disabled-by-default |
| Trusted registry | services/registry/*_test.go | Go | 6 | Hash pinning, cosign verification, model fetch authorization |

## Coverage by Security Category

### Data Protection

| Area | Tests | Notes |
|------|-------|-------|
| PII stripping | ~27 | Redacts personal data from outbound search queries |
| Clipboard isolation | ~30 | Prevents data leakage through clipboard |
| Differential privacy | ~37 | Statistical privacy guarantees for search patterns |
| Emergency wipe | ~65 | Secure destruction of all sensitive data |

### Network Security

| Area | Tests | Notes |
|------|-------|-------|
| Tool firewall | 10 | Default-deny egress, allowlist enforcement |
| Airlock | 10 | Controlled network access with sanitization |
| Traffic analysis resistance | ~41 | Prevents metadata-based surveillance |

### System Integrity

| Area | Tests | Notes |
|------|-------|-------|
| Quarantine pipeline | ~96 | 7-stage model scanning before trust |
| Trusted registry | 6 | Hash pinning and signature verification |
| Canary/tripwire system | ~49 | Tamper detection across filesystem |
| Update verification | ~74 | Signed updates with automatic rollback |

### Runtime Protection

| Area | Tests | Notes |
|------|-------|-------|
| Memory protection | ~37 | Prevents secrets from leaking to disk |
| Vault auto-lock | ~18 | Automatic vault lock on idle |
| Web UI security | ~11 | CSRF, CSP, input validation |

## Total Test Counts

| Language | Security Tests | Non-Security Tests | Total |
|----------|---------------|-------------------|-------|
| Python | ~530+ | ~65 | ~595+ |
| Go | 26 | 0 | 26 |
| **Total** | **~556+** | **~65** | **~621+** |

## Running Security Tests

To run all security-related Python tests:

```bash
pytest tests/test_pipeline.py tests/test_search.py tests/test_memory_protection.py \
       tests/test_traffic_analysis.py tests/test_differential_privacy.py \
       tests/test_clipboard_isolation.py tests/test_canary_tripwire.py \
       tests/test_emergency_wipe.py tests/test_update_rollback.py \
       tests/test_vault_watchdog.py tests/test_ui.py
```

To run all Go security tests:

```bash
cd services/registry && go test ./...
cd services/tool-firewall && go test ./...
cd services/airlock && go test ./...
```
