# Security Test Matrix

This document maps each security feature to its corresponding test files, test counts, and coverage areas.

Last updated: 2026-03-13

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
| GPU integrity watch | services/gpu-integrity-watch/*_test.go | Go | 81 | GPU probe scoring, baseline verification, degradation actions, daemon mode, driver fingerprint, device allowlist, attestor/incident integration |
| MCP firewall | services/mcp-firewall/*_test.go | Go | 30+ | MCP tool call policy, default-deny, input redaction, taint tracking |
| Policy engine | services/policy-engine/*_test.go | Go | 37 | Unified decisions across 6 domains, evidence provenance, auth |
| Runtime attestor | services/runtime-attestor/*_test.go | Go | 46 | TPM2 quote verification, HMAC bundles, state machine, startup gating, service digest verification |
| Integrity monitor | services/integrity-monitor/*_test.go | Go | 42 | Baseline computation, continuous scanning, violation detection, state machine, model/binary/policy watching |
| Incident recorder | services/incident-recorder/*_test.go | Go | 47 | Incident creation, auto-containment, lifecycle (open/contained/resolved/acknowledged), severity ranking, policy loading |
| Agent verified supervisor + HSM keys | tests/test_agent.py | Python | 159 | HMAC-SHA256 token signing, nonce replay protection, expiry, tamper detection, two-phase approval, policy evidence, keystore abstraction (software/TPM2/PKCS#11), key rotation, key derivation |

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
| MCP firewall | 30+ | MCP tool call policy, input redaction, taint tracking |
| Traffic analysis resistance | ~41 | Prevents metadata-based surveillance |

### System Integrity

| Area | Tests | Notes |
|------|-------|-------|
| Quarantine pipeline | ~96 | 7-stage model scanning before trust |
| Trusted registry | 6 | Hash pinning and signature verification |
| Canary/tripwire system | ~49 | Tamper detection across filesystem |
| Update verification | ~74 | Signed updates with automatic rollback |
| GPU integrity | 81 | GPU probe scoring, baseline, degradation, driver fingerprint, device allowlist, attestor/incident integration |
| Runtime attestation | 46 | TPM2 quotes, HMAC bundles, state machine, startup gating |
| Continuous integrity | 42 | Baseline scanning, violation detection, model/binary/policy watching |
| Incident recorder | 47 | Incident creation, auto-containment, lifecycle, severity ranking |
| Agent verified supervisor + HSM keys | 159 | HMAC tokens, nonce replay, two-phase approval, policy evidence, keystore (software/TPM2/PKCS#11) |

### Runtime Protection

| Area | Tests | Notes |
|------|-------|-------|
| Memory protection | ~37 | Prevents secrets from leaking to disk |
| Vault auto-lock | ~18 | Automatic vault lock on idle |
| Web UI security | ~11 | CSRF, CSP, input validation |

## Total Test Counts

| Language | Security Tests | Non-Security Tests | Total |
|----------|---------------|-------------------|-------|
| Python | ~596+ | ~65 | ~661+ |
| Go | 309+ | 0 | 309+ |
| **Total** | **~905+** | **~65** | **~970+** |

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
cd services/gpu-integrity-watch && go test ./...
cd services/mcp-firewall && go test ./...
cd services/policy-engine && go test ./...
cd services/runtime-attestor && go test ./...
cd services/integrity-monitor && go test ./...
cd services/incident-recorder && go test ./...
```
