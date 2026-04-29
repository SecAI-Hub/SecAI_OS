# Security Test Matrix

This document maps each security feature to its corresponding test files, test counts, and coverage areas.

Last updated: 2026-04-29

## Security Feature to Test Mapping

| Security Feature | Test File | Language | Tests / Scope | Key Areas Covered |
|-----------------|-----------|----------|---------------|-------------------|
| Quarantine pipeline | tests/test_quarantine_pipeline.py | Python | 13 | 7-stage scanning, pass/fail logic, malformed input handling, YARA rule behavior |
| PII stripping | tests/test_search.py | Python | 36 file total | Email, phone, SSN, address redaction from search queries |
| Injection detection | tests/test_search.py | Python | 36 file total | Prompt injection, command injection, query sanitization |
| Memory protection | tests/test_memory_protection.py | Python | 37 | Swap encryption, zswap disabling, core dump prevention, mlock enforcement, TEE detection |
| Traffic analysis resistance | tests/test_traffic_analysis.py | Python | 41 | Packet padding, timing jitter, dummy traffic, traffic shaping |
| Differential privacy | tests/test_differential_privacy.py | Python | 37 | Noise injection, epsilon/delta budgets, query indistinguishability |
| Clipboard isolation | tests/test_clipboard_isolation.py | Python | 30 | Clipboard access controls, paste sanitization, cross-context isolation |
| Canary/tripwire system | tests/test_canary_tripwire.py | Python | 49 | Token placement, filesystem tripwires, tamper detection, alerting |
| Emergency wipe | tests/test_emergency_wipe.py | Python | 65 | 3-level panic escalation, secure deletion, vault destruction, recovery prevention |
| Update verification | tests/test_update_rollback.py | Python | 74 | Signature verification, rollback triggers, version pinning, recovery |
| Vault auto-lock | tests/test_vault_watchdog.py | Python | 21 | Idle detection, lock timer, UI lock/unlock controls |
| Web UI security | tests/test_ui.py, tests/test_ui_cookies.py, tests/test_ui_file_handling.py | Python | 79 total | Route protection, input validation, CSP/cookie headers, upload/path handling |
| Tool firewall | services/tool-firewall/*_test.go | Go | 15 | Default-deny policy, rule evaluation, egress filtering |
| Airlock | services/airlock/*_test.go | Go | 11 | Request sanitization, policy enforcement, disabled-by-default |
| Trusted registry | services/registry/*_test.go | Go | 22 | Hash pinning, cosign verification, model fetch authorization |
| GPU integrity watch | services/gpu-integrity-watch/*_test.go | Go | 62 | GPU probe scoring, baseline verification, degradation actions, daemon mode, driver fingerprint, device allowlist, attestor/incident integration |
| MCP firewall | services/mcp-firewall/*_test.go | Go | 71 | MCP tool call policy, default-deny, input redaction, taint tracking, adversarial coverage |
| Policy engine | services/policy-engine/*_test.go | Go | 45 | Unified decisions across 6 domains, evidence provenance, auth |
| Runtime attestor | services/runtime-attestor/*_test.go | Go | 55 | TPM2 quote verification, HMAC bundles, state machine, startup gating, service digest verification |
| Integrity monitor | services/integrity-monitor/*_test.go | Go | 50 | Baseline computation, continuous scanning, violation detection, state machine, model/binary/policy watching |
| Incident recorder | services/incident-recorder/*_test.go | Go | 97 | Incident creation, auto-containment, lifecycle, severity ranking, policy loading, recovery and forensic export |
| Agent verified supervisor + HSM keys | tests/test_agent.py | Python | 172 | HMAC-SHA256 token signing, nonce replay protection, expiry, tamper detection, two-phase approval, policy evidence, keystore abstraction (software/TPM2/PKCS#11), key rotation, key derivation |
| CI app-security lint | .github/scripts/check-hadolint.sh, .github/scripts/run-semgrep.sh | Shell / Semgrep | CI gate | Containerfile/Dockerfile linting and repo-owned Semgrep security rules |

## Coverage by Security Category

### Data Protection

| Area | Tests | Notes |
|------|-------|-------|
| PII stripping | 36 file total | Redacts personal data from outbound search queries |
| Clipboard isolation | 30 | Prevents data leakage through clipboard |
| Differential privacy | 37 | Statistical privacy guarantees for search patterns |
| Emergency wipe | 65 | Secure destruction of all sensitive data |

### Network Security

| Area | Tests | Notes |
|------|-------|-------|
| Tool firewall | 15 | Default-deny egress, allowlist enforcement |
| Airlock | 11 | Controlled network access with sanitization |
| MCP firewall | 71 | MCP tool call policy, input redaction, taint tracking |
| Traffic analysis resistance | 41 | Prevents metadata-based surveillance |

### System Integrity

| Area | Tests | Notes |
|------|-------|-------|
| Quarantine pipeline | 13 pipeline tests plus scanner-specific release/config checks | 7-stage model scanning before trust |
| Trusted registry | 22 | Hash pinning and signature verification |
| Canary/tripwire system | 49 | Tamper detection across filesystem |
| Update verification | 74 | Signed updates with automatic rollback |
| GPU integrity | 62 | GPU probe scoring, baseline, degradation, driver fingerprint, device allowlist, attestor/incident integration |
| Runtime attestation | 55 | TPM2 quotes, HMAC bundles, state machine, startup gating |
| Continuous integrity | 50 | Baseline scanning, violation detection, model/binary/policy watching |
| Incident recorder | 97 | Incident creation, auto-containment, lifecycle, severity ranking |
| Agent verified supervisor + HSM keys | 172 | HMAC tokens, nonce replay, two-phase approval, policy evidence, keystore (software/TPM2/PKCS#11) |

### Runtime Protection

| Area | Tests | Notes |
|------|-------|-------|
| Memory protection | 37 | Prevents secrets from leaking to disk |
| Vault auto-lock | 21 | Automatic vault lock on idle |
| Web UI security | 79 total | CSRF, CSP, cookie flags, input validation, upload/path handling |

## Total Test Counts

| Language | Current Automated Tests | Source of Truth |
|----------|--------------------------|-----------------|
| Python | 1132 | `docs/test-counts.json` and `pytest --collect-only` |
| Go | 428 | `docs/test-counts.json` and `go test -v -count=1 ./...` |
| **Total** | **1560** | Enforced by `.github/scripts/check-test-counts.sh` |

Security coverage overlaps heavily with functional coverage, so the feature tables above use exact file or service totals rather than attempting to split each test into exclusive "security" and "non-security" buckets.

## Running Security Tests

To run all security-related Python tests:

```bash
PYTHONPATH=services python -m pytest \
       tests/test_quarantine_pipeline.py tests/test_search.py tests/test_memory_protection.py \
       tests/test_traffic_analysis.py tests/test_differential_privacy.py \
       tests/test_clipboard_isolation.py tests/test_canary_tripwire.py \
       tests/test_emergency_wipe.py tests/test_update_rollback.py \
       tests/test_vault_watchdog.py tests/test_ui.py tests/test_ui_cookies.py \
       tests/test_ui_file_handling.py -v
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
