# Security Test Matrix

This document maps each security feature to its corresponding test files, test counts, and coverage areas.

Last updated: 2026-08-02

## Security Feature to Test Mapping

| Security Feature | Test File | Language | Tests / Scope | Key Areas Covered |
|-----------------|-----------|----------|---------------|-------------------|
| Quarantine pipeline | tests/test_quarantine_pipeline.py | Python | 51 | 7-stage scanning, provenance, pass/fail logic, malformed input handling, and YARA behavior |
| PII stripping | tests/test_search.py | Python | 37 file total | Email, phone, SSN, address redaction from search queries |
| Injection detection | tests/test_search.py | Python | 37 file total | Prompt injection, command injection, query sanitization |
| Memory protection | tests/test_memory_protection.py | Python | 33 | Swap encryption, zswap disabling, core dump prevention, mlock enforcement, TEE detection |
| Traffic analysis resistance | tests/test_traffic_analysis.py | Python | 41 | Packet padding, timing jitter, dummy traffic, traffic shaping |
| Differential privacy | tests/test_differential_privacy.py | Python | 37 | Noise injection, epsilon/delta budgets, query indistinguishability |
| Clipboard isolation | tests/test_clipboard_isolation.py | Python | 19 | Clipboard access controls, paste sanitization, cross-context isolation |
| Canary/tripwire system | tests/test_canary_tripwire.py | Python | 49 | Token placement, filesystem tripwires, tamper detection, alerting |
| Emergency containment | tests/test_emergency_wipe.py | Python | 20 | Three-level panic escalation, fail-closed vault handling, and recovery boundaries |
| Update verification | tests/test_update_rollback.py | Python | 80 | Signature verification, rollback triggers, version pinning, recovery |
| Vault auto-lock | tests/test_vault_watchdog.py | Python | 32 | Idle detection, exact mount identity, local-console lock/unlock, and web-secret rejection |
| Web UI security | tests/test_ui.py, tests/test_ui_cookies.py, tests/test_ui_file_handling.py | Python | 139 total | Route protection, input validation, exact control credentials, session-bound generation readiness, CSP/cookie headers, setup completion, upload/path handling |
| Tool firewall | services/tool-firewall/*_test.go | Go | 32 | Default-deny typed-argument policy, nested blocklists and path constraints, strict request decoding, audit redaction and file-identity checks, and fail-closed allowed decisions |
| Airlock | services/airlock/*_test.go | Go | 27 | Request sanitization, policy enforcement, disabled-by-default |
| Trusted registry | services/registry/*_test.go | Go | 36 | Hash pinning, cosign verification, model fetch authorization |
| GPU integrity watch | services/gpu-integrity-watch/*_test.go | Go | 63 | GPU probe scoring, baseline verification, degradation actions, daemon mode, driver fingerprint, device allowlist, attestor/incident integration |
| MCP firewall | services/mcp-firewall/*_test.go | Go | 71 | MCP tool call policy, default-deny, input redaction, taint tracking, adversarial coverage |
| Policy engine | services/policy-engine/*_test.go | Go | 45 | Unified decisions across 6 domains, evidence provenance, auth |
| Runtime attestor | services/runtime-attestor/*_test.go | Go | 64 | TPM2 quote verification, HMAC bundles, state machine, startup gating, service digest verification |
| Integrity monitor | services/integrity-monitor/*_test.go | Go | 54 | Baseline computation, continuous scanning, violation detection, state machine, model/binary/policy watching |
| Incident recorder | services/incident-recorder/*_test.go | Go | 108 | Incident creation, auto-containment, lifecycle, severity ranking, policy loading, recovery and forensic export |
| Sandbox UI ingress | services/ui-ingress/*_test.go | Go | 6 | Uncredentialed fixed routes, bounded relaying, dual UI/controller health, current protocol identity, and fail-closed upstream errors |
| Sandbox host controller | tests/test_sandbox_control_server.py | Python | 70 | Exact high-entropy signing keys, request HMACs, restart-persistent nonce replay protection, token-nondisclosing protocol probes, session/profile-bound state proofs, bounded HTTP concurrency, manifest-backed generation/profile reads, pinned runtime/safe host binds, cross-platform process-tree cancellation, and verified shutdown |
| Podman control-network anchor | tests/test_podman_anchor.py | Python | 5 | Exact image/identity hardening, project-only gateway lifecycle, stopped and orphan recovery, and owner-only state |
| Agent verified supervisor + HSM keys | tests/test_agent.py | Python | 191 | HMAC-SHA256 token signing, nonce replay protection, expiry, tamper detection, two-phase approval, policy evidence, fail-closed tool-firewall responses, keystore abstraction (software/TPM2/PKCS11), key rotation, key derivation |
| Hardware qualification evidence | tests/test_hardware_qualification.py | Python | 6 | Recursive identifier redaction, allowlisted host evidence, scoped SELinux and Podman security state, owner-only atomic reports, and explicit non-certification |
| CI app-security lint | .github/scripts/check-hadolint.sh, .github/scripts/run-semgrep.sh | Shell / Semgrep | CI gate | Containerfile/Dockerfile linting and repo-owned Semgrep security rules |

## Coverage by Security Category

### Data Protection

| Area | Tests | Notes |
|------|-------|-------|
| PII stripping | 37 file total | Redacts personal data from outbound search queries |
| Clipboard isolation | 19 | Prevents data leakage through clipboard |
| Differential privacy | 37 | Statistical privacy guarantees for search patterns |
| Emergency containment | 20 | Executes staged fail-closed panic controls without exposing recovery secrets |

### Network Security

| Area | Tests | Notes |
|------|-------|-------|
| Tool firewall | 32 | Default-deny typed arguments, nested constraints, audit file-identity checks, and fail-closed enforcement |
| Airlock | 27 | Controlled network access with sanitization |
| MCP firewall | 71 | MCP tool call policy, input redaction, taint tracking |
| Traffic analysis resistance | 41 | Prevents metadata-based surveillance |

### System Integrity

| Area | Tests | Notes |
|------|-------|-------|
| Quarantine pipeline | 51 pipeline tests plus scanner-specific isolation suites | 7-stage model scanning before trust |
| Trusted registry | 36 | Hash pinning and signature verification |
| Canary/tripwire system | 49 | Tamper detection across filesystem |
| Update verification | 80 | Signed updates with automatic rollback |
| GPU integrity | 63 | GPU probe scoring, baseline, degradation, driver fingerprint, device allowlist, attestor/incident integration |
| Runtime attestation | 64 | TPM2 quotes, HMAC bundles, state machine, startup gating |
| Continuous integrity | 54 | Baseline scanning, violation detection, model/binary/policy watching |
| Incident recorder | 108 | Incident creation, auto-containment, lifecycle, severity ranking |
| Agent verified supervisor + HSM keys | 191 | HMAC tokens, nonce replay, two-phase approval, policy evidence, fail-closed tool-firewall responses, keystore (software/TPM2/PKCS11) |
| Hardware qualification evidence | 6 | Redacts machine identifiers while recording scoped SELinux and Podman security state without self-certifying the host |

### Runtime Protection

| Area | Tests | Notes |
|------|-------|-------|
| Memory protection | 33 | Prevents secrets from leaking to disk |
| Vault auto-lock | 32 | Automatic vault lock on idle |
| Web UI security | 139 total | CSRF, CSP, cookie flags, setup completion, exact control credentials, session-bound sandbox readiness, input validation, upload/path handling |
| Sandbox UI ingress | 6 | Keeps the browser entry point loopback-only, validates both relay paths, and stores no credential in the relay |
| Sandbox host controller | 70 | Bounds authenticated automation, verifies exact protocol/session/profile identity without probe token disclosure, and cancels active process trees before teardown |

## Total Test Counts

| Language | Current Automated Tests | Source of Truth |
|----------|--------------------------|-----------------|
| Python | 1568 | `docs/test-counts.json` and `pytest --collect-only` |
| Go | 506 | `docs/test-counts.json` and `go test -v -count=1 ./...` |
| **Total** | **2074** | Enforced by `.github/scripts/check-test-counts.sh` |

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
       tests/test_ui_file_handling.py tests/test_sandbox.py \
       tests/test_sandbox_bundle.py tests/test_sandbox_control_server.py \
       tests/test_podman_anchor.py tests/test_hardware_qualification.py -v
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
cd services/ui-ingress && go test ./...
```
