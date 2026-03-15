# M5 Control Matrix — Stronger Isolation Acceptance Criteria

This matrix maps each M5 security control to its enforcing component, failure mode, test coverage, and audit evidence. A reviewer or operator can use this matrix to verify that every claimed control is actually implemented, tested, and observable.

Last updated: 2026-03-14

## Control Matrix

| # | Control | Enforcing Component | Failure Mode | Test Covering It | Audit Evidence | Operator Verification |
|---|---------|-------------------|--------------|-----------------|----------------|----------------------|
| 1 | Startup gating via TPM2 attestation | Runtime Attestor (:8505) | Service refuses to start; reports `attestation_failure` to Incident Recorder | `TestPerformAttestation_RequireTPM_FailsInCI`, `TestChain_AttestationFailure_ContainmentDispatched` | `incident-recorder-audit.jsonl` entry class=attestation_failure | `curl http://localhost:8505/health` + `curl http://localhost:8505/api/v1/state` |
| 2 | Continuous file integrity monitoring | Integrity Monitor (:8510) | State transitions to `degraded`; reports violations to Incident Recorder | `TestVerifyBaselineHMAC_Tampered`, `TestChain_IntegrityViolation_FreezeAndDisable` | Baseline scan results + incident report with file paths/hashes | `curl http://localhost:8510/health` + `curl http://localhost:8510/api/v1/state` |
| 3 | Auto-containment on integrity violation | Incident Recorder (:8515) | freeze_agent + disable_airlock + force_vault_relock dispatched | `TestChain_IntegrityViolation_FreezeAndDisable`, `TestExecuteContainment_FreezeAgent` | Containment dispatch logs + target service acknowledgment | `curl http://localhost:8515/api/v1/incidents?class=integrity_violation&state=contained` |
| 4 | Auto-containment on attestation failure | Incident Recorder (:8515) | freeze_agent + disable_airlock + force_vault_relock dispatched | `TestChain_AttestationFailure_ContainmentDispatched` | Incident record with state=contained | `curl http://localhost:8515/api/v1/incidents?class=attestation_failure&state=contained` |
| 5 | Model quarantine on manifest mismatch | Incident Recorder (:8515) → Registry (:8470) | quarantine_model + freeze_agent dispatched | `TestChain_ManifestMismatch_QuarantinesModel` | POST to /api/v1/quarantine with model_path | `curl http://localhost:8470/health` + `curl http://localhost:8515/api/v1/incidents?class=manifest_mismatch` |
| 6 | GPU runtime integrity verification | GPU Integrity Watch (:8495) | Warning/critical verdict triggers incident report | `TestDriverFingerprint_VersionMismatch`, `TestChain_GPUAnomaly_IncidentAndQuarantine` | GPU probe results + incident class=model_behavior_anomaly | `curl http://localhost:8495/health` |
| 7 | Centralised policy decisions (6 domains) | Policy Engine (:8500) | Allow/deny with structured evidence | `TestDecide_ToolAccess_*`, `TestDecide_AgentRisk_*` (37 tests) | PolicyDecision JSON with decision, reason, evidence | `curl http://localhost:8500/health` |
| 8 | Deny-by-default tool firewall | Tool Firewall (:8475) | Unknown tools denied | `TestEvaluate_*` (10 tests) | Audit log with tool name + decision | `curl http://localhost:8475/health` |
| 9 | Deny-by-default MCP firewall | MCP Firewall (:8496) | Unknown servers/tools denied; taint propagation; input redaction | `TestEvaluate_*`, `TestAdversarial_*` (44+ tests) | Hash-chained audit log + signed decision receipts | `curl http://localhost:8496/health` + `curl http://localhost:8496/v1/audit/verify` |
| 10 | HMAC-signed capability tokens | Agent (:8476) capabilities.py | Token verification: expiry, nonce replay, HMAC signature | `TestTokenSigning`, `test_stale_capability_token_rejected`, `test_replayed_capability_token_rejected` | Token ID in agent-audit.jsonl per step | `test_adversarial.py::TestPolicyBypass::test_stale_capability_token_rejected` |
| 11 | Two-phase approval for high-risk actions | Agent (:8476) policy.py | TRUST_CHANGE, EXPORT_DATA, WIDEN_SCOPE etc. always escalated to "ask" | `test_two_phase_actions_require_approval` | PolicyDecision with decision=ask for TWO_PHASE_ACTIONS | `test_adversarial.py::TestPolicyBypass::test_two_phase_actions_require_approval` |
| 12 | Step signature validation | Agent sandbox.py | Step modified between planning and execution is rejected | `test_signed_step_verifies`, `test_tampered_step_fails_verification` | Step signature in audit trail | `test_adversarial.py::TestStepSignature::test_tampered_step_fails_verification` |
| 13 | Per-step capability re-validation | Agent sandbox.py | Path/tool/scope mutations caught at execution time | `test_path_mutation_caught_at_execution`, `test_tool_mutation_caught_at_execution` | Re-validation check in executor log | `test_adversarial.py::TestRevalidation::test_path_mutation_caught_at_execution` |
| 14 | Workspace hard walls | Agent sandbox.py WorkspaceGuard | Symlink escape, cross-workspace FD reuse, hardlink tricks detected | `test_symlink_traversal_blocked`, `test_workspace_id_spoofing_blocked` | Workspace violation log entry | `test_adversarial.py::TestPolicyBypass::test_symlink_traversal_blocked` |
| 15 | Storage gateway blocked paths | Agent storage.py | /etc/shadow, /etc/passwd, policy files, service tokens always blocked | `test_shadow_file_blocked`, `test_service_token_blocked` | Storage gateway deny in audit log | `test_adversarial.py::TestBlockedPaths::test_shadow_file_blocked` |
| 16 | Sensitivity ceiling enforcement | Agent policy.py + storage.py | Files exceeding sensitivity ceiling are blocked | `TestSensitivity_*` | Sensitivity classification in read result | `test_m5_acceptance.py::TestM5_PolicyCentralization::test_always_deny_enforced` |
| 17 | Recovery ceremony after containment | Incident Recorder recovery.go | Require ack + re-attestation before returning to trusted mode | `TestRecovery_CriticalRequiresReattestation` | Recovery requirement record with ack/reattest timestamps | `curl http://localhost:8515/api/v1/recovery/status` |
| 18 | Latched degraded states | Incident Recorder recovery.go | attestation_failure, integrity_violation, unauthorized_access, manifest_mismatch remain latched | `TestLatchedClasses` | Incident state remains until manual review | `go test -run TestLatchedClasses ./services/incident-recorder/...` |
| 19 | Severity escalation | Incident Recorder recovery.go | Repeated medium-severity events escalate per rules | `TestEscalation_RepeatedPromptInjection` | Escalated severity in incident record | `go test -run TestEscalation ./services/incident-recorder/...` |
| 20 | Forensic bundle export | Incident Recorder recovery.go | Signed export of incidents, audit, state, policy digest | `TestForensicBundle_ExportAndVerify`, `TestForensicBundle_TamperDetection` | Forensic bundle JSON with HMAC signature | `curl http://localhost:8515/api/v1/forensic/export -o forensic-bundle.json` |
| 21 | Service token propagation | Incident Recorder containment.go | Bearer token included in all containment HTTP calls | `TestChain_BearerToken_PropagatedToContainment` | Authorization header in containment requests | `go test -run TestChain_BearerToken ./services/incident-recorder/...` |
| 22 | HSM/TPM2 key management | Agent keystore.py | Software/TPM2/PKCS#11 backends with auto-detection | `TestKeystore_*` (31 tests) | Keystore provider name in agent startup log | `journalctl -u secure-ai-agent --grep "keystore provider"` |
| 23 | Prompt injection detection | MCP Firewall global rules | Shell metacharacters and prompt patterns detected and denied | `TestAdversarial_MalformedMCPPayload` | Global rule match in audit log | `go test -run TestAdversarial_MalformedMCPPayload ./services/mcp-firewall/...` |
| 24 | MCP taint tracking | MCP Firewall taint.go | Session-scoped taint propagation prevents data flow violations | `TestAdversarial_TaintBypassAttempt`, `TestTaint_*` | Taint entries per session ID | `go test -run "TestTaint\|TestAdversarial_Taint" ./services/mcp-firewall/...` |
| 25 | SBOM generation verification | CI supply-chain-verify job | Syft generates SBOMs for all services | CI workflow step output | CycloneDX SBOM artifacts | `syft dir:services/registry -o cyclonedx-json` (repeat per service) |
| 26 | Release provenance attestation | Release workflow (release.yml) | cosign attest with SLSA3 provenance | CI workflow attestation step | Signed provenance attestation | `cosign verify-attestation --type slsa ghcr.io/sec_ai/secai_os:latest` |

## End-to-End Enforcement Paths

### Path 1: Bad Attestation → Service Startup Blocked
```
Runtime Attestor detects TPM2 quote mismatch
  → State transitions to "failed"
  → POST to Incident Recorder: class=attestation_failure, severity=critical
  → Incident Recorder creates incident with auto-containment
  → Containment: freeze_agent + disable_airlock + force_vault_relock
  → Recovery: requires operator ack + re-attestation ceremony
```
**Test:** `TestChain_AttestationFailure_ContainmentDispatched`

### Path 2: Baseline Mismatch → Degraded → Incident → Containment
```
Integrity Monitor detects file hash mismatch
  → State transitions to "degraded"
  → POST to Incident Recorder: class=integrity_violation, severity=high
  → Incident Recorder creates incident with auto-containment
  → Containment: freeze_agent + disable_airlock + force_vault_relock
  → State latched until manual review
```
**Test:** `TestChain_IntegrityViolation_FreezeAndDisable`

### Path 3: High-Risk Agent Action → Two-Phase Approval
```
Agent planner proposes TRUST_CHANGE step
  → Policy engine evaluate_with_evidence: decision="ask"
  → Step remains PENDING until user approves via /v1/task/<id>/approve
  → On approval: token re-verified, step signature re-checked
  → Executor re-validates capability before execution
```
**Test:** `test_two_phase_actions_require_approval`

### Path 4: MCP Request with Tainted Input → Deny/Sanitize
```
MCP Firewall receives request from tainted session
  → TaintState checked for session: external-data label found
  → TaintRule "no-external-to-write" matches target tool
  → Decision: deny with reason "taint rule violation"
  → Audit entry with taint evidence
```
**Test:** `TestAdversarial_TaintBypassAttempt`

## Operator Verification

An operator can verify the enforcement chain is active by:

1. **Check service health:** `curl http://localhost:8515/health` — incident recorder reports open incident count
2. **Check recovery status:** `curl http://localhost:8515/api/v1/recovery/status` — pending recovery ceremonies
3. **Export forensic bundle:** `curl http://localhost:8515/api/v1/forensic/export` — signed evidence package
4. **Check attestation state:** `curl http://localhost:8505/api/v1/state` — current attestation status
5. **Check integrity state:** `curl http://localhost:8510/api/v1/state` — current integrity baseline status
6. **Verify audit chain:** `curl http://localhost:8496/v1/audit/verify` — MCP firewall audit chain integrity
