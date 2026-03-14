# Recovery Runbook — Operator Procedures

This runbook documents the operational procedures for responding to security incidents, recovering from degraded states, and exporting forensic evidence. All commands target the Incident Recorder service at `localhost:8515`.

Last updated: 2026-03-14

---

## Degradation Triggers

The system enters a degraded or contained state when any of the following events occur:

| Event | Incident Class | Default Severity | Containment Actions |
|-------|---------------|-----------------|-------------------|
| TPM2 attestation quote mismatch | `attestation_failure` | critical | `freeze_agent`, `disable_airlock`, `force_vault_relock` |
| File integrity baseline mismatch | `integrity_violation` | critical | `freeze_agent`, `disable_airlock`, `force_vault_relock` |
| Unauthorized access attempt | `unauthorized_access` | critical | `freeze_agent`, `force_vault_relock`, `log_alert` |
| Model manifest hash mismatch | `manifest_mismatch` | high | `quarantine_model`, `freeze_agent` |
| Policy bypass attempt | `policy_bypass_attempt` | high | `freeze_agent`, `log_alert` |
| Prompt injection detected | `prompt_injection` | high | `freeze_agent`, `log_alert` |
| Rapid tool call burst | `tool_call_burst` | medium | `freeze_agent` |
| Model behavior anomaly (GPU) | `model_behavior_anomaly` | high | `quarantine_model`, `log_alert` |
| Forbidden airlock request | `forbidden_airlock_request` | medium | `log_alert` (no auto-containment) |

When auto-containment triggers, the incident state transitions from `open` to `contained`, and the listed containment actions execute immediately against their target services.

---

## Containment Latch Behavior

### Latched Incident Classes

Four incident classes are **latched**, meaning the system remains in a degraded/contained state until an operator explicitly reviews and acknowledges the incident. Latched incidents cannot be auto-resolved.

| Latched Class | Why It Latches |
|--------------|---------------|
| `attestation_failure` | Trust root compromise. The system cannot self-verify its own integrity. |
| `integrity_violation` | File tampering detected. Root cause must be identified before resuming. |
| `unauthorized_access` | Credential or access boundary breach. Forensic review required. |
| `manifest_mismatch` | Model supply chain violation. Model provenance must be re-verified. |

### What "Latched" Means Operationally

1. The incident remains in `contained` state indefinitely -- no timeout, no auto-clear.
2. All containment actions (agent freeze, airlock disable, vault relock) remain active.
3. The agent cannot execute tasks, the airlock rejects all outbound requests, and the vault is locked.
4. The system will not return to `trusted` mode without completing the full recovery ceremony (see below).
5. Non-latched incident classes (e.g., `prompt_injection`, `tool_call_burst`) can be resolved directly without re-attestation.

### Checking Latch State

```bash
# Check for latched incidents
curl -s http://localhost:8515/api/v1/incidents?state=contained | jq '.[] | {id, class, severity, state}'
```

---

## Acknowledgment Procedure

Acknowledging an incident records that an operator has reviewed the incident details, understands the root cause, and accepts responsibility for the recovery.

### Step 1: Review the Incident

```bash
# List all open/contained incidents
curl -s http://localhost:8515/api/v1/incidents?state=contained | jq .

# Get details of a specific incident
curl -s "http://localhost:8515/api/v1/incidents/get?id=INC-20260314-120000-0001" | jq .
```

Review the incident record fields:
- `class` -- what type of security event
- `severity` -- how urgent
- `evidence` -- what was detected (file paths, hashes, model paths, etc.)
- `containment_actions` -- what actions were taken automatically
- `created_at` -- when the event occurred

### Step 2: Check Recovery Requirements

```bash
# See what recovery steps are pending
curl -s http://localhost:8515/api/v1/recovery/status | jq .
```

Response example:
```json
{
  "pending_recoveries": [
    {
      "incident_id": "INC-20260314-120000-0001",
      "require_ack": true,
      "require_reattest": true,
      "acked_at": "",
      "acked_by": "",
      "re_attested_at": "",
      "recovery_complete": false
    }
  ],
  "count": 1
}
```

### Step 3: Acknowledge the Incident

```bash
curl -s -X POST http://localhost:8515/api/v1/recovery/ack \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "INC-20260314-120000-0001",
    "operator": "admin@secai"
  }' | jq .
```

Expected response:
```json
{
  "status": "acknowledged"
}
```

The incident record now has `acked_at` and `acked_by` populated. If the incident only requires acknowledgment (non-critical, non-latched), recovery is now complete and the system can return to trusted mode.

---

## Re-Attestation Procedure

For critical incidents and latched classes (`attestation_failure`, `integrity_violation`), acknowledgment alone is not sufficient. The operator must also trigger a re-attestation to re-establish the trust root.

### When Re-Attestation Is Required

Re-attestation is required when:
- The incident severity is `critical`, OR
- The incident class is `attestation_failure`, OR
- The incident class is `integrity_violation`

### Step 1: Fix the Root Cause

Before re-attesting, address the underlying issue:
- **attestation_failure**: Verify TPM2 state, check for firmware updates, ensure PCR values match expected configuration.
- **integrity_violation**: Identify changed files, verify they are legitimate updates or restore from known-good state. Re-run integrity baseline if the change is authorized.

### Step 2: Trigger Re-Attestation

```bash
curl -s -X POST http://localhost:8515/api/v1/recovery/reattest \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "INC-20260314-120000-0001"
  }' | jq .
```

Expected response:
```json
{
  "status": "re-attestation recorded"
}
```

### Step 3: Verify Recovery Is Complete

```bash
curl -s http://localhost:8515/api/v1/recovery/status | jq .
```

If both acknowledgment and re-attestation are recorded, the recovery requirement shows:
```json
{
  "pending_recoveries": [],
  "count": 0
}
```

---

## Return to Trusted Mode — Full Ceremony Flow

This is the complete recovery ceremony for a critical latched incident. Follow each step in order.

### 1. Detect the Incident

```bash
# Check health — non-zero open_incidents indicates degradation
curl -s http://localhost:8515/health | jq .
# Response: {"status":"ok","open_incidents":1,"total_incidents":5}
```

### 2. Identify the Incident

```bash
# List contained incidents
curl -s http://localhost:8515/api/v1/incidents?state=contained | jq .
```

Note the `id` field of the incident you need to recover from. Example: `INC-20260314-120000-0001`.

### 3. Review Evidence and Root Cause

```bash
# Get full incident details
curl -s "http://localhost:8515/api/v1/incidents/get?id=INC-20260314-120000-0001" | jq .
```

Examine the `evidence` field. For `integrity_violation`, this contains file paths and mismatched hashes. For `attestation_failure`, this contains the TPM2 state that failed.

### 4. Fix the Root Cause

This is operator-specific. Examples:
- Restore tampered files from a known-good backup
- Update the integrity baseline if the change was authorized
- Fix TPM2 configuration
- Remove or re-verify a quarantined model

### 5. Check Recovery Requirements

```bash
curl -s http://localhost:8515/api/v1/recovery/status | jq .
```

### 6. Acknowledge the Incident

```bash
curl -s -X POST http://localhost:8515/api/v1/recovery/ack \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "INC-20260314-120000-0001",
    "operator": "admin@secai"
  }' | jq .
# Response: {"status":"acknowledged"}
```

### 7. Trigger Re-Attestation (if required)

```bash
curl -s -X POST http://localhost:8515/api/v1/recovery/reattest \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "INC-20260314-120000-0001"
  }' | jq .
# Response: {"status":"re-attestation recorded"}
```

### 8. Verify Recovery Complete

```bash
curl -s http://localhost:8515/api/v1/recovery/status | jq .
# Response: {"pending_recoveries":[],"count":0}
```

### 9. Resolve the Incident

```bash
curl -s -X POST http://localhost:8515/api/v1/incidents/resolve \
  -H "Content-Type: application/json" \
  -d '{"id": "INC-20260314-120000-0001"}' | jq .
# Response: incident record with state="resolved" and resolved_at timestamp
```

### 10. Verify System Health

```bash
# Incident recorder health
curl -s http://localhost:8515/health | jq .
# Expected: {"status":"ok","open_incidents":0,...}

# Attestation state
curl -s http://localhost:8505/api/v1/state | jq .
# Expected: state="trusted"

# Integrity state
curl -s http://localhost:8510/api/v1/state | jq .
# Expected: state="trusted"
```

---

## Forensic Export

The forensic bundle is a signed evidence package containing all incidents, audit log entries, system state, and a policy digest. It is HMAC-signed using the service token to ensure tamper detection.

### Export a Forensic Bundle

```bash
curl -s http://localhost:8515/api/v1/forensic/export -o forensic-bundle.json
```

### Inspect the Bundle

```bash
# View bundle metadata
jq '{exported_at, bundle_hash, signature}' forensic-bundle.json

# Count incidents in the bundle
jq '.incidents | length' forensic-bundle.json

# List incident IDs and classes
jq '.incidents[] | {id, class, severity, state}' forensic-bundle.json

# View system state snapshot
jq '.system_state' forensic-bundle.json

# View audit entries
jq '.audit_entries' forensic-bundle.json
```

### Verify Bundle Integrity

The bundle includes a SHA-256 hash over its contents and an HMAC signature using the service token. To verify programmatically:

1. Extract `bundle_hash` and `signature` from the bundle JSON.
2. Recompute SHA-256 over the serialized `{exported_at, incidents, audit_entries, system_state, policy_digest}` fields.
3. Compare the computed hash to `bundle_hash`.
4. If you have the service signing key, verify the HMAC-SHA256 signature of the `bundle_hash`.

The Go test `TestForensicBundle_ExportAndVerify` demonstrates this verification flow. The test `TestForensicBundle_TamperDetection` confirms that any modification to the bundle (e.g., changing an incident ID) causes verification to fail.

```bash
# Run the forensic bundle verification tests
cd services/incident-recorder && go test -v -race -run TestForensicBundle ./...
```

### Preserving the Bundle for Audit

```bash
# Save with timestamp in filename
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
curl -s http://localhost:8515/api/v1/forensic/export -o "forensic-bundle-${TIMESTAMP}.json"

# Compute an independent checksum
sha256sum "forensic-bundle-${TIMESTAMP}.json" > "forensic-bundle-${TIMESTAMP}.sha256"
```

---

## Severity Escalation Reference

The system automatically escalates incident severity when repeated events of the same class occur within a time window. These rules are built into the Incident Recorder:

| Incident Class | Threshold | Window | Escalates To |
|---------------|-----------|--------|-------------|
| `prompt_injection` | 3 events | 5 minutes | critical |
| `tool_call_burst` | 5 events | 1 minute | high |
| `policy_bypass_attempt` | 2 events | 10 minutes | critical |
| `forbidden_airlock_request` | 5 events | 5 minutes | high |
| `model_behavior_anomaly` | 3 events | 15 minutes | critical |

When escalation triggers, the incident is upgraded to the higher severity level, which may trigger additional containment actions (e.g., an escalated `prompt_injection` at `critical` level will require re-attestation during recovery).

---

## Incident Statistics

```bash
# Overall incident statistics
curl -s http://localhost:8515/api/v1/stats | jq .
```

Response includes:
- `total_incidents` -- total incidents recorded since service start
- `open_incidents` -- currently open or contained incidents
- `contained_count` -- incidents that triggered auto-containment
- `resolved_count` -- incidents that have been resolved
- `by_class` -- breakdown by incident class
- `open_by_severity` -- open incidents grouped by severity
