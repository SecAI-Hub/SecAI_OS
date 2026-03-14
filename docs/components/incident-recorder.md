# Incident Recorder

Security event capture and automated containment service.

## Overview

The incident recorder provides a formal incident management workflow for SecAI_OS. When security events are detected by other services (runtime attestor, integrity monitor, tool firewall, airlock, policy engine), they report incidents to this service. The recorder captures full incident details, applies automatic containment actions per policy, and tracks the incident lifecycle from detection through resolution.

## Architecture

```
                    +-----------------------+
   attestor ------->|                       |
   integrity ------>|   Incident Recorder   |---> Audit Log (JSONL)
   policy-engine -->|       :8515           |
   tool-firewall -->|                       |---> Containment Actions
   airlock -------->|                       |     (freeze, disable, relock)
                    +-----------------------+
                              |
                    incident-containment.yaml
```

## Incident Classes

| Class | Auto-Contain | Default Severity | Containment Actions |
|-------|-------------|-----------------|---------------------|
| `attestation_failure` | Yes | Critical | freeze_agent, disable_airlock, force_vault_relock |
| `policy_bypass_attempt` | Yes | High | freeze_agent, log_alert |
| `manifest_mismatch` | Yes | High | quarantine_model, freeze_agent |
| `forbidden_airlock_request` | No | Medium | log_alert |
| `prompt_injection` | Yes | High | freeze_agent, log_alert |
| `tool_call_burst` | Yes | Medium | freeze_agent |
| `model_behavior_anomaly` | Yes | High | quarantine_model, log_alert |
| `integrity_violation` | Yes | Critical | freeze_agent, disable_airlock, force_vault_relock |
| `unauthorized_access` | Yes | Critical | freeze_agent, force_vault_relock, log_alert |

## Incident Lifecycle

```
                  report
                    |
                    v
               +--------+
               |  Open  |
               +---+----+
                   |
          auto_contain=true?
          /              \
        yes               no
         |                |
         v                |
   +------------+         |
   | Contained  |         |
   +-----+------+         |
         |                |
    resolve / acknowledge
         |                |
         v                v
   +----------+    +--------------+
   | Resolved |    | Acknowledged |
   +----------+    +--------------+
```

**States:**
- **open** — Incident reported, no containment applied yet (or auto_contain=false)
- **contained** — Automatic containment actions have been applied
- **resolved** — Human operator has resolved the root cause
- **acknowledged** — Human operator has reviewed but deferred resolution

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | No | Health check |
| GET | `/api/v1/incidents` | No | List incidents (filtered by `?class=`, `?state=`, `?severity=`) |
| GET | `/api/v1/incidents/get` | No | Get single incident by `?id=` |
| GET | `/api/v1/stats` | No | Incident statistics (counts by state, class, severity) |
| POST | `/api/v1/incidents/report` | Token | Report a new incident |
| POST | `/api/v1/incidents/resolve` | Token | Mark incident as resolved |
| POST | `/api/v1/incidents/acknowledge` | Token | Acknowledge incident |
| POST | `/api/v1/reload` | Token | Reload containment policy |

### Report Incident

```bash
curl -X POST http://127.0.0.1:8515/api/v1/incidents/report \
  -H "Authorization: Bearer $(cat /run/secure-ai/service-token)" \
  -H "Content-Type: application/json" \
  -d '{
    "class": "attestation_failure",
    "source": "runtime-attestor",
    "description": "TPM2 PCR mismatch detected on PCR 7",
    "evidence": {"expected_pcr7": "abc123", "actual_pcr7": "def456"}
  }'
```

### List Incidents

```bash
# All open critical incidents
curl "http://127.0.0.1:8515/api/v1/incidents?state=open&severity=critical"

# All attestation failures
curl "http://127.0.0.1:8515/api/v1/incidents?class=attestation_failure"
```

### Resolve Incident

```bash
curl -X POST http://127.0.0.1:8515/api/v1/incidents/resolve \
  -H "Authorization: Bearer $(cat /run/secure-ai/service-token)" \
  -H "Content-Type: application/json" \
  -d '{"id": "INC-20260313-abc123"}'
```

## Configuration

### Containment Policy (`/etc/secure-ai/policy/incident-containment.yaml`)

```yaml
version: 1

rules:
  attestation_failure:
    auto_contain: true
    actions:
      - freeze_agent
      - disable_airlock
      - force_vault_relock
    default_severity: critical

  policy_bypass_attempt:
    auto_contain: true
    actions:
      - freeze_agent
      - log_alert
    default_severity: high
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BIND_ADDR` | `127.0.0.1:8515` | Listen address |
| `CONTAINMENT_POLICY_PATH` | `/etc/secure-ai/policy/incident-containment.yaml` | Containment policy file |
| `AUDIT_LOG_PATH` | `/var/lib/secure-ai/logs/incident-recorder-audit.jsonl` | Audit log location |
| `SERVICE_TOKEN_PATH` | `/run/secure-ai/service-token` | Service token for authenticated endpoints |

## Containment Actions

Containment actions are recorded in the incident record. Integrating services are responsible for implementing the actual containment:

| Action | Implementing Service | Effect |
|--------|---------------------|--------|
| `freeze_agent` | Agent | Pause all agent task execution |
| `disable_airlock` | Airlock | Block all outbound network requests |
| `force_vault_relock` | UI / Vault Watchdog | Lock the encrypted vault immediately |
| `quarantine_model` | Registry | Move suspicious model to quarantine |
| `log_alert` | Incident Recorder | Write critical alert to audit log |

## Hardening

| Mechanism | Setting |
|-----------|---------|
| Dynamic user | `DynamicUser=yes` |
| Filesystem | `ProtectSystem=strict`, `ProtectHome=yes` |
| Network | `RestrictAddressFamilies=AF_UNIX AF_INET`, localhost only |
| Capabilities | `CapabilityBoundingSet=` (empty — no capabilities) |
| Syscalls | `SystemCallFilter=@system-service`, deny `@privileged @resources @mount @clock @debug @swap @reboot @raw-io @module @cpu-emulation @obsolete` |
| Memory | `MemoryDenyWriteExecute=yes`, `MemoryMax=128M` |
| Seccomp | Custom seccomp-BPF profile (default-deny, 5 allowed groups) |
| Landlock | Read: `/etc/secure-ai`, `/run/secure-ai`; Write: `/var/lib/secure-ai/logs` |
| Resources | `CPUQuota=10%`, `TasksMax=32`, `LimitNOFILE=512` |

## Test Coverage

47 tests covering:
- Containment policy loading (3 tests)
- Incident creation and auto-containment (9 tests)
- Incident lifecycle transitions (4 tests)
- Input validation (3 tests)
- HTTP endpoints (18 tests)
- Token authentication (3 tests)
- Audit logging (1 test)
- Containment action verification (3 tests)
- Severity ranking and filtering (3 tests)

```bash
cd services/incident-recorder && go test -v -race ./...
```
