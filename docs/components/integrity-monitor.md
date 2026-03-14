# Integrity Monitor

The integrity monitor continuously verifies the SHA-256 hashes of all critical files (service binaries, policy files, promoted models, systemd units, and trust material) against an HMAC-signed baseline. It replaces the 15-minute timer-based integrity check with 30-second continuous scanning and automatic state transitions.

## Overview

| Property | Value |
|----------|-------|
| Port | 8510 |
| Language | Go |
| Binary | `/usr/libexec/secure-ai/integrity-monitor` |
| Config | `/etc/secure-ai/policy/integrity-monitor.yaml` |
| Systemd unit | `secure-ai-integrity-monitor.service` |
| Audit log | `/var/lib/secure-ai/logs/integrity-monitor-audit.jsonl` |

## State Machine

```
  +---------+
  | trusted |  (all files match baseline)
  +----+----+
       |
  1+ violations
       |
  +----v-----+
  | degraded |  (some files changed, below threshold)
  +----+-----+
       |
  violations >= threshold
       |
  +----v-----------+
  | recovery_req.  |  (too many violations, appliance compromised)
  +----------------+
```

**Transitions:**
- `trusted` -> `degraded`: 1+ files differ from baseline
- `trusted` -> `recovery_required`: violations >= `degradation_threshold` (default: 3)
- `degraded` -> `trusted`: Rebaseline or all files restored
- `degraded` -> `recovery_required`: Violations accumulate past threshold

## Watched File Categories

| Category | Examples | Action on Violation |
|----------|---------|-------------------|
| `service_binary` | registry, tool-firewall, etc. | `degrade_appliance` |
| `policy_file` | policy.yaml, agent.yaml | `reload_policy` |
| `model_file` | *.gguf in registry dir | `quarantine_model` |
| `systemd_unit` | secure-ai-*.service | `degrade_appliance` |
| `trust_material` | cosign.pub | `degrade_appliance` |

## Signed Baselines

At startup, the monitor computes a baseline of all watched files. Each baseline entry contains:

| Field | Description |
|-------|-------------|
| `path` | Absolute file path |
| `hash` | SHA-256 hex digest |
| `category` | Watch category (service_binary, policy_file, etc.) |
| `size` | File size in bytes |

The baseline itself is HMAC-signed to prevent tampering. If the HMAC key is not available, baselines are marked "unsigned".

## API Endpoints

### `GET /health`
Service health and current integrity state.

### `GET /api/v1/status`
Full status including watched file count, violation count, and active violations.

### `GET /api/v1/baseline`
Returns the current signed baseline manifest.

### `GET /api/v1/verify`
Lightweight check: 200 if trusted, 503 if degraded or recovery_required.

### `POST /api/v1/scan` (token required)
Forces an immediate integrity scan.

### `POST /api/v1/rebaseline` (token required)
Recomputes the baseline from current file state. Clears all violations and resets state to trusted.

### `POST /api/v1/reload` (token required)
Reloads the monitor policy from disk.

## Configuration

The monitor policy (`/etc/secure-ai/policy/integrity-monitor.yaml`) controls:

| Key | Default | Description |
|-----|---------|-------------|
| `scan_interval` | `30s` | How often to scan all watched files |
| `service_binaries` | All Go service paths | Binaries to monitor |
| `policy_files` | policy.yaml + agent.yaml + more | Policy files to monitor |
| `model_dirs` | `/var/lib/secure-ai/registry` | Directories containing model files |
| `systemd_units` | Critical service units | Systemd units to monitor |
| `trust_material` | cosign.pub | Trust anchors to monitor |
| `hmac_key_path` | `/run/secure-ai/integrity-hmac-key` | HMAC key for baseline signing |
| `degradation_threshold` | `3` | Violations before recovery_required state |

## Comparison with Previous Approach

| Feature | Timer-based (integrity-check.sh) | Continuous (integrity-monitor) |
|---------|--------------------------------|-------------------------------|
| Scan interval | 15 minutes | 30 seconds |
| Watched files | Models only | Binaries + policies + models + units + trust |
| Baseline | None (live registry API) | HMAC-signed manifest |
| State machine | ok/failed | trusted/degraded/recovery_required |
| API | File-based result | HTTP API with scan/rebaseline/verify |
| Language | Bash | Go |
| Rebaseline | N/A | POST /api/v1/rebaseline |

## Hardening

- **Systemd sandbox:** DynamicUser, ProtectSystem=strict, MemoryDenyWriteExecute, no capabilities
- **Seccomp-BPF:** Allowlisted syscalls only
- **Landlock:** Read-only access to service binaries, policies, models, systemd units; write to audit logs only
- **Resource limits:** 256M memory (hashes large model files), 15% CPU, 32 tasks

## Tests

42 tests covering:
- Policy loading (defaults, from YAML, invalid, missing fields)
- File hashing (valid, missing, deterministic)
- Baseline computation (with files, sorted, HMAC with/without key, verification)
- Integrity scanning (no violations, modified file, deleted file, many violations -> recovery_required)
- Counter tracking (scan count, degraded count)
- Action determination (per-category actions)
- HTTP endpoints (health, status, baseline, scan, rebaseline, reload, verify)
- Token authentication (no config, requires bearer, invalid, valid)
- Audit logging (violations logged)
- Model directory watching (model tamper detection)
- Rebaseline after tampering (clears violations)

Run tests:
```bash
cd services/integrity-monitor && go test -v -race ./...
```
