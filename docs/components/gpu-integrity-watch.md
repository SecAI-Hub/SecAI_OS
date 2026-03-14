# GPU Integrity Watch

**Service:** `secure-ai-gpu-integrity-watch.service`
**Binary:** `/usr/libexec/secure-ai/gpu-integrity-watch`
**Port:** 8495 (loopback only)
**Language:** Go

## Purpose

Continuous GPU runtime integrity verification. Monitors the GPU hardware and driver stack to detect tampering, unexpected changes, or anomalies that could compromise model execution trust. Integrates with the runtime attestor and incident recorder for end-to-end GPU security.

## Architecture

GPU Integrity Watch runs as a daemon that periodically probes the GPU subsystem and scores results against a trusted baseline. If the score exceeds a configurable threshold, it triggers degradation actions and reports incidents.

```
+-----------+     +-----------+     +-----------+     +-------------------+
| Probes    | --> | Scoring   | --> | Actions   | --> | Integrations      |
| (6 types) |     | (weighted |     | (degrade, |     | - incident-recorder|
|           |     |  history) |     |  alert,   |     | - runtime-attestor |
|           |     |           |     |  disable) |     |                   |
+-----------+     +-----------+     +-----------+     +-------------------+
```

## Probes

| Probe | Type | Default Weight | What It Checks |
|-------|------|--------|----------------|
| Tensor Hash | `tensor_hash` | 1.0 | SHA-256 of model files vs baseline |
| Sentinel Inference | `sentinel_inference` | 1.0 | Known input/output pairs for behavioral consistency |
| Reference Drift | `reference_drift` | 0.8 | Multi-pass variance detection (corruption signature) |
| ECC Status | `ecc_status` | 0.6 | GPU memory error counters (nvidia-smi) |
| Driver Fingerprint | `driver_fingerprint` | 1.0 | GPU driver version + kernel module identity vs baseline |
| Device Allowlist | `device_allowlist` | 0.8 | GPU device nodes (/dev/dri/*, /dev/nvidia*) vs expected list |

### Verdict Classification

| Composite Score | Verdict |
|----------------|---------|
| 0.0 - 0.3 | `healthy` |
| 0.3 - 0.9 | `warning` |
| >= 0.9 or any probe `fail` | `critical` |

## Integrations

### Runtime Attestor

The `/v1/attest-state` endpoint returns a `GPUAttestState` summary that the runtime attestor can include in the signed attestation bundle:

```json
{
  "timestamp": "2026-03-13T12:00:00Z",
  "verdict": "healthy",
  "composite_score": 0.0,
  "probe_statuses": {"hash": "pass", "driver": "pass"},
  "driver_version": "565.57.01",
  "device_nodes": ["/dev/dri/card0", "/dev/dri/renderD128"],
  "trend": 0.0
}
```

### Incident Recorder

On `warning` or `critical` verdicts, GPU Integrity Watch automatically reports incidents to the incident-recorder service (`http://127.0.0.1:8515`). Incident classes are mapped from probe failures:

| Probe Failure | Incident Class | Severity |
|--------------|----------------|----------|
| Tensor hash fail | `manifest_mismatch` | critical |
| ECC uncorrected errors | `integrity_violation` | critical |
| Driver fingerprint change | `integrity_violation` | high |
| Device allowlist fail | `integrity_violation` | high |
| Other anomalies | `model_behavior_anomaly` | high |

## Configuration

- **Profile:** `/etc/secure-ai/gpu-integrity/default-profile.yaml`
- **Baseline:** `/var/lib/secure-ai/gpu-integrity/baseline.yaml`
- **Audit log:** `/var/lib/secure-ai/logs/gpu-integrity-audit.jsonl`

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `INTEGRITY_PROFILE` | `profiles/default-profile.yaml` | Profile YAML path |
| `SERVICE_TOKEN` | (none) | Bearer token for protected endpoints |
| `AUDIT_LOG` | (none) | JSONL audit log path |
| `INCIDENT_RECORDER_URL` | (from profile) | Override incident-recorder URL |

## CLI Commands

```bash
gpu-integrity-watch check      # Run probes once, exit 0/1/2
gpu-integrity-watch watch      # Continuous foreground monitoring
gpu-integrity-watch daemon     # HTTP daemon + background monitoring
gpu-integrity-watch baseline   # Capture baseline hashes
gpu-integrity-watch status     # Query daemon status
```

## Actions

| Action | Type | Trigger | Effect |
|--------|------|---------|--------|
| Alert | `alert` | warning | Send webhook or log alert |
| Reload | `reload` | warning | Signal inference server to reload model |
| Quarantine | `quarantine` | critical | Move model files to quarantine directory |
| Fail Closed | `fail_closed` | critical | Shut down inference server |

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | No | Liveness check |
| POST | `/v1/check` | No | Trigger full probe cycle |
| GET | `/v1/status` | No | Latest verdict, trend, probes, actions |
| GET | `/v1/history` | No | Score history array |
| GET | `/v1/metrics` | No | Counter metrics |
| GET | `/v1/attest-state` | No | GPU attestation state for runtime-attestor |
| POST | `/v1/baseline` | Token | Recapture baseline from model directory |
| POST | `/v1/reload` | Token | Reload profile and baseline from disk |

## Systemd Hardening

| Mechanism | Setting |
|-----------|---------|
| Dynamic user | `DynamicUser=yes` |
| Filesystem | `ProtectSystem=strict`, `ProtectHome=yes` |
| Network | `RestrictAddressFamilies=AF_UNIX AF_INET`, localhost only |
| Capabilities | `CapabilityBoundingSet=` (empty) |
| Memory | `MemoryDenyWriteExecute=yes` |
| Seccomp | Custom seccomp-BPF profile |
| Landlock | Read: `/etc/secure-ai`, `/sys/class/drm`, `/sys/bus/pci/devices`, `/dev/dri`; Write: `/var/lib/secure-ai/logs`, `/var/lib/secure-ai/gpu-integrity` |

## Test Coverage

81 tests covering:
- Tensor hash probes (5 tests)
- Sentinel inference/drift probes (3 tests)
- ECC status parsing (5 tests)
- Similarity computation (4 tests)
- Scoring engine (7 tests)
- Action execution (5 tests)
- Integration pipeline (2 tests)
- HTTP endpoints (10 tests)
- Token authentication (3 tests)
- Driver fingerprint probes (5 tests)
- Device allowlist probes (5 tests)
- Attestation state building (3 tests)
- Incident classification (4 tests)
- New probe integration (2 tests)
- Scoring with new weights (1 test)

```bash
cd services/gpu-integrity-watch && go test -v -race ./...
```

## Related

- [Runtime Attestor](runtime-attestor.md) -- consumes GPU attest-state
- [Incident Recorder](incident-recorder.md) -- receives GPU integrity incidents
- [Integrity Monitor](integrity-monitor.md) -- continuous file integrity
- [Architecture](../architecture.md) -- system design overview
- [Threat Model](../threat-model.md) -- GPU-related threat classes
