# GPU Integrity Watch

**Service:** `secure-ai-gpu-integrity-watch.service`
**Binary:** `/usr/libexec/secure-ai/gpu-integrity-watch`
**Port:** 8495 (loopback only)
**Language:** Go

## Purpose

Continuous GPU runtime integrity verification. Monitors the GPU hardware and driver stack to detect tampering, unexpected changes, or anomalies that could compromise model execution trust. Reports incidents and publishes authenticated completed-cycle evidence. Main runtime-attestor bundle/recovery/UI adoption is a separate pending integration stage; this producer alone does not establish end-to-end GPU attestation.

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

`POST /v1/attest-state` uses a dedicated challenge/response protocol. GET and the old raw `GPUAttestState` response are retired. The existing monitoring bearer token does not authorize this route, and the evidence key does not authorize action routes.

A request contains exactly `schema_version: 1`, the producer's fixed `scope` (`runtime` or `bootstrap`), a fresh 64-lowercase-hex `request_nonce`, and `request_mac`. Requests use HMAC-SHA256 over the UTF-8 domain `SecAI GPU evidence request v1`, a NUL byte, and canonical JSON with `request_mac` empty. Responses use the distinct domain `SecAI GPU evidence response v1` and canonical JSON with `response_mac` empty. Canonicalization sorts object keys recursively and preserves JSON numbers. The key is never transmitted in a header or payload.

The response contains schema, fixed scope, echoed nonce, random producer instance, latest sequence, availability/reason, snapshot and response MAC. A snapshot has actual cycle start/completion times, exact loaded profile/baseline hashes, baseline state, verdict/composite score, and a sorted list of typed probe IDs/types/statuses/scores/reason codes. It excludes raw findings, prompts, model output, model paths, device paths and driver-detail strings. Each snapshot is published atomically after its selected probe run and scoring; readers cannot mix cycles. A new invalid/aborted cycle clears prior success. Requests do not run probes or refresh cycle timestamps.

No completed cycle is `unavailable` with a null snapshot. Missing required baseline is `unverified`, not healthy; an observed critical verdict remains critical. A loaded baseline hash identifies bytes, not operator approval. Source authentication is also separate from trust: consumers verify MAC/nonce and independently approved profile/baseline/probe coverage, healthy/all-pass results and bounded cycle freshness. Stale/unknown/critical evidence cannot satisfy that policy check. The native runtime attestor now includes separate bootstrap and runtime evidence in schema-2 bundles; UI and agent action admission and incident recovery require the current runtime decision. See [runtime attestor](runtime-attestor.md) for policy and startup ordering. This wiring does not establish native hardware qualification.

Limits: 4 KiB requests, 64 KiB responses, 64 probes, 8 concurrent evidence requests, one retained completed snapshot, 5-second exchange deadline and at most 1,000 existing scoring-history entries. Profile/baseline inputs are protected, bounded regular files; credential copies must be owner-only, single-link canonical 256-bit hex files. JSON rejects unknown/missing/null-required fields, duplicate Unicode-equivalent keys and trailing data. Native client origins are numeric loopback with an explicit port; proxies and redirects are disabled.

The native bootstrap daemon binds `127.0.0.1:8492`; the runtime daemon binds
`127.0.0.1:8495`, and the probe adapter binds `127.0.0.1:8497`. The MCP
firewall retains `127.0.0.1:8496`. Attestation pins the matching dedicated
endpoint for each GPU scope.

The first appliance target is the RTX 5080. The observed development device
reports ECC mode and counters as unavailable, so its bootstrap/runtime profiles
disable ECC and require the supported driver/device checks plus runtime model
hash and sentinel checks. These profiles cannot claim ECC assurance. Approval
pins remain empty until the Fedora hardware and model are qualified; Ubuntu
driver observations do not enroll a release. An ECC-capable hardware release
must explicitly enable and require its ECC probe. The ECC parser rejects
unavailable or malformed telemetry and preserves the worst result across GPUs.

The runtime GPU unit fixes `scope=runtime` and loads only `gpu-runtime-attestation-hmac.key`. The separate native bootstrap unit fixes `scope=bootstrap`, uses `gpu-bootstrap-attestation-hmac.key`, and rejects model/inference probe types. A dedicated authenticated probe adapter performs only approved bounded runtime reference requests. The measured policy explicitly selects `required`, `optional`, or `no_gpu`; shipped required approvals are empty and cannot pass until a reviewed release supplies them. An approved CPU-only release enforces CPU execution. Compose does not define equivalent attestation services or scoped readiness wiring, so compose GPU attestation remains unsupported.

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
- **Native runtime baseline:** `/etc/secure-ai/gpu-integrity/runtime-baseline.yaml`
- **Audit log:** `/var/lib/secure-ai/logs/gpu-integrity-audit.jsonl`

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `INTEGRITY_PROFILE` | `profiles/default-profile.yaml` | Profile YAML path |
| `SERVICE_TOKEN_PATH` | (required) | Monitoring/action bearer credential file |
| `GPU_ATTESTATION_SCOPE` | (required) | Fixed producer scope; shipped unit uses `runtime` |
| `GPU_ATTESTATION_KEY_PATH` | (required) | Dedicated scope-specific HMAC credential file, never a bearer token |
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

`-profile FILE` overrides `INTEGRITY_PROFILE`, including when it is the final
argument pair. Repeated selectors use the last supplied profile.

Driver evidence currently measures the reported version and module name. An
enrolled `module_hash` returns an error until a module-binary measurement source
is implemented; the daemon cannot publish healthy evidence by skipping that
requirement. A sysfs lifecycle status file is not a module binary, and an on-disk
binary hash would not by itself authenticate loaded kernel memory.

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
| POST | `/v1/check` | Bearer | Trigger full probe cycle |
| GET | `/v1/status` | Bearer | Latest verdict, trend, probes, actions |
| GET | `/v1/history` | Bearer | Score history array |
| GET | `/v1/metrics` | Bearer | Counter metrics |
| POST | `/v1/attest-state` | Dedicated request MAC | Authenticated immutable completed-cycle snapshot |
| POST | `/v1/baseline` | Bearer | Disabled; offline enrollment required (403) |
| POST | `/v1/reload` | Bearer | Disabled; supervised maintenance restart required (409) |

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

The `TestGPUEvidence*` suite uses synthetic probes, clocks and keys for authentication, atomic publication, privacy, baseline/freshness/coverage rejection, malformed frames, source substitution and bounded exchange tests. It performs no physical GPU probes. Existing probe tests may access hardware and must be selected deliberately.

```bash
cd services/gpu-integrity-watch
go test -race -run '^TestGPUEvidence' -timeout=45s ./...
```

## Related

- [Runtime Attestor](runtime-attestor.md) -- signed-bundle consumer integration pending
- [Incident Recorder](incident-recorder.md) -- receives GPU integrity incidents
- [Integrity Monitor](integrity-monitor.md) -- continuous file integrity
- [Architecture](../architecture.md) -- system design overview
- [Threat Model](../threat-model.md) -- GPU-related threat classes
