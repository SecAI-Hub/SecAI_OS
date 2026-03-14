# Runtime Attestor

The runtime attestor verifies the integrity of the appliance at boot and periodically, producing HMAC-signed attestation bundles that downstream services can use to gate startup and detect drift.

## Overview

| Property | Value |
|----------|-------|
| Port | 8505 |
| Language | Go |
| Binary | `/usr/libexec/secure-ai/runtime-attestor` |
| Config | `/etc/secure-ai/policy/attestation.yaml` |
| Systemd unit | `secure-ai-runtime-attestor.service` |
| Audit log | `/var/lib/secure-ai/logs/runtime-attestor-audit.jsonl` |

## State Machine

```
     +----------+
     | pending  |  (initial state at service start)
     +----+-----+
          |
    performAttestation()
          |
    +-----+------+-------+
    |             |       |
    v             v       v
+--------+  +---------+  +------+
|attested|  |degraded |  |failed|
+---+----+  +----+----+  +------+
    |            |
    +----+-------+  (periodic refresh can transition between attested/degraded)
         |
    performAttestation()
```

**State transitions:**
- `pending` -> `attested`: All checks pass (service binaries present, no policy violations)
- `pending` -> `degraded`: Non-critical failures (missing binary, hash drift)
- `pending` -> `failed`: Critical failures (TPM required but absent, Secure Boot required but disabled)
- `attested` -> `degraded`: Periodic refresh detects drift
- `degraded` -> `attested`: Periodic refresh re-verifies successfully

## Startup Gating

The attestor starts **before** all other security services. The systemd ordering chain is:

```
runtime-attestor
    -> policy-engine
        -> registry, tool-firewall, agent, airlock, mcp-firewall, inference
```

Other services can call `/api/v1/verify` during startup to check attestation state. If the attestor is in `degraded` or `failed` state, the verify endpoint returns HTTP 503, allowing services to refuse to start or enter a restricted mode.

## Runtime State Bundle

Each attestation produces a signed bundle containing:

| Field | Description |
|-------|-------------|
| `timestamp` | ISO 8601 timestamp of attestation |
| `state` | Current attestation state |
| `boot_measurements` | Secure Boot status, TPM2 PCR values |
| `deployment_digest` | SHA-256 of rpm-ostree deployment status |
| `service_digests` | SHA-256 hashes of all service binaries |
| `policy_digest` | SHA-256 of all policy files combined |
| `registry_manifest_hash` | SHA-256 of registry manifest |
| `kernel_cmdline` | Current kernel command line |
| `kernel_lockdown` | Kernel lockdown state |
| `tpm_available` | Whether TPM2 hardware is present |
| `tpm_quote_verified` | Whether TPM2 PCR values match expected |
| `failures` | List of verification failures (if any) |
| `bundle_hmac` | HMAC-SHA256 signature of the bundle |

## API Endpoints

### `GET /health`
Returns service health and current attestation state.

**Response:**
```json
{
  "status": "ok",
  "state": "attested"
}
```

### `GET /api/v1/attest`
Returns the current attestation state and full bundle.

**Response:**
```json
{
  "state": "attested",
  "bundle": { ... }
}
```

### `GET /api/v1/verify`
Lightweight verification endpoint for startup gating. Returns 200 if attested, 503 otherwise.

**Response (attested):**
```json
{
  "verified": true,
  "state": "attested"
}
```

**Response (not attested):**
```json
{
  "verified": false,
  "state": "degraded"
}
```

### `POST /api/v1/refresh` (token required)
Forces an immediate re-attestation and returns the new bundle.

### `GET /api/security/status`
Extended status with attestation counters and diagnostics.

**Response:**
```json
{
  "attestation_state": "attested",
  "tpm_available": false,
  "tpm_quote_verified": false,
  "secure_boot": false,
  "policy_digest": "abc123...",
  "deployment_digest": "def456...",
  "service_count": 6,
  "failure_count": 0,
  "last_attested": "2026-03-13T12:00:00Z",
  "attest_count": 5,
  "degrade_count": 0,
  "fail_count": 0
}
```

## Configuration

The attestation policy (`/etc/secure-ai/policy/attestation.yaml`) controls:

| Key | Default | Description |
|-----|---------|-------------|
| `require_tpm` | `false` | Require TPM2 hardware for attestation |
| `require_secure_boot` | `false` | Require UEFI Secure Boot enabled |
| `expected_pcrs` | `{}` | Map of PCR index to expected SHA-256 value |
| `service_binaries` | All Go services | Map of service name to binary path |
| `policy_files` | policy.yaml + agent.yaml | Policy files to hash |
| `refresh_interval` | `5m` | How often to re-attest |
| `hmac_key_path` | `/run/secure-ai/attestation-hmac-key` | Path to HMAC signing key |

## Hardening

- **Systemd sandbox:** DynamicUser, ProtectSystem=strict, MemoryDenyWriteExecute, no capabilities
- **Seccomp-BPF:** Allowlisted syscalls only (includes execve for tpm2_pcrread/rpm-ostree)
- **Landlock:** Read-only access to EFI vars, sysfs, service binaries, policies; write to audit logs only
- **PrivateNetwork:** No (needs localhost HTTP for verify endpoint and external command execution)
- **Resource limits:** 128M memory, 10% CPU, 32 tasks, no core dumps

## Tests

46 tests covering:
- Attestation policy loading (defaults, YAML, validation)
- Service digest collection (present, missing, deterministic, different)
- Policy digest computation (valid, missing, deterministic, order-sensitive)
- HMAC bundle signing (no key, with key, deterministic, different keys, correctness)
- Attestation state machine (no requirements, missing binary, valid binary, TPM required)
- Counter tracking (attest count, degrade count)
- HTTP endpoints (health, attest, verify, refresh, security status)
- Token authentication (no config, requires bearer, invalid, valid)
- Audit logging
- Graceful degradation (no TPM, no Secure Boot, no rpm-ostree)

Run tests:
```bash
cd services/runtime-attestor && go test -v -race ./...
```
