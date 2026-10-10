# Runtime Attestor

The runtime attestor verifies the integrity of the appliance at boot and
periodically. On qualified bare metal, it issues a fresh 256-bit challenge to
the TPM, runs `tpm2_quote`, verifies the signature and nonce with
`tpm2_checkquote`, and compares the authenticated quoted PCR blob with the
locally enrolled PCR 0/2/4/7 baseline. It then emits a canonical,
HMAC-SHA256-authenticated evidence bundle.

## Overview

| Property | Value |
|----------|-------|
| Port | 8505 |
| Language | Go |
| Binary | `/usr/libexec/secure-ai/runtime-attestor` |
| Config | `/etc/secure-ai/policy/attestation.yaml` |
| Hardware profile | `/var/lib/secure-ai/tpm-attestation/profile.json` (root `0600`) |
| AK public key | `/var/lib/secure-ai/tpm-attestation/ak-public.pem` (root `0600`) |
| Persistent AK handle | `0x81010020` |
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
- `pending` -> `attested`: All checks required by the explicit hardware or
  evaluation profile pass
- `pending` -> `degraded`: Non-critical failures (missing binary, hash drift)
- `pending` -> `failed`: Critical failures (TPM required but absent, Secure Boot required but disabled)
- `attested` -> `degraded`: Periodic refresh detects drift
- `degraded` -> `attested`: Periodic refresh re-verifies successfully

## Startup Gating

The attestor starts only after the signed boot check, first-boot hardware
detection, and TPM enrollment service. The systemd ordering chain separates
independent GPU bootstrap checks from checks that need the loaded model:

```
boot-verify + firstboot + gpu-bootstrap
    -> tpm-attestation-setup
        -> runtime-attestor
    -> policy-engine
        -> registry, tool-firewall, airlock, mcp-firewall, inference
            -> gpu-integrity-watch (full runtime)
```

The attestor's startup gate calls `/api/v1/verify/bootstrap`, explicitly scoped
to the existing boot checks and independent GPU prerequisites. Ordinary
`/api/v1/verify` represents full runtime assurance; bootstrap success cannot
satisfy it. Chat admission, agent planning and each agent execution step check
that full result, including fresh GPU cycle evidence. Management and recovery
endpoints remain available while these actions are blocked.

`verified` means cryptographically verified hardware evidence only.
`policy_satisfied` requires verified evidence for a hardware profile, while
an explicitly generated VM evaluation profile may start limited evaluation
services without claiming hardware assurance. A missing profile is never
silently treated as evaluation in the production unit.

The release-measured `gpu` policy explicitly chooses `required`, `optional`, or
`no_gpu`. GPU scopes pin exact reviewed profile/baseline bytes, required probe
IDs/types and bounded cycle ages. The shipped required policy has empty pins
and an unenrolled bootstrap baseline: it deliberately cannot pass until a
reviewed release supplies those approvals. Producer observations never enroll
themselves. Optional GPU checks can permit bootstrap, but missing or rejected
live evidence still blocks full runtime trust. A CPU-only release explicitly
uses `gpu: {mode: no_gpu}` without GPU scopes; the inference selector enforces
zero GPU offload even if hardware detection requests it. Device absence or
failed probes never choose this mode automatically.

Bundles use `schema_version: 2`, with separate signed bootstrap state and GPU
bootstrap/runtime outcomes. Old bundles cannot satisfy current incident
recovery. A recovery GPU cycle must start and finish after containment; a fresh
TPM quote or nonce over an older GPU cycle does not qualify. Both full verify
and recovery gates reject expired evidence. Native GPU access and dependent
live probe integration require separate qualification; synthetic tests do not
establish physical GPU assurance.

## Runtime State Bundle

Each attestation produces a schema-2 signed bundle containing:

- Separate bootstrap and full runtime GPU scope evidence, explicit policy mode,
  approved input pins, probe coverage, cycle times and authenticated sequence identity

| Field | Description |
|-------|-------------|
| `timestamp` | ISO 8601 timestamp of attestation |
| `state` | Current attestation state |
| `assurance_mode` | `hardware` or explicit `evaluation` |
| `evidence_verified` | True only for the complete hardware trust chain |
| `request_nonce` | Fresh 256-bit request/quote challenge |
| `boot_measurements` | Secure Boot status, TPM2 PCR values |
| `deployment_digest` | SHA-256 of rpm-ostree deployment status |
| `service_digests` | SHA-256 hashes of all service binaries |
| `policy_digest` | SHA-256 of all policy files combined |
| `registry_manifest_hash` | SHA-256 of registry manifest |
| `kernel_cmdline` | Current kernel command line |
| `kernel_lockdown` | Kernel lockdown state |
| `tpm_available` | Whether TPM2 hardware is present |
| `tpm_quote_verified` | `tpm2_checkquote` verified the AK signature and fresh nonce |
| `tpm_measurements_verified` | Authenticated quoted PCR blob and live PCRs match enrollment |
| `tpm_ak_public_key_sha256` | SHA-256 of the AK public key used by `tpm2_checkquote` |
| `tpm_quote_pcr_selection` | Exact quoted PCR bank and indexes |
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

### `GET /api/v1/attest` (service token required)
Returns the current attestation state and full bundle.

**Response:**
```json
{
  "state": "attested",
  "bundle": { ... }
}
```

### `GET /api/v1/verify` (service token required)
Lightweight verification endpoint for startup gating. Returns 200 if attested, 503 otherwise.

**Response (attested):**
```json
{
  "verified": true,
  "policy_satisfied": true,
  "state": "attested",
  "assurance_mode": "hardware",
  "evidence_verified": true
}
```

**Response (not attested):**
```json
{
  "verified": false,
  "policy_satisfied": false,
  "state": "failed",
  "assurance_mode": "hardware",
  "evidence_verified": false
}
```

### `POST /api/v1/refresh` (token required)

Forces an immediate re-attestation. Recovery callers send a fresh challenge:

```json
{"request_nonce":"64-lowercase-hex-characters"}
```

The same nonce is bound into `tpm2_quote`, returned as `request_nonce`, and
covered by the bundle HMAC. An empty request is supported for local periodic
operations and causes the attestor to generate its own nonce.

### `GET /api/security/status` (service token required)
Extended status with attestation counters and diagnostics.

**Response:**
```json
{
  "attestation_state": "attested",
  "assurance_mode": "hardware",
  "evidence_verified": true,
  "tpm_available": true,
  "tpm_quote_verified": true,
  "secure_boot": true,
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

The policy is mandatory: a missing or unsafe file stops startup instead of
selecting defaults. It must be one version-1 YAML document, at most 1 MiB, with
known fields, canonical measurement paths, valid SHA-256 PCR values and a
refresh interval between one second and 24 hours. Group- or world-writable
files, symlinks and special files are rejected.

The image finalizer installs the shipped policy as a regular `root:root` file
with mode `0644` before generating its release measurement. This does not depend
on the source checkout's group-write bits or the file-copy module's defaults.

Release verification always includes this policy, even when `policy_files`
omits it. The release baseline must match the exact bytes loaded by the
attestor, and changes to the file after loading invalidate verification.

| Key | Shipped value | Description |
|-----|---------|-------------|
| `require_tpm` | `false` | Compatibility floor; a hardware enrollment profile always overrides this to true |
| `require_secure_boot` | `false` | Require UEFI Secure Boot enabled |
| `expected_pcrs` | `{}` | Map of PCR index to expected SHA-256 value |
| `service_binaries` | Explicit service list | Map of service name to binary path |
| `policy_files` | Explicit policy and unit list | Policy files to hash; the attestation policy is always release-verified |
| `refresh_interval` | `5m` | How often to re-attest |
| `hmac_key_path` | systemd credential | Canonical 256-bit HMAC key; missing or malformed credentials stop startup |

## Enrollment and PCR changes

`secure-ai-tpm-attestation-setup.service` runs after first boot and signed-boot
verification. Bare metal must have Secure Boot and a usable TPM. The service
creates or validates the ECC AK at `0x81010020`, refuses a foreign handle
collision, verifies a fresh quote, and atomically commits the public key and
profile as root-only files. It flushes only TPM contexts created by its own
invocation. After initial enrollment, boot-time setup validates the signed
deployment, AK, quote, and PCRs against the existing profile without rewriting
the baseline. Only the physical-console `reenroll` command below can replace
that baseline.

VMs receive an explicit `evaluation` profile. A host-controlled vTPM is not
accepted as bare-metal hardware assurance, and evaluation mode cannot complete
the re-attestation step for a latched critical incident.

After a legitimate signed firmware, Secure Boot database, bootloader, or OS
change alters PCRs, inspect the change from a physical Linux virtual console
(`/dev/ttyN`, not SSH, a pseudo-terminal, or automation) and re-enroll:

```bash
sudo /usr/libexec/secure-ai/secure-tpm-attestation.py \
  reenroll --confirm ENROLL-ATTESTATION
sudo systemctl restart secure-ai-runtime-attestor.service
```

Never re-enroll merely to clear an unexplained attestation failure.

## Hardening

- **Systemd sandbox:** DynamicUser, ProtectSystem=strict, MemoryDenyWriteExecute, no capabilities
- **TPM device DAC:** Dynamic user receives the Fedora `tss` group and an
  explicit device-cgroup allowlist for `/dev/tpmrm0` and `/dev/tpm0`
- **Bounded tools:** PCR read, quote, checkquote, and rpm-ostree commands have
  five-second per-command deadlines and bounded output
- **Landlock:** Read-only access to EFI vars, sysfs, service binaries, policies; write to audit logs only
- **PrivateNetwork:** No (needs localhost HTTP for verify endpoint and external command execution)
- **Resource limits:** 128M memory, 10% CPU, 32 tasks, no core dumps

## Tests

Tests cover:
- Attestation policy loading (required file, bounded strict YAML, unsafe files and validation)
- Loaded-policy identity, mandatory release inclusion and changes after loading
- Service digest collection (present, missing, deterministic, different)
- Policy digest computation (valid, missing, deterministic, order-sensitive)
- HMAC bundle signing (no key, with key, deterministic, different keys, correctness)
- Attestation state machine, hardware/evaluation distinction, and fail-closed TPM policy
- Fresh nonce binding, AK mismatch, quote/checkquote failure, and PCR baseline mismatch
- Cross-service canonical HMAC compatibility and tamper rejection
- Counter tracking (attest count, degrade count)
- HTTP endpoints (health, attest, verify, refresh, security status)
- Token authentication (no config, requires bearer, invalid, valid)
- Audit logging
- Graceful degradation (no TPM, no Secure Boot, no rpm-ostree)

Run tests:
```bash
cd services/runtime-attestor && go test -v -race ./...
```

## Dependent GPU probes

The runtime observer has a distinct `secure-ai-model-read` group and a
read-only model path, without registry writer membership. Fresh vault setup
creates exact read-only access/default ACLs; model promotion preserves them.
A separate native gate inspects the verified encrypted mount and reader ACLs.
It never repairs or migrates existing populated vaults.

Sentinel/reference probes call only the authenticated `/v1/probe` adapter on
127.0.0.1:8497. Requests identify an approved reference, not a prompt, path or
model selection. Protected release-pinned reference data fixes the input,
expected output and model identity. The adapter alone holds a separate backend
API credential; the observer holds a different HMAC key. Responses bind the
request nonce, reference, policy hashes, backend alias and output. The adapter
limits concurrency, requests, replay, time, body size and generation to64tokens.
It exposes no reload, shutdown, slot or model-management routes.

The signed `expected_model_sha256` is the enrolled expectation. Pre/post
backend reads check the alias; they do not measure loaded weights or GPU memory.
The separate stable tensor-hash probe checks disk bytes and rejects replacements
or concurrent writes. These software checks cannot establish GPU firmware or
VRAM authenticity. Hardware qualification and original audit closure remain
separate from component verification.
