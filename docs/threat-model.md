# Threat Model and Security Goals

## Scope

A bootable USB appliance for a single user on a PC with an NVIDIA RTX GPU (or Apple Silicon CPU-only).
The system keeps sensitive data local by default and applies defense-in-depth across: boot, updates,
model acquisition, verification, scanning, runtime isolation, tool gating, and optional online augmentation.

## Core Promise

Make data leakage **hard and detectable** by enforcing strict trust boundaries and a default-off network
policy. The system does **not** claim "impossible to leak" guarantees, especially for data-in-use
(RAM/VRAM), which requires confidential computing hardware not available on consumer GPUs.

## Architecture Zones

| Zone | Purpose | Network | Trust Level |
|------|---------|---------|-------------|
| A) Base OS | Immutable image, signed updates | Host network (updates only) | Highest |
| B) Acquisition | Download models/containers from allowlisted sources | Internet (restricted) | Untrusted input |
| C) Quarantine | Verify, scan, smoke-test artifacts before promotion | None | Untrusted until promoted |
| D) Runtime | Sealed inference with tool firewall | None (default) | Trusted code, untrusted prompts |
| E) Airlock | Optional sanitized egress proxy | Internet (restricted) | Mediated |

## Threat Classes

### In Scope

| Threat | Primary Controls | Residual Risk |
|--------|-----------------|---------------|
| **Malicious model / tampered artifact** | Allowlist + hash pinning; signature verification; format gate (deny pickle); quarantine scanning + smoke tests | Advanced backdoors may evade tests; isolation reduces blast radius |
| **Remote attacker / network adversary** | Runtime offline by default; strict firewall; allowlisted egress only via airlock | If online mode enabled, exposure increases |
| **Accidental data leakage** (logs, telemetry) | No raw prompt logging; redaction; encrypted vault; minimal audit metadata | User can still attempt to send text online unless blocked by policy |
| **Supply chain compromise** | Cosign verification for containers; hash pinning for models; Trivy/Grype scanning | Zero-day in upstream dependencies |
| **Unauthorized tool use by model** | Tool firewall with deny-by-default policy; path allowlists; no direct socket access | Policy misconfiguration |

### Out of Scope (acknowledged risks)

| Threat | Why Out of Scope | Mitigation Advice |
|--------|-----------------|-------------------|
| Firmware/UEFI compromise | Cannot be solved in software | Use Secure Boot; trusted hardware baseline |
| Physical side-channel attacks | Requires hardware countermeasures | Physical security of device |
| GPU memory side channels | Consumer GPUs lack confidential computing | H100/datacenter-class GPUs with attestation |
| Malicious user (single-user system) | The user IS the trust principal | N/A |

## Security Invariants (Enforced)

These invariants must hold at all times. Each has acceptance tests.

- **G1. No autonomous internet:** Models and agents cannot open sockets. Any outbound request must pass through the airlock gate.
- **G2. No unverified artifacts:** Models and containers must pass verification and scans before they can run.
- **G3. No raw sensitive exports:** High-sensitivity data (PHI, financial, credentials) never leaves the device. The airlock rejects it.
- **G4. Least privilege:** Each component runs with minimal filesystem access, device access, and permissions.
- **G5. Predictable updates:** Updates are signed. Any new artifact triggers re-verify + re-scan before use.

## Data Sensitivity Labels

| Level | Examples | Policy |
|-------|----------|--------|
| High | Credentials, financial statements, health records, government IDs | Never leaves device, including via airlock |
| Medium | Personal notes, emails, contacts | Can be processed locally; airlock blocks by default |
| Low | Public data, non-identifying context | May pass through airlock if destination is allowlisted |

## Dataflow Summary

```
User -> [Web UI :8480]
          |
          v
     [Tool Firewall :8475] -- policy check --> [Policy Engine]
          |
          v
     [Inference Worker :8465] <-- read-only model mount -- [Registry :8470]
          |
          v (if online mode enabled)
     [Airlock :8490] -- sanitize + allowlist --> Internet
```

All inter-service communication is localhost-only. The runtime VM has no default route.
