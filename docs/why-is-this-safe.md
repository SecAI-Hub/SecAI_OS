# Why is SecAI OS Safe?

This page explains SecAI OS security in plain language. For the full technical model, see [threat-model.md](threat-model.md) and the [Security Dashboard](http://127.0.0.1:8480/security) in the UI.

## Your Data Stays on This Device

SecAI OS runs all AI inference locally — on your hardware, using your GPU. No prompts, responses, or model data are sent to any cloud service. The network firewall blocks all outbound connections by default.

## What's Running

SecAI OS has three operating profiles:

| Profile | Network | What It Means |
|---------|---------|---------------|
| **Maximum Privacy** (default) | Blocked | Nothing leaves your device. Not even DNS. |
| **Web-Assisted Research** | Tor only | Search queries are anonymized through Tor with PII stripping. |
| **Full Lab** | Filtered | Outbound traffic goes through the airlock proxy with logging. |

You choose your profile at first boot. You can change it later from Settings. The active profile is always visible in the UI header.

## What Happens If Something Goes Wrong

| Scenario | Automatic Response |
|----------|-------------------|
| Tampered model detected | Quarantined and removed from the trusted store |
| Integrity check fails | System degrades to safe mode, alerts you |
| Suspicious agent activity | Agent frozen, airlock disabled, vault re-locked |
| Bad OS update | Greenboot auto-rolls back to last known-good state |
| Worst case | 3-level emergency panic: lock, wipe keys, or full wipe |

## No Telemetry

SecAI OS does **not** collect any telemetry:

- No usage analytics
- No crash reports sent externally
- No phone-home or heartbeat
- No automatic connections to external servers

The only network activity is what you explicitly enable by switching to the "research" or "full lab" profile. See [telemetry-policy.md](telemetry-policy.md) for the full statement.

## How to Verify

You don't have to take our word for it:

- **Security Dashboard** (`http://127.0.0.1:8480/security`) shows real-time verification: Secure Boot status, TPM2 sealing, audit chain integrity, model provenance, SLO compliance.
- **Audit logs** are hash-chained — any tampering breaks the chain visibly.
- **OS image** is cosign-signed with SLSA3 provenance attestation. Verify with:
  ```bash
  cosign verify --key cosign.pub ghcr.io/secai-hub/secai_os:latest
  ```
- **Every model** passes 7 automated stages (source policy, format gate, integrity, provenance, static scan, behavioral test, diffusion scan) before it can be used.
- **Forensic export** bundles all verification evidence into a signed archive you can review offline.

## Further Reading

- [Threat Model](threat-model.md) — formal threat classes, invariants, residual risks
- [Security Status](security-status.md) — implementation status of all 54 milestones
- [Telemetry Policy](telemetry-policy.md) — no-telemetry guarantee
- [Audit Quick Path](audit-quick-path.md) — step-by-step verification for auditors
