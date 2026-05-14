# SecAI OS Security Hardening Roadmap

Last updated: 2026-05-14

This document is a historical roadmap for milestones M12 through M24. Those milestones are now implemented and tracked in the current [Security Status](security-status.md) document. Keep this page for context only; do not use it as the source of truth for current security posture.

---

## Current Status

| Milestone | Area | Current Status | Primary Verification |
|---|---|---|---|
| M12 | Continuous model integrity monitoring | Implemented | Registry verify endpoints, integrity timer, UI verify-all flow |
| M13 | Hash-chained audit logs | Implemented | Audit verification endpoints and `verify-release.sh` checks |
| M14 | Local UI authentication | Implemented | Scrypt passphrase setup/login/session tests |
| M15 | Vault auto-lock | Implemented | Vault watchdog tests and UI/API lock controls |
| M16 | Advanced process isolation | Implemented | Systemd hardening, seccomp profiles, Landlock policy |
| M17 | Secure Boot + measured boot | Implemented | MOK tooling, TPM2 sealing, boot verification docs |
| M18 | Memory protection | Implemented | Swap/zswap/core dump/mlock/TEE tests |
| M19 | Traffic analysis protection | Implemented | Padding, timing jitter, dummy traffic tests |
| M20 | Differential privacy for search | Implemented | Decoy query, uniqueness, and batching tests |
| M21 | Clipboard isolation | Implemented | Clipboard isolation tests and service hardening |
| M22 | Canary/tripwire system | Implemented | Canary placement and tamper-detection tests |
| M23 | Emergency wipe | Implemented | Three-level panic tests |
| M24 | Update verification + rollback | Implemented | Cosign/rpm-ostree verification and rollback tests |

The broader implementation status is maintained in:

- [Security Status](security-status.md)
- [Security Test Matrix](security-test-matrix.md)
- [M5 Control Matrix](m5-control-matrix.md)
- [Production Readiness Checklist](production-readiness-checklist.md)

---

## Historical Design Intent

The original M12-M24 roadmap focused on closing these risks:

- Detect model tampering after promotion.
- Make audit logs tamper-evident.
- Require local UI authentication and vault auto-lock.
- Harden process, filesystem, memory, network, and clipboard boundaries.
- Add measured boot, update verification, rollback, canaries, and emergency wipe.
- Preserve user privacy by avoiding metadata in generated outputs unless required for trust verification.

Those design goals remain active project invariants, but implementation details have moved into the component docs, policy schema, tests, and operations guides.
