# Capability and Assurance Matrix

This is the authoritative statement of SecAI OS product and assurance status.
An implementation milestone means source code exists; it does not by itself
mean that a release, hardware combination, or deployment path is production
certified.

Last updated: 2026-07-27

## Status Definitions

| Status | Meaning |
|--------|---------|
| **Verified** | Exercised by automated tests and release-specific evidence on the stated deployment path. |
| **Implemented** | Code and unit tests exist, but deployment or release validation is incomplete. |
| **Experimental** | Available for evaluation; interfaces, behavior, or support may change. |
| **Hardware-dependent** | Requires evidence from a named hardware/firmware/driver combination. |
| **Sandbox-only** | Intended for the lower-assurance compose/development deployment, not the Fedora appliance. |
| **Planned** | Design or stub exists, but the capability is not available. |

## Deployment Paths

| Path | Status | Production boundary |
|------|--------|---------------------|
| Fedora 44 bootable appliance | Implemented | Not production-verified until a release completes the signed readiness checklist, boot/reboot tests, update/rollback tests, and hardware qualification. |
| Digest-pinned Fedora rebase | Implemented | Requires a non-placeholder digest, valid image signature, signed provenance, and a passing release verifier. |
| Compose sandbox | Experimental | Local evaluation only; the host and container runtime remain fully trusted. |
| Development services | Experimental | No appliance-wide boot, firewall, vault, or measured-boot assurances. |
| macOS native appliance | Planned | No native macOS appliance is currently built. Metal/MPS code paths may be used only through explicitly documented development or sandbox runtimes. |
| ARM64 appliance media | Planned | Current release media is x86_64. |

## Security Controls

| Capability | Status | Required evidence before “Verified” |
|------------|--------|-------------------------------------|
| Service authentication | Implemented | Cold-boot and reboot tests proving every protected service fails closed without its own credential. |
| Model quarantine | Implemented | Disposable hostile-parser workers, atomic promotion, parser-failure and artifact-replacement tests. |
| Airlock egress | Implemented | Network tests proving no workload can bypass the authenticated fetch proxy. |
| Signed updates | Implemented | Candidate-digest verification and negative tests for missing key, bad identity, rollback, and signature failure. |
| Runtime integrity | Implemented | Persistent signed release baseline, restart-tamper test, and authenticated rebaseline ceremony. |
| TPM2 measured boot | Hardware-dependent | Root-only first-boot AK/PCR enrollment, fresh request nonce, `tpm2_quote` + `tpm2_checkquote`, pinned AK digest, authenticated PCR-blob comparison, and explicit non-recoverable VM evaluation mode. |
| Secure Boot | Hardware-dependent | Boot-chain evidence on named firmware with negative unsigned-kernel/module tests. |
| Landlock/custom seccomp | Implemented | Process-level negative tests proving the target workload—not a preparatory helper—is restricted. |
| Tamper-evident audit | Implemented | Keyed chain verification across rotation, truncation, deletion, and full-log replacement. |
| Clipboard isolation | Implemented | Guest controls, host-side clipboard/drag-and-drop verification, and per-user Wayland/X11 auto-clear tests on the target desktop. |
| Software keystore | Implemented | Rotation, recovery, permission, and corruption tests. |
| TPM2 keystore | Hardware-dependent | Sealing/unsealing, PCR mismatch, recovery, and rotation on a named TPM. |
| PKCS#11/HSM operations | Planned | A supported HSM plus sign, verify, rotation, availability, and recovery integration tests. |
| Release provenance/SBOM | Implemented | Media bound to a canonical image digest, non-empty final-artifact SBOMs, verified attestations, and reproducible network-disabled build evidence. |

## Product Features

| Capability | Status | Notes |
|------------|--------|-------|
| Local chat and GGUF inference | Implemented | Requires a verified model and a qualified runtime backend. |
| Model catalog/import | Implemented | Offline import is the default path while Airlock is disabled. |
| Image/video generation | Experimental | Backend and hostile-image resource limits require deployment validation. |
| Private Tor search | Implemented | Requires end-to-end privacy, failure, and leak testing in the target deployment. |
| Agent APIs | Implemented | Policy-bound APIs exist. |
| Agent task/approval UI | Experimental | Must expose task state, cancellation, approval diffs, policy evidence, and recovery before general availability. |
| Forensic export | Implemented | Export content, signing, redaction, and recovery handling require release evidence. |
| Backup/restore | Implemented | A release is not production-ready until an encrypted restore drill demonstrates its stated RPO/RTO. |
| Fleet administration | Planned | Must remain opt-in and must not transmit prompts, model data, or customer artifacts. |

## Hardware Qualification

Hardware support is published per release, not inferred from the existence of a
backend. Each qualified entry must record the exact GPU, CPU, firmware, kernel,
driver, runtime, model, workload, test duration, and result.

Collect a redacted starting report on the appliance under test:

```bash
python3 scripts/qualification/collect_hardware_evidence.py \
  --output hardware-evidence.json
```

The collector intentionally emits `certified: false`; a reviewer combines this
inventory with workload, boot-security, failure, and soak-test results. The
report omits hostnames, usernames, network addresses, serials, TPM unique
values, and device UUIDs.

Until such evidence is attached to a release:

- NVIDIA appliance acceleration is **hardware-dependent**.
- AMD and Intel appliance acceleration are **experimental**.
- Apple Metal/MPS is **sandbox/development only**.
- ARM64 appliance media is **planned**.
