# Security Implementation Status

This document is split into two sections. The first section covers **Security Assurance Controls** -- all implemented milestones (M0 through M43) that satisfy the M5 security assurance acceptance criteria. Every control listed there is complete and tested. The second section is the **Product Feature Roadmap**, which tracks planned product capabilities (Agent Mode Phases 2 and 3). These are product enhancements, not security assurance requirements; the M5 security posture is fully met without them.

Last updated: 2026-03-14

---

## Security Assurance Controls (M5 Complete)

All M5 security assurance criteria are met. The controls below have been implemented, tested, and integrated into the CI pipeline.

| Control | Status | Milestone | Notes |
|---------|--------|-----------|-------|
| Threat model, dataflow, invariants | Implemented | M0 | Formal threat model in docs/threat-model.md |
| Bootable OS, encrypted vault, GPU drivers | Implemented | M1 | Fedora Silverblue 42 (uBlue) base, LUKS2 vault |
| Trusted Registry, hash pinning, cosign | Implemented | M2 | Go registry service on :8470, cosign signature verification |
| 7-stage quarantine pipeline | Implemented | M3 | Python quarantine watcher, multi-stage scanning |
| Tool Firewall, default-deny policy | Implemented | M4 | Go tool-firewall service on :8475, default-deny egress |
| Online Airlock, sanitization | Implemented | M5 | Go airlock service on :8490, disabled by default (privacy risk) |
| Systemd sandboxing, kernel hardening, nftables | Implemented | M6 | Systemd unit hardening, sysctl tuning, nftables rules |
| CI/CD, Go/Python tests, shellcheck | Implemented | M7 | GitHub Actions ci.yml. See docs/test-counts.json for current counts (399 Go, 718 Python as of 2026-03-14) |
| Image/video generation, diffusion worker | Implemented | M8 | Diffusion worker for image generation workloads |
| Multi-GPU support (NVIDIA/AMD/Intel/Apple) | Implemented | M9 | CUDA, ROCm/HIP, XPU/Vulkan, Metal/MPS backends |
| Tor-routed search, SearXNG, PII stripping | Implemented | M10 | Search mediator with Tor routing and PII redaction |
| VM support, OVA/QCOW2 builds | Implemented | M11 | VirtualBox, VMware, KVM/QEMU, Proxmox support |
| Model integrity monitoring | Implemented | M12 | Hash-based model file integrity checks |
| Tamper-evident audit logs | Implemented | M13 | Hash-chained audit logs with periodic verification |
| Local passphrase auth | Implemented | M14 | Scrypt hashing with rate limiting |
| Vault auto-lock | Implemented | M15 | Idle detection watchdog with UI controls |
| Seccomp-BPF + Landlock process isolation | Implemented | M16 | Seccomp-BPF syscall filtering, Landlock filesystem restrictions |
| Secure Boot + TPM2 measured boot | Implemented | M17 | MOK signing, TPM2 vault sealing, measured boot chain |
| Memory protection (swap/zswap/core dumps/mlock/TEE) | Implemented | M18 | Swap encryption, zswap hardening, core dump prevention, mlock, TEE detection |
| Traffic analysis protection | Implemented | M19 | Padding, timing jitter, dummy traffic for anonymity |
| Privacy-preserving query obfuscation for search | Implemented | M20 | Decoy queries, k-anonymity, timing randomization, query padding |
| Clipboard isolation | Implemented | M21 | Clipboard access controls and sanitization |
| Canary/tripwire system | Implemented | M22 | Canary tokens and filesystem tripwires |
| Emergency wipe (3-level panic) | Implemented | M23 | Three escalation levels for emergency data destruction |
| Update verification + auto-rollback | Implemented | M24 | Signed update verification with automatic rollback on failure |
| UI polish + security hardening | Implemented | M25 | Flask UI hardening, CSP headers, input validation |
| Fail-closed pipeline, service auth, CSRF, supply chain pinning | Implemented | M26 | Fail-closed on error, inter-service auth, CSRF protection, dependency pinning |
| Enhanced scanners, provenance manifests, fs-verity | Implemented | M27 | Extended scanner coverage, provenance tracking, fs-verity integrity |
| Weight distribution fingerprinting | Implemented | M28 | Statistical fingerprinting of model weight distributions |
| Garak LLM vulnerability scanner | Implemented | M29 | Garak integration for LLM vulnerability scanning |
| gguf-guard deep GGUF integrity scanner | Implemented | M30 | Deep GGUF file format integrity and safety scanning |
| Agent Mode (Phase 1: safe local autopilot) | Implemented | M31 | Policy-bound agent with deny-by-default policy engine, capability tokens, hard budgets, storage gateway, workspace ID abstraction, Unix socket IPC (UI->Agent), 93 tests across 11 classes |
| GPU Integrity Watch (continuous GPU runtime verification) | Implemented | M32 | Go daemon with probe-based scoring, baseline comparison, degradation actions, 40+ tests |
| MCP Firewall (Model Context Protocol policy gateway) | Implemented | M33 | Go policy gateway for MCP tool calls with default-deny, input redaction, taint tracking, 30+ tests |
| Release provenance + per-service SBOMs | Implemented | M34 | Dedicated release workflow with SLSA3 provenance attestation, per-service CycloneDX SBOMs, cosign-signed checksums |
| Unified policy decision engine | Implemented | M35 | Go service on :8500, 6 decision domains (tool_access, path_access, egress, agent_risk, sensitivity, model_promotion), structured decision evidence, OPA/Rego-upgradeable, 37 tests |
| Runtime attestation + startup gating | Implemented | M36 | Go service on :8505, TPM2 quote verification, HMAC-signed runtime state bundles, startup gating chain (attestor -> policy-engine -> all services), 4-state machine (pending/attested/degraded/failed), periodic refresh, incident-recorder integration, 55 tests |
| Continuous integrity monitor | Implemented | M37 | Go service on :8510, baseline-verified continuous file watcher (30s scans vs 15-min timer), signed baselines, 3-state machine (trusted/degraded/recovery_required), watches binaries+policies+models+units+trust material, incident-recorder integration, 50 tests |
| Incident recorder + containment automation | Implemented | M38 | Go service on :8515, 9 incident classes, 4-state lifecycle (open/contained/resolved/acknowledged), auto-containment per policy (freeze agent, disable airlock, force vault relock, quarantine model), severity-ranked listing, 65 tests |
| GPU integrity deep integration | Implemented | M39 | 2 new probe types (driver fingerprint, device allowlist), /v1/attest-state for runtime attestor integration, incident-recorder auto-reporting on warning/critical verdicts, 81 tests (up from 61) |
| Agent Verified Supervisor hardening | Implemented | M40 | HMAC-SHA256 signed capability tokens bound to task/intent/policy, nonce replay protection, token expiry, two-phase approval for high-risk actions, per-step PolicyDecision evidence in audit trail, 128 agent tests (up from 93) |
| HSM-backed key handling | Implemented | M41 | Keystore abstraction layer with pluggable backends (software/TPM2/PKCS#11), key rotation, PCR-sealed TPM2 key hierarchy, PKCS#11 HSM stub for external hardware, auto-detection of available backends, keystore.yaml config, 159 agent tests (up from 128) |
| Enforcement wiring + CI supply chain verification | Implemented | M42 | Integrity monitor -> incident recorder reporting, runtime attestor -> incident recorder reporting, incident recorder -> containment action execution (freeze agent, disable airlock, force vault relock, quarantine model), CI SBOM generation verification via Syft, cosign availability check, release workflow provenance validation |
| Stronger isolation (M5 hardening) | Implemented | M43 | Per-service sandbox tightening (device cgroups, resource limits, namespace isolation), agent execution compartmentalization (step signatures, subprocess isolation, per-step capability re-validation), workspace hard walls (symlink/hardlink/FD-reuse detection), model worker isolation profiles, formal adversarial test suite (prompt injection, policy bypass, containment, GPU tamper), CI security regression gate, MCP-specific isolation (trust tier enforcement, per-tool profiles, session binding, dynamic registration denial), recovery ceremony (ack + re-attestation), latched degraded states, severity escalation rules, forensic bundle export (signed), M5 control matrix doc, supply chain provenance doc, M5 acceptance suite (30 tests) |
| Auditability and documentation hardening | Implemented | M44 | Test-count drift CI check with single source of truth (docs/test-counts.json), CI evidence links and GitHub Actions badges in README, M4/M5 terminology disambiguation (project milestones vs M5 security assurance level), operator verification column in M5 control matrix, external audit quick-path doc, recovery runbook with concrete curl commands, verify-release.sh auditor script, sample release bundle doc, security-status split into assurance controls vs product roadmap |

---

## Product Feature Roadmap

The items below are planned product features. They are **not** required for the M5 security assurance posture, which is fully satisfied by the controls above. These features enhance the product's autonomous and online capabilities and will be implemented incrementally.

| Feature | Status | Notes |
|---------|--------|-------|
| Agent Mode Phase 2: Explainability | Planned | Detailed explanations for quarantine/registry/airlock decisions, per-workspace permissions, audit views |
| Agent Mode Phase 3: Online-assisted | Planned | Airlock-mediated outbound, search mediation, redaction flows, approval UX for online steps |
