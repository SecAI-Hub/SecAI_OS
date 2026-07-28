# Security Implementation Status

This document inventories implementation milestones. “Implemented” means the
associated source and unit tests exist; it does not mean that every deployment
path, release, or hardware combination has passed production certification.
The [capability matrix](capability-matrix.md) and a release-specific signed
[production readiness checklist](production-readiness-checklist.md) are
authoritative for assurance claims.

Last updated: 2026-05-14

---

## Security Control Implementations

The controls below are implementation milestones. Release-level validation,
negative testing, and hardware evidence remain mandatory where stated in the
capability matrix.

| Control | Status | Milestone | Notes |
|---------|--------|-----------|-------|
| Threat model, dataflow, invariants | Implemented | M0 | Formal threat model in docs/threat-model.md |
| Bootable OS, encrypted vault, GPU drivers | Implemented | M1 | Fedora Silverblue 44 (uBlue) base; hardware qualification is release-specific |
| Trusted Registry, hash pinning, cosign | Implemented | M2 | Go registry service on :8470, cosign signature verification |
| 7-stage quarantine pipeline | Implemented | M3 | Python quarantine watcher, multi-stage scanning |
| Tool Firewall, default-deny policy | Implemented | M4 | Go tool-firewall service on :8475, default-deny egress |
| Online Airlock, sanitization | Implemented | M5 | Go airlock service on :8490, disabled by default (privacy risk) |
| Systemd sandboxing, kernel hardening, nftables | Implemented | M6 | Systemd unit hardening, sysctl tuning, nftables rules |
| CI/CD, Go/Python tests, shellcheck | Implemented | M7 | GitHub Actions ci.yml; enforced count floors are maintained in docs/test-counts.json |
| Image/video generation, diffusion worker | Implemented | M8 | Diffusion worker for image generation workloads |
| Multi-backend runtime code | Implemented | M9 | CUDA, ROCm/HIP and XPU/Vulkan appliance paths; Metal/MPS is sandbox/development only |
| Tor-routed search, SearXNG, PII stripping | Implemented | M10 | Search mediator with Tor routing and PII redaction |
| VM support, local OVA/QCOW2 builds | Implemented | M11 | User-specific encrypted builds for VirtualBox, VMware, KVM/QEMU, and Proxmox; CI artifacts are qualification-only |
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
| Agent Mode (Phase 1: safe local autopilot) | Implemented | M31 | Policy-bound agent with deny-by-default policy engine, capability tokens, hard budgets, storage gateway, workspace ID abstraction, Unix socket IPC (UI->Agent); current `test_agent.py` coverage is 186 tests |
| GPU Integrity Watch (continuous GPU runtime verification) | Implemented | M32 | Go daemon with probe-based scoring, baseline comparison, degradation actions, 63 tests |
| MCP Firewall (Model Context Protocol policy gateway) | Implemented | M33 | Go policy gateway for MCP tool calls with default-deny, input redaction, taint tracking, 71 tests |
| Release provenance + per-service SBOMs | Implemented | M34 | Dedicated release workflow with SLSA3 provenance attestation, per-service CycloneDX SBOMs, cosign-signed checksums |
| Unified policy decision engine | Implemented | M35 | Go service on :8500, 6 decision domains (tool_access, path_access, egress, agent_risk, sensitivity, model_promotion), structured decision evidence, OPA/Rego-upgradeable, 45 tests |
| Runtime attestation + startup gating | Implemented | M36 | Go service on :8505, TPM2 quote verification, HMAC-signed runtime state bundles, startup gating chain (attestor -> policy-engine -> all services), 4-state machine (pending/attested/degraded/failed), periodic refresh, incident-recorder integration, 64 tests |
| Continuous integrity monitor | Implemented | M37 | Go service on :8510, baseline-verified continuous file watcher (30s scans vs 15-min timer), signed baselines, 3-state machine (trusted/degraded/recovery_required), watches binaries+policies+models+units+trust material, incident-recorder integration, 54 tests |
| Incident recorder + containment automation | Implemented | M38 | Go service on :8515, 9 incident classes, 4-state lifecycle (open/contained/resolved/acknowledged), auto-containment per policy (freeze agent, disable airlock, force vault relock, quarantine model), severity-ranked listing, 108 tests |
| GPU integrity deep integration | Implemented | M39 | 2 new probe types (driver fingerprint, device allowlist), /v1/attest-state for runtime attestor integration, incident-recorder auto-reporting on warning/critical verdicts, 63 current service tests |
| Agent Verified Supervisor hardening | Implemented | M40 | HMAC-SHA256 signed capability tokens bound to task/intent/policy, nonce replay protection, token expiry, two-phase approval for high-risk actions, per-step PolicyDecision evidence in audit trail, 128 agent tests (up from 93) |
| Keystore abstraction | Implemented | M41 | Software and TPM2 code paths exist. PKCS#11 is a degraded/stub provider; full HSM signing and rotation remain planned and hardware-dependent. |
| Enforcement wiring + CI supply chain verification | Implemented | M42 | Integrity monitor -> incident recorder reporting, runtime attestor -> incident recorder reporting, incident recorder -> containment action execution (freeze agent, disable airlock, force vault relock, quarantine model), CI SBOM generation verification via Syft, cosign availability check, release workflow provenance validation |
| Stronger isolation (M5 hardening) | Implemented | M43 | Per-service sandbox tightening (device cgroups, resource limits, namespace isolation), agent execution compartmentalization (step signatures, subprocess isolation, per-step capability re-validation), workspace hard walls (symlink/hardlink/FD-reuse detection), model worker isolation profiles, formal adversarial test suite (prompt injection, policy bypass, containment, GPU tamper), CI security regression gate, MCP-specific isolation (trust tier enforcement, per-tool profiles, session binding, dynamic registration denial), recovery ceremony (ack + re-attestation), latched degraded states, severity escalation rules, forensic bundle export (signed), M5 control matrix doc, supply chain provenance doc, M5 acceptance suite (32 tests) |
| Auditability and documentation hardening | Implemented | M44 | Test-count drift CI check with single source of truth (docs/test-counts.json), CI evidence links and GitHub Actions badges in README, M4/M5 terminology disambiguation (project milestones vs M5 security assurance level), operator verification column in M5 control matrix, external audit quick-path doc, recovery runbook with concrete curl commands, verify-release.sh auditor script, sample release bundle doc, security-status split into assurance controls vs product roadmap |
| Production readiness hardening | Implemented | M45 | Incident recorder file-backed persistence (survives restarts), graceful shutdown (SIGTERM/SIGINT with connection draining) for all 9 Go services, HTTP server timeouts for mcp-firewall and gpu-integrity-watch, systemd production hardening (TimeoutStartSec, TimeoutStopSec, StartLimitInterval, StartLimitBurst) for all 12 daemon units, first-boot health validation script, audit log rotation via logrotate, CI dependency vulnerability scanning (govulncheck + pip-audit), production operations guide (upgrade, key rotation, capacity limits, monitoring) |
| Operational maturity | Implemented | M46 | Bootstrap trust gap fix (cosign verify before unverified rebase, documented trust gap rationale), CI runs on all changes (removed blanket paths-ignore for .md files), Python quality gates (ruff lint + bandit security scan + split test suites into unit/integration and adversarial/acceptance), docs-validation CI job (broken link detection, required docs check, test-counts.json validation), production-readiness checklist (formal release gate), SLOs (availability/latency/correctness targets + alerting thresholds), release channel policy (stable/candidate/dev + versioning + upgrade paths + security patch SLA), support lifecycle (hardware matrix, driver versions, support windows, deprecation policy, scope boundaries), CI evidence table with current job descriptions and workflow links, sample verification output for verify-release.sh |
| CI enforcement hardening | Implemented | M47 | Enforced vulnerability scanning: bandit fails CI on HIGH-severity/HIGH-confidence findings, govulncheck fails on unwaived Go vulns, pip-audit fails on unwaived Python vulns. Waiver mechanism (`.github/vuln-waivers.json`) with mandatory expiry dates for reviewed/accepted findings. mypy type checking gate for security-sensitive services (common, agent, quarantine, ui). Reproducible Python CI and runtime dependencies are installed only from hash-complete lockfiles (`requirements-ci.lock`, service locks, and the application wheel lock). Go service CI and container builders use the repository-pinned Go toolchain. Verification-first bootstrap documentation keeps the signed rebase as the production path. |
| Production hardening | Implemented | M48 | Build script fail-closed for required services + binary verification gate, incident-store fsync, GPU backend metadata, llama-server watchdog, externalized model catalog, circuit breaker, post-upgrade verification, and key-rotation documentation. Deployment validation remains release-specific. |
| Signed-first install path | Implemented | M49 | Signed bootstrap script (`secai-bootstrap.sh`) configures container signing policy (policy.json + registries.d + cosign public key) before first rebase -- eliminates unverified transport from production install path. Digest-pinned install flow (CI publishes image digest in build summary and release assets). First-boot setup wizard (interactive verification of image integrity, transport, vault setup, TPM2 sealing, health check). Signing policy files baked into OS image (`/etc/pki/containers/secai-cosign.pub`, `/etc/containers/registries.d/secai-os.yaml`, policy.json merge in build script). Recovery/dev bootstrap path separated into dedicated doc with clear warnings. |
| Production operations package | Implemented | M50 | Backup script (`secai-backup.sh`) with full/config/logs/keys categories, age/gpg encryption, internal SHA256 manifest, LUKS header backup. Restore script (`secai-restore.sh`) with integrity verification, staging extraction, double-confirmation LUKS header restore, post-restore health check. Production operations doc extended with rollback decision matrix (Greenboot auto-rollback triggers + manual criteria), 5 break-glass recovery procedures (token loss, attestation failure, Level 1 panic lockout, signing policy break, Greenboot exhaustion), formal data retention policy (7 data classes with retention periods, disk capacity thresholds at 70/80/90/95%). |
| Stronger observability | Implemented | M51 | Unified appliance health dashboard (trusted/degraded/recovery_required state derived from runtime attestor + integrity monitor + incident recorder, including recorder unavailability). Live SLO compliance monitoring (in-process tracker measuring uptime % and P95 latency against docs/slos.md targets, 7-day rolling window). Webhook alerting hooks for containment events (fire-and-forget POST with retry, configurable per-event-type filtering in incident-containment.yaml). Forensic bundle export uses a root-only local-console CLI (`secai-forensic`) with independent bearer and HMAC credentials; the web UI intentionally has no forensic authority. Recovery ceremony endpoints use a separate recovery-administrator credential. |
| Better release verification UX | Implemented | M52 | Repo-root Makefile (verify-release, test, shellcheck, lint targets). RELEASE_MANIFEST.json generated by release CI (image digest, binaries with SHA256, SBOMs, provenance type, checksums, build metadata -- transitively signed via SHA256SUMS). verify-release.sh enhanced with --json and --report flags for machine-readable and human-readable structured output, backward-compatible argument parsing. audit-quick-path.md wired to verify-release.sh with Make target reference. sample-release-bundle.md updated with manifest documentation. |
| Harder CI gates for production branches | Implemented | M53 | Release-branch hardened gate job (zero-tolerance bandit HIGH at any confidence, CVE-ID-level govulncheck waivers, M5 acceptance re-run) only runs on release/stable branches. CI triggers extended to release/stable. Docs consistency checks: milestone count cross-check (README vs security-status.md), m5-control-matrix test reference verification, test-counts.json staleness warning. Container pin check wired into CI (check-container-pins.sh). Hadolint and Semgrep application security linting wired into CI. Release preflight job verifies CI passed before publishing. Branch protection documentation with setup script. |

---

## Product Feature Roadmap

The items below are planned or incomplete product features. Their absence and
the unverified security controls above must be reflected in release notes and
support decisions.

| Feature | Status | Notes |
|---------|--------|-------|
| Agent Mode Phase 2: Explainability | Planned | Detailed explanations for quarantine/registry/airlock decisions, per-workspace permissions, audit views |
| Agent Mode Phase 3: Online-assisted | Planned | Airlock-mediated outbound, search mediation, redaction flows, approval UX for online steps |
| Full PKCS#11 HSM operations | Planned | Replace degraded-provider detection with hardware-backed sign/verify/rotation once a supported HSM and python-pkcs11 test fixture are available |
| Quarantine scanner Python uplift | Planned | Move quarantine to Python 3.13+ once required scanners publish compatible metadata; `modelscan 0.8.8` currently declares `Requires-Python: >=3.10,<3.13`, and Garak remains opt-in until its vulnerable LiteLLM pin is resolved upstream. |
