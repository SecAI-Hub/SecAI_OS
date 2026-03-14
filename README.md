# SecAI OS

[![CI](https://github.com/SecAI-Hub/SecAI_OS/actions/workflows/ci.yml/badge.svg)](https://github.com/SecAI-Hub/SecAI_OS/actions/workflows/ci.yml)
[![Build](https://github.com/SecAI-Hub/SecAI_OS/actions/workflows/build.yml/badge.svg)](https://github.com/SecAI-Hub/SecAI_OS/actions/workflows/build.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Fedora 42](https://img.shields.io/badge/Fedora-42-blue)](https://fedoraproject.org/)
[![uBlue](https://img.shields.io/badge/Built_on-uBlue-purple)](https://universal-blue.org/)

**Bootable local-first AI OS with sealed runtime, model quarantine pipeline, airlock egress controls, encrypted vault, and private Tor-routed search.**

Built on [uBlue](https://universal-blue.org/) (Fedora Atomic / Silverblue). All AI compute -- inference and generation -- stays on-device. Network egress is denied by default. GPU auto-detected at first boot.

```
+-------------------+     +-------------------+     +-------------------+
|  A) Base OS       | --> |  B) Acquisition   | --> |  C) Quarantine    |
|  immutable image  |     |  dirty net /      |     |  7-stage pipeline |
|  signed updates   |     |  allowlist only   |     |  fully automatic  |
+-------------------+     +-------------------+     +--------+----------+
                                                             |
                          +-------------------+     +--------v----------+
                          |  E) Airlock       | <-- |  D) Runtime       |
                          |  sanitized egress |     |  sealed inference |
                          |  (optional)       |     |  no internet      |
                          +-------------------+     +-------------------+
```

---

## Who This Is For

- **Privacy-conscious AI users** who want LLM and image generation without cloud services
- **Security researchers** evaluating model supply-chain risks
- **Air-gapped environments** that need AI inference with no internet dependency
- **Organizations** requiring auditable, policy-enforced AI workstations

## What Makes It Different

- **Default-deny egress** -- The runtime has no internet unless explicitly enabled via the airlock.
- **Supply-chain distrust** -- Models are untrusted until they pass a 7-stage quarantine pipeline (source, format, integrity, provenance, static scan, behavioral test, diffusion scan).
- **Hands-off security** -- All scanning, verification, and promotion happens automatically. Users never run security tools manually.
- **Deterministic policy** -- Promotion to "trusted" is rule-based (signatures, hashes, scans, tests), not ad-hoc.
- **Short-lived workers** -- No swap, tmpfs for temp data, inference workers restart between sessions.
- **25+ defense layers** -- From UEFI Secure Boot and TPM2 to seccomp-BPF, Landlock, runtime attestation, continuous integrity monitoring, automated incident containment, and 3-level emergency wipe.

---

## Quickstart

### Install (Fedora Atomic)

```bash
# 1. Verify image signature BEFORE installing (mandatory)
cosign verify --key cosign.pub ghcr.io/sec_ai/secai_os:latest

# 2. Rebase to the signed image
sudo rpm-ostree rebase ostree-image-signed:docker://ghcr.io/sec_ai/secai_os:latest
sudo systemctl reboot

# 3. Set up encrypted vault
sudo /usr/libexec/secure-ai/setup-vault.sh /dev/sdX
```

> **First install on a fresh Fedora Silverblue?** The signed transport requires that
> the signing policy is already configured. On a fresh install, see
> [docs/install/bare-metal.md](docs/install/bare-metal.md) for the one-time bootstrap
> procedure (uses cosign verification + a single unverified pull, then locks to signed
> transport permanently).

See [docs/install/](docs/install/) for detailed guides: [bare metal](docs/install/bare-metal.md) | [virtual machine](docs/install/vm.md) | [development](docs/install/dev.md)

### Get Your First Model

Open `http://127.0.0.1:8480`, go to **Models**, and click **Download** on any model in the catalog. The 7-stage quarantine pipeline runs automatically. Once promoted, the model is ready to use.

Or via CLI:

```bash
sudo cp your-model.gguf /var/lib/secure-ai/quarantine/incoming/
journalctl -u secure-ai-quarantine-watcher -f  # watch pipeline
```

---

## Architecture

### Services

| Service | Port | Language | Purpose |
|---------|------|----------|---------|
| Registry | 8470 | Go | Trusted artifact manifest, read-only model store |
| Tool Firewall | 8475 | Go | Policy-gated tool invocation gateway |
| Web UI | 8480 | Python | Chat, image/video generation, model management |
| Airlock | 8490 | Go | Sanitized egress proxy (disabled by default) |
| Inference Worker | 8465 | llama.cpp | LLM inference (CUDA / ROCm / Vulkan / Metal / CPU) |
| Diffusion Worker | 8455 | Python | Image and video generation |
| Agent | 8476 | Python | Policy-bound local autopilot (deny-by-default, capability tokens) |
| Quarantine | -- | Python | 7-stage verify, scan, and promote pipeline |
| GPU Integrity Watch | 8495 | Go | Continuous GPU runtime verification and anomaly detection |
| MCP Firewall | 8496 | Go | Model Context Protocol policy gateway (default-deny, taint tracking) |
| Policy Engine | 8500 | Go | Unified policy decision point (6 domains, decision evidence, OPA-upgradeable) |
| Runtime Attestor | 8505 | Go | TPM2 quote verification, HMAC-signed state bundles, startup gating |
| Integrity Monitor | 8510 | Go | Continuous baseline-verified file watcher (binaries, policies, models, trust material) |
| Incident Recorder | 8515 | Go | Security event capture, incident lifecycle, auto-containment |
| Search Mediator | 8485 | Python | Tor-routed web search with PII stripping |
| SearXNG | 8888 | Python | Self-hosted metasearch (privacy-respecting engines) |
| Tor | 9050 | C | Anonymous SOCKS5 proxy |

See [docs/architecture.md](docs/architecture.md) for design decisions and service dependencies. Per-service docs: [registry](docs/components/registry.md) | [tool-firewall](docs/components/tool-firewall.md) | [agent](docs/components/agent.md) | [airlock](docs/components/airlock.md) | [quarantine](docs/components/quarantine.md) | [search-mediator](docs/components/search-mediator.md) | [gpu-integrity-watch](docs/components/gpu-integrity-watch.md) | [mcp-firewall](docs/components/mcp-firewall.md) | [policy-engine](docs/components/policy-engine.md) | [runtime-attestor](docs/components/runtime-attestor.md) | [integrity-monitor](docs/components/integrity-monitor.md) | [incident-recorder](docs/components/incident-recorder.md)

### 7-Stage Quarantine Pipeline

Every model passes through the same fully automatic pipeline:

| Stage | Name | What It Does |
|-------|------|-------------|
| 1 | **Source Policy** | Verifies origin against allowlist |
| 2 | **Format Gate** | Validates headers, rejects unsafe formats (pickle, .pt, .bin) |
| 3 | **Integrity Check** | SHA-256 hash pinning verification |
| 4 | **Provenance** | Cosign signature verification |
| 5 | **Static Scan** | ModelScan + entropy analysis + gguf-guard (weight-level anomaly detection) |
| 6 | **Behavioral Test** | 22 adversarial prompts across 10 attack categories (LLM only) |
| 7 | **Diffusion Scan** | Config integrity, symlink detection (diffusion only) |

---

## Security Model

### Defense Layers

| Layer | Mechanism |
|-------|-----------|
| **Boot** | Immutable OS (rpm-ostree), cosign-verified updates, greenboot auto-rollback |
| **Secure Boot** | UEFI Secure Boot + MOK signing, TPM2 vault key sealing (PCR 0,2,4,7) |
| **Kernel** | IOMMU forced, ASLR, slab_nomerge, init_on_alloc/free, lockdown=confidentiality |
| **Memory** | Swap/zswap disabled, core dumps discarded, mlock for secrets, TEE detection |
| **Network** | nftables default-deny egress, DNS rate-limited, traffic analysis countermeasures |
| **Filesystem** | Encrypted vault (LUKS2/AES-256/Argon2id), restrictive permissions, fs-verity |
| **Models** | 7-stage quarantine pipeline with gguf-guard deep integrity scanning |
| **Tools** | Default-deny policy, path allowlisting, traversal protection, rate limiting |
| **Egress** | Airlock disabled by default, PII/credential scanning, destination allowlist |
| **Search** | Tor-routed, privacy-preserving query obfuscation (decoy queries, k-anonymity), injection detection |
| **Audit** | Hash-chained tamper-evident logs with periodic verification |
| **Auth** | Scrypt passphrase hashing, rate-limited login, session management |
| **Vault** | Auto-lock after 30 min idle, TPM2-sealed keys |
| **Services** | Systemd sandboxing: ProtectSystem, PrivateNetwork, seccomp-bpf, Landlock |
| **Agent** | Deny-by-default policy engine, HMAC-signed capability tokens, hard budgets, loopback-only IPC |
| **Policy Engine** | Unified decision point (6 domains), structured evidence, OPA/Rego-upgradeable |
| **Attestation** | TPM2 quote verification, HMAC-signed runtime state bundles, startup gating |
| **Integrity** | Continuous baseline-verified file watcher (30s scans), signed baselines, auto-degradation |
| **Incident Response** | 9 incident classes, auto-containment (freeze agent, disable airlock, vault relock, quarantine model) |
| **GPU** | Vendor-specific DeviceAllow, PrivateNetwork, driver fingerprinting, device allowlist |
| **HSM/Keys** | Pluggable keystore (software/TPM2/PKCS#11), key rotation, PCR-sealed key hierarchy |
| **Clipboard** | VM clipboard agents disabled, auto-clear every 60s |
| **Tripwire** | Canary files in sensitive dirs, inotify real-time monitoring |
| **Emergency** | 3-level panic (lock / wipe keys / full wipe) with passphrase gates |
| **Updates** | Cosign-verified rpm-ostree, staged workflow, greenboot auto-rollback |
| **Supply Chain** | Per-service CycloneDX SBOMs, SLSA3 provenance attestation, cosign-signed checksums |

See [docs/threat-model.md](docs/threat-model.md) for threat classes, residual risks, and security invariants. See [docs/security-status.md](docs/security-status.md) for implementation status of all 47 milestones.

### Verify Image Signatures

```bash
cosign verify --key cosign.pub ghcr.io/sec_ai/secai_os:latest
```

---

## Hardware Support

GPU is **auto-detected at first boot**. No manual configuration needed.

| Vendor | GPUs | Backend | LLM | Diffusion |
|--------|------|---------|-----|-----------|
| **NVIDIA** | RTX 5090/5080/4090/4080/3090/3080 | CUDA | Full offload | Full offload |
| **AMD** | RX 7900 XTX/XT, RX 7800/7700, RDNA/CDNA | ROCm (HIP) | Full offload | Full offload |
| **Intel** | Arc A770/A750/A580, Arc B-series | XPU (oneAPI) | Via Vulkan | Via IPEX |
| **Apple** | M4/M3/M2/M1 (Pro/Max/Ultra) | Metal / MPS | Full offload | MPS acceleration |
| **CPU** | x86_64 (AVX2/AVX-512), ARM64 (NEON) | CPU | Optimized | Functional |

**Minimum:** 16 GB RAM, 8 GB VRAM, 64 GB storage. See [docs/compatibility-matrix.md](docs/compatibility-matrix.md) for detailed specs.

---

## Configuration

All config lives in `/etc/secure-ai/` (baked into the image, read-only at runtime):

| File | Purpose |
|------|---------|
| `config/appliance.yaml` | Mode, paths, inference/diffusion settings, service binds |
| `policy/policy.yaml` | Tool firewall, airlock, quarantine stages, search settings |
| `policy/agent.yaml` | Agent mode: operating modes, budgets, workspace scopes, allow/deny matrix |
| `policy/models.lock.yaml` | Pinned model hashes (supply-chain verification) |
| `policy/sources.allowlist.yaml` | Trusted model sources |

See [docs/policy-schema.md](docs/policy-schema.md) for full schema reference. See [examples/sample-policy.yaml](examples/sample-policy.yaml) for annotated example.

---

## Verification & Audit

### Workflow Files

- [CI Workflow](.github/workflows/ci.yml)
- [Build Workflow](.github/workflows/build.yml)
- [Release Workflow](.github/workflows/release.yml)

### Security Documentation

- [M5 Control Matrix](docs/m5-control-matrix.md)
- [Supply Chain Provenance](docs/supply-chain-provenance.md)
- [Security Status](docs/security-status.md)

### CI Verification Evidence

All CI jobs are defined in [`.github/workflows/ci.yml`](.github/workflows/ci.yml). View the [latest CI run](https://github.com/SecAI-Hub/SecAI_OS/actions/workflows/ci.yml).

| Job | Workflow Link | What It Proves |
|-----|--------------|---------------|
| `go-build-and-test` | [View job](https://github.com/SecAI-Hub/SecAI_OS/actions/workflows/ci.yml) | 399 Go tests across 9 services with `-race` (build, test, vet) |
| `python-test` | [View job](https://github.com/SecAI-Hub/SecAI_OS/actions/workflows/ci.yml) | 718 Python tests (unit/integration + adversarial/acceptance), ruff lint, bandit security scan (enforced on HIGH/HIGH), mypy type checking |
| `security-regression` | [View job](https://github.com/SecAI-Hub/SecAI_OS/actions/workflows/ci.yml) | Adversarial test suite: prompt injection, policy bypass, containment, recovery |
| `supply-chain-verify` | [View job](https://github.com/SecAI-Hub/SecAI_OS/actions/workflows/ci.yml) | SBOM generation via Syft, cosign availability, provenance keywords in release/build workflows |
| `test-count-check` | [View job](https://github.com/SecAI-Hub/SecAI_OS/actions/workflows/ci.yml) | Prevents documented test counts from drifting below actual (source of truth: [test-counts.json](docs/test-counts.json)) |
| `dependency-audit` | [View job](https://github.com/SecAI-Hub/SecAI_OS/actions/workflows/ci.yml) | Enforced Go vulnerability scanning (govulncheck) + Python dependency audit (pip-audit) with [waiver mechanism](.github/vuln-waivers.json) |
| `shellcheck` | [View job](https://github.com/SecAI-Hub/SecAI_OS/actions/workflows/ci.yml) | Static analysis of all shell scripts (first-boot, build, verify-release, etc.) |
| `policy-validate` | [View job](https://github.com/SecAI-Hub/SecAI_OS/actions/workflows/ci.yml) | YAML schema validation for all policy and recipe files |
| `check-pins` | [View job](https://github.com/SecAI-Hub/SecAI_OS/actions/workflows/ci.yml) | Verifies all GitHub Actions are pinned to specific commit SHAs (not tags) |
| `docs-validation` | [View job](https://github.com/SecAI-Hub/SecAI_OS/actions/workflows/ci.yml) | Broken link detection, required docs presence, test-counts.json format validation |

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | System design, zones, data flow, service dependencies |
| [Threat Model](docs/threat-model.md) | Threat classes, invariants, residual risks |
| [API Reference](docs/api.md) | HTTP API for all services |
| [Policy Schema](docs/policy-schema.md) | Full policy.yaml schema reference |
| [Security Status](docs/security-status.md) | Implementation status of all 47 milestones |
| [Test Matrix](docs/test-matrix.md) | Test coverage: 1,117 tests across Go and Python (see [test-counts.json](docs/test-counts.json)) |
| [Compatibility Matrix](docs/compatibility-matrix.md) | GPU, VM, and hardware support |
| [Security Test Matrix](docs/security-test-matrix.md) | Security feature test coverage |
| [FAQ](docs/faq.md) | Common questions |
| [Glossary](docs/glossary.md) | Key terms and concepts |
| [Non-Goals](docs/non-goals.md) | What SecAI OS does NOT try to do |

### Component Docs

| Component | Description |
|-----------|-------------|
| [Registry](docs/components/registry.md) | Trusted artifact manifest and model store |
| [Tool Firewall](docs/components/tool-firewall.md) | Policy-gated tool invocation |
| [Airlock](docs/components/airlock.md) | Sanitized egress proxy |
| [Quarantine](docs/components/quarantine.md) | 7-stage scanning pipeline |
| [Agent](docs/components/agent.md) | Policy-bound local autopilot with verified supervisor |
| [Search Mediator](docs/components/search-mediator.md) | Tor-routed web search |
| [GPU Integrity Watch](docs/components/gpu-integrity-watch.md) | Continuous GPU runtime verification |
| [MCP Firewall](docs/components/mcp-firewall.md) | Model Context Protocol policy gateway |
| [Policy Engine](docs/components/policy-engine.md) | Unified policy decision point |
| [Runtime Attestor](docs/components/runtime-attestor.md) | TPM2 attestation and startup gating |
| [Integrity Monitor](docs/components/integrity-monitor.md) | Continuous file integrity verification |
| [Incident Recorder](docs/components/incident-recorder.md) | Security event capture and auto-containment |
| [M5 Control Matrix](docs/m5-control-matrix.md) | M5 acceptance criteria, enforcement paths, operator verification |
| [Supply Chain Provenance](docs/supply-chain-provenance.md) | Provenance pipeline, SBOM coverage, key material |
| [Audit Quick Path](docs/audit-quick-path.md) | External auditor step-by-step verification guide |
| [Recovery Runbook](docs/recovery-runbook.md) | Operator procedures for degradation, containment, and recovery |
| [Sample Release Bundle](docs/sample-release-bundle.md) | Release artifact structure and verification commands |
| [Production Operations](docs/production-operations.md) | First-boot checks, upgrades, key rotation, monitoring, capacity |
| [Production Readiness Checklist](docs/production-readiness-checklist.md) | Formal release gate checklist for production deployments |
| [SLOs](docs/slos.md) | Service level objectives: availability, latency, correctness targets |
| [Release Policy](docs/release-policy.md) | Release channels (stable/candidate/dev), versioning, upgrade paths |
| [Support Lifecycle](docs/support-lifecycle.md) | Hardware matrix, driver versions, support windows, deprecation policy |

### Install Guides

| Guide | Description |
|-------|-------------|
| [Bare Metal](docs/install/bare-metal.md) | Fresh install on dedicated hardware |
| [Virtual Machine](docs/install/vm.md) | VirtualBox, VMware, KVM/QEMU |
| [Development](docs/install/dev.md) | Local dev without OS rebase |

### Examples

| Example | Description |
|---------|-------------|
| [Import a GGUF Model](examples/import-gguf-model.md) | Safe model import walkthrough |
| [Quarantine Promotion](examples/promote-through-quarantine.md) | Full pipeline walkthrough |
| [Run Fully Offline](examples/run-fully-offline.md) | Air-gapped operation |
| [Enable Web Search](examples/enable-web-search.md) | Tor-routed search setup |
| [Vault Management](examples/lock-unlock-vault.md) | Lock, unlock, keepalive |
| [Recover from Failed Update](examples/recover-failed-update.md) | Rollback and recovery |
| [VM vs Bare Metal](examples/vm-vs-bare-metal.md) | Comparison and tradeoffs |
| [Add Model Source](examples/add-model-source.md) | Allowlist a new source |

### Machine-Readable

| Resource | Description |
|----------|-------------|
| [OpenAPI Spec](schemas/openapi.yaml) | OpenAPI 3.0 for all HTTP APIs |
| [Policy Schema](schemas/policy.schema.json) | JSON Schema for policy.yaml |
| [Appliance Schema](schemas/appliance.schema.json) | JSON Schema for appliance.yaml |
| [Service Diagram](docs/service-diagram.md) | Mermaid dependency diagram |
| [llms.txt](llms.txt) | LLM-friendly project summary |
| [llms-full.txt](llms-full.txt) | Extended LLM-friendly reference |

---

## Using the Appliance

### Web Interface

Open `http://127.0.0.1:8480`:

- **Chat** -- LLM interaction with optional Tor-routed web search
- **Models** -- Browse catalog, one-click download, import, verify hashes
- **Generate** -- Text-to-image, image-to-image, text-to-video with diffusion models
- **Security** -- Service health, Secure Boot/TPM2 status, audit chain, emergency panic
- **Updates** -- Staged update workflow (check / stage / apply / rollback)
- **Settings** -- Vault lock/unlock, passphrase change, session management

### Emergency Panic

```bash
sudo securectl panic 1                          # Lock (reversible)
sudo securectl panic 2 --confirm "passphrase"   # Wipe keys
sudo securectl panic 3 --confirm "passphrase"   # Full wipe (DATA UNRECOVERABLE)
```

Also available via Web UI (Security page) and API (`POST /api/emergency/panic`).

### Vault Management

```bash
curl http://127.0.0.1:8480/api/vault/status         # Check status
curl -X POST http://127.0.0.1:8480/api/vault/lock    # Lock
curl -X POST http://127.0.0.1:8480/api/vault/unlock \ # Unlock
  -H 'Content-Type: application/json' \
  -d '{"passphrase": "your-passphrase"}'
```

### Web Search (Tor-Routed, Optional)

```bash
# Enable in policy, then start the search stack
sudo systemctl start secure-ai-tor secure-ai-searxng secure-ai-search-mediator
```

Privacy: Tor-routed, PII stripped, injection detection, privacy-preserving query obfuscation (decoy queries, k-anonymity), audit logged. See [examples/enable-web-search.md](examples/enable-web-search.md).

---

## Running Tests

```bash
# Go tests (399 total across 9 services)
for svc in airlock registry tool-firewall gpu-integrity-watch mcp-firewall \
           policy-engine runtime-attestor integrity-monitor incident-recorder; do
  (cd services/$svc && go test -v -race ./...)
done

# Python tests (718 total)
pip install pytest flask requests pyyaml
python -m pytest tests/ -v

# Shell script linting
shellcheck files/system/usr/libexec/secure-ai/*.sh files/scripts/*.sh
```

See [docs/test-matrix.md](docs/test-matrix.md) for full breakdown.

---

## Roadmap

<details>
<summary>All 47 project milestones (click to expand)</summary>

- [x] **Milestone 0** -- Threat model, dataflow, invariants, policy files
- [x] **Milestone 1** -- Bootable OS, encrypted vault, GPU drivers
- [x] **Milestone 2** -- Trusted Registry, hash pinning, cosign verification
- [x] **Milestone 3** -- 7-stage quarantine pipeline
- [x] **Milestone 4** -- Tool Firewall, default-deny policy
- [x] **Milestone 5** -- Online Airlock, sanitization
- [x] **Milestone 6** -- Systemd sandboxing, kernel hardening, nftables
- [x] **Milestone 7** -- CI/CD, Go/Python tests, shellcheck
- [x] **Milestone 8** -- Image/video generation, diffusion worker
- [x] **Milestone 9** -- Multi-GPU support (NVIDIA/AMD/Intel/Apple)
- [x] **Milestone 10** -- Tor-routed search, SearXNG, PII stripping
- [x] **Milestone 11** -- VM support, OVA/QCOW2 builds
- [x] **Milestone 12** -- Model integrity monitoring
- [x] **Milestone 13** -- Tamper-evident audit logs
- [x] **Milestone 14** -- Local passphrase auth
- [x] **Milestone 15** -- Vault auto-lock
- [x] **Milestone 16** -- Seccomp-BPF + Landlock process isolation
- [x] **Milestone 17** -- Secure Boot + TPM2 measured boot
- [x] **Milestone 18** -- Memory protection (swap/zswap/core dumps/mlock/TEE)
- [x] **Milestone 19** -- Traffic analysis protection
- [x] **Milestone 20** -- Privacy-preserving query obfuscation for search
- [x] **Milestone 21** -- Clipboard isolation
- [x] **Milestone 22** -- Canary/tripwire system
- [x] **Milestone 23** -- Emergency wipe (3-level panic)
- [x] **Milestone 24** -- Update verification + auto-rollback
- [x] **Milestone 25** -- UI polish + security hardening
- [x] **Milestone 26** -- Fail-closed pipeline, service auth, CSRF, supply chain pinning
- [x] **Milestone 27** -- Enhanced scanners, provenance manifests, fs-verity
- [x] **Milestone 28** -- Weight distribution fingerprinting
- [x] **Milestone 29** -- Garak LLM vulnerability scanner
- [x] **Milestone 30** -- gguf-guard deep GGUF integrity scanner
- [x] **Milestone 31** -- Agent Mode (Phase 1: safe local autopilot)
- [x] **Milestone 32** -- GPU Integrity Watch (continuous GPU runtime verification)
- [x] **Milestone 33** -- MCP Firewall (Model Context Protocol policy gateway)
- [x] **Milestone 34** -- Release provenance + per-service SBOMs (SLSA3, CycloneDX, cosign)
- [x] **Milestone 35** -- Unified policy decision engine (6 domains, OPA/Rego-upgradeable)
- [x] **Milestone 36** -- Runtime attestation + startup gating (TPM2, HMAC state bundles)
- [x] **Milestone 37** -- Continuous integrity monitor (baseline-verified file watcher)
- [x] **Milestone 38** -- Incident recorder + containment automation (9 classes, 4-state lifecycle)
- [x] **Milestone 39** -- GPU integrity deep integration (driver fingerprinting, attestor/incident wiring)
- [x] **Milestone 40** -- Agent verified supervisor hardening (signed tokens, replay protection, two-phase approval)
- [x] **Milestone 41** -- HSM-backed key handling (pluggable keystore: software/TPM2/PKCS#11)
- [x] **Milestone 42** -- Enforcement wiring + CI supply chain verification
- [x] **Milestone 43** -- Stronger isolation: sandbox tightening, adversarial tests, CI security regression, MCP isolation, recovery ceremonies, M5 acceptance suite
- [x] **Milestone 44** -- Auditability and documentation hardening: test-count drift CI check, CI evidence links and badges, M4/M5 terminology disambiguation, audit quick-path doc, recovery runbook, verify-release script, security/product roadmap split
- [x] **Milestone 45** -- Production readiness hardening: incident persistence (file-backed), graceful shutdown for all Go services, HTTP timeouts, systemd production hardening, first-boot validation, audit log rotation, CI vulnerability scanning, production operations guide
- [x] **Milestone 46** -- Operational maturity: bootstrap trust gap fix (cosign verify before rebase), CI runs on all changes (removed paths-ignore for .md), Python quality gates (ruff + bandit + split test suites), docs-validation CI job, production-readiness checklist, SLOs, release channel policy, support lifecycle, sample verification output
- [x] **Milestone 47** -- CI enforcement hardening: enforced vulnerability scanning (govulncheck + pip-audit + bandit fail on HIGH/HIGH) with waiver mechanism, mypy type checking for security-sensitive services, pinned reproducible Python CI dependencies, Go 1.23→1.25 (12 stdlib CVE fixes), verification-first bootstrap docs

</details>

---

## Project Structure

```
recipes/                    BlueBuild recipe (image definition)
files/
  system/
    etc/secure-ai/          Policy and config files baked into image
    etc/nftables/            Firewall rules (default-deny egress)
    usr/lib/systemd/         Systemd service units (sandboxed)
    usr/libexec/             Helper scripts (firstboot, vault, securectl, canary)
services/
  registry/                 Go -- Trusted Registry (:8470)
  tool-firewall/            Go -- Policy-gated tool gateway (:8475)
  airlock/                  Go -- Online egress proxy (:8490)
  gpu-integrity-watch/      Go -- GPU runtime verification (:8495)
  mcp-firewall/             Go -- MCP policy gateway (:8496)
  policy-engine/            Go -- Unified policy decisions (:8500)
  runtime-attestor/         Go -- TPM2 attestation + startup gating (:8505)
  integrity-monitor/        Go -- Continuous file integrity watcher (:8510)
  incident-recorder/        Go -- Incident capture + containment (:8515)
  agent/                    Python/Flask -- Verified supervisor autopilot (:8476)
  quarantine/               Python -- 7-stage verification + scanning pipeline
  diffusion-worker/         Python -- Image/video generation (:8455)
  search-mediator/          Python -- Tor-routed web search (:8485)
  ui/                       Python/Flask -- Web UI (:8480)
  common/                   Python -- Shared utilities (audit, auth, mlock)
tests/                      718 Python tests, 399 Go tests (1,117 total)
docs/                       Architecture, API, threat model, install guides
schemas/                    OpenAPI spec, JSON Schema for config files
examples/                   Task-oriented walkthroughs
.github/workflows/          CI (test/lint), build (image), release (SLSA3/SBOM)
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for local dev setup, coding standards, and PR rules.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and threat boundaries.

## License

[Apache License 2.0](LICENSE)
