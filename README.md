# SecAI OS

[![CI](https://github.com/SecAI-Hub/SecAI_OS/actions/workflows/ci.yml/badge.svg)](https://github.com/SecAI-Hub/SecAI_OS/actions/workflows/ci.yml)
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
- **20+ defense layers** -- From UEFI Secure Boot and TPM2 to seccomp-BPF, Landlock, canary files, and 3-level emergency wipe.

---

## Quickstart

### Install (Fedora Atomic)

```bash
# Rebase to unsigned image first
sudo rpm-ostree rebase ostree-unverified-registry:ghcr.io/sec_ai/secai_os:latest
sudo systemctl reboot

# Then rebase to signed image
sudo rpm-ostree rebase ostree-image-signed:docker://ghcr.io/sec_ai/secai_os:latest
sudo systemctl reboot

# Set up encrypted vault
sudo /usr/libexec/secure-ai/setup-vault.sh /dev/sdX
```

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
| Search Mediator | 8485 | Python | Tor-routed web search with PII stripping |
| SearXNG | 8888 | Python | Self-hosted metasearch (privacy-respecting engines) |
| Tor | 9050 | C | Anonymous SOCKS5 proxy |

See [docs/architecture.md](docs/architecture.md) for design decisions and service dependencies. Per-service docs: [registry](docs/components/registry.md) | [tool-firewall](docs/components/tool-firewall.md) | [agent](docs/components/agent.md) | [airlock](docs/components/airlock.md) | [quarantine](docs/components/quarantine.md) | [search-mediator](docs/components/search-mediator.md)

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
| **Agent** | Deny-by-default policy engine, capability tokens, hard budgets, loopback-only IPC, IPAddressDeny |
| **GPU** | Vendor-specific DeviceAllow, PrivateNetwork on all workers |
| **Clipboard** | VM clipboard agents disabled, auto-clear every 60s |
| **Tripwire** | Canary files in sensitive dirs, inotify real-time monitoring |
| **Emergency** | 3-level panic (lock / wipe keys / full wipe) with passphrase gates |
| **Updates** | Cosign-verified rpm-ostree, staged workflow, greenboot auto-rollback |

See [docs/threat-model.md](docs/threat-model.md) for threat classes, residual risks, and security invariants. See [docs/security-status.md](docs/security-status.md) for implementation status of all 31 milestones.

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

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | System design, zones, data flow, service dependencies |
| [Threat Model](docs/threat-model.md) | Threat classes, invariants, residual risks |
| [API Reference](docs/api.md) | HTTP API for all services |
| [Policy Schema](docs/policy-schema.md) | Full policy.yaml schema reference |
| [Security Status](docs/security-status.md) | Implementation status of all 31 milestones |
| [Test Matrix](docs/test-matrix.md) | Test coverage: 700+ tests across Go, Python, shell |
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
| [Agent](docs/components/agent.md) | Policy-bound local autopilot |
| [Search Mediator](docs/components/search-mediator.md) | Tor-routed web search |

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
# Go tests (26 total)
cd services/registry && go test -v -race ./...
cd services/tool-firewall && go test -v -race ./...
cd services/airlock && go test -v -race ./...

# Python tests (700+ total)
pip install pytest flask requests pyyaml
python -m pytest tests/ -v

# Shell script linting
shellcheck files/system/usr/libexec/secure-ai/*.sh files/scripts/*.sh
```

See [docs/test-matrix.md](docs/test-matrix.md) for full breakdown.

---

## Roadmap

<details>
<summary>All 31 milestones (click to expand)</summary>

- [x] **M0** -- Threat model, dataflow, invariants, policy files
- [x] **M1** -- Bootable OS, encrypted vault, GPU drivers
- [x] **M2** -- Trusted Registry, hash pinning, cosign verification
- [x] **M3** -- 7-stage quarantine pipeline
- [x] **M4** -- Tool Firewall, default-deny policy
- [x] **M5** -- Online Airlock, sanitization
- [x] **M6** -- Systemd sandboxing, kernel hardening, nftables
- [x] **M7** -- CI/CD, Go/Python tests, shellcheck
- [x] **M8** -- Image/video generation, diffusion worker
- [x] **M9** -- Multi-GPU support (NVIDIA/AMD/Intel/Apple)
- [x] **M10** -- Tor-routed search, SearXNG, PII stripping
- [x] **M11** -- VM support, OVA/QCOW2 builds
- [x] **M12** -- Model integrity monitoring
- [x] **M13** -- Tamper-evident audit logs
- [x] **M14** -- Local passphrase auth
- [x] **M15** -- Vault auto-lock
- [x] **M16** -- Seccomp-BPF + Landlock process isolation
- [x] **M17** -- Secure Boot + TPM2 measured boot
- [x] **M18** -- Memory protection (swap/zswap/core dumps/mlock/TEE)
- [x] **M19** -- Traffic analysis protection
- [x] **M20** -- Privacy-preserving query obfuscation for search
- [x] **M21** -- Clipboard isolation
- [x] **M22** -- Canary/tripwire system
- [x] **M23** -- Emergency wipe (3-level panic)
- [x] **M24** -- Update verification + auto-rollback
- [x] **M25** -- UI polish + security hardening
- [x] **M26** -- Fail-closed pipeline, service auth, CSRF, supply chain pinning
- [x] **M27** -- Enhanced scanners, provenance manifests, fs-verity
- [x] **M28** -- Weight distribution fingerprinting
- [x] **M29** -- Garak LLM vulnerability scanner
- [x] **M30** -- gguf-guard deep GGUF integrity scanner
- [x] **M31** -- Agent Mode (Phase 1: safe local autopilot)

</details>

---

## Project Structure

```
recipes/                BlueBuild recipe (image definition)
files/
  system/
    etc/secure-ai/      Policy and config files baked into image
    etc/nftables/        Firewall rules (default-deny egress)
    usr/lib/systemd/     Systemd service units (sandboxed)
    usr/libexec/         Helper scripts (firstboot, vault, securectl, canary)
services/
  registry/             Go -- Trusted Registry
  tool-firewall/        Go -- Policy engine + tool gateway
  airlock/              Go -- Online egress proxy
  agent/                Python/Flask -- Policy-bound local autopilot
  quarantine/           Python -- 7-stage verification + scanning pipeline
  diffusion-worker/     Python -- Image/video generation
  search-mediator/      Python -- Tor-routed web search
  ui/                   Python/Flask -- Web UI
tests/                  700+ Python tests, 26 Go tests
docs/                   Architecture, API, threat model, install guides
schemas/                OpenAPI spec, JSON Schema for config files
examples/               Task-oriented walkthroughs
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for local dev setup, coding standards, and PR rules.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and threat boundaries.

## License

[Apache License 2.0](LICENSE)
