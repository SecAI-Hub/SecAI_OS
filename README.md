# SecAI OS

A bootable, local-first AI appliance with defense-in-depth security. Supports NVIDIA, AMD, Intel, and Apple Silicon GPUs — all compute stays on-device.

Built on [uBlue](https://universal-blue.org/) (Fedora Atomic / Silverblue) with an immutable OS, encrypted vault, and sealed runtime where sensitive data never leaves the device by default.

## Design Principles

- **Local-first** -- Prompts, documents, credentials, and personal data stay on-device.
- **Default-deny egress** -- The runtime has no internet unless explicitly enabled via the airlock.
- **Supply-chain distrust** -- Models, containers, and plugins are untrusted until verified and scanned.
- **Deterministic policy** -- Promotion to "trusted" is rule-based (signatures, hashes, scans, tests), not ad-hoc.
- **Short-lived workers** -- No swap, tmpfs for temp data, inference workers restart between sessions.
- **Hands-off security** -- All scanning, verification, and promotion happens automatically. Users never run security tools manually.

## Architecture

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

## Services

| Service | Port | Language | Purpose |
|---------|------|----------|---------|
| Registry | 8470 | Go | Trusted artifact manifest, read-only model store |
| Tool Firewall | 8475 | Go | Policy-gated tool invocation gateway |
| Web UI | 8480 | Python | Chat, image/video generation, model management |
| Airlock | 8490 | Go | Sanitized egress proxy (disabled by default) |
| Inference Worker | 8465 | llama.cpp | LLM inference (CUDA / ROCm / Vulkan / Metal / CPU) |
| Diffusion Worker | 8455 | Python | Image and video generation (CUDA / ROCm / XPU / MPS / CPU) |
| Quarantine | -- | Python | 7-stage verify, scan, and promote pipeline |
| Search Mediator | 8485 | Python | Sanitized web search (query PII stripping + result cleaning) |
| SearXNG | 8888 | Python | Self-hosted metasearch engine (privacy-respecting engines only) |
| Tor | 9050 | C | Anonymous SOCKS5 proxy (all searches routed through Tor) |

## Hardware Support

GPU is **auto-detected at first boot** — no manual configuration needed. The `detect-gpu.sh` script identifies your hardware and writes the optimal settings.

### Supported GPUs

| Vendor | GPUs | Backend | LLM (llama.cpp) | Diffusion (PyTorch) |
|--------|------|---------|-----------------|-------------------|
| **NVIDIA** | RTX 5090/5080/4090/4080/3090/3080, any CUDA GPU | CUDA | Full offload | Full offload |
| **AMD** | RX 7900 XTX/XT, RX 7800/7700, RX 6900/6800, any RDNA/CDNA | ROCm (HIP) | Full offload | Full offload |
| **Intel** | Arc A770/A750/A580, Arc B-series, Data Center Max | XPU (oneAPI) | Via Vulkan | Via IPEX |
| **Apple** | M4/M3/M2/M1 (Pro/Max/Ultra) | Metal / MPS | Full offload | MPS acceleration |
| **Any CPU** | x86_64 (AVX2/AVX-512), ARM64 (NEON) | CPU | Optimized | Functional |

### Backend Priority

The system auto-selects the best available backend in this order:
1. **CUDA** (NVIDIA) — highest throughput for both LLM and diffusion
2. **ROCm** (AMD) — near-CUDA performance on RDNA3/CDNA
3. **MPS** (Apple Silicon) — Metal acceleration on macOS
4. **XPU** (Intel Arc) — oneAPI/SYCL for discrete Intel GPUs
5. **Vulkan** (cross-vendor) — universal GPU compute fallback for llama.cpp
6. **CPU** — AVX2/AVX-512/NEON auto-vectorized, works on everything

### Security Note

All GPU backends run locally with the same sandboxing:
- `PrivateNetwork=yes` — no network access regardless of GPU vendor
- `DeviceAllow` restricts access to only the specific GPU device nodes needed
- AMD ROCm uses `/dev/kfd` + `/dev/dri/*`; NVIDIA uses `/dev/nvidia*`; Intel uses `/dev/dri/*`
- No cloud compute, no driver telemetry endpoints (blocked by nftables default-deny)

**Minimum requirements:**

- 16 GB RAM (32 GB recommended for larger models)
- 8 GB VRAM for GPU offload (24 GB recommended for 13B+ models or image generation)
- 64 GB storage (32 GB OS + encrypted vault)
- USB 3.0 flash drive (16 GB+) or spare SSD for bootable install

---

## Installation

There are three ways to run SecAI OS, depending on your situation.

### Option A: Create a Bootable USB (Fresh Install)

This is the recommended approach for a dedicated AI workstation.

#### Prerequisites

- A USB flash drive (16 GB minimum, USB 3.0+ recommended) **or** a spare SSD/NVMe
- An existing Linux machine (or live USB) to create the bootable media
- A second partition or drive for the encrypted vault (recommended)

#### Step 1: Download the Fedora Silverblue ISO

SecAI OS is built on top of Fedora Silverblue. Start by downloading the base installer:

```bash
# Download Fedora Silverblue 42 (or latest)
# https://fedoraproject.org/atomic-desktops/silverblue/
curl -LO https://download.fedoraproject.org/pub/fedora/linux/releases/42/Silverblue/x86_64/iso/Fedora-Silverblue-ostree-x86_64-42-1.1.iso
```

#### Step 2: Write the ISO to USB

```bash
# Identify your USB device (BE CAREFUL — this erases the drive)
lsblk

# Write the ISO (replace /dev/sdX with your USB device)
sudo dd if=Fedora-Silverblue-ostree-x86_64-42-1.1.iso of=/dev/sdX bs=4M status=progress oflag=sync
```

Alternatively, use [Fedora Media Writer](https://docs.fedoraproject.org/en-US/fedora/latest/preparing-boot-media/) or [balenaEtcher](https://etcher.balena.io/).

#### Step 3: Install Fedora Silverblue

1. Boot from the USB drive (press F12 / F2 / Del during POST to select boot device).
2. Follow the Anaconda installer.
3. **Partitioning suggestion for dedicated machines:**
   - `/boot` — 1 GB (ext4)
   - `/boot/efi` — 512 MB (EFI System Partition) — UEFI systems only
   - `/` (root) — 32 GB (automatic / btrfs) — immutable OS lives here
   - Remaining space — leave **unformatted** (we'll use it for the encrypted vault)
4. Complete the installation and reboot into Fedora Silverblue.

#### Step 4: Rebase to SecAI OS

Once booted into your fresh Fedora Silverblue install:

```bash
# First rebase to the unsigned image to get signing keys
sudo rpm-ostree rebase ostree-unverified-registry:ghcr.io/sec_ai/secai_os:latest

sudo systemctl reboot

# After reboot, rebase to the signed image
sudo rpm-ostree rebase ostree-image-signed:docker://ghcr.io/sec_ai/secai_os:latest

sudo systemctl reboot
```

After the second reboot, you are running SecAI OS.

#### Step 5: Set Up the Encrypted Vault

The encrypted vault stores your models, documents, and inference outputs. It uses LUKS2 with AES-256 and Argon2id key derivation.

```bash
# Identify the unused partition from Step 3 (e.g., /dev/sda3)
lsblk

# Run the vault setup script (included in the image)
sudo /usr/libexec/secure-ai/setup-vault.sh /dev/sda3
```

You will be prompted to:
1. Confirm that the partition will be erased
2. Set an encryption passphrase (use a strong passphrase — this protects all your data)

The script will output `crypttab` and `fstab` entries. Add them so the vault auto-mounts on boot:

```bash
# Add to /etc/crypttab (use the UUID printed by the script)
echo "secure-ai-vault  UUID=<your-uuid>  none  luks,discard" | sudo tee -a /etc/crypttab

# Add to /etc/fstab
echo "/dev/mapper/secure-ai-vault  /var/lib/secure-ai  ext4  defaults,nodev,nosuid  0  2" | sudo tee -a /etc/fstab
```

On every subsequent boot, you'll be prompted for the vault passphrase before services start.

#### Step 6: First Boot Initialization

On the first boot after vault setup, the `secure-ai-firstboot` service runs automatically and:

- Creates the directory structure (`/var/lib/secure-ai/{vault,registry,quarantine,logs,keys}`)
- Generates a local cosign signing key pair for model promotion
- Sets restrictive permissions on all directories
- Verifies the nftables firewall is active
- Disables swap

You can check the status:

```bash
systemctl status secure-ai-firstboot
journalctl -u secure-ai-firstboot
```

---

### Option B: Rebase an Existing Fedora Atomic Installation

If you already run Fedora Silverblue, Kinoite, or any Fedora Atomic variant:

```bash
# Rebase to unsigned image first
sudo rpm-ostree rebase ostree-unverified-registry:ghcr.io/sec_ai/secai_os:latest
sudo systemctl reboot

# Then rebase to signed image
sudo rpm-ostree rebase ostree-image-signed:docker://ghcr.io/sec_ai/secai_os:latest
sudo systemctl reboot
```

Then follow **Step 5** and **Step 6** above to set up the encrypted vault.

### Option C: Development / Testing (No Rebase)

For development or testing without rebasing your OS, you can run the services directly:

```bash
# Clone the repository
git clone https://github.com/SecAI-Hub/SecAI_OS.git
cd SecAI_OS

# Build Go services
cd services/registry && go build -o ../../bin/registry . && cd ../..
cd services/tool-firewall && go build -o ../../bin/tool-firewall . && cd ../..
cd services/airlock && go build -o ../../bin/airlock . && cd ../..

# Install Python dependencies
# For NVIDIA: pip install torch --index-url https://download.pytorch.org/whl/cu124
# For AMD:    pip install torch --index-url https://download.pytorch.org/whl/rocm6.1
# For CPU:    pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install flask requests pyyaml diffusers transformers accelerate torch safetensors

# Run the UI (Flask)
cd services/ui && python -m flask --app ui.app run --port 8480
```

> [!NOTE]
> In development mode, services run without systemd sandboxing and without the nftables firewall. This is **not** security-equivalent to the full appliance.

---

## Quick Start: Getting Your First Model

After installation, open the Web UI at `http://127.0.0.1:8480`. SecAI OS is designed so that **all security scanning is fully automatic** — you never need to run any scanning tools manually.

### One-Click Download (Recommended)

1. Open `http://127.0.0.1:8480` and go to the **Models** page.
2. Browse the **Model Catalog** — a curated list of pre-verified models for both LLM chat and image/video generation.
3. Click **Download** next to any model. The download begins in the background.
4. Track progress on the Models page. When complete, the model enters quarantine automatically.
5. The 7-stage quarantine pipeline runs without any user intervention:
   - Source verification (confirms origin against allowlist)
   - Format validation (header checks, rejects unsafe formats)
   - Integrity check (hash pinning)
   - Provenance verification (signature checks)
   - Static scan + entropy analysis (detects hidden payloads)
   - Behavioral smoke test (22 adversarial prompts — LLM models only)
   - Diffusion deep scan (config integrity — diffusion models only)
6. If all stages pass, the model is **promoted to the trusted registry** and becomes available immediately.
7. If any stage fails, the model is **rejected and quarantined**. Check the logs for details.

That's it. Pick a model, click download, and start using it once promotion completes.

### Pre-Curated Model Catalog

**LLM Models (Chat):**

| Model | Size | VRAM | Best For |
|-------|------|------|----------|
| Phi-3 Mini 3.8B (Q4_K_M) | ~2 GB | 4 GB | Quick responses, testing, low-VRAM systems |
| Mistral 7B Instruct (Q4_K_M) | ~4 GB | 6 GB | General-purpose chat, fast inference |
| Llama 3.1 8B Instruct (Q4_K_M) | ~5 GB | 7 GB | Strong reasoning, coding assistance |

**Diffusion Models (Image/Video):**

| Model | Size | VRAM | Best For |
|-------|------|------|----------|
| Stable Diffusion 1.5 | ~4 GB | 6 GB | Fast image generation, many community styles |
| Stable Diffusion XL | ~7 GB | 10 GB | High-quality images, better composition |
| Stable Video Diffusion XT | ~10 GB | 16 GB | Short video clips from images |

### Importing Your Own Models

You can also import models you've downloaded or created yourself. Custom models go through the **exact same 7-stage quarantine pipeline** as catalog models:

**Via the Web UI:**
1. Go to the **Models** page
2. Click **Import** and select your model file (`.gguf` or `.safetensors`)
3. The quarantine pipeline runs automatically — no manual steps needed

**Via the CLI:**
```bash
# Copy a model into the quarantine incoming directory
sudo cp /path/to/your-model.gguf /var/lib/secure-ai/quarantine/incoming/

# The quarantine watcher picks it up automatically
# Watch the pipeline progress:
journalctl -u secure-ai-quarantine-watcher -f

# Once promoted, verify it appears in the registry:
curl http://127.0.0.1:8470/v1/models | python3 -m json.tool
```

**Via securectl:**
```bash
# List models in the registry
securectl list

# Verify a model's integrity
securectl verify --name your-model
```

> [!IMPORTANT]
> Custom models with no known source are subject to stricter scrutiny. Models from sources not in the allowlist will have their source policy stage flagged. The remaining 6 stages still run, and the model can be promoted if it passes all other checks.

---

## Using the Appliance

### Web Interface

Open `http://127.0.0.1:8480` in a browser. The UI provides:

- **Chat** — Interact with your loaded LLM model
- **Generate** — Create images and videos with diffusion models
  - Text-to-Image: Describe what you want, set resolution and steps
  - Image-to-Image: Upload a reference image and transform it with a prompt
  - Text-to-Video: Generate short video clips from text descriptions
- **Models** — Browse catalog, one-click download, import, verify, and manage models
- **Status** — Check health of all services (inference, diffusion, registry, airlock)

### Service Management

```bash
# Check overall status
systemctl status secure-ai-*

# View inference logs
journalctl -u secure-ai-inference -f

# View diffusion worker logs
journalctl -u secure-ai-diffusion -f

# Restart a service
sudo systemctl restart secure-ai-inference

# View firewall rules
sudo nft list ruleset
```

### Panic Switch (Emergency Lockdown)

If you suspect a compromise or data leak in progress:

```bash
sudo systemctl start secure-ai-panic
```

This immediately:
1. Replaces all firewall rules with a total-deny policy (loopback only)
2. Flushes all network routes
3. Stops the airlock and UI services
4. Writes an audit record

To recover from panic mode, reboot the system.

### Airlock (Optional Online Access)

The airlock is **disabled by default**. To enable it for downloading models:

```bash
sudo systemctl start secure-ai-airlock
```

The airlock enforces:
- HTTPS only
- Destination allowlist (Hugging Face, Ollama registry by default)
- PII scanning (blocks SSNs, emails, etc.)
- Credential scanning (blocks API keys, tokens, passwords)
- Rate limiting (30 requests/minute)
- Body size limits (10 MB)

Edit the allowlist at `/etc/secure-ai/policy/policy.yaml` under `airlock.allowed_destinations`.

To disable the airlock again:

```bash
sudo systemctl stop secure-ai-airlock
```

### Web Search (Tor-Routed, Optional)

Web search is **disabled by default**. When enabled, the LLM can augment its answers with web search results — all routed through Tor for anonymity.

**How it works:**
1. The LLM generates a search query (your raw prompt never leaves the device)
2. The search mediator strips PII (emails, phone numbers, SSNs, API keys, IPs) from the query
3. The sanitized query goes to a local SearXNG instance
4. SearXNG routes the search through Tor (your IP is hidden from search engines)
5. Results come back through Tor, are stripped of HTML/scripts, and checked for prompt injection
6. Clean results are injected as context for the LLM to formulate a better answer
7. The UI shows a "web sources used" indicator with citations

**To enable:**

```bash
# Enable in policy first
# Edit /etc/secure-ai/policy/policy.yaml and set search.enabled: true

# Start the search stack (Tor -> SearXNG -> Search Mediator)
sudo systemctl start secure-ai-tor
sudo systemctl start secure-ai-searxng
sudo systemctl start secure-ai-search-mediator
```

**Privacy protections:**
- All traffic routed through Tor (IP hidden from search engines)
- Only privacy-respecting engines enabled (DuckDuckGo, Wikipedia, StackOverflow, GitHub)
- PII automatically stripped from outbound queries
- Queries with >50% PII content are blocked entirely
- Inbound results scanned for prompt injection attacks
- Every search is audit-logged (query hash only, not raw content)
- `offline-only` session mode hard-blocks all search even if enabled

**To disable:**

```bash
sudo systemctl stop secure-ai-search-mediator secure-ai-searxng secure-ai-tor
```

---

## Security Overview

### 7-Stage Quarantine Pipeline

Every model — whether downloaded from the catalog or imported by the user — passes through the same fully automatic pipeline. No manual scanning is required.

| Stage | Name | What It Does |
|-------|------|-------------|
| 1 | **Source Policy** | Verifies the download URL against `sources.allowlist.yaml`. Local imports pass; unknown remote sources are flagged. |
| 2 | **Format Gate** | Validates file headers (GGUF magic bytes, safetensors JSON header). Rejects unsafe formats (pickle, .pt, .bin, .exe). For diffusion model directories, scans all component files and checks JSON configs for embedded code. |
| 3 | **Integrity Check** | Computes SHA-256 hash and compares against pinned hashes in `models.lock.yaml`. Supports both single files and multi-file directories. |
| 4 | **Provenance** | Verifies cosign signatures for container-sourced models. Records provenance metadata for audit trail. |
| 5 | **Static Scan + Entropy Analysis** | Runs ModelScan (if installed) to detect known malicious patterns. Performs entropy analysis on weight files — near-random entropy (>7.99 bits/byte) indicates possible steganographic or encrypted payloads hidden in model weights. |
| 6 | **Behavioral Smoke Test** | (LLM models only) Runs the model against a suite of 22 adversarial prompts across 10 categories: command injection, file exfiltration, network exfiltration, credential theft, PII handling, canary leak detection, jailbreak resistance, tool abuse, and prompt injection. Checks responses against 40+ danger patterns. Category-based scoring with stricter thresholds for critical attack vectors. |
| 7 | **Diffusion Deep Scan** | (Diffusion models only) Validates `model_index.json` structure, verifies all declared components exist, detects symlinks, and scans configs for suspicious URLs or code injection. |

**Scoring:** The smoke test uses category-weighted scoring. Critical categories (command injection, file exfiltration, network exfiltration, credential theft) have a stricter threshold — a single critical flag or >30% overall flag rate causes rejection.

### Defense Layers

| Layer | Mechanism |
|-------|-----------|
| **Boot** | Immutable OS image (rpm-ostree), signed updates (cosign) |
| **Kernel** | IOMMU forced, ASLR, slab_nomerge, init_on_alloc/free, lockdown=confidentiality |
| **Network** | nftables default-deny egress, services use PrivateNetwork=yes |
| **Swap** | Disabled (kernel arg + runtime check) — prevents secrets hitting disk |
| **Filesystem** | Encrypted vault (LUKS2/AES-256/Argon2id), restrictive permissions |
| **Models** | 7-stage quarantine: source, format, integrity, provenance, static scan, behavioral test, diffusion scan |
| **Tools** | Default-deny policy, path allowlisting, traversal protection, rate limiting |
| **Egress** | Airlock disabled by default, PII/credential scanning, destination allowlist |
| **Search** | Tor-routed, PII stripped from queries, injection detection on results, audit logged |
| **Services** | Systemd sandboxing: ProtectSystem=strict, PrivateNetwork, syscall filters |
| **GPU Isolation** | Vendor-specific DeviceAllow (NVIDIA `/dev/nvidia*`, AMD `/dev/kfd`, Intel `/dev/dri/*`), PrivateNetwork on all |
| **Emergency** | Panic switch: instant network kill + route flush + service stop |

### Systemd Sandboxing

Every service runs with defense-in-depth sandboxing:

- `ProtectSystem=strict` — read-only root filesystem
- `PrivateNetwork=yes` — no network access (except airlock)
- `NoNewPrivileges=yes` — cannot escalate
- `PrivateTmp=yes` — isolated temp directory
- `ProtectHome=yes` — no access to home directories
- `CapabilityBoundingSet=` — no capabilities (except where needed)
- `SystemCallFilter=@system-service` — restricted syscalls
- `MemoryDenyWriteExecute=yes` — no JIT/RWX memory

Both inference and diffusion workers have GPU-specific sandboxing:
- `DeviceAllow=/dev/nvidia* rw` — NVIDIA CUDA access
- `DeviceAllow=/dev/kfd rw` — AMD ROCm compute access
- `DeviceAllow=/dev/dri/* rw` — AMD/Intel DRI render nodes
- `ReadWritePaths=/var/lib/secure-ai/vault/outputs` — write only to outputs directory
- `ReadOnlyPaths=/var/lib/secure-ai/registry` — read-only model access
- Unused GPU device nodes are harmless — systemd silently ignores DeviceAllow for non-existent devices

### Verify Image Signatures

```bash
cosign verify --key cosign.pub ghcr.io/sec_ai/secai_os:latest
```

See [docs/threat-model.md](docs/threat-model.md) for the full threat model, threat classes, and residual risk analysis.

---

## Configuration

All configuration lives in `/etc/secure-ai/` (baked into the image, read-only at runtime):

| File | Purpose |
|------|---------|
| `config/appliance.yaml` | Mode, paths, inference/diffusion settings, service binds |
| `policy/policy.yaml` | Tool firewall rules, airlock settings, model format rules, quarantine stages |
| `policy/models.lock.yaml` | Pinned model hashes (supply-chain verification) |
| `policy/sources.allowlist.yaml` | Trusted container/model sources |

### Key Configuration Options

**GPU backend** (`config/appliance.yaml`):
```yaml
gpu:
  backend: "auto"   # auto | cuda | rocm | xpu | vulkan | mps | cpu
```

**Inference settings** (`config/appliance.yaml`):
```yaml
inference:
  gpu_layers: -1    # -1 = offload all to GPU, 0 = CPU only
  context_size: 8192
```

**Diffusion settings** (`config/appliance.yaml`):
```yaml
diffusion:
  bind: "127.0.0.1:8455"
  max_resolution: 2048
  max_steps: 100
  max_frames: 120
```

**Session modes** (`config/appliance.yaml`):
```yaml
session:
  mode: "normal"       # normal | sensitive | offline-only
  # sensitive: aggressive worker recycling after each task
  # offline-only: hard-block all network even if airlock is enabled
```

**Quarantine pipeline stages** (`policy/policy.yaml`):
```yaml
quarantine:
  stages:
    source_policy: true       # Stage 1: verify origin
    format_gate: true         # Stage 2: validate headers
    integrity_check: true     # Stage 3: hash pinning
    provenance_check: true    # Stage 4: signature verification
    static_scan: true         # Stage 5: modelscan + entropy
    behavioral_test: true     # Stage 6: adversarial prompts (LLM)
    diffusion_deep_scan: true # Stage 7: config integrity (diffusion)
  smoke_test_max_score: 0.3   # fail if >30% prompts flagged
  smoke_test_max_critical: 1  # fail if >1 critical flag
```

**Web search** (`policy/policy.yaml`):
```yaml
search:
  enabled: false          # disabled by default
  strip_pii: true         # always strip PII from queries
  detect_injection: true  # scan results for prompt injection
  audit: true             # log every search (hash only)
  allowed_engines:        # privacy-respecting engines only
    - duckduckgo
    - wikipedia
    - stackoverflow
```

**Tool firewall policy** (`policy/policy.yaml`):
```yaml
tools:
  default: "deny"       # deny all tools unless explicitly allowed
  allow:
    - name: "filesystem.read"
      paths_allowlist: ["/vault/user_docs/**"]
    - name: "filesystem.write"
      paths_allowlist: ["/vault/outputs/**"]
  deny:
    - name: "shell.exec"
    - name: "network.fetch"
```

To modify configuration on the running system, create overlay files or rebuild the image with updated files in `files/system/etc/secure-ai/`.

---

## Project Structure

```
recipes/                BlueBuild recipe (image definition)
files/
  system/
    etc/secure-ai/      Policy and config files baked into image
    etc/nftables/        Firewall rules (default-deny egress)
    etc/sysctl.d/        Kernel hardening parameters
    usr/lib/systemd/     Systemd service units (sandboxed)
    usr/libexec/         Helper scripts (firstboot, vault, model select, panic)
services/
  registry/             Go -- Trusted Registry
  tool-firewall/        Go -- Policy engine + tool gateway
  airlock/              Go -- Online egress proxy
  quarantine/           Python -- 7-stage verification + scanning pipeline
  inference-worker/     llama.cpp wrapper
  diffusion-worker/     Python -- Stable Diffusion image/video generation
  search-mediator/      Python -- Tor-routed web search with PII stripping
  ui/                   Python/Flask -- Web UI (chat, generate, model management)
tests/
  test_pipeline.py      Quarantine pipeline tests (48 tests)
  test_search.py        Search mediator tests (27 tests)
  test_ui.py            Web UI tests (7 tests)
docs/
  threat-model.md       Formal threat model and security invariants
```

## Running Tests

```bash
# Go tests (26 total)
cd services/registry && go test -v -race ./...
cd services/tool-firewall && go test -v -race ./...
cd services/airlock && go test -v -race ./...

# Python tests (82 total)
pip install pytest flask requests pyyaml
python -m pytest tests/ -v

# Shell script linting
shellcheck files/system/usr/libexec/secure-ai/*.sh files/scripts/*.sh
```

## Roadmap

- [x] **M0 Spec** -- Threat model, dataflow, invariants, policy files
- [x] **M1 Bootable OS** -- Encrypted vault, GPU drivers, runtime offline
- [x] **M2 Trusted Registry** -- Allowlist + hash pinning + cosign verification
- [x] **M3 Quarantine Pipeline** -- 7-stage scanning (source, format, integrity, provenance, static, behavioral, diffusion)
- [x] **M4 Tool Firewall** -- Policy-gated tool calls + file access gateway
- [x] **M5 Online Airlock** -- Sanitization + allowlist + user approval UI
- [x] **M6 Hardening** -- Systemd sandboxing, kernel params, nftables, panic switch
- [x] **M7 CI/CD** -- GitHub Actions, Go/Python tests, shellcheck, YAML validation
- [x] **M8 Image/Video Generation** -- Diffusion worker, one-click downloads, generate UI
- [x] **M9 Multi-GPU Support** -- NVIDIA/AMD/Intel/Apple auto-detection, Vulkan fallback
- [x] **M10 Tor-Routed Search** -- SearXNG + Tor, PII stripping, injection detection, audit
- [ ] **M11 Polish** -- OPA/Rego policy engine, appliance setup wizard, documentation site

## Troubleshooting

### "No model found" — Inference won't start

The inference worker needs at least one `.gguf` model in the registry:

```bash
# Check if any models are registered
curl http://127.0.0.1:8470/v1/models

# Import a model (or use the one-click catalog in the Web UI)
sudo cp your-model.gguf /var/lib/secure-ai/quarantine/incoming/

# Watch the quarantine pipeline
journalctl -u secure-ai-quarantine-watcher -f
```

### Model stuck in quarantine

If a model download completes but never appears in the registry:

```bash
# Check quarantine watcher logs for pipeline results
journalctl -u secure-ai-quarantine-watcher --no-pager -n 100

# Common reasons for rejection:
# - Source not in allowlist (add to sources.allowlist.yaml)
# - Unsafe format detected (pickle, .pt, .bin files)
# - Hash mismatch (update models.lock.yaml)
# - Smoke test failed (model responded to adversarial prompts)
# - High entropy in weights (possible hidden payload)
```

### Services won't start

```bash
# Check which services are running
systemctl list-units 'secure-ai-*'

# Check a specific service
journalctl -u secure-ai-registry --no-pager -n 50

# Verify the vault is mounted
mount | grep secure-ai
```

### GPU not detected

```bash
# Re-run GPU detection
sudo /usr/libexec/secure-ai/detect-gpu.sh

# Check what was detected
cat /var/lib/secure-ai/inference.env

# NVIDIA: check driver
nvidia-smi
lsmod | grep nvidia

# AMD: check ROCm
rocminfo
ls -la /dev/kfd /dev/dri/renderD128

# Intel: check DRI
ls -la /dev/dri/renderD128
cat /sys/class/drm/card0/device/vendor  # should be 0x8086

# Vulkan (any vendor)
vulkaninfo --summary

# Apple Silicon (Metal runs on host, not in container)
system_profiler SPDisplaysDataType
```

### Image generation not working

```bash
# Check diffusion worker health
curl http://127.0.0.1:8455/health

# Check diffusion worker logs
journalctl -u secure-ai-diffusion -f

# Verify a diffusion model is in the registry
curl http://127.0.0.1:8455/v1/models
```

### Firewall blocking something it shouldn't

```bash
# Check current rules
sudo nft list ruleset

# Check dropped packets
journalctl -k | grep secure-ai

# Temporarily reload default rules (reverts on reboot)
sudo nft -f /etc/nftables/secure-ai.nft
```

### Recovering from Panic Mode

Panic mode blocks all network and stops services. To recover:

```bash
# Simply reboot — the normal firewall rules and services are restored
sudo systemctl reboot
```

## License

See [LICENSE](LICENSE).
