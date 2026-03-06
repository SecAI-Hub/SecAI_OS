# SecAI OS

A bootable, local-first AI appliance with defense-in-depth security for consumer RTX workstations and Apple Silicon.

Built on [uBlue](https://universal-blue.org/) (Fedora Atomic / Silverblue) with an immutable OS, encrypted vault, and sealed runtime where sensitive data never leaves the device by default.

## Design Principles

- **Local-first** -- Prompts, documents, credentials, and personal data stay on-device.
- **Default-deny egress** -- The runtime has no internet unless explicitly enabled via the airlock.
- **Supply-chain distrust** -- Models, containers, and plugins are untrusted until verified and scanned.
- **Deterministic policy** -- Promotion to "trusted" is rule-based (signatures, hashes, scans, tests), not ad-hoc.
- **Short-lived workers** -- No swap, tmpfs for temp data, inference workers restart between sessions.

## Architecture

```
+-------------------+     +-------------------+     +-------------------+
|  A) Base OS       | --> |  B) Acquisition   | --> |  C) Quarantine    |
|  immutable image  |     |  dirty net /      |     |  verify + scan +  |
|  signed updates   |     |  allowlist only   |     |  smoke test       |
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
| Web UI | 8480 | Python | Local chat and management interface |
| Airlock | 8490 | Go | Sanitized egress proxy (disabled by default) |
| Inference Worker | 8465 | llama.cpp | LLM inference (CUDA + Metal) |
| Quarantine | -- | Python | Verify, scan, and promote model artifacts |

## Hardware Support

| Platform | GPU Acceleration | Notes |
|----------|-----------------|-------|
| NVIDIA RTX 5080 | CUDA (full offload) | Primary target; uses nvidia-open drivers |
| NVIDIA RTX 4090/4080/3090 | CUDA (full offload) | Any RTX card with sufficient VRAM |
| Apple M4 / M3 / M2 / M1 | Metal (via llama.cpp) | CPU-only container, Metal on host |
| Any x86_64 | CPU fallback | Slower but functional |

**Minimum requirements:**

- 16 GB RAM (32 GB recommended for larger models)
- 8 GB VRAM for GPU offload (24 GB recommended for 13B+ models)
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

# Run the UI (Flask)
pip install flask requests pyyaml
cd services/ui && python -m flask --app ui.app run --port 8480
```

> [!NOTE]
> In development mode, services run without systemd sandboxing and without the nftables firewall. This is **not** security-equivalent to the full appliance.

---

## Post-Install: Importing Your First Model

After installation, you need to import a model before you can use the chat interface.

### Method 1: Via the Web UI

1. Open a browser to `http://127.0.0.1:8480`
2. Navigate to the **Models** page
3. Upload a `.gguf` model file

The file is placed into quarantine, scanned, and promoted to the trusted registry automatically if it passes all checks.

### Method 2: Manual Import via CLI

```bash
# Copy a GGUF model file into the quarantine incoming directory
sudo cp /path/to/your-model.gguf /var/lib/secure-ai/quarantine/incoming/

# The quarantine watcher service picks it up automatically.
# Check its progress:
journalctl -u secure-ai-quarantine-watcher -f

# Once promoted, verify it appears in the registry:
curl http://127.0.0.1:8470/v1/models | python3 -m json.tool
```

### Method 3: Using securectl

```bash
# List models in the registry
securectl list

# Verify a model's integrity
securectl verify --name your-model
```

### Recommended Models (GGUF Format)

| Model | Size | VRAM Needed | Notes |
|-------|------|-------------|-------|
| Mistral 7B Q4_K_M | ~4 GB | 6 GB | Good general-purpose, fast |
| Llama 3.1 8B Q4_K_M | ~5 GB | 7 GB | Strong reasoning |
| Llama 3.1 70B Q4_K_M | ~40 GB | 48 GB | Best quality, needs multi-GPU or CPU offload |
| Phi-3 Mini 3.8B Q4_K_M | ~2 GB | 4 GB | Smallest, good for testing |

Download models from [Hugging Face](https://huggingface.co/models?sort=trending&search=gguf) in GGUF format.

---

## Using the Appliance

### Web Interface

Open `http://127.0.0.1:8480` in a browser. The UI provides:

- **Chat** — Interact with your loaded model
- **Models** — View, import, verify, and delete models
- **Status** — Check service health

### Service Management

```bash
# Check overall status
systemctl status secure-ai-*

# View inference logs
journalctl -u secure-ai-inference -f

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

---

## Security Overview

### Defense Layers

| Layer | Mechanism |
|-------|-----------|
| **Boot** | Immutable OS image (rpm-ostree), signed updates (cosign) |
| **Kernel** | IOMMU forced, ASLR, slab_nomerge, init_on_alloc/free, lockdown=confidentiality |
| **Network** | nftables default-deny egress, services use PrivateNetwork=yes |
| **Swap** | Disabled (kernel arg + runtime check) — prevents secrets hitting disk |
| **Filesystem** | Encrypted vault (LUKS2/AES-256/Argon2id), restrictive permissions |
| **Models** | Format validation, hash pinning, static scanning, behavioral smoke tests |
| **Tools** | Default-deny policy, path allowlisting, traversal protection, rate limiting |
| **Egress** | Airlock disabled by default, PII/credential scanning, destination allowlist |
| **Services** | Systemd sandboxing: ProtectSystem=strict, PrivateNetwork, syscall filters |
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
| `config/appliance.yaml` | Mode, paths, inference settings, service binds |
| `policy/policy.yaml` | Tool firewall rules, airlock settings, model format rules |
| `policy/models.lock.yaml` | Pinned model hashes (supply-chain verification) |
| `policy/sources.allowlist.yaml` | Trusted container/model sources |

### Key Configuration Options

**Inference settings** (`config/appliance.yaml`):
```yaml
inference:
  gpu_layers: -1    # -1 = offload all to GPU, 0 = CPU only
  context_size: 8192
```

**Session modes** (`config/appliance.yaml`):
```yaml
session:
  mode: "normal"       # normal | sensitive | offline-only
  # sensitive: aggressive worker recycling after each task
  # offline-only: hard-block all network even if airlock is enabled
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
  quarantine/           Python -- Verification + scanning pipeline
  inference-worker/     llama.cpp wrapper
  ui/                   Python/Flask -- Web chat UI
tests/
  test_pipeline.py      Quarantine pipeline tests (16 tests)
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

# Python tests (23 total)
pip install pytest flask requests pyyaml
python -m pytest tests/ -v

# Shell script linting
shellcheck files/system/usr/libexec/secure-ai/*.sh files/scripts/*.sh
```

## Roadmap

- [x] **M0 Spec** -- Threat model, dataflow, invariants, policy files
- [x] **M1 Bootable OS** -- Encrypted vault, GPU drivers, runtime offline
- [x] **M2 Trusted Registry** -- Allowlist + hash pinning + cosign verification
- [x] **M3 Quarantine Pipeline** -- Static scanning + smoke tests + promotion gate
- [x] **M4 Tool Firewall** -- Policy-gated tool calls + file access gateway
- [x] **M5 Online Airlock** -- Sanitization + allowlist + user approval UI
- [x] **M6 Hardening** -- Systemd sandboxing, kernel params, nftables, panic switch
- [x] **M7 CI/CD** -- GitHub Actions, Go/Python tests, shellcheck, YAML validation
- [ ] **M8 Polish** -- OPA/Rego policy engine, appliance setup wizard, documentation site

## Troubleshooting

### "No model found" — Inference won't start

The inference worker needs at least one `.gguf` model in the registry:

```bash
# Check if any models are registered
curl http://127.0.0.1:8470/v1/models

# Import a model
sudo cp your-model.gguf /var/lib/secure-ai/quarantine/incoming/

# Watch the quarantine pipeline
journalctl -u secure-ai-quarantine-watcher -f
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
# Check NVIDIA driver
nvidia-smi

# If not loaded, check kernel modules
lsmod | grep nvidia

# For Apple Silicon, GPU acceleration runs on the host (not in container)
# Verify Metal support:
system_profiler SPDisplaysDataType
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
