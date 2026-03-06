# Secure AI OS

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
| Apple M4 | Metal (via llama.cpp) | CPU-only container, Metal on host |
| Any x86_64 | CPU fallback | Slower but functional |

## Installation

> [!WARNING]
> This is an experimental project. The bootable image is not yet published.

To rebase an existing Fedora Atomic installation:

```bash
# First rebase to unsigned image to get signing keys
rpm-ostree rebase ostree-unverified-registry:ghcr.io/sec_ai/secai_os:latest

systemctl reboot

# Then rebase to the signed image
rpm-ostree rebase ostree-image-signed:docker://ghcr.io/sec_ai/secai_os:latest

systemctl reboot
```

## Project Structure

```
recipes/              BlueBuild recipe (image definition)
files/
  system/
    etc/secure-ai/    Policy and config files baked into image
    usr/lib/systemd/  Systemd service units
services/
  registry/           Go -- Trusted Registry
  tool-firewall/      Go -- Policy engine + tool gateway
  airlock/            Go -- Online egress proxy
  quarantine/         Python -- Verification + scanning pipeline
  inference-worker/   llama.cpp wrapper
  ui/                 Python/Flask -- Web chat UI
docs/
  threat-model.md     Formal threat model and security invariants
```

## Roadmap

- [x] **M0 Spec** -- Threat model, dataflow, invariants, policy files
- [ ] **M1 Bootable OS** -- USB image, encrypted vault, GPU drivers, runtime offline
- [ ] **M2 Trusted Registry** -- Allowlist + hash pinning + cosign verification
- [ ] **M3 Quarantine Pipeline** -- Static scanning + smoke tests + promotion gate
- [ ] **M4 Tool Firewall** -- Policy-gated tool calls + file access gateway
- [ ] **M5 Online Airlock** -- Sanitization + allowlist + user approval UI
- [ ] **M6 Hardening** -- Reproducible builds, CI policy tests, signed releases

## Security

See [docs/threat-model.md](docs/threat-model.md) for the full threat model.

Images are signed with [cosign](https://github.com/sigstore/cosign). Verify with:

```bash
cosign verify --key cosign.pub ghcr.io/sec_ai/secai_os:latest
```

## License

See [LICENSE](LICENSE).
