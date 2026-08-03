# Support Boundaries and Lifecycle

Defines the hardware support matrix, software compatibility, support windows, and deprecation policy for SecAI OS.

Last updated: 2026-07-27

---

## Hardware Support Matrix

### GPU Support

| Vendor | Generation | Models | Backend | Support Level | Notes |
|--------|-----------|--------|---------|--------------|-------|
| **NVIDIA** | Ada Lovelace | RTX 40-series | CUDA | Hardware-dependent | Qualification report required |
| **NVIDIA** | Blackwell | RTX 50-series | CUDA | Hardware-dependent | Qualification report required |
| **NVIDIA** | Ampere | RTX 30-series | CUDA | Hardware-dependent | Qualification report required |
| **AMD** | RDNA/CDNA | Supported by runtime | ROCm/HIP | Experimental | Qualification pending |
| **Intel** | Arc | A/B-series | XPU/Vulkan | Experimental | Qualification pending |
| **Apple** | M1–M4 | Apple Silicon | Metal/MPS | Sandbox-only | No native Fedora appliance |
| **CPU** | x86_64 | AVX2 or AVX-512 | CPU | Supported fallback | Slow but functional |
| **CPU** | ARM64 | NEON | CPU | Planned appliance | Development runtimes only |

**Support levels:**
- **Verified:** Release-specific hardware evidence is published.
- **Hardware-dependent:** Code support exists; release qualification is required.
- **Experimental:** Available for evaluation without production support.
- **Sandbox-only:** Not part of the Fedora appliance.
- **Community:** Not actively tested. Community contributions welcome.

### Driver Versions

| GPU Vendor | Minimum Driver | Recommended Driver | Notes |
|-----------|---------------|-------------------|-------|
| NVIDIA | 535.x | 550.x or later | CUDA 12.2+ required |
| AMD | ROCm 5.7 | ROCm 6.0+ | HIP runtime |
| Intel | Level Zero 1.3 | Latest stable | oneAPI 2024.0+ |
| Apple | N/A | N/A | No native macOS appliance; sandbox/dev only |

### System Requirements

| Resource | Minimum | Recommended | Notes |
|----------|---------|-------------|-------|
| CPU | 4 cores, x86_64 | 8+ cores | Current appliance media is x86_64 |
| RAM | 16 GB | 32 GB+ | Swap is disabled by design |
| Storage | 64 GB SSD | 256 GB+ NVMe | For OS + models + vault |
| GPU VRAM | 8 GB | 16 GB+ | Determines max model size |
| Network | Optional | Ethernet | Only needed for initial setup / airlock |
| TPM | Optional | TPM 2.0 | Required for measured boot and key sealing |
| UEFI | Required | Secure Boot capable | Secure Boot optional but recommended |

---

## Install Path Support Matrix

| Install Path | Support Level | Security Features | Notes |
|-------------|-------------|-------------------|-------|
| **Bare metal (ISO)** | Candidate | TPM2, Secure Boot, hardware isolation, fs-verity | Requires release-specific sign-off |
| **Bare metal (rebase)** | Candidate | Full intended control set | Requires release-specific sign-off |
| **VM (local OVA/QCOW2 build)** | Evaluation | Limited: host-controlled vTPM only, host visibility of VM memory | User-specific encrypted build; not a release artifact or for sensitive model data |
| **Sandbox (compose)** | Evaluation | Limited: policy enforcement, quarantine, audit, agent, airlock; no measured boot or kernel isolation | Best for onboarding and workflow validation |
| **VM (manual)** | Community | Limited | Self-configured |
| **Container (dev)** | Development | Minimal: no systemd hardening, no firewall, no vault | Service development only |

### Production Support Statement

Bare-metal installations using the **stable** release channel with
digest-pinned images are the intended production path. No release is
production-supported until its signed evidence bundle completes the production
readiness checklist. Target service levels after certification are:

- Security patches within 72 hours of disclosure
- Automated rollback via Greenboot
- Supply-chain verification (cosign + SLSA3 provenance)
- Documented recovery procedures

VM installations are supported for **evaluation and development** only. Known limitations:
- A vTPM may be used only with the explicit degraded-lab `--allow-vtpm`
  acknowledgement. Its state is host-controlled, so sealing is evaluation-only
  and retains a passphrase recovery keyslot.
- No Secure Boot chain verification (depends on hypervisor configuration)
- Reduced GPU performance (passthrough required for full acceleration)
- Host hypervisor has full visibility of guest memory

Sandbox deployments are supported for **evaluation only**. Known limitations:
- Shared host kernel and container runtime can inspect memory, files, and traffic
- No Secure Boot, TPM2, measured boot, or rpm-ostree immutability guarantees
- No systemd unit sandboxing or appliance-wide nftables enforcement
- Optional inference and diffusion profiles depend on user-supplied runtime configuration

> **Note:** Neither an ISO nor a rebase is certified solely because it builds.
> Certification requires boot/reboot, update/rollback, negative-security,
> backup/restore, resilience, and named-hardware evidence.

---

## Software Compatibility

### Base OS

| Component | Version | Support Window | Notes |
|-----------|---------|---------------|-------|
| Fedora Silverblue | 44 | Fedora lifecycle | Current base |
| uBlue framework | Latest | Follows Fedora lifecycle | Image build framework |
| rpm-ostree | 2024.x+ | Follows Fedora lifecycle | Immutable OS layer |

### Runtime Dependencies

| Component | Version | Pinned | Notes |
|-----------|---------|--------|-------|
| Go (services) | 1.26.5 toolchain | Yes (CI and container builders) | 10 tested modules: 9 native release services plus the sandbox UI ingress |
| Python | 3.12/3.14 | Yes (service locks and images) | Quarantine stays on Python 3.12 while scanner metadata requires it; sandbox UI, agent, search, and diffusion images use patched Python 3.14.5 runtimes where compatible. |
| llama.cpp | Latest stable | Via build | LLM inference engine |
| Flask | 3.x | Via pip | Web UI framework |
| cosign | 3.1.1+ | Yes (CI pins 3.1.1) | Minimum supported verifier for Rekor v2-backed image attestations |
| Syft | Latest stable | Via CI | SBOM generation |

### Inference Backends

| Backend | Model Format | Supported Versions | Notes |
|---------|-------------|-------------------|-------|
| llama.cpp | GGUF | v3 header format | Primary inference engine |
| Diffusers | Safetensors | HuggingFace format | Image/video generation |

**Unsupported formats:** Pickle (`.pt`, `.pkl`, `.bin`) — rejected by quarantine stage 2 (Format Gate) due to arbitrary code execution risk.

---

## Support Windows

### Release Support

| Release Type | Active Support | Security Patches | Notes |
|-------------|---------------|-----------------|-------|
| Current stable | Full | Full | Latest `vX.Y.Z` tag |
| Previous minor | Security only | 6 months after next minor | e.g., v1.2.x after v1.3.0 ships |
| Previous major | None | 12 months after next major | e.g., v1.x after v2.0.0 ships |

### Feature Deprecation Policy

1. **Announce:** Feature marked as deprecated in release notes and documentation
2. **Warn:** Deprecated feature emits log warnings when used (minimum 1 minor release)
3. **Remove:** Feature removed in next major version

**Minimum deprecation window:** 2 minor releases or 6 months, whichever is longer.

### API Deprecation Policy

| API Change | Notice Period | Backward Compatible |
|-----------|--------------|-------------------|
| New endpoint | Immediate | Yes (additive) |
| New optional field | Immediate | Yes (additive) |
| Remove endpoint | 2 minor releases | No (removed in next major) |
| Change field semantics | 1 minor release | Aliased during transition |
| Policy schema change | 1 major release | Migration tool provided |

---

## Configuration Compatibility

### Policy Schema

| Schema Version | Compatible Releases | Migration |
|---------------|-------------------|-----------|
| v1 (current) | v1.x | N/A |
| v2 (future) | v2.x | Migration tool + docs |

Policy files (`policy.yaml`, `agent.yaml`) are validated at startup. Invalid policy files cause fail-closed behavior (all requests denied) rather than silent degradation.

### Upgrade Compatibility Matrix

| From → To | Method | Automatic | Data Migration |
|-----------|--------|-----------|---------------|
| Patch → Patch | `update-verify.sh check/stage/apply` | Yes | None |
| Minor → Minor | `update-verify.sh check/stage/apply` | Yes | None (new defaults) |
| Major → Major | Release-specific verified update + migration | Semi-auto | Per release notes |
| Rollback (any) | `update-verify.sh rollback` | Yes | N/A (previous state) |

---

## End-of-Life Policy

When a release reaches end-of-life:

1. No further security patches
2. No bug fixes
3. CI may stop testing against that version
4. Documentation may reference newer versions only
5. Users should upgrade to a supported release

**Notification:** EOL announcements are made at least 30 days in advance via:
- GitHub Release notes
- README update
- Security advisory (if security-relevant)

---

## Scope Boundaries

### In Scope (Supported)

- SecAI OS image and all bundled services
- Policy configuration within documented schema
- GPU acceleration for supported hardware (see matrix above)
- Upgrade/rollback via rpm-ostree
- Supply chain verification via cosign/SBOM
- Incident response automation
- Audit logging and integrity monitoring

### Out of Scope (Not Supported)

- Custom kernel modules or drivers not in the base image
- Third-party services not bundled with SecAI OS
- Model training (inference only)
- Multi-node/cluster deployments (single-node appliance only)
- Cloud provider integrations
- Custom OCI image modifications (fork the recipe instead)
- Performance tuning beyond documented configuration
- Recovery from emergency panic level 3 (full wipe is unrecoverable by design)

### Community-Supported

- Non-standard GPU configurations
- Exotic hardware (FPGA, custom accelerators)
- Running in containers (not as a host OS)
- Non-x86_64/ARM64 architectures
