# Support Boundaries and Lifecycle

Defines the hardware support matrix, software compatibility, support windows, and deprecation policy for SecAI OS.

Last updated: 2026-03-14

---

## Hardware Support Matrix

### GPU Support

| Vendor | Generation | Models | Backend | Support Level | Notes |
|--------|-----------|--------|---------|--------------|-------|
| **NVIDIA** | Ada Lovelace | RTX 4090, 4080, 4070 Ti/Super | CUDA 12.x | Full | Primary development target |
| **NVIDIA** | Blackwell | RTX 5090, 5080 | CUDA 12.x | Full | Tested on RTX 5080 |
| **NVIDIA** | Ampere | RTX 3090, 3080, 3070 Ti | CUDA 12.x | Full | |
| **AMD** | RDNA 3 | RX 7900 XTX/XT, 7800 XT, 7700 XT | ROCm 6.x (HIP) | Full | |
| **AMD** | CDNA 3 | MI300X | ROCm 6.x (HIP) | Full | Data center GPU |
| **Intel** | Alchemist | Arc A770, A750, A580 | XPU (oneAPI) | Supported | Via Vulkan for LLM |
| **Intel** | Battlemage | Arc B-series | XPU (oneAPI) | Supported | Via Vulkan for LLM |
| **Apple** | M4 | M4, M4 Pro, M4 Max, M4 Ultra | Metal / MPS | Full | Via llama.cpp Metal |
| **Apple** | M3 | M3, M3 Pro, M3 Max, M3 Ultra | Metal / MPS | Full | |
| **Apple** | M2 | M2, M2 Pro, M2 Max, M2 Ultra | Metal / MPS | Full | |
| **Apple** | M1 | M1, M1 Pro, M1 Max, M1 Ultra | Metal / MPS | Full | |
| **CPU** | x86_64 | AVX2 or AVX-512 required | CPU | Supported | Slow but functional |
| **CPU** | ARM64 | NEON required | CPU | Supported | Slow but functional |

**Support levels:**
- **Full:** Actively tested, optimized, documented. Issues prioritized.
- **Supported:** Tested, functional. Issues accepted but lower priority.
- **Community:** Not actively tested. Community contributions welcome.

### Driver Versions

| GPU Vendor | Minimum Driver | Recommended Driver | Notes |
|-----------|---------------|-------------------|-------|
| NVIDIA | 535.x | 550.x or later | CUDA 12.2+ required |
| AMD | ROCm 5.7 | ROCm 6.0+ | HIP runtime |
| Intel | Level Zero 1.3 | Latest stable | oneAPI 2024.0+ |
| Apple | macOS 14.0 | macOS 15.0+ | Metal 3 for best performance |

### System Requirements

| Resource | Minimum | Recommended | Notes |
|----------|---------|-------------|-------|
| CPU | 4 cores, x86_64 or ARM64 | 8+ cores | AVX2 required for x86_64 |
| RAM | 16 GB | 32 GB+ | Swap is disabled by design |
| Storage | 64 GB SSD | 256 GB+ NVMe | For OS + models + vault |
| GPU VRAM | 8 GB | 16 GB+ | Determines max model size |
| Network | Optional | Ethernet | Only needed for initial setup / airlock |
| TPM | Optional | TPM 2.0 | Required for measured boot and key sealing |
| UEFI | Required | Secure Boot capable | Secure Boot optional but recommended |

---

## Software Compatibility

### Base OS

| Component | Version | Support Window | Notes |
|-----------|---------|---------------|-------|
| Fedora Silverblue | 42 | Until Fedora 42 EOL (~13 months from release) | Current base |
| uBlue framework | Latest | Follows Fedora lifecycle | Image build framework |
| rpm-ostree | 2024.x+ | Follows Fedora lifecycle | Immutable OS layer |

### Runtime Dependencies

| Component | Version | Pinned | Notes |
|-----------|---------|--------|-------|
| Go (services) | 1.23 | Yes (go.mod) | 9 Go services |
| Python | 3.12 | Yes (Fedora 42 default) | 6 Python services |
| llama.cpp | Latest stable | Via build | LLM inference engine |
| Flask | 3.x | Via pip | Web UI framework |
| cosign | 2.4.x | Via release workflow | Image/artifact signing |
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
| Patch → Patch | `rpm-ostree upgrade` | Yes | None |
| Minor → Minor | `rpm-ostree upgrade` | Yes | None (new defaults) |
| Major → Major | `rpm-ostree upgrade` + migration | Semi-auto | Per release notes |
| Rollback (any) | `rpm-ostree rollback` | Yes | N/A (previous state) |

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
