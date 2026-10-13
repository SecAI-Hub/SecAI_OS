# Development Setup

This guide covers running SecAI OS services locally for development and testing, without building a full OS image.

---

## Prerequisites

- **Go 1.27.2** to match the pinned native service builds and CI.
- **Python 3.12** for local services and the locked test environment. The native appliance currently installs Python 3.12.15; the UI and agent evaluation containers pin Python 3.14.8. Use each service's checked-in Dockerfile and dependency lock for its exact runtime rather than treating package metadata as a tested version range.
- **pip** for Python dependency management
- **git** for version control
- **make** (optional, for convenience targets)

---

## Clone the Repository

```bash
git clone https://github.com/SecAI-Hub/SecAI_OS.git
cd SecAI_OS
```

---

## Build Go Services

Each Go service is in its own directory under `services/`. To exercise the same service set as CI:

```bash
make test-go
```

To build or run an individual service, enter that service directory and use the normal Go tooling:

```bash
cd services/registry
go build -o registry .
./registry
```

The tested Go module set is: `airlock`, `registry`, `tool-firewall`,
`gpu-integrity-watch`, `mcp-firewall`, `policy-engine`, `runtime-attestor`,
`integrity-monitor`, `incident-recorder`, and the sandbox-only `ui-ingress`.
The first nine are native release services; `ui-ingress` is built only for the
Compose evaluation path.

On a computer shared with other tasks, check current available memory, disk
space, and pressure before starting a build. Run one build or test workload at
a time. Limit compiler parallelism with `GOMAXPROCS=1 go test -p 1 ./...` when
working in an individual Go service. Large image builds and VM qualification
also need writable artifact storage and enough free memory for the desktop
and other active tasks; installed RAM alone is not an admission check.

On Linux with a systemd user manager, a focused test can run with an enforced
memory and CPU budget:

```bash
systemd-run --user --scope \
  -p MemoryMax=768M -p MemorySwapMax=0 -p CPUQuota=50% -p TasksMax=64 \
  nice -n 10 timeout --kill-after=5 60 \
  python -m pytest -q tests/test_ui.py -k quarantine_status
```

Choose a budget that leaves headroom for the other tasks. This command limits
its own process tree; it does not limit a separate Docker daemon or a libvirt
guest. Those workloads need their own limits. Do not force-mount or repair a
storage volume that belongs to another bootable system to make room for a
build.

---

## Install Python Dependencies

```bash
python -m pip install --require-hashes -r requirements-ci.lock
python -m pip install --require-hashes -r services/agent/requirements.lock
python -m pip install --require-hashes -r services/search-mediator/requirements.lock
python -m pip install --require-hashes -r services/ui/requirements.lock
python -m pip install --require-hashes -r services/quarantine/requirements.lock
python -m pip install --no-deps -e services/agent -e services/ui -e services/quarantine
```

---

## Run Python Services

### UI

```bash
cd services/ui
python -m ui.app
```

The UI listens on port 8480. Open `http://localhost:8480` in a browser.

### Quarantine Pipeline

The quarantine pipeline runs as a watcher service that monitors the quarantine directory:

```bash
cd services/quarantine
python -m quarantine.watcher
```

### Search Mediator

```bash
cd services/search-mediator
python app.py
```

The search mediator listens on port 8485. Requires a running SearXNG instance and Tor for full functionality.

---

## Run Tests

### Go Tests

```bash
make test-go
```

### Python Tests

```bash
# All Python tests
PYTHONPATH=services python -m pytest tests/ -v

# Specific test suites
PYTHONPATH=services python -m pytest tests/test_quarantine_pipeline.py -v
PYTHONPATH=services python -m pytest tests/test_ui.py -v
PYTHONPATH=services python -m pytest tests/test_memory_protection.py -v
PYTHONPATH=services python -m pytest tests/test_differential_privacy.py -v
PYTHONPATH=services python -m pytest tests/test_traffic_analysis.py -v
```

---

## Configuration in Dev Mode

Services look for configuration files in the following order:

1. Path specified by environment variable (e.g., `SECAI_POLICY_PATH`)
2. `./policy.yaml` in the current working directory
3. `/etc/secure-ai/policy/policy.yaml` (production path, unlikely to exist in dev)

For development, copy the default policy file:

```bash
cp files/system/etc/secure-ai/policy/policy.yaml ./policy.yaml
```

Edit `policy.yaml` to adjust settings for your dev environment.

---

## Missing Sandboxing in Dev Mode

When running services directly (outside of the full OS image), the following security features are not active:

- **Systemd sandboxing:** ProtectSystem, ProtectHome, PrivateTmp, NoNewPrivileges, and other systemd hardening directives only apply when services run under systemd.
- **nftables firewall:** Network rules are not applied in dev mode. Services can make arbitrary network connections.
- **Seccomp-BPF filters:** System call filtering requires the systemd service units.
- **Landlock LSM:** Filesystem access restrictions require the systemd service units.
- **Encrypted vault:** The LUKS encrypted volume is not present in dev mode. Models are stored in plain directories.
- **Read-only root:** The immutable filesystem is a property of the OS image, not the services.

Dev mode is for development and testing only. Do not use dev mode for processing sensitive data or running untrusted models.

---

## Running Without an Inference Worker

If you do not have llama.cpp installed or do not need actual inference:

- The UI, registry, and tool firewall can run independently.
- Chat and generation endpoints will return errors without an inference worker.
- Model management (import, quarantine, promote) works without inference.

To set up llama-server for local inference:

```bash
# Build llama.cpp
git clone https://github.com/ggerganov/llama.cpp.git
cd llama.cpp
make -j$(nproc)

# Start the server with a model
./llama-server -m /path/to/model.gguf --port 8081
```
