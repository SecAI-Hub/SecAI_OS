# Development Setup

This guide covers running SecAI OS services locally for development and testing, without building a full OS image.

---

## Prerequisites

- **Go 1.25+** for building Go services
- **Python 3.11+** for running Python services (quarantine, UI, search-mediator)
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

The Go service set is: `airlock`, `registry`, `tool-firewall`, `gpu-integrity-watch`, `mcp-firewall`, `policy-engine`, `runtime-attestor`, `integrity-monitor`, and `incident-recorder`.

---

## Install Python Dependencies

```bash
python -m pip install -r requirements-ci.txt
python -m pip install -r services/agent/requirements.txt
python -m pip install -r services/search-mediator/requirements.txt
python -m pip install --require-hashes -r services/ui/requirements.lock
python -m pip install --require-hashes -r services/quarantine/requirements.lock
python -m pip install -e services/agent -e services/ui -e services/quarantine
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
python -m pytest tests/test_quarantine_pipeline.py -v
python -m pytest tests/test_ui.py -v
python -m pytest tests/test_memory_protection.py -v
python -m pytest tests/test_differential_privacy.py -v
python -m pytest tests/test_traffic_analysis.py -v
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
