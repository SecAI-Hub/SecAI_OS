# System Architecture

SecAI OS is a bootable local-first AI appliance built on uBlue (Fedora Atomic/Silverblue F42). It enforces defense-in-depth through five architecture zones, immutable OS layers, encrypted storage, and default-deny networking.

---

## Architecture Zones

### 1. Base OS

The immutable Fedora Silverblue foundation. The root filesystem is read-only and managed via rpm-ostree. Updates are atomic and can be rolled back with a single command. Greenboot health checks run after each boot to verify system integrity.

### 2. Acquisition

Handles model intake from external sources. The Airlock (disabled by default) provides a sanitized egress proxy for downloading models from allowlisted destinations. All acquired artifacts land in quarantine before they can be used.

### 3. Quarantine

A 7-stage verification pipeline that every model must pass before promotion. Checks include source policy, format validation, integrity hashing, signature verification, static scanning (including gguf-guard for GGUF files), behavioral smoke testing, and diffusion-specific deep scans. Models that fail any stage are rejected.

### 4. Runtime

The active inference environment. llama-server runs promoted models from the trusted registry. The Tool Firewall gates all tool invocations through a default-deny policy. The Search Mediator (disabled by default) provides sanitized, Tor-routed web search.

### 5. Agent Layer

A policy-bound local autopilot that orchestrates bounded local workflows. The Agent (:8476) decomposes user intent into steps, evaluates each step against a deny-by-default policy engine with capability tokens and sensitivity labels, then executes approved steps through the storage gateway and tool firewall. Low-risk local actions (search, summarize, draft) run automatically; high-risk actions (outbound requests, exports, trust changes) require explicit approval. See [Agent Mode](components/agent.md) for full details.

### 6. Airlock

The controlled boundary between the appliance and the external network. Disabled by default because it represents the largest privacy risk surface. When enabled, it enforces destination allowlists, PII scanning, credential scanning, rate limiting, and HTTPS-only connections.

---

## Data Flow

```
                              +------------------+
                              |    External Net   |
                              +--------+---------+
                                       |
                              (disabled by default)
                                       |
                              +--------v---------+
                              |     Airlock       |
                              |  :8490 (Go)       |
                              +--------+---------+
                                       |
           +---------------------------+---------------------------+
           |                                                       |
  +--------v---------+                                    +--------v---------+
  |   Quarantine      |                                    |  Search Mediator  |
  |   Pipeline (Py)   |                                    |  :8485 (Py)       |
  +--------+----------+                                    +--------+----------+
           |                                                        |
           | (promote)                                     (Tor -> SearXNG)
           |                                                        |
  +--------v---------+      +------------------+           +--------v---------+
  |    Registry       +----->  Inference Worker |           |   LLM Context    |
  |  :8470 (Go)       |      | (llama-server)   |           |   Injection      |
  +-------------------+      +--------+---------+           +------------------+
                                       |
                              +--------v---------+
                              |  Tool Firewall    |
                              |  :8475 (Go)       |
                              +--------+---------+
                                       |
                              +--------v---------+
                              |   Agent Autopilot |
                              |  :8476 (Py)       |
                              | (planner, policy, |
                              |  storage gateway) |
                              +--------+---------+
                                       |
                              +--------v---------+
                              |     UI (Flask)    |
                              |  :8480 (Py)       |
                              +--------+---------+
                                       |
                              +--------v---------+
                              |      User         |
                              +-------------------+
```

### Request Path

1. User interacts with the Flask UI on port 8480.
2. Chat and generation requests go to the inference worker (llama-server).
3. If the model invokes a tool, the request passes through the Tool Firewall on port 8475.
4. If web search is enabled, the Search Mediator on port 8485 routes queries through Tor to SearXNG.
5. Model downloads (when Airlock is enabled) pass through the Airlock on port 8490, then enter the Quarantine Pipeline for verification before promotion to the Registry.

---

## Service Dependency Diagram

```
UI (:8480)
  |-- Agent (:8476)                 [task orchestration, policy enforcement]
  |     |-- Inference Worker         [planning via LLM]
  |     |-- Tool Firewall (:8475)   [tool invocation gating]
  |     |-- Storage Gateway          [mediated file access]
  |     +-- Airlock (:8490)         [outbound requests, if enabled]
  |-- Inference Worker (llama-server)
  |     |-- Registry (:8470)        [model loading]
  |     |-- Tool Firewall (:8475)   [tool invocation]
  |     +-- Search Mediator (:8485) [web search, optional]
  |           +-- SearXNG (via Tor)
  |-- Registry (:8470)              [model listing, management]
  |-- Quarantine Pipeline           [model verification]
  |     +-- Registry (:8470)        [promotion target]
  +-- Airlock (:8490)               [egress proxy, disabled by default]
```

---

## Design Decisions

### Go for Latency-Sensitive Services

The Registry, Tool Firewall, and Airlock are written in Go. These services sit in the hot path of inference requests or act as network gateways where latency matters. Go provides low-latency HTTP handling, easy concurrency, and compiles to a single static binary with no runtime dependencies.

### Python for Scanning and UI

The Quarantine Pipeline and UI are written in Python. The pipeline leverages Python-native security scanning libraries (modelscan, entropy analysis). The UI uses Flask for rapid prototyping. Neither is latency-critical.

### llama.cpp Over Ollama

Ollama was rejected because it wants to own model management (downloading, storing, and serving models). This conflicts with the trusted registry architecture where every model must pass through quarantine before use. llama.cpp (via llama-server) accepts models from any path, allowing the registry to control the model lifecycle.

### Default-Deny Networking

All outbound network traffic is blocked by nftables rules. The only exceptions are explicitly allowlisted destinations when the Airlock is enabled. This prevents data exfiltration by compromised models or services.

---

## Trust Boundaries

| Boundary | From | To | Controls |
|---|---|---|---|
| Network perimeter | External network | Airlock | nftables, destination allowlist, PII scanning |
| Acquisition boundary | Airlock | Quarantine | Format validation, source policy |
| Promotion boundary | Quarantine | Registry | 7-stage pipeline, SHA-256 pinning, cosign signatures |
| Execution boundary | Registry | Inference Worker | Read-only model access, systemd sandboxing |
| Tool boundary | Inference Worker | Tool Firewall | Default-deny policy, path allowlisting, rate limiting |
| Agent boundary | UI / User | Agent | Capability tokens, deny-by-default policy, hard budgets, sensitivity ceiling |
| Agent→Service boundary | Agent | Tool Firewall / Airlock | Loopback-only IPC, service tokens, IPAddressDeny=any, fail-closed |
| Search boundary | Inference Worker | Search Mediator | PII stripping, injection detection, Tor routing |
| User boundary | UI | User | Local passphrase auth, vault encryption |

The user is the trust principal. SecAI OS does not defend against a malicious local user -- it defends the user against untrusted models and network exposure.
