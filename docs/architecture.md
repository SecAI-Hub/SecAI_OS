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

The active inference environment. llama-server runs promoted models from the trusted registry. The Tool Firewall gates all tool invocations through a default-deny policy. The MCP Firewall (:8496) enforces default-deny policy on Model Context Protocol tool calls with input redaction and taint tracking. The Search Mediator (disabled by default) provides sanitized, Tor-routed web search.

### 5. Agent Layer

A policy-bound local autopilot that orchestrates bounded local workflows. The Agent (:8476) decomposes user intent into steps, evaluates each step against the unified Policy Engine (:8500) with HMAC-signed capability tokens and sensitivity labels, then executes approved steps through the storage gateway and tool firewall. Low-risk local actions (search, summarize, draft) run automatically; high-risk actions (outbound requests, exports, trust changes) require two-phase approval. See [Agent Mode](components/agent.md) for full details.

### 6. Airlock

The controlled boundary between the appliance and the external network. Disabled by default because it represents the largest privacy risk surface. When enabled, it enforces destination allowlists, PII scanning, credential scanning, rate limiting, and HTTPS-only connections.

### 7. Verification & Enforcement Layer

A set of services that continuously verify system integrity and automatically respond to security events:

- **Policy Engine** (:8500) — Unified decision point for 6 policy domains (tool_access, path_access, egress, agent_risk, sensitivity, model_promotion). All services query the policy engine for allow/deny decisions with structured evidence. OPA/Rego-upgradeable.
- **Runtime Attestor** (:8505) — Verifies TPM2 quotes, measures boot state, computes HMAC-signed runtime state bundles. Gates service startup: all downstream services depend on valid attestation. Reports degraded/failed attestation to the Incident Recorder.
- **Integrity Monitor** (:8510) — Continuous baseline-verified file watcher (30s scan intervals). Monitors service binaries, policy files, model files, systemd units, and trust material. Reports violations to the Incident Recorder with severity classification.
- **Incident Recorder** (:8515) — Captures security events across 9 incident classes with 4-state lifecycle (open → contained → resolved → acknowledged). Executes auto-containment actions per policy: freeze agent, disable airlock, force vault relock, quarantine model.
- **GPU Integrity Watch** (:8495) — Continuous GPU runtime verification with driver fingerprinting, device allowlist, and baseline comparison. Reports anomalies to the Incident Recorder.

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
                   +-------------------+-------------------+
                   |                                       |
          +--------v---------+                    +--------v---------+
          |  Tool Firewall    |                    |  MCP Firewall    |
          |  :8475 (Go)       |                    |  :8496 (Go)      |
          +--------+---------+                    +------------------+
                   |
          +--------v---------+
          |  Agent Autopilot  |
          |  :8476 (Py)       |
          | (verified super-  |
          |  visor, planner,  |
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

### Enforcement Chain

```
  Boot                        Runtime (continuous)             Response
  ====                        ===================             ========

  +------------------+     +---------------------+     +-------------------+
  | Runtime Attestor |---->| Integrity Monitor   |---->| Incident Recorder |
  | :8505 (Go)       |     | :8510 (Go)          |     | :8515 (Go)        |
  | TPM2 quotes,     |     | 30s baseline scans, |     | 9 incident classes|
  | state bundles,   |     | binary/policy/model |     | auto-containment: |
  | startup gating   |     | file watching       |     |  - freeze agent   |
  +--------+---------+     +--------+------------+     |  - disable airlock|
           |                        |                   |  - vault relock   |
           |    reports             |    reports         |  - quarantine     |
           |    degraded/failed     |    violations      +--------+----------+
           +------------+   +------+                             |
                        |   |                         executes   |
                        v   v                         actions    |
                 +------+---+-------+                    +-------v---------+
                 | Incident Recorder |<-------------------| Target Services |
                 | :8515 (Go)        |                    | Agent, Airlock, |
                 +-------------------+                    | Registry, Vault |
                                                          +-----------------+

  Policy Engine (:8500) consulted by all services for allow/deny decisions.
  GPU Integrity Watch (:8495) feeds GPU anomalies into incident chain.
```

### Request Path

1. User interacts with the Flask UI on port 8480.
2. Chat and generation requests go to the inference worker (llama-server).
3. If the model invokes a tool, the request passes through the Tool Firewall on port 8475. MCP tool calls route through the MCP Firewall on port 8496.
4. If web search is enabled, the Search Mediator on port 8485 routes queries through Tor to SearXNG.
5. Model downloads (when Airlock is enabled) pass through the Airlock on port 8490, then enter the Quarantine Pipeline for verification before promotion to the Registry.
6. At boot, the Runtime Attestor verifies TPM2 quotes and gates all downstream services. Continuously, the Integrity Monitor verifies file baselines every 30 seconds. Any violations trigger incident reports with automatic containment.

---

## Service Dependency Diagram

```
UI (:8480)
  |-- Agent (:8476)                     [verified supervisor, task orchestration]
  |     |-- Inference Worker             [planning via LLM]
  |     |-- Tool Firewall (:8475)       [tool invocation gating]
  |     |-- MCP Firewall (:8496)        [MCP tool call policy]
  |     |-- Policy Engine (:8500)       [allow/deny decisions]
  |     |-- Storage Gateway              [mediated file access]
  |     +-- Airlock (:8490)             [outbound requests, if enabled]
  |-- Inference Worker (llama-server)
  |     |-- Registry (:8470)            [model loading]
  |     |-- Tool Firewall (:8475)       [tool invocation]
  |     +-- Search Mediator (:8485)     [web search, optional]
  |           +-- SearXNG (via Tor)
  |-- Registry (:8470)                  [model listing, management]
  |-- Quarantine Pipeline               [model verification]
  |     +-- Registry (:8470)            [promotion target]
  +-- Airlock (:8490)                   [egress proxy, disabled by default]

Enforcement Layer (continuous, independent of user requests):
  Runtime Attestor (:8505)
    |-- Policy Engine (:8500)           [attestation policy]
    +-- Incident Recorder (:8515)       [degraded/failed state reports]
  Integrity Monitor (:8510)
    +-- Incident Recorder (:8515)       [violation reports]
  GPU Integrity Watch (:8495)
    +-- Incident Recorder (:8515)       [GPU anomaly reports]
  Incident Recorder (:8515)
    |-- Agent (:8476)                   [freeze_agent containment]
    |-- Airlock (:8490)                 [disable_airlock containment]
    +-- Registry (:8470)                [quarantine_model containment]
  Policy Engine (:8500)                 [consulted by all services]
```

---

## Design Decisions

### Go for Latency-Sensitive and Security-Critical Services

The Registry, Tool Firewall, Airlock, GPU Integrity Watch, MCP Firewall, Policy Engine, Runtime Attestor, Integrity Monitor, and Incident Recorder are written in Go. These services sit in the hot path of inference requests, act as network gateways, or perform continuous security verification where latency and reliability matter. Go provides low-latency HTTP handling, easy concurrency, and compiles to a single static binary with no runtime dependencies.

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
| MCP boundary | Inference Worker | MCP Firewall | Default-deny policy, input redaction, taint tracking |
| Policy boundary | All services | Policy Engine | Centralized decisions, structured evidence, 6 domains |
| Agent boundary | UI / User | Agent | HMAC-signed capability tokens, deny-by-default policy, hard budgets, two-phase approval |
| Agent→Service boundary | Agent | Tool Firewall / Airlock | Loopback-only IPC, service tokens, IPAddressDeny=any, fail-closed |
| Search boundary | Inference Worker | Search Mediator | PII stripping, injection detection, Tor routing |
| Attestation boundary | Runtime Attestor | All services | TPM2 quotes, HMAC-signed state bundles, startup gating |
| Integrity boundary | Integrity Monitor | File system | Signed baselines, continuous verification, auto-degradation |
| Incident boundary | Reporting services | Incident Recorder | Classified incidents, policy-driven containment, severity ranking |
| Containment boundary | Incident Recorder | Agent / Airlock / Registry | Auto-freeze, auto-disable, auto-quarantine, vault relock |
| GPU boundary | GPU Integrity Watch | GPU runtime | Driver fingerprint, device allowlist, baseline comparison |
| User boundary | UI | User | Local passphrase auth, vault encryption |

The user is the trust principal. SecAI OS does not defend against a malicious local user -- it defends the user against untrusted models and network exposure.
