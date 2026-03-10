# Agent Mode

Policy-bound local autopilot for SecAI_OS. Automates bounded local
workflows while preserving the project's security and privacy posture.

## Design

The agent is a **supervised local autopilot**, not a free-roaming autonomous
agent. It runs low-risk local tasks automatically and interrupts only at
high-risk boundaries such as outbound requests, export actions, destructive
operations, or trust-state changes.

### Architecture (5 components)

```
User Intent
    ↓
┌──────────┐
│ Planner  │  Decomposes intent into steps (via inference worker or heuristic)
└────┬─────┘
     ↓
┌──────────────┐
│ Policy Engine│  Deny-by-default. Evaluates each step against capabilities,
│              │  workspace scope, sensitivity labels, and session mode.
└────┬─────────┘
     ↓ allow / ask / deny
┌──────────────┐
│  Executor    │  Runs approved steps with budget enforcement.
│              │  Dispatches to storage gateway, tool firewall, or airlock.
└────┬─────────┘
     ↓
┌──────────────┐       ┌────────────────┐
│ Storage GW   │       │  Tool Firewall │
│ (file access)│       │  (:8475)       │
└──────────────┘       └────────────────┘
```

### Operating modes

| Mode | Network | File scope | Approval style |
|------|---------|-----------|----------------|
| **Offline-only** | Blocked | Approved workspaces | Auto for low-risk |
| **Standard** (default) | Disabled unless enabled | Approved workspaces | Auto + ask |
| **Online-assisted** | Airlock-mediated | Approved workspaces | Always ask for online |
| **Sensitive** | Blocked | Explicitly scoped | Tighter budgets, aggressive recycling |

### Allow / deny matrix

- **Allow by default (auto)**: local search, summarize, draft, classify, report, explain security decisions
- **Configurable (user preference: always / ask / never)**: file reads, file writes, tool invocations
- **Hard approval required**: outbound requests, data export, trust changes, batch deletes, scope widening, new tools
- **Always denied**: security setting changes

## Service details

| Property | Value |
|----------|-------|
| Port | 8476 |
| Language | Python (Flask) |
| Bind | 127.0.0.1 (loopback only) |
| Systemd unit | `secure-ai-agent.service` |
| Policy file | `/etc/secure-ai/policy/agent.yaml` |
| Audit log | `/var/lib/secure-ai/logs/agent-audit.jsonl` |
| Depends on | registry, tool-firewall, inference |

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/task` | Submit a new task |
| GET | `/v1/task/<id>` | Get task status |
| POST | `/v1/task/<id>/approve` | Approve pending steps |
| POST | `/v1/task/<id>/deny` | Deny pending steps |
| POST | `/v1/task/<id>/cancel` | Cancel a task |
| GET | `/v1/tasks` | List tasks |
| GET | `/v1/modes` | List operating modes |
| GET | `/health` | Health check |

## Capability tokens

Every task run receives a scoped capability token defining:
- **Readable paths**: which directories the agent may read
- **Writable paths**: where the agent may write output
- **Allowed tools**: which tools may be invoked through the tool firewall
- **Online access**: whether outbound requests are even possible
- **Sensitivity ceiling**: maximum data sensitivity level (low / medium / high)

## Hard budgets

Each task is constrained by:
- Max plan steps (default: 30)
- Max tool calls (default: 80)
- Max tokens (default: 32,000)
- Max wall-clock time (default: 600s)
- Max files touched (default: 20)
- Max output size (default: 1 MB)

Sensitive mode uses tighter limits (10 steps, 120s, 5 files).

## Storage gateway

All file access goes through the storage gateway, which:
- Validates paths against the capability token scope
- Blocks access to sensitive system files (`/etc/shadow`, service tokens, etc.)
- Classifies file sensitivity (heuristic: SSN, email, credit card, credential patterns)
- Enforces sensitivity ceiling (high-sensitivity files blocked in low-ceiling sessions)
- Redacts sensitive content before any outbound use
- Enforces file size limits (2 MB read, 1 MB write)

## Sandboxing

The agent systemd service uses the same defense-in-depth as other services, with additional network-level restrictions:

- `DynamicUser=yes`, `ProtectSystem=strict`, `ProtectHome=yes`
- `PrivateTmp=yes`, `PrivateDevices=yes`, `NoNewPrivileges=yes`
- `MemoryDenyWriteExecute=yes`, `RestrictNamespaces=yes`
- `IPAddressDeny=any`, `IPAddressAllow=localhost` — enforces loopback-only IPC at the network level
- `RestrictAddressFamilies=AF_UNIX AF_INET` — no raw sockets or other families
- `SystemCallFilter=@system-service @network-io` — @network-io required for loopback HTTP to peer services; combined with IPAddressDeny this prevents any non-loopback traffic
- `SystemCallFilter=~@privileged @resources @mount @clock @debug @swap @reboot @raw-io @module @cpu-emulation @obsolete`
- `MemoryMax=512M`, `CPUQuota=50%`, `TasksMax=64`
- Read-only access to vault user docs and service tokens; read-write only to outputs and logs

## Inter-service authentication

The agent communicates with other services (registry, tool firewall, airlock, inference) over loopback HTTP. Authentication and access control:

- **Loopback-only binding**: All services bind to `127.0.0.1`, never `0.0.0.0`. Only processes on the local machine can reach service endpoints.
- **Service tokens**: The agent reads a shared service token from `/run/secure-ai/service-token` (mounted read-only). This Bearer token authenticates requests to peer services with mutating endpoints. If the token file is absent (dev mode), auth is bypassed.
- **UI→Agent auth**: The UI proxies agent requests through `/api/agent/*` endpoints. These are protected by session-based authentication (scrypt passphrase) and are not in the public endpoint list. All state-changing endpoints (approve, deny, cancel) require an authenticated session.
- **CSRF protection**: The UI applies CSRF token validation on all POST requests, including agent proxy endpoints. Direct agent-to-agent calls are backend-only (no browser origin).
- **Fail-closed**: If any peer service is unreachable, the agent returns an error rather than bypassing the service (e.g., tool firewall unreachable → tool invocation fails, airlock unreachable → outbound request fails).

## Implementation phases

1. **Phase 1** (current): Safe local autopilot — planner, policy engine, storage gateway, tool-firewall mediation, capability tokens, automatic low-risk workflows, UI approval flow
2. **Phase 2**: Security explainability — detailed explanations for quarantine/registry/airlock decisions, per-workspace permissions, sensitivity labels, audit views
3. **Phase 3**: Online-assisted mode — airlock-mediated outbound, search mediation, redaction flows, approval UX for online steps
4. **Phase 4**: Stronger isolation — adversarial testing, signed releases, additional sandboxing profiles, policy bypass regression tests
