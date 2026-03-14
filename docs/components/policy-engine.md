# Policy Engine

**Service:** `secure-ai-policy-engine.service`
**Binary:** `/usr/libexec/secure-ai/policy-engine`
**Port:** 8500 (loopback only)
**Language:** Go

## Purpose

Unified policy decision point for the entire SecAI OS appliance. Replaces scattered enforcement logic across tool-firewall, airlock, registry, and agent with a single, auditable decision API. Every allow/deny/ask decision emits a structured evidence object for full traceability.

Designed as a stepping stone toward full OPA/Rego: the current implementation uses the existing YAML policy files directly, but the decision API contract is identical to what an embedded OPA engine would expose. The upgrade path is to swap the evaluation internals without changing any caller.

## Architecture

```
+----------------+     +----------------+     +----------------+
| Tool Firewall  | --> |                | <-- | Agent          |
| (8475)         |     |  Policy Engine |     | (8476)         |
+----------------+     |  (8500)        |     +----------------+
                        |                |
+----------------+     |  /api/v1/decide|     +----------------+
| Airlock        | --> |                | <-- | Registry       |
| (8490)         |     +-------+--------+     | (8470)         |
+----------------+             |              +----------------+
                               v
                    +---------------------+
                    | Decision Evidence   |
                    | (audit log + API)   |
                    +---------------------+
```

## Decision Domains

| Domain | Subject | What It Decides |
|--------|---------|-----------------|
| `tool_access` | tool name | Allow/deny a tool invocation based on allowlist, denylist, path constraints |
| `path_access` | file path | Allow/deny agent read/write based on workspace scope |
| `egress` | destination URL | Allow/deny outbound network based on airlock state and destination allowlist |
| `agent_risk` | action name | Allow/deny/ask for agent actions based on risk classification |
| `sensitivity` | sensitivity level | Allow/deny based on sensitivity ceiling enforcement |
| `model_promotion` | model name | Allow/deny model format based on allowed/denied format lists |

## Decision Evidence

Every response includes a `DecisionEvidence` object:

```json
{
  "timestamp": "2026-03-13T12:00:00Z",
  "domain": "tool_access",
  "policy_digest": "sha256:f1b3cb15d629...",
  "rule_id": "tools.allow.filesystem.read",
  "input_hash": "a1b2c3d4e5f6",
  "eval_time_us": 42
}
```

- **policy_digest** — SHA-256 of loaded policy files. Changes when policy is reloaded.
- **rule_id** — which specific rule matched the decision.
- **input_hash** — truncated SHA-256 of the request for correlation.
- **eval_time_us** — evaluation latency in microseconds.

## Configuration

- **Policy file:** `/etc/secure-ai/policy/policy.yaml` (main policy)
- **Agent policy:** `/etc/secure-ai/policy/agent.yaml` (agent-specific rules)
- **Audit log:** `/var/lib/secure-ai/logs/policy-engine-audit.jsonl`

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | None | Liveness check with policy digest |
| POST | `/api/v1/decide` | None | Evaluate a policy decision |
| GET | `/api/v1/stats` | None | Decision statistics (allow/deny/ask counts) |
| GET | `/api/v1/digest` | None | Current policy digest for cache invalidation |
| POST | `/api/v1/reload` | Token | Hot-reload policy files without restart |

## Systemd Hardening

- `DynamicUser=yes` -- no persistent user
- `PrivateNetwork=yes` -- Unix socket communication only
- `ProtectSystem=strict` -- read-only root
- `PrivateDevices=yes` -- no device access
- `MemoryMax=128M` -- minimal footprint
- Per-service seccomp profile
- Landlock filesystem restrictions

## Upgrade Path to OPA/Rego

The policy engine is designed for a clean upgrade to embedded OPA:

1. Replace `evaluate()` internals with `rego.New()` + `rego.PrepareForEval()`
2. Convert `policy.yaml` → Rego data bundle
3. Convert `agent.yaml` → Rego data bundle
4. Write Rego rules for each domain (tool_access.rego, etc.)
5. The HTTP API contract and evidence format stay identical

## Related

- [Tool Firewall](tool-firewall.md) -- current tool-level enforcement (caller)
- [Agent](agent.md) -- agent policy engine (caller)
- [Architecture](../architecture.md) -- system design overview
- [Policy Schema](../policy-schema.md) -- YAML policy file reference
