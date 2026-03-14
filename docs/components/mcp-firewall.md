# MCP Firewall

**Service:** `secure-ai-mcp-firewall.service`
**Binary:** `/usr/libexec/secure-ai/mcp-firewall`
**Port:** 8496 (loopback only)
**Language:** Go

## Purpose

Policy gateway for Model Context Protocol (MCP) tool calls. Intercepts, validates, and audits all MCP tool invocations before they reach backend services. Enforces default-deny with explicit allow rules, input redaction, and taint tracking.

## Architecture

The MCP Firewall sits between the agent (or any MCP client) and MCP tool servers, acting as a transparent policy enforcement point.

```
+--------+     +---------------+     +------------+
| Agent  | --> | MCP Firewall  | --> | MCP Server |
| (8476) |    | (8496)        |    | (tool)     |
+--------+     +---------------+     +------------+
                  |  policy.yaml
                  |  audit log
                  v
               /var/lib/secure-ai/logs/mcp-firewall-audit.jsonl
```

## Policy Enforcement

### Default Deny

All MCP tool calls are denied unless explicitly allowed by the policy file. Each rule specifies:

- **Tool name** -- which MCP tool is allowed
- **Input constraints** -- parameter validation (regex, range, enum)
- **Sensitivity level** -- required session sensitivity for the tool
- **Rate limits** -- per-tool and global rate limiting

### Input Redaction

Sensitive values (paths, secrets, PII patterns) are automatically redacted from tool inputs before forwarding. Redaction rules are configurable in the policy file.

### Taint Tracking

Tool outputs are tagged with taint labels based on the tool type and sensitivity level. Tainted outputs that flow into subsequent tool calls trigger escalated policy checks.

## Configuration

- **Policy:** `/etc/secure-ai/mcp-firewall/default-policy.yaml`
- **Audit log:** `/var/lib/secure-ai/logs/mcp-firewall-audit.jsonl`

## Systemd Hardening

- `DynamicUser=yes` -- no persistent user
- `PrivateNetwork=yes` -- Unix socket communication only
- `ProtectSystem=strict` -- read-only root
- `PrivateDevices=yes` -- no device access
- Per-service seccomp profile (`/etc/secure-ai/seccomp/mcp-firewall.json`)
- Landlock filesystem restrictions

## Audit Logging

Every MCP tool call produces a structured audit record:

```json
{
  "timestamp": "2026-03-13T12:00:00Z",
  "tool": "filesystem.read",
  "decision": "allow",
  "input_hash": "sha256:abc123...",
  "redacted_fields": ["path"],
  "taint_labels": ["filesystem"],
  "latency_ms": 2,
  "session_id": "ws-001"
}
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness check |
| POST | `/api/v1/invoke` | Proxy an MCP tool call through policy |
| GET | `/api/v1/policy` | Current loaded policy summary |
| GET | `/api/v1/stats` | Call counts, deny rates, latency |

## Related

- [Tool Firewall](tool-firewall.md) -- HTTP-level tool policy gateway
- [Agent](agent.md) -- policy-bound local autopilot
- [Architecture](../architecture.md) -- system design overview
