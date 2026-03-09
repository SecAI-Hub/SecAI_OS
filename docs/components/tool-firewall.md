# Tool Firewall

## Overview

- **Purpose:** Policy-gated tool invocation gateway
- **Port:** 8475
- **Language:** Go
- **Systemd unit:** secure-ai-tool-firewall.service

The Tool Firewall mediates all tool calls from the inference worker. It enforces a default-deny policy: tools must be explicitly allowlisted before they can be invoked. This prevents models from executing arbitrary operations on the host.

---

## Policy Model

### Default-Deny

All tool invocations are denied unless the tool name appears in the allow list defined in `policy.yaml`. This is the opposite of a blocklist approach -- unknown tools are always rejected.

### Allow and Deny Lists

- **Allow list:** Tools that may be invoked. Each entry can include restrictions on allowed arguments.
- **Deny list:** Tools that are explicitly blocked, even if they appear on an allow list (deny takes precedence).

### Path Allowlisting

Tool arguments that reference filesystem paths are validated against a path allowlist. Only paths under explicitly permitted directories are accepted.

### Traversal Protection

All path arguments are checked for directory traversal patterns. Arguments containing `../` or other traversal sequences are rejected regardless of the allow list.

---

## Rate Limiting

| Parameter | Value |
|---|---|
| Request rate | 120 requests per minute |
| Burst allowance | 20 requests |

Requests exceeding the rate limit receive a `429 Too Many Requests` response.

---

## Argument Validation

### Args Blocklist

Tool arguments are scanned for dangerous patterns. The following are blocked by default:

- `../` -- directory traversal
- `/etc/` -- system configuration access
- `/usr/` -- system binary access
- Other patterns defined in `policy.yaml`

### Max Argument Length

Arguments exceeding the configured maximum length are rejected. This prevents buffer-based attacks and excessive resource consumption.

---

## API

### POST /v1/tool/invoke

Invoke a tool through the firewall.

**Request body:**

```json
{
  "tool": "read_file",
  "arguments": {
    "path": "/var/lib/secure-ai/data/example.txt"
  }
}
```

**Response (allowed):** `200 OK`

```json
{
  "status": "allowed",
  "result": { ... }
}
```

**Response (denied):** `403 Forbidden`

```json
{
  "status": "denied",
  "reason": "tool 'exec_shell' is not in the allow list"
}
```

**Response (rate limited):** `429 Too Many Requests`

**Response (invalid arguments):** `400 Bad Request`

```json
{
  "status": "denied",
  "reason": "argument contains blocked pattern: '../'"
}
```
