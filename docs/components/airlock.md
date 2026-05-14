# Airlock

## Overview

- **Purpose:** Sanitized egress decision gate
- **Port:** 8490
- **Language:** Go
- **Systemd unit:** secure-ai-airlock.service
- **Default state:** Disabled

The Airlock is the policy decision point for outbound network traffic from the appliance. It is disabled by default because it represents the largest privacy risk surface. When enabled, it decides whether a requested destination/method/body is allowed. The UI then performs approved model downloads into quarantine and re-checks redirects through the Airlock.

---

## Why Disabled by Default

SecAI OS is designed for local-first, air-gapped operation. Any network egress creates a potential data exfiltration vector. The Airlock exists for users who need to download models from remote sources, but it is off by default to maintain the strongest possible privacy posture.

Enable the Airlock only when you need to fetch models from external registries.

---

## Destination Allowlist

The Airlock only permits connections to explicitly allowlisted destinations. The default allowlist includes:

- **HuggingFace** (huggingface.co) -- model downloads
- **Ollama Registry** (registry.ollama.ai) -- model downloads

All other destinations are blocked. The allowlist is configured in `policy.yaml`.

---

## PII Scanning

All outbound request bodies and headers are scanned for personally identifiable information. The following patterns trigger a block:

- Social Security Numbers (SSN)
- Email addresses
- Phone numbers
- Other PII patterns defined in the scanning rules

Requests containing detected PII are rejected with a `403 Forbidden` response.

---

## Credential Scanning

Outbound data is scanned for credentials and secrets:

- API keys (common patterns for OpenAI, Anthropic, AWS, GCP, etc.)
- Bearer tokens
- Authorization headers with non-allowlisted values
- Private keys

Requests containing detected credentials are rejected.

---

## Rate Limiting

| Parameter | Value |
|---|---|
| Request rate | 30 requests per minute |
| Burst allowance | N/A |

The lower rate limit (compared to the Tool Firewall) reflects the higher risk of egress operations.

---

## Body Size Limits

| Parameter | Value |
|---|---|
| Maximum body inspected in an egress decision | 10 MB |

---

## HTTPS Only

The Airlock only approves HTTPS destinations. HTTP (plaintext) destinations are rejected. This prevents accidental exposure of data in transit.

---

## API

### POST /v1/egress/check

Decide whether an outbound request is allowed.

**Request body:**

```json
{
  "destination": "https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.3-GGUF/resolve/main/mistral-7b-instruct-v0.3.Q4_K_M.gguf",
  "method": "GET",
  "body": ""
}
```

**Response (allowed):** `200 OK`

```json
{
  "allowed": true
}
```

**Response (blocked destination):** `403 Forbidden`

```json
{
  "allowed": false,
  "reason": "destination not in allowlist: example.com"
}
```

**Response (PII detected):** `403 Forbidden`

```json
{
  "allowed": false,
  "reason": "request blocked: PII detected in request body"
}
```

**Response (rate limited):** `429 Too Many Requests`

### GET /v1/stats

Return request counters and allowlist summary.

### POST /v1/reload

Reload policy and source allowlist. Requires the service bearer token when token auth is enabled.
