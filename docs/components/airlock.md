# Airlock

## Overview

- **Purpose:** Sanitized egress proxy
- **Port:** 8490
- **Language:** Go
- **Systemd unit:** secure-ai-airlock.service
- **Default state:** Disabled

The Airlock is the only authorized path for outbound network traffic from the appliance. It is disabled by default because it represents the largest privacy risk surface. When enabled, it enforces strict controls on what data can leave the system and where it can go.

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
| Maximum request body | 10 MB |
| Maximum response body | Unlimited (for model downloads) |

---

## HTTPS Only

The Airlock only proxies HTTPS connections. HTTP (plaintext) requests are rejected. This prevents accidental exposure of data in transit.

---

## API

### POST /v1/proxy

Proxy a request through the Airlock.

**Request body:**

```json
{
  "url": "https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.3-GGUF/resolve/main/mistral-7b-instruct-v0.3.Q4_K_M.gguf",
  "method": "GET",
  "headers": {},
  "body": null
}
```

**Response (allowed):** `200 OK` with proxied response.

**Response (blocked destination):** `403 Forbidden`

```json
{
  "error": "destination not in allowlist: example.com"
}
```

**Response (PII detected):** `403 Forbidden`

```json
{
  "error": "request blocked: PII detected in request body"
}
```

**Response (rate limited):** `429 Too Many Requests`
