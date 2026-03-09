# Search Mediator

## Overview

- **Purpose:** Sanitized web search with PII stripping and injection detection
- **Port:** 8485
- **Language:** Python
- **Systemd unit:** secure-ai-search-mediator.service
- **Default state:** Disabled

The Search Mediator allows the LLM to perform web searches while maintaining user privacy. All queries are sanitized, routed through Tor, and results are scanned for injection attacks before being fed back to the model as context.

---

## Request Flow

```
LLM generates query
       |
       v
PII stripped from query
       |
       v
Query routed through Tor
       |
       v
SearXNG meta-search engine
       |
       v
Results cleaned and normalized
       |
       v
Injection detection scan
       |
       v
Safe results injected as LLM context
```

1. The LLM generates a search query as part of its reasoning.
2. The Search Mediator strips any PII (names, emails, addresses, etc.) from the query before it leaves the appliance.
3. The sanitized query is sent to a local SearXNG instance, which routes the request through Tor.
4. SearXNG aggregates results from privacy-respecting search engines.
5. Returned results are cleaned (HTML stripped, normalized) and scanned for prompt injection patterns.
6. Clean results are injected into the LLM's context window for the current conversation.

---

## Privacy Controls

### Tor Routing

All search traffic is routed through the Tor network. The search engines never see the appliance's real IP address.

### Privacy-Respecting Engines Only

SearXNG is configured to query only privacy-respecting sources:

- DuckDuckGo (DDG)
- Wikipedia
- Stack Overflow (SO)
- GitHub

Google, Bing, and other tracking-heavy engines are excluded.

### Differential Privacy

To prevent traffic analysis and query correlation:

- **Decoy queries:** The mediator periodically issues plausible but meaningless queries to mask real search patterns.
- **K-anonymity:** Queries are generalized to reduce uniqueness before submission.
- **Batch timing:** Multiple queries are batched and submitted together to prevent timing correlation.

### Traffic Analysis Protection

- **Query padding:** All queries are padded to a uniform length to prevent length-based fingerprinting.
- **Timing randomization:** Random delays are added between queries to break timing patterns.

---

## Injection Detection

Search results are scanned for prompt injection patterns before being injected into the LLM context. Detected patterns include:

- Instructions embedded in result text (e.g., "ignore previous instructions")
- Encoded payloads (base64, URL-encoded instructions)
- Excessive special characters or formatting designed to break context boundaries

Results containing detected injection patterns are filtered out and logged.

---

## API

### POST /search

Submit a search query.

**Request body:**

```json
{
  "query": "how to configure nftables firewall rules",
  "max_results": 5
}
```

**Response:** `200 OK`

```json
{
  "results": [
    {
      "title": "nftables wiki - Quick reference",
      "url": "https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference",
      "snippet": "This page provides a quick reference for nftables rule syntax..."
    }
  ],
  "query_sanitized": true,
  "results_filtered": 0
}
```

**Response (disabled):** `503 Service Unavailable`

```json
{
  "error": "search mediator is disabled"
}
```

---

## Enabling the Search Mediator

The Search Mediator is disabled by default. To enable it:

1. Set `search.enabled: true` in `policy.yaml`.
2. Ensure the Tor service is running.
3. Restart the search-mediator service.

Enabling search introduces a privacy trade-off: even with Tor and differential privacy, the act of searching reveals that the appliance is active and interested in certain topics.
