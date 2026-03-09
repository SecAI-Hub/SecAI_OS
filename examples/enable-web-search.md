# Enabling Web Search

Web search in the Secure AI Appliance is Tor-routed, PII-stripped, and
disabled by default. This guide walks through enabling it safely and
understanding the privacy protections in place.

---

## Step 1: Enable Search in Policy

Edit `/etc/secure-ai/policy/policy.yaml`:

```yaml
search:
  enabled: true
  max_query_length: 200
  max_results: 5
  max_context_length: 4000
  strip_pii: true
  block_high_pii_queries: true
  detect_injection: true
  audit: true
  allowed_engines:
    - duckduckgo
    - wikipedia
    - stackoverflow
    - github
  differential_privacy:
    enabled: true
    decoy_count: 2
    uniqueness_mode: "warn"
    batch_window: 5.0
```

Ensure `strip_pii` and `detect_injection` remain `true`. These are
critical privacy and security controls.

## Step 2: Verify Session Mode

The session mode must NOT be `offline-only`. Check
`/etc/secure-ai/config/appliance.yaml`:

```yaml
session:
  mode: "normal"  # or "sensitive"
```

If it is set to `offline-only`, search will be blocked regardless of the
search.enabled setting.

## Step 3: Start the Services

Start Tor, SearXNG, and the search mediator:

```bash
sudo systemctl start tor.service
sudo systemctl start secure-ai-searxng.service
sudo systemctl start secure-ai-search-mediator.service
```

Enable them for automatic start on boot (optional):

```bash
sudo systemctl enable tor.service
sudo systemctl enable secure-ai-searxng.service
sudo systemctl enable secure-ai-search-mediator.service
```

## Step 4: Verify Tor Is Working

Check the search mediator health endpoint:

```bash
curl http://127.0.0.1:8485/health
```

Expected response:

```json
{
  "status": "ok",
  "search_enabled": true,
  "session_mode": "normal",
  "searxng_reachable": true,
  "tor_routed": true
}
```

All four fields should be as shown. If `searxng_reachable` is false,
Tor may still be bootstrapping (this can take 30-60 seconds on first start).

Run the connectivity test:

```bash
curl http://127.0.0.1:8485/v1/search/test
```

Expected response:

```json
{
  "status": "ok",
  "searxng_status": 200,
  "tor_routed": true
}
```

## Step 5: Test a Search

From the Web UI:

1. Open `http://127.0.0.1:8480`.
2. In the chat interface, toggle the **Search** switch to ON.
3. Type a question. The UI will search the web and augment the LLM's
   response with the results.
4. Search-augmented responses are labeled with a "Sources from web" indicator.

From the command line:

```bash
curl -X POST http://127.0.0.1:8485/v1/search \
  -H "Content-Type: application/json" \
  -d '{"query": "python asyncio tutorial"}'
```

---

## Privacy Protections in Place

When search is enabled, these protections are always active:

### Outbound Query Protection

1. **PII Stripping** -- Email addresses, phone numbers, SSNs, credit card
   numbers, IP addresses, dates of birth, and API keys are redacted from
   queries before they leave the appliance.

2. **High-PII Blocking** -- If more than 50% of query tokens are redacted
   PII, the query is blocked entirely.

3. **Query Length Limit** -- Queries are truncated to `max_query_length`
   (default 200 characters).

4. **Query Padding** -- Queries are padded to fixed-size buckets (256, 512,
   or 1024 bytes) to prevent length-based traffic analysis.

### Differential Privacy

5. **Decoy Searches** -- Before each real search, 2 decoy searches from a
   curated list of generic queries are sent through Tor to obscure which
   query is real.

6. **Query Generalization** -- If the query contains sensitive keywords
   (medical, legal, financial), a broader category search is sent first
   as cover traffic.

7. **Uniqueness Detection** -- Queries containing proper names, addresses,
   case numbers, or other highly identifying terms are flagged. In `warn`
   mode, a warning is returned. In `auto-block` mode, the query is silently
   rejected.

8. **Batch Timing** -- Queries within a configurable time window (default 5s)
   are grouped together to prevent timing correlation.

### Traffic Analysis Protection

9. **Random Delay** -- A random 0.5-3 second delay is added before each
   search to decorrelate query timing.

10. **Tor Circuit Rotation** -- Tor circuits are rotated every 30 seconds
    (`MaxCircuitDirtiness 30`) for faster circuit changes.

11. **Tor Connection Padding** -- Dummy Tor cells are added to obscure
    traffic patterns.

12. **DNS Leak Detection** -- A periodic check (every 60 minutes) verifies
    that DNS queries are not leaking outside of Tor.

### Inbound Result Protection

13. **HTML Stripping** -- All HTML tags and scripts are removed from results.

14. **Injection Detection** -- Results are scanned for prompt injection
    patterns (e.g., "ignore previous instructions", script tags). Matches
    are silently dropped.

15. **Result Limit** -- Only `max_results` (default 5) results are returned.

16. **Snippet Truncation** -- Each result snippet is truncated to 500
    characters.

17. **Context Limit** -- The total context injected into the LLM is capped
    at `max_context_length` (default 4000 characters).

### Audit

18. **Hash-Chained Audit Log** -- Every search attempt is logged with a
    query hash (not the raw query), sanitized query, redaction count, and
    result count. The log is hash-chained for tamper evidence.

---

## Disabling Search Again

To disable search:

1. Set `search.enabled: false` in policy.yaml.
2. Stop the services:

```bash
sudo systemctl stop secure-ai-search-mediator.service
sudo systemctl stop secure-ai-searxng.service
sudo systemctl stop tor.service
```

Or set `session.mode: "offline-only"` to block all network access.
