# Running in Fully Offline Mode

The Secure AI Appliance is designed to operate without any network access.
This guide explains how to configure and verify fully offline operation.

---

## Step 1: Set Session Mode to offline-only

Edit `/etc/secure-ai/config/appliance.yaml`:

```yaml
session:
  mode: "offline-only"
```

This mode hard-blocks all network access, even if the airlock is enabled
in policy.yaml. It overrides all other network settings.

The three session modes are:
- **normal** -- airlock and search follow their own enabled/disabled settings.
- **sensitive** -- same as normal, plus aggressive worker recycling after each task.
- **offline-only** -- all outbound network access is blocked regardless of other settings.

## Step 2: Disable the Airlock

For defense in depth, also explicitly disable the airlock in
`/etc/secure-ai/policy/policy.yaml`:

```yaml
airlock:
  enabled: false
```

## Step 3: Disable Web Search

Ensure search is disabled in policy.yaml:

```yaml
search:
  enabled: false
```

## Step 4: Stop Network-Dependent Services

Stop the Tor, SearXNG, and search mediator services:

```bash
sudo systemctl stop tor.service
sudo systemctl stop secure-ai-searxng.service
sudo systemctl stop secure-ai-search-mediator.service
sudo systemctl stop secure-ai-airlock.service
```

To prevent them from starting on reboot:

```bash
sudo systemctl disable tor.service
sudo systemctl disable secure-ai-searxng.service
sudo systemctl disable secure-ai-search-mediator.service
sudo systemctl disable secure-ai-airlock.service
```

## Step 5: Verify No Network Access

Check that the nftables firewall is active and blocking egress:

```bash
sudo nft list ruleset | grep -A5 "chain output"
```

You should see a default drop policy with only loopback allowed.

Verify from the Web UI:

1. Open `http://127.0.0.1:8480`.
2. Go to **Security** tab.
3. The status should show:
   - Session mode: `offline-only`
   - Airlock: disabled
   - Search: disabled
   - Egress: blocked

Try a connectivity test from the search status API:

```bash
curl http://127.0.0.1:8485/health
```

Expected response:

```json
{
  "status": "ok",
  "search_enabled": false,
  "session_mode": "offline-only",
  "searxng_reachable": false,
  "tor_routed": true
}
```

The `search_enabled: false` and `session_mode: offline-only` confirm no
outbound queries will be made.

## Pre-Loading Models Before Going Offline

You must import models while you still have network access (or via USB/local copy).

### Option A: Download from Catalog While Online

1. Temporarily set `session.mode: "normal"` and `airlock.enabled: true`.
2. Open the Web UI and download models from the catalog.
3. Wait for all models to pass quarantine and appear in the registry.
4. Switch back to `session.mode: "offline-only"` and `airlock.enabled: false`.

### Option B: Copy from USB Drive

1. Mount the USB drive.
2. Copy GGUF files to quarantine:

```bash
cp /mnt/usb/*.gguf /var/lib/secure-ai/quarantine/incoming/
```

3. Monitor the pipeline:

```bash
journalctl -u secure-ai-quarantine.service -f
```

4. Once promoted, verify:

```bash
securectl list
```

### Option C: Pre-Build into the Image

For fully air-gapped deployments, you can bake models into the OS image
by adding them to `files/system/var/lib/secure-ai/registry/` and updating
the `models.lock.yaml` file with their hashes. These models bypass
quarantine since they are part of the signed image.

## Verifying Offline Integrity

The appliance continues to run integrity checks on offline models:

- Every 15 minutes (configurable via `monitoring.integrity_interval`),
  the system verifies SHA-256 hashes of all promoted models.
- Every 30 minutes (configurable via `monitoring.audit_interval`),
  the audit log chain is verified for integrity.
- Canary files in sensitive directories are monitored continuously
  via inotify.

Check the last integrity result:

```bash
curl http://127.0.0.1:8470/v1/integrity/status
```

## Returning to Online Mode

To re-enable network features:

1. Set `session.mode: "normal"` in `appliance.yaml`.
2. Set `airlock.enabled: true` in `policy.yaml` (if desired).
3. Set `search.enabled: true` in `policy.yaml` (if desired).
4. Start the network services:

```bash
sudo systemctl start tor.service
sudo systemctl start secure-ai-searxng.service
sudo systemctl start secure-ai-search-mediator.service
sudo systemctl start secure-ai-airlock.service
```
