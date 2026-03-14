# Production Operations Guide

## First Boot

After imaging and booting the appliance for the first time:

```bash
sudo /usr/libexec/secure-ai/first-boot-check.sh
```

This validates:
- All core services are running
- Health endpoints respond
- Attestation state is verified
- Integrity monitor baseline is established
- No open incidents
- Service token is present
- No services exposed on public interfaces

## Upgrade Procedure

1. **Pre-upgrade snapshot** (if supported by hardware):
   ```bash
   rpm-ostree status              # Record current deployment
   sudo cp /var/lib/secure-ai/data/incidents.jsonl /tmp/incidents-backup.jsonl
   ```

2. **Pull update**:
   ```bash
   rpm-ostree upgrade
   ```

3. **Reboot and verify**:
   ```bash
   sudo systemctl reboot
   # After reboot:
   sudo /usr/libexec/secure-ai/first-boot-check.sh
   ```

4. **Rollback if needed**:
   ```bash
   rpm-ostree rollback
   sudo systemctl reboot
   ```

## Log Rotation

Audit logs are rotated automatically via `/etc/logrotate.d/secure-ai`:
- **Audit JSONL** (`/var/lib/secure-ai/logs/*.jsonl`): daily, 30 days retained, max 50MB per file
- **Incident store** (`/var/lib/secure-ai/data/*.jsonl`): weekly, 12 weeks retained, max 100MB

To manually trigger rotation:
```bash
sudo logrotate -f /etc/logrotate.d/secure-ai
```

## Key Rotation

### Service Token

The inter-service bearer token at `/run/secure-ai/service-token`:

1. Generate new token:
   ```bash
   openssl rand -hex 32 > /tmp/new-token
   ```

2. Replace atomically:
   ```bash
   sudo mv /tmp/new-token /run/secure-ai/service-token
   sudo chmod 0640 /run/secure-ai/service-token
   ```

3. Restart all services (they read token at startup):
   ```bash
   sudo systemctl restart secure-ai-*.service
   ```

### HMAC Signing Key (Attestation Bundles)

1. Generate new key:
   ```bash
   openssl rand 32 > /tmp/new-hmac-key
   ```

2. Replace and restart attestor:
   ```bash
   sudo mv /tmp/new-hmac-key /run/secure-ai/attestation-hmac-key
   sudo chmod 0640 /run/secure-ai/attestation-hmac-key
   sudo systemctl restart secure-ai-runtime-attestor
   ```

### Cosign Signing Key (Image & Release)

Rotate via the GitHub repository secrets. Update `SIGNING_SECRET` in repository settings, then trigger a new build.

## Monitoring

### Service Health

All services expose `/health` on their localhost ports:

| Service | Port | Endpoint |
|---------|------|----------|
| Policy Engine | 8500 | `/health` |
| Registry | 8470 | `/health` |
| Tool Firewall | 8475 | `/health` |
| Runtime Attestor | 8505 | `/health` |
| Integrity Monitor | 8510 | `/health` |
| Incident Recorder | 8515 | `/health` |
| MCP Firewall | 8496 | `/health` |
| GPU Integrity Watch | 8495 | `/health` |

### Incident Dashboard

```bash
# Open incidents
curl -s http://127.0.0.1:8515/api/v1/stats | python3 -m json.tool

# Attestation state
curl -s http://127.0.0.1:8505/api/v1/verify | python3 -m json.tool

# Integrity status
curl -s http://127.0.0.1:8510/api/v1/status | python3 -m json.tool
```

### Journal Logs

```bash
# All Secure AI services
journalctl -u 'secure-ai-*' --since "1 hour ago"

# Specific service
journalctl -u secure-ai-incident-recorder -f

# Security events only
journalctl -u 'secure-ai-*' -g 'FAIL\|DENIED\|degraded\|violation' --since today
```

## Capacity Limits

| Resource | Service | Default Limit | Notes |
|----------|---------|---------------|-------|
| Memory | Agent | 512MB | Increase for large context windows |
| Memory | Registry | 128MB | Scales with model count |
| Memory | Policy Engine | 128MB | Scales with rule count |
| CPU | Agent | 50% | Primary workload |
| CPU | GPU Integrity | 15% | Background monitoring |
| Incidents | Recorder | 1000 max | Oldest trimmed; persisted to disk |
| Models | Registry | Unlimited | Bounded by vault size |

## Graceful Shutdown

All Go services handle SIGTERM for clean shutdown:
- In-flight HTTP requests complete (up to 10s drain)
- Incident recorder flushes persistence file
- Audit log files are closed cleanly
- systemd `TimeoutStopSec=15` enforces hard deadline
