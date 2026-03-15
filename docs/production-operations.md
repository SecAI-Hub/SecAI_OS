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

### Cosign Signing Key (Image & Release Artifacts)

The cosign signing key is used to sign:
- OCI container images (`ghcr.io/secai-hub/secai_os:*`)
- SBOM attestations (CycloneDX per-service)
- Release checksums (`SHA256SUMS.sig`)
- SLSA provenance attestations

#### Key Generation

```bash
# Generate a new cosign key pair (interactive passphrase prompt)
cosign generate-key-pair

# This creates cosign.key (private) and cosign.pub (public)
# Store cosign.key in a password manager or HSM — never commit to git
```

#### Rotation Schedule

| Trigger | Action |
|---------|--------|
| **Annual** (recommended) | Proactive rotation, even with no incident |
| **Key compromise** | Immediate emergency rotation |
| **Personnel change** | Rotate if key holder leaves the project |
| **CI provider breach** | Rotate if GitHub Actions secrets may be exposed |

#### Rotation Procedure

1. **Generate new key pair** (on an air-gapped machine if possible):
   ```bash
   cosign generate-key-pair
   ```

2. **Update GitHub repository secret**:
   - Go to: Settings → Secrets and variables → Actions
   - Update `SIGNING_SECRET` with the new `cosign.key` contents
   - Verify the secret is updated (name shows "Updated just now")

3. **Update the public key in deployed appliances**:
   ```bash
   # Copy the new cosign.pub to the appliance
   scp cosign.pub admin@appliance:/tmp/cosign.pub
   # On the appliance (requires local admin access):
   sudo cp /tmp/cosign.pub /etc/secure-ai/cosign.pub
   sudo chmod 0644 /etc/secure-ai/cosign.pub
   ```

4. **Tag a new release** to produce signed artifacts with the new key:
   ```bash
   git tag -s vX.Y.Z -m "Release vX.Y.Z (key rotation)"
   git push origin vX.Y.Z
   ```

5. **Verify** the new signature:
   ```bash
   cosign verify --key cosign.pub ghcr.io/secai-hub/secai_os:vX.Y.Z
   ```

#### Emergency Revocation

If the signing key is compromised:

1. **Immediately** rotate the key (steps above)
2. **Revoke trust** in old images: update all deployed appliances' `cosign.pub`
3. **Re-sign** the latest stable release with the new key:
   ```bash
   cosign sign --key cosign.key ghcr.io/secai-hub/secai_os:latest
   ```
4. **Announce** the compromise via GitHub Security Advisory
5. **Audit** CI logs for any unauthorized release activity during the exposure window

#### Key Audit Checklist

- [ ] Private key stored in encrypted vault or HSM (never on disk in plaintext)
- [ ] Only CI (`SIGNING_SECRET`) and key custodian have access to private key
- [ ] Public key shipped in OS image at `/etc/secure-ai/cosign.pub`
- [ ] `verify-release.sh` uses the shipped public key, not a remote fetch
- [ ] Key rotation date recorded in `CHANGELOG.md`
- [ ] Previous public key archived (for verifying older releases)

#### Future: HSM Migration

When HSM support is implemented (planned milestone):
- Private key will be generated inside the HSM and never exported
- Cosign will use `--key` with a PKCS#11 URI instead of a file path
- Rotation becomes: generate new key in HSM → update PKCS#11 URI in CI
- See `docs/security-status.md` for HSM milestone tracking

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
