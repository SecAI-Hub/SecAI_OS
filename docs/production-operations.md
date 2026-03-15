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

## Backup and Restore

### What Is Backed Up

| Category | Paths | Criticality |
|----------|-------|-------------|
| Policy + config | `/etc/secure-ai/policy/*.yaml`, `/etc/secure-ai/config/appliance.yaml`, `/etc/secure-ai/model-catalog.yaml` | High |
| Incidents | `/var/lib/secure-ai/data/incidents.jsonl` | High — audit trail |
| Audit logs | `/var/lib/secure-ai/logs/*.jsonl` | High — hash-chained evidence |
| Registry manifest | `/var/lib/secure-ai/registry/manifest.json` | Medium — model inventory |
| Signing keys | `/var/lib/secure-ai/keys/` (cosign, TPM2) | Critical |
| LUKS header | Vault partition header | Critical — data recovery |

**Note:** Model files (GGUF binaries) are NOT included in backups due to their
size (4–70 GB each). The registry manifest is backed up, so you know exactly
which models to re-download after a restore.

### Creating a Backup

```bash
# Full backup (config + logs + keys + manifest + LUKS header)
sudo secai-backup.sh full

# Config only (policy, appliance config, model catalog)
sudo secai-backup.sh config

# Logs and incidents only
sudo secai-backup.sh logs

# Keys and LUKS header only (most sensitive)
sudo secai-backup.sh keys --encrypt

# Full encrypted backup to external USB
sudo secai-backup.sh full --encrypt --output /media/usb/backups
```

### Verifying a Backup

```bash
sudo secai-backup.sh verify /var/lib/secure-ai/backups/secai-backup-full-20260314-120000.tar.gz
```

### Restoring from Backup

```bash
# Inspect backup contents before restoring
sudo secai-restore.sh inspect <backup-file>

# Full restore
sudo secai-restore.sh full <backup-file>

# Selective restore (config, logs, or keys)
sudo secai-restore.sh config <backup-file>
sudo secai-restore.sh logs <backup-file>
sudo secai-restore.sh keys <backup-file>    # Requires YES confirmation for LUKS header
```

After restore, the script automatically restarts services and runs the health check.

### Backup Schedule

| Environment | Frequency | Retention | Encryption |
|-------------|-----------|-----------|------------|
| Production | Daily (config + logs), weekly (full) | 30 days | Required |
| Development | Weekly (full) | 14 days | Optional |
| Pre-upgrade | Immediately before upgrade | Until next successful upgrade verified | Required |

### Backup Storage

- Store backups on a **separate physical device** (USB, NAS, air-gapped machine).
- Never store unencrypted key backups on network-attached storage.
- The LUKS header backup + vault passphrase can decrypt the entire vault — treat as highly sensitive.
- Verify backup integrity periodically: `secai-backup.sh verify <file>`.

## Rollback Decision Matrix

### Automatic Rollback (Greenboot)

Greenboot triggers automatic `rpm-ostree rollback` when health checks fail
after boot. The checks are defined in
`/etc/greenboot/check/required.d/01-secure-ai-health.sh`:

| Check | Failure Condition | Auto-Rollback? |
|-------|-------------------|----------------|
| nftables service | Not active | Yes |
| Registry / Tool Firewall / UI | Enabled but failed to start within 60s | Yes |
| Registry API | `/health` unreachable after 30s | Yes |
| Model integrity | SHA256 mismatch against manifest | Yes |
| nftables rules | `secure_ai` table not loaded | Yes |
| Critical scripts | securectl / verify-boot-chain / canary-check missing | Yes |

Maximum **2 automatic rollback attempts**. After exhaustion, the system halts
on the broken deployment for manual intervention (see Break-Glass Scenario 5 below).

### Manual Rollback Criteria

| Symptom | Severity | Action | Rationale |
|---------|----------|--------|-----------|
| Inference quality degraded, all services healthy | Low | Fix forward | Not a security regression |
| Single non-critical service failing (e.g., GPU watch) | Low | Fix forward | Other services compensate |
| Policy engine or tool firewall failing | **Critical** | **Rollback** | Security enforcement compromised |
| Attestation stuck in failed state | **Critical** | **Rollback** | Trust root broken |
| Multiple services crash-looping | High | **Rollback** | Systemic regression |
| Disk full preventing log writes | Medium | Fix forward | Clear space, not a code issue |
| Network rules missing or wrong | **Critical** | **Rollback** | Default-deny bypassed |
| Incident recorder down | **Critical** | **Rollback** | Audit trail broken |
| UI unreachable but API services healthy | Low | Fix forward | Non-critical for security |

### Rollback Procedure

```bash
# Manual rollback
sudo rpm-ostree rollback
sudo systemctl reboot

# Or via the update verification tool
sudo /usr/libexec/secure-ai/update-verify.sh rollback
```

### Post-Rollback Verification

```bash
# Health check
sudo /usr/libexec/secure-ai/first-boot-check.sh

# Check deployment status
rpm-ostree status

# Review journal for the failed deployment
journalctl -u 'secure-ai-*' --since "1 hour ago" -g 'FAIL\|ERROR\|panic'
```

## Break-Glass Procedures

These procedures are for exceptional situations where normal operational
tools are unavailable. Each requires physical or console access to the
appliance.

### Scenario 1: Service Token Lost or Corrupted

**Symptoms:** All inter-service calls fail with 401. Services are running but
cannot communicate.

**Diagnosis:**
```bash
ls -la /run/secure-ai/service-token   # Missing or empty?
curl -s http://127.0.0.1:8470/health  # Registry returns 401?
```

**Recovery:**
```bash
# Generate a new token
openssl rand -hex 32 | sudo tee /run/secure-ai/service-token > /dev/null
sudo chmod 0640 /run/secure-ai/service-token

# Restart all services so they pick up the new token
sudo systemctl restart secure-ai-*.service

# Verify
sudo /usr/libexec/secure-ai/first-boot-check.sh
```

### Scenario 2: Attestation Stuck in Failed State

**Symptoms:** Services frozen in degraded mode. Incident recorder shows
latched attestation_failure or integrity_violation. Normal recovery
ceremony fails because the incident recorder is unreachable.

**Diagnosis:**
```bash
curl -sf http://127.0.0.1:8505/health    # Attestor healthy?
curl -sf http://127.0.0.1:8515/health    # Incident recorder healthy?
curl -s http://127.0.0.1:8515/api/v1/stats | python3 -m json.tool
```

**Recovery Option A** (if incident recorder is reachable): Run the
[recovery ceremony](recovery-runbook.md) — acknowledge → re-attest → resolve.

**Recovery Option B** (if incident recorder is unreachable):
```bash
# Stop all services
sudo systemctl stop secure-ai-*.service

# Clear panic state
sudo rm -f /run/secure-ai/panic-state.json

# Regenerate service token
openssl rand -hex 32 | sudo tee /run/secure-ai/service-token > /dev/null
sudo chmod 0640 /run/secure-ai/service-token

# Restart services
sudo systemctl start secure-ai-*.service

# Run full health check and recovery ceremony
sudo /usr/libexec/secure-ai/first-boot-check.sh
```

### Scenario 3: System Locked After Level 1 Panic

**Context:** `securectl panic 1` was triggered — vault locked, services stopped,
sessions invalidated. This is fully reversible.

**Recovery:**
```bash
# Unlock the vault (you will be prompted for the passphrase)
sudo cryptsetup open /dev/<vault-partition> secure-ai-vault
sudo mount /dev/mapper/secure-ai-vault /var/lib/secure-ai

# Regenerate service token (invalidated by panic)
openssl rand -hex 32 | sudo tee /run/secure-ai/service-token > /dev/null
sudo chmod 0640 /run/secure-ai/service-token

# Start all services
sudo systemctl start secure-ai-*.service

# Verify
sudo /usr/libexec/secure-ai/first-boot-check.sh
```

Find the vault partition: `grep secure-ai-vault /etc/crypttab`.

### Scenario 4: Signing Policy Breaks

**Context:** `rpm-ostree upgrade` fails with signature verification errors.
The signing policy (`policy.json` or cosign public key) is corrupted.

**Diagnosis:**
```bash
cat /etc/containers/policy.json | python3 -m json.tool    # Valid JSON?
cat /etc/containers/registries.d/secai-os.yaml            # Present?
ls /etc/pki/containers/secai-cosign.pub                   # Present?
```

**Recovery:** Re-run the bootstrap script in dry-run mode first, then for real:
```bash
curl -sSfL https://raw.githubusercontent.com/SecAI-Hub/SecAI_OS/main/files/scripts/secai-bootstrap.sh \
  -o /tmp/secai-bootstrap.sh
sudo bash /tmp/secai-bootstrap.sh --dry-run   # verify
sudo bash /tmp/secai-bootstrap.sh             # apply
```

See [recovery-bootstrap.md](install/recovery-bootstrap.md) for the full manual
fallback procedure.

### Scenario 5: Greenboot Exhaustion (Max Rollbacks Reached)

**Context:** Greenboot hit `MAX_ROLLBACKS=2`. The system is halted on the
broken deployment. Automatic rollback has stopped to prevent an infinite
reboot loop.

**Recovery** (requires USB boot media):
1. Boot from a Fedora Silverblue USB drive (Live session, not install).
2. Mount the system partition:
   ```bash
   sudo mount /dev/sda3 /mnt    # Adjust device as needed
   ```
3. Reset the rollback counter:
   ```bash
   sudo rm -f /mnt/run/secure-ai/rollback-count
   ```
4. Pin the last known-good deployment:
   ```bash
   sudo chroot /mnt rpm-ostree rollback
   ```
5. Reboot into the system (remove USB):
   ```bash
   sudo reboot
   ```

See [recover-failed-update.md](../examples/recover-failed-update.md) for
additional boot loop recovery scenarios.

## Data Retention Policy

### Retention Requirements

| Data Class | Minimum Retention | Maximum Retention | Rotation | Notes |
|------------|-------------------|-------------------|----------|-------|
| Audit logs (`*.jsonl`) | 30 days | 90 days | logrotate (daily, 30 rotations) | Hash-chained; broken chains are snapshotted |
| Incident store | 12 weeks | 6 months | logrotate (weekly, 12 rotations) | Latched incidents retained until resolution |
| Forensic bundles | 1 year | Indefinite | Manual export | Export via `/api/v1/forensic/export` before pruning |
| Backup archives | 30 days (prod) | 90 days | Operator-managed | Encrypted, stored on external media |
| Model files (GGUF) | While promoted | N/A | Manual prune | Quarantined models auto-expire in 30 days |
| LUKS header backup | Indefinite | Indefinite | Manual | Critical for recovery; store offline |
| Panic audit log | 1 year | Indefinite | Not rotated | Emergency event record |

### Disk Capacity Management

When `/var/lib/secure-ai` usage exceeds thresholds (check with
`df -h /var/lib/secure-ai`):

| Usage | Action |
|-------|--------|
| > 70% | Review and prune quarantined models in `/var/lib/secure-ai/quarantine/` |
| > 80% | Archive oldest audit logs to external media, remove unpromoted models from staging |
| > 90% | Emergency: force logrotate (`sudo logrotate -f /etc/logrotate.d/secure-ai`), remove all quarantined models |
| > 95% | **Critical:** Services may fail to write logs. Immediate operator intervention required |

### Model Pruning

```bash
# List models by size
du -sh /var/lib/secure-ai/registry/*.gguf 2>/dev/null | sort -rh

# List quarantined models (safe to remove)
ls -lh /var/lib/secure-ai/quarantine/incoming/
ls -lh /var/lib/secure-ai/quarantine/tampered/

# Remove all quarantined models
sudo rm -rf /var/lib/secure-ai/quarantine/incoming/*
sudo rm -rf /var/lib/secure-ai/quarantine/tampered/*
```

### Archive Procedures

Before allowing logrotate to trim old data:
1. **Export forensic bundle** (preserves incident + audit evidence with HMAC signature):
   ```bash
   curl -s http://127.0.0.1:8515/api/v1/forensic/export > forensic-$(date +%Y%m%d).json
   ```
2. **Create a log-only backup** to external media:
   ```bash
   sudo secai-backup.sh logs --encrypt --output /media/usb/archives
   ```
3. **Verify the archive** before allowing rotation:
   ```bash
   sudo secai-backup.sh verify /media/usb/archives/secai-backup-logs-*.tar.gz
   ```
