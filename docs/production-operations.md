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

1. **Record the current deployment**:
   ```bash
   rpm-ostree status              # Record current deployment
   ```

   Keep the deployment record in an operator-controlled location. Complete
   backup and active restore remain gated by the [backup foundation](backup-foundation.md).

2. **Resolve and stage a verified exact-digest update**:
   ```bash
   sudo systemctl start secure-ai-update-check.service
   sudo /usr/libexec/secure-ai/update-verify.sh stage
   ```

   The check requires an explicit network maintenance lease. Its root admission
   dependency rejects closed or unverified admission state. A failed service
   start must be resolved before staging; inspect its journal for the failure.

3. **Re-verify, apply, reboot, and verify**:
   ```bash
   sudo /usr/libexec/secure-ai/update-verify.sh apply
   # After reboot:
   sudo /usr/libexec/secure-ai/first-boot-check.sh
   ```

4. **Rollback if needed**:
   ```bash
   sudo /usr/libexec/secure-ai/update-verify.sh rollback
   ```

## Update-check admission boundary

`secure-ai-native-admission.service` initializes a private authority for
`secure-ai-update-check.service`. The check supervisor retains its shared lock
until the service's complete cgroup is empty of descendants, including processes
that outlive the direct updater child. A supervisor crash can release the lock
while descendants remain; a free lock alone does not establish quiescence.

The root-only `secure-native-admission.py close-update-check` operation durably
closes admission, inhibits the fixed timer/service, stops them and verifies their
manager state, retained cgroup and exclusive lock. It reports only this writer's
quiescence. Other writers, direct root updater invocations, staging, applying and
emergency containment remain outside this boundary. It cannot authorize restore.

Closure persists across reboot. Record the `closure` UUID returned by the close
operation. To inspect the control state or explicitly resume this writer:

```bash
sudo /usr/libexec/secure-ai/secure-native-admission.py status
sudo /usr/libexec/secure-ai/secure-native-admission.py reopen-update-check --closure CURRENT_CLOSURE_UUID
```

Replace `CURRENT_CLOSURE_UUID` with the exact current closure ID. Resume rejects
stale receipts, unknown metadata, pending jobs or live descendants. It validates
the fixed service and timer, establishes exclusive admission, removes their
runtime masks and persists the current boot binding before committing open
admission. It does not enable or start either unit. Start an update check
explicitly after successful resume when a network maintenance lease is available.

`status` reads the authority without creating or repairing it. It distinguishes
uninitialized, open, closed and unbound admission and includes the current closure
ID. This control report does not establish appliance health or global quiescence.
After interruption, inspect it to determine whether reopening committed. Unknown
or incomplete metadata remains an error; do not delete private state to bypass it.

Closing this writer does not provide a complete backup or restore maintenance
boundary and is not a routine pre-upgrade step.

## Log Rotation

Audit logs are rotated automatically via `/etc/logrotate.d/secure-ai`:
- **Audit JSONL** (`/var/lib/secure-ai/logs/*.jsonl`): daily, 30 days retained, max 50MB per file
- **Incident store** (`/var/lib/secure-ai/data/*.jsonl`): weekly, 12 weeks retained, max 100MB

To manually trigger rotation:
```bash
sudo logrotate -f /etc/logrotate.d/secure-ai
```

## Key Rotation

### Scoped service credentials

Native services receive private copies through systemd `LoadCredential=` from
root-owned mode-`0600` files under `/var/lib/secure-ai/credentials`. The source
directory is mode `0700` on encrypted host state. Rotating a source does not
replace credential copies already held by running services. Select one purpose
and identify every consumer from its installed `LoadCredential=` mappings;
preserve the service's enabled state and restart only consumers that were active.

For example, `registry-promote.token` is shared by the registry's promotion
endpoint and quarantine watcher. During a planned interruption, record their
active state, stop the watcher before the registry, then replace the source:

```bash
sudo systemctl stop secure-ai-quarantine-watcher.service secure-ai-registry.service
sudo python3 - <<'PY'
import os
import secrets
import stat
from pathlib import Path

directory = Path('/var/lib/secure-ai/credentials')
target = directory / 'registry-promote.token'
parent = directory.lstat()
current = target.lstat()
if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
        or stat.S_IMODE(parent.st_mode) != 0o700
        or not stat.S_ISREG(current.st_mode) or current.st_uid != 0
        or current.st_gid != 0 or current.st_nlink != 1
        or stat.S_IMODE(current.st_mode) != 0o600):
    raise SystemExit('Credential ownership or type requires administrator review')
temporary = directory / ('.rotation-' + secrets.token_hex(16))
fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
try:
    with os.fdopen(fd, 'wb') as handle:
        handle.write((secrets.token_hex(32) + '\n').encode('ascii'))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, target)
    parent_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
finally:
    temporary.unlink(missing_ok=True)
PY
```

Start the registry, then the watcher, only if each was active before rotation.
Check their authenticated health and the next promotion attempt. Other roles
(read, verify, administration and containment) have distinct tokens and consumer
sets; rotating this promotion credential does not rotate those authorities.
If interruption leaves the outcome uncertain, inspect the source and services
before retrying. Do not print credential contents or restart every SecAI unit.

### HMAC Signing Key (Attestation Bundles)

The runtime attestor signs with this key and the incident recorder receives the
same key only to verify fresh recovery bundles. Rotate both consumers
together. The source must remain a root-owned mode-`0600` canonical
64-lowercase-hex credential on encrypted host state.

1. Generate and validate a new source:
   ```bash
   sudo sh -c 'umask 077; openssl rand -hex 32 \
     > /var/lib/secure-ai/credentials/.attestation-hmac.key.new'
   sudo grep -Eq '^[0-9a-f]{64}$' \
     /var/lib/secure-ai/credentials/.attestation-hmac.key.new
   ```

2. Stop both consumers, replace atomically, and restart:
   ```bash
   sudo systemctl stop secure-ai-incident-recorder.service \
     secure-ai-runtime-attestor.service
   sudo mv /var/lib/secure-ai/credentials/.attestation-hmac.key.new \
     /var/lib/secure-ai/credentials/attestation-hmac.key
   sudo chown root:root \
     /var/lib/secure-ai/credentials/attestation-hmac.key
   sudo chmod 0600 \
     /var/lib/secure-ai/credentials/attestation-hmac.key
   sudo systemctl start secure-ai-runtime-attestor.service \
     secure-ai-incident-recorder.service
   ```

3. Trigger a fresh attestation. Previously recorded recovery evidence is not
   reusable after key rotation.

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

These services expose `/health` on their localhost ports. Liveness alone does
not establish authenticated readiness or runtime admission:

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
sudo python3 - <<'PY'
import json
import os
import re
import stat
from pathlib import Path
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

opener = build_opener(ProxyHandler({}), NoRedirects())
for label, port, endpoint, credential in (
    ('Incidents', 8515, '/api/v1/stats', 'incident-read.token'),
    ('Attestation', 8505, '/api/v1/verify', 'runtime-attestor.token'),
    ('Integrity', 8510, '/api/v1/status', 'integrity-monitor.token'),
):
    path = Path('/var/lib/secure-ai/credentials') / credential
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise SystemExit('Unsafe credential source: ' + credential)
        raw_token = os.read(fd, 66)
        if len(raw_token) != metadata.st_size or len(raw_token) not in (64, 65):
            raise SystemExit('Invalid credential size: ' + credential)
        token = raw_token.decode('ascii').removesuffix('\n')
        if not re.fullmatch('[0-9a-f]{64}', token):
            raise SystemExit('Invalid credential source: ' + credential)
    finally:
        os.close(fd)
    request = Request('http://127.0.0.1:' + str(port) + endpoint,
                      headers={'Authorization': 'Bearer ' + token})
    with opener.open(request, timeout=5) as response:
        raw = response.read(1048577)
        if len(raw) > 1048576:
            raise SystemExit('Status response exceeds limit')
        print(label + ':')
        print(json.dumps(json.loads(raw), indent=2))
PY
```

These reads use the installed scoped credentials without placing their values
in shell history or process arguments. Review the returned status and incident
details locally; a reachable endpoint is not a passing security decision.

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

Active `full`, `config`, `logs`, and `keys` restore commands are currently gated.
The durable maintenance transaction, producer import/export adapters, historical
verification/enrollment, and rotation reconciliation must qualify before these
commands can publish active state. Inspection and inert export do not establish
complete recoverability. See [the archive foundation and synthetic rehearsal](backup-foundation.md).

Version 2 is explicitly a **legacy partial selection**, including when its
category is named `full`. It omits user documents, outputs, model bytes, and much
durable state; its sources are not quiesced. The registry manifest alone does
not establish that every model can be recovered. `/keys` contains device-bound
material in current native provisioning; no blanket product-signing-key claim
is made. Its LUKS header is a separate sensitive artifact, not a copy of the vault.

Legacy creation requires an explicit partial acknowledgement and a native age
recipient. Replace the recipient, identity path, and exact artifact name below
with the values from the separately held recovery kit:

```bash
sudo secai-backup.sh config --legacy-partial --recipient age1... --output /media/usb/backups
sudo secai-backup.sh verify /media/usb/backups/EXACT-ARTIFACT.tar.gz.age --identity /private/recovery.identity
sudo secai-restore.sh inspect /media/usb/backups/EXACT-ARTIFACT.tar.gz.age --identity /private/recovery.identity
```

The `.sha256` sidecar is checked as transport information. An independently
retained ciphertext digest can be supplied with `--trusted-sha256 HEX`; a digest
found only on the same backup medium is not an independent origin anchor.
Public-recipient age encryption proves ciphertext integrity, not which appliance
created the backup. Successful inspection does not prove freshness. The bounded
helper currently supports native unencrypted age identity files, kept private;
passphrase-encrypted identity, passphrase archive, SSH and plugin adapters are
explicitly unavailable rather than falling back to unbounded terminal decryption.

Version 3 `export-inert` includes selected data-only classes with exact logical
filenames and empty directories, encoded as object IDs. It records all installed
class dispositions and pending adapters. It remains `partial_unquiesced` and
cannot be applied to live roots. Authentication sessions, runtime secrets and
capabilities are excluded. Catalog/history/incident/audit/hardware semantics
remain unavailable pending their producer adapters.

Plaintext staging is private and bounded. The helper does not attest storage
encryption, tmpfs, quota reservation, power-loss durability, or secure erasure.
Use separately verified encrypted staging storage and account for plaintext,
ciphertext, object metadata and reserve space. No automatic backup schedule,
retention deletion, measured RPO/RTO, or complete replacement-device rehearsal is
established by this implementation. Keep the recovery identity and trusted
receipt independently of both the appliance and its writable backup medium.

The preserved LUKS repair ceremony requires the explicit restore flag, exact
block device and matching archived/current/confirmed UUID, plus no mounts,
children or holders. It is unreachable while active restore is gated. Ordinary
inspection and inert export never invoke header replacement.

## Rollback Decision Matrix

### Automatic Rollback (Greenboot)

Greenboot triggers automatic `rpm-ostree rollback` when health checks fail
after boot. The checks are defined in
`/etc/greenboot/check/required.d/01-secure-ai-health.sh`:

| Check | Failure Condition | Auto-Rollback? |
|-------|-------------------|----------------|
| nftables service | Not active | Yes |
| Required service profile | Any declared required unit fails to start within 60s | Yes |
| Registry API | `/health` unreachable after 30s | Yes |
| Registry model integrity | Authenticated `/v1/models/verify-all` fails | Yes |
| Continuous integrity | Authenticated scan is not `trusted` | Yes |
| Incident state | One or more incidents remain open | Yes |
| nftables rules | `secure_ai` table not loaded | Yes |
| Critical scripts | securectl / verify-boot-chain / canary-check missing | Yes |
| Encrypted vault | A configured vault is not mounted from its expected mapper | Yes |

The gate records at most one failure per boot in persistent root-only state.
After **2 failed boots**, it still returns failure and enters
`emergency.target`; it never marks a broken deployment healthy merely to stop
a loop. See Break-Glass Scenario 5 below.

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
sudo mount /dev/mapper/secure-ai-vault /var/lib/secure-ai/vault

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

**Context:** `update-verify.sh check` fails with signature verification errors.
The signing policy (`policy.json` or cosign public key) is corrupted.

**Diagnosis:**
```bash
cat /etc/containers/policy.json | python3 -m json.tool    # Valid JSON?
cat /etc/containers/registries.d/secai-os.yaml            # Present?
ls /etc/pki/containers/secai-cosign.pub                   # Present?
```

**Recovery:** Verify the signed release bundle, then re-run a reviewed
bootstrap script against its exact release channel and digest:
```bash
IMAGE_DIGEST="$(tr -d '\r\n' < IMAGE_DIGEST)"
sudo bash ./secai-bootstrap.sh \
  --tag release-vMAJOR.MINOR.PATCH \
  --digest "$IMAGE_DIGEST" \
  --dry-run
sudo bash ./secai-bootstrap.sh \
  --tag release-vMAJOR.MINOR.PATCH \
  --digest "$IMAGE_DIGEST"
```

See [recovery-bootstrap.md](install/recovery-bootstrap.md) for the complete
verified recovery procedure. There is no unverified transport fallback.

### Scenario 5: Greenboot Exhaustion (Max Rollbacks Reached)

**Context:** Greenboot hit `MAX_ROLLBACKS=2` across distinct boot IDs and
entered the local emergency recovery target. The health gate continues to
report failure so the broken deployment is never accepted as healthy.

**Recovery** (requires USB boot media):
1. Boot from a Fedora Silverblue USB drive (Live session, not install).
2. Mount the system partition:
   ```bash
   sudo mount /dev/sda3 /mnt    # Adjust device as needed
   ```
3. Reset the rollback counter:
   ```bash
   sudo rm -f /mnt/var/lib/secure-ai/state/greenboot-failures
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
| Model files (GGUF) | While promoted | Operator-defined | Manual review | No general quarantine expiration or automatic pruning is established |
| LUKS header backup | Indefinite | Indefinite | Manual | Critical for recovery; store offline |
| Panic audit log | 1 year | Indefinite | Not rotated | Emergency event record |

### Disk Capacity Management

When `/var/lib/secure-ai` usage exceeds thresholds (check with
`df -h /var/lib/secure-ai`):

| Usage | Action |
|-------|--------|
| > 70% | Review model, quarantine, staging, and retained job inventories; plan exact artifact removal |
| > 80% | Stop new imports/downloads, verify external archive capacity, and preserve required audit/incident evidence |
| > 90% | Stop active transfer/scan owners before reviewed cleanup; retain job inventories and incident artifacts |
| > 95% | **Critical:** Services may fail to write logs. Immediate operator intervention required |

### Model Pruning

```bash
# Inspect model storage; the registry manifest is separate from model files
du -sh /var/lib/secure-ai/vault/models/* 2>/dev/null | sort -rh

# Inspect pending and retained quarantine artifacts
ls -lh /var/lib/secure-ai/quarantine/incoming/
ls -lh /var/lib/secure-ai/quarantine/tampered/
```

An incoming file may still belong to a download or scan, and a tampered file
may be incident evidence. Record the active state of the catalog worker,
quarantine watcher, scanner, and registry before stopping the applicable
owners for maintenance. Review the durable catalog job and scanner inventories
alongside the registry manifest and incident records. Keep the required audit
chain and forensic evidence, and verify any archive before removing its source.
Remove only exact reviewed artifacts after those checks; broad wildcard deletion
can strand retained job state or destroy evidence. Automatic cleanup of started
catalog attempts is unavailable. Restart only the services that were active
before maintenance.

### Archive Procedures

Before allowing logrotate to trim old data:
1. **Export forensic bundle** (preserves incident + audit evidence with HMAC signature):
   ```bash
   sudo secai-forensic export --output forensic-$(date +%Y%m%d).json
   ```
2. **Create a log-only backup** to external media:
   ```bash
   sudo secai-backup.sh logs --legacy-partial --recipient age1... --output /media/usb/archives
   ```
3. **Verify the archive** before allowing rotation:
   ```bash
   sudo secai-backup.sh verify /media/usb/archives/EXACT-ARTIFACT.tar.gz.age --identity /private/recovery.identity
   ```
