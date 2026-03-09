# Recovering from a Failed Update

The Secure AI Appliance uses rpm-ostree (immutable OS) with Greenboot
health checks and automatic rollback. This guide covers recovery scenarios
from simple auto-rollback to full factory reset.

---

## Scenario 1: Greenboot Auto-Rollback

Greenboot runs health checks after every boot. If the post-update boot
fails the health checks, Greenboot automatically rolls back to the
previous deployment.

### How It Works

1. An update is applied via `rpm-ostree upgrade` (staged or immediate).
2. The system reboots into the new deployment.
3. Greenboot runs health checks within `health_check_timeout` seconds
   (default: 300 seconds / 5 minutes).
4. Health checks verify:
   - Core services are running (registry, tool firewall, UI).
   - The vault can be mounted.
   - The inference engine responds on its health endpoint.
   - Network firewall rules are intact.
5. If any check fails, Greenboot initiates a rollback.
6. The system reboots into the previous (known-good) deployment.
7. Maximum `max_rollback_attempts` (default: 2) rollback cycles are
   attempted before halting for manual intervention.

### Checking Rollback Status

After a rollback, check the update status:

```bash
curl http://127.0.0.1:8480/api/update/status
```

Or via the Web UI under the **Updates** tab.

Check Greenboot logs:

```bash
journalctl -u greenboot-healthcheck.service
```

Check the health check result file:

```bash
cat /var/lib/secure-ai/logs/health-check.json
```

### Viewing Deployment History

```bash
rpm-ostree status
```

This shows the current and previous deployments. The rollback deployment
will be marked as active, and the failed deployment will be listed but
not booted.

---

## Scenario 2: Manual Rollback

If the system is running but unstable after an update, you can manually
roll back without waiting for Greenboot.

### Via Web UI

1. Go to the **Updates** tab.
2. Click **Rollback**.
3. Confirm the action.
4. The system will schedule a rollback and reboot.

### Via API

```bash
curl -X POST http://127.0.0.1:8480/api/update/rollback \
  -H "Authorization: Bearer <session-token>" \
  -H "X-CSRF-Token: <csrf-token>"
```

### Via Command Line

```bash
sudo rpm-ostree rollback
sudo systemctl reboot
```

After reboot, verify the rollback:

```bash
rpm-ostree status
```

The previous deployment should now be active.

---

## Scenario 3: Re-Running First Boot After Key Wipe

If you executed a Level 2 panic (key wipe) and need to recover, the
cryptographic keys (LUKS header, cosign keys, TPM2 keys, MOK key)
have been shredded. The vault data is still on disk but cannot be
decrypted without the LUKS header backup.

### If You Have a LUKS Header Backup

1. Restore the LUKS header:

```bash
sudo cryptsetup luksHeaderRestore /dev/<vault-partition> \
  --header-backup-file /path/to/luks-header-backup
```

2. Open the vault with your passphrase:

```bash
sudo cryptsetup open /dev/<vault-partition> secure-ai-vault
sudo mount /dev/mapper/secure-ai-vault /var/lib/secure-ai
```

3. Re-run the first boot script to regenerate keys:

```bash
sudo /usr/libexec/secure-ai/firstboot.sh
```

This will:
- Generate new cosign signing keys.
- Generate a new MOK (Machine Owner Key) if Secure Boot is enabled.
- Generate a new service-to-service auth token.
- Re-seal the vault key to TPM2 PCR values.
- Set up canary files.

4. Restart all services:

```bash
sudo systemctl restart secure-ai-*.service
```

### If You Do NOT Have a LUKS Header Backup

The vault data is unrecoverable. You must perform a full reinstall:

1. Re-image the system with the SecAI OS ISO.
2. The installer will create a new LUKS partition.
3. First boot will set up all keys and services.
4. Import models fresh.

---

## Scenario 4: Factory Reset from Level 3 Panic

A Level 3 panic performs a full wipe:
- The vault is re-encrypted with a random key (data unrecoverable).
- Memory is cleared.
- Logs, registry, and auth data are deleted.
- TPM2 keys and MOK key are shredded.

After a Level 3 panic, the system is in a blank state. To recover:

1. Reboot the system.
2. The first-boot script will run automatically and:
   - Create a new LUKS partition (or re-initialize the existing one).
   - Generate new cryptographic keys.
   - Set up the passphrase.
   - Configure TPM2 sealing.
3. Access the Web UI at `http://127.0.0.1:8480`.
4. Set up a new passphrase on the login page (first-boot setup flow).
5. Import models through the catalog or manual import.

All previous data (models, outputs, chat history, logs) is permanently
lost. This is by design -- Level 3 is the "everything must go" option.

---

## Scenario 5: Boot Loop Recovery

If the system is stuck in a boot loop (Greenboot keeps failing and
rollback is exhausted):

1. Boot from the SecAI OS USB installer.
2. Mount the system partitions.
3. Check the Greenboot failure logs:

```bash
mount /dev/<root-partition> /mnt
cat /mnt/var/log/journal/*/system.journal  # binary, use journalctl
journalctl --root=/mnt -u greenboot-healthcheck.service
```

4. If the issue is a bad update, manually pin the previous deployment:

```bash
chroot /mnt rpm-ostree rollback
```

5. Unmount and reboot.

If the root filesystem is corrupted beyond repair:

1. Re-image from USB.
2. If the vault partition is intact, mount it after reinstall to recover
   models and outputs.

---

## Preventive Measures

### Enable Staged Updates

In `appliance.yaml`:

```yaml
updates:
  staged_updates: true
```

With staged updates, the system downloads and prepares the update but
does not apply it until you explicitly confirm via the UI or API. This
gives you a chance to review before rebooting.

### Enable Cosign Verification

```yaml
updates:
  cosign_verify: true
```

This verifies the update's cryptographic signature before applying,
preventing tampered or unsigned updates from being installed.

### Keep LUKS Header Backups

After initial setup, back up your LUKS header to a secure offline location:

```bash
sudo cryptsetup luksHeaderBackup /dev/<vault-partition> \
  --header-backup-file /media/usb/luks-header-backup
```

Store this backup securely. Anyone with the backup and your passphrase
can decrypt the vault.
