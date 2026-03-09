# Vault Management

The Secure AI Appliance stores all sensitive data (models, outputs, keys,
auth state) on a LUKS-encrypted partition called the vault. The vault
auto-locks after inactivity and can be manually locked or unlocked.

---

## Check Vault Status

### Via API

```bash
curl http://127.0.0.1:8480/api/vault/status
```

Example response:

```json
{
  "state": "unlocked",
  "detail": "",
  "idle_seconds": 142,
  "last_activity": 1741444200.0
}
```

Fields:
- **state** -- `locked`, `unlocked`, or `unknown`.
- **detail** -- Reason for the last state change (e.g., `manual_lock`,
  `auto_lock_idle`, `tpm2_unseal`).
- **idle_seconds** -- Seconds since last user activity.
- **last_activity** -- Unix timestamp of last activity.

### Via Web UI

Open the **Security** tab in the Web UI. The vault status is shown at the
top with a lock/unlock indicator and the idle timer.

---

## Lock the Vault Manually

### Via API

```bash
curl -X POST http://127.0.0.1:8480/api/vault/lock \
  -H "Authorization: Bearer <session-token>" \
  -H "X-CSRF-Token: <csrf-token>"
```

This will:
1. Stop all AI services (inference, diffusion).
2. Sync filesystem buffers.
3. Unmount `/var/lib/secure-ai`.
4. Close the LUKS device (`cryptsetup close secure-ai-vault`).
5. Update the vault state file to `locked`.

Response on success:

```json
{
  "success": true,
  "state": "locked"
}
```

### Via Web UI

1. Go to the **Security** tab.
2. Click **Lock Vault**.
3. Confirm the action. The UI will show a "Vault Locked" state and all
   AI features will be unavailable until unlocked.

### What Gets Locked

When the vault locks:
- All model files become inaccessible (they are on the encrypted partition).
- Inference and diffusion services stop.
- The Web UI remains accessible (it runs from the immutable OS partition)
  but can only show the unlock form.
- Auth state remains in memory briefly but the session is invalidated.
- Outputs, logs, and keys on the vault are inaccessible.

---

## Unlock the Vault

### Via API

```bash
curl -X POST http://127.0.0.1:8480/api/vault/unlock \
  -H "Content-Type: application/json" \
  -d '{"passphrase": "your-luks-passphrase"}'
```

This will:
1. Open the LUKS device with the provided passphrase
   (`cryptsetup open <partition> secure-ai-vault`).
2. Mount the vault at `/var/lib/secure-ai`.
3. Reset the activity timer.
4. Restart AI services (inference, diffusion, UI).
5. Update the vault state to `unlocked`.

Response on success:

```json
{
  "success": true,
  "state": "unlocked"
}
```

Response on wrong passphrase:

```json
{
  "success": false,
  "error": "incorrect passphrase or device error"
}
```

### Via Web UI

When the vault is locked, the UI shows an unlock form:

1. Enter the LUKS passphrase.
2. Click **Unlock**.
3. Wait for services to restart (10-30 seconds).
4. The UI returns to normal operation.

### TPM2 Auto-Unlock (at Boot)

If Secure Boot and TPM2 are configured, the vault key is sealed to
TPM2 PCR values. At boot:
- If the boot chain is intact (firmware, kernel, bootloader, secure boot
  state match the sealed PCR values), the TPM2 unseals the key automatically.
- If any PCR value has changed (e.g., after a kernel update), the TPM2
  refuses to unseal and the user must enter the passphrase manually.

---

## Keep the Vault Alive During Long Tasks

The vault auto-locks after `vault.auto_lock_timeout` minutes of inactivity
(default: 30 minutes). During long inference runs, you may want to prevent
auto-lock.

### Via API

Send a keepalive request to reset the idle timer:

```bash
curl -X POST http://127.0.0.1:8480/api/vault/keepalive \
  -H "Authorization: Bearer <session-token>" \
  -H "X-CSRF-Token: <csrf-token>"
```

Response:

```json
{
  "success": true
}
```

### Via Web UI

The Web UI automatically sends keepalive requests while you are actively
using it. If you leave the tab open but inactive, the vault will eventually
auto-lock.

The **Security** tab shows the idle timer and has a **Keep Alive** button
for manual reset.

### Scripted Keepalive

For automated workloads, send periodic keepalives:

```bash
# Send a keepalive every 10 minutes
while true; do
  curl -s -X POST http://127.0.0.1:8480/api/vault/keepalive \
    -H "Authorization: Bearer $TOKEN" \
    -H "X-CSRF-Token: $CSRF"
  sleep 600
done
```

---

## Auto-Lock Behavior

The vault watchdog checks for inactivity every `vault.check_interval` seconds
(default: 30 seconds). When the idle time exceeds `vault.auto_lock_timeout`
minutes:

1. A warning is logged.
2. AI services are stopped.
3. The vault is unmounted and the LUKS device is closed.
4. The vault state is set to `locked` with detail `auto_lock_idle`.
5. A `vault_auto_locked` audit entry is written.

To change the auto-lock timeout, edit `appliance.yaml`:

```yaml
vault:
  auto_lock_timeout: 60  # lock after 60 minutes of inactivity
  check_interval: 30     # check every 30 seconds
```

To disable auto-lock entirely (not recommended):

```yaml
vault:
  auto_lock_timeout: 0
```

---

## Configuring Auth Timeout

Independent of the vault lock, the authentication session also has a timeout.
After `auth.session_timeout` minutes of inactivity, the user must log in
again (but the vault stays unlocked if the timeout has not passed).

```yaml
auth:
  session_timeout: 30       # re-authenticate after 30 min idle
  max_failed_attempts: 5    # lock out after 5 failed attempts
  lockout_duration: 60      # initial lockout: 60 seconds
  escalated_lockout: 900    # escalated lockout: 15 minutes
```
