# SecAI OS — Security Hardening Roadmap

This roadmap covers 13 milestones (M12–M24) that harden SecAI OS beyond the
current baseline. Each milestone is self-contained and can be implemented
independently, though the suggested order minimizes rework.

**Guiding principle:** No metadata is attached to produced outputs (images, text,
etc.) unless it is strictly required for verifying the output came from a
legitimate, non-poisoned model. User-facing outputs are clean and metadata-free.

---

## Current State (as of M11)

| Area | Status |
|---|---|
| Model hash at promotion | Done — SHA256 stored in registry manifest |
| On-demand hash verify | Done — `/v1/model/verify` endpoint + UI button |
| Continuous model monitoring | **Not implemented** — no periodic checks |
| Audit log tamper detection | **Not implemented** — plain text logs |
| Output integrity verification | **Not implemented** — no pre-inference model check |
| UI authentication | **Not implemented** — open localhost |
| Vault auto-lock | **Not implemented** — LUKS stays unlocked |
| Process sandboxing (advanced) | **Partial** — systemd basics, no seccomp/Landlock |
| Secure boot chain | **Not implemented** |
| Memory protection | **Not implemented** |
| Network traffic analysis protection | **Not implemented** |
| Canary/tripwire system | **Not implemented** |
| Differential privacy for search | **Not implemented** |
| Emergency wipe | **Not implemented** |
| Update verification + rollback | **Not implemented** |
| Clipboard isolation | **Not implemented** |

---

## Phase 1: Foundation Hardening (M12–M15)

These milestones close the most critical gaps.

### M12 — Continuous Model Integrity Monitor

**Problem:** Model hashes are only checked on-demand. A tampered model could
serve poisoned outputs for hours/days before anyone clicks "Verify".

**Implementation:**
- New systemd timer: `secure-ai-integrity.timer`
  - Runs every **15 minutes** by default (configurable in appliance.yaml)
  - Calls `secure-ai-integrity.service` (oneshot)
- Integrity service (`/usr/libexec/secure-ai/integrity-check.sh`):
  - Iterates all models in registry manifest
  - Re-computes SHA256, compares to stored hash
  - On mismatch: logs CRITICAL alert, quarantines the model (moves to
    `/var/lib/secure-ai/quarantine/tampered/`), removes from manifest,
    kills any running inference using that model
  - Writes check results to `/var/lib/secure-ai/logs/integrity.jsonl`
- Registry API additions:
  - `GET /v1/models/verify-all` — triggers immediate full verification
  - `GET /v1/integrity/status` — returns last check time, results, next scheduled
- UI additions:
  - Integrity status indicator on dashboard (green/red)
  - Alert banner if any model failed verification
  - Manual "Verify All Now" button
- **Monitoring frequency defaults:**
  - Model hashes: every 15 minutes
  - Can be set to 5/15/30/60 min in appliance.yaml under `monitoring.integrity_interval`

**Output integrity (pre-inference check):**
- Before loading any model for inference, the inference worker verifies the
  model's hash against the registry manifest
- If hash doesn't match, inference is refused and the model is flagged
- This ensures every output comes from a verified, non-tampered model
- No metadata is added to the output itself — the verification is internal only

### M13 — Audit Log Integrity (Hash-Chained Logs)

**Problem:** Audit logs can be silently modified or deleted.

**Implementation:**
- Hash-chained append-only log format:
  - Each log entry includes: timestamp, event, data, `prev_hash` (SHA256 of
    previous entry), `entry_hash` (SHA256 of current entry including prev_hash)
  - First entry uses a genesis hash derived from the system's cosign public key
- New Python module: `services/common/audit_chain.py`
  - `append(event, data)` — writes hash-chained entry
  - `verify_chain(log_path)` — walks the chain, returns first broken link or OK
  - `export_signed(log_path)` — exports log with cosign signature
- All services updated to use chained audit logging:
  - Quarantine, registry, tool-firewall, airlock, search-mediator, inference, diffusion
- Periodic verification:
  - systemd timer: `secure-ai-audit-verify.timer` — runs every **30 minutes**
  - Verifies all audit chains are intact
  - On break: CRITICAL alert, snapshot the broken log, start new chain
- Log rotation:
  - When a log file exceeds 50MB, it's signed (cosign) and rotated
  - Signed archives are read-only (chmod 444)
- UI: audit log viewer with chain verification status

### M14 — Web UI Authentication

**Problem:** Anyone with localhost access can control the entire system.

**Implementation:**
- Local passphrase authentication (no external auth server):
  - On first boot, user sets a UI passphrase (stored as argon2id hash)
  - Login page with passphrase input
  - Session tokens (32-byte random, HttpOnly, Secure, SameSite=Strict)
  - Session timeout: 30 minutes idle (configurable)
- Rate limiting:
  - 5 failed attempts -> 60 second lockout
  - 15 failed attempts -> 15 minute lockout
  - Logged as security events in audit chain
- API authentication:
  - All `/api/*` endpoints require valid session
  - `/health` endpoints exempt (no sensitive data)
- Optional: TOTP second factor (stretch goal, not required for M14)
- Password change via Settings page
- Force re-auth for destructive operations (model deletion, GPU toggle, vault operations)

### M15 — Vault Auto-Lock

**Problem:** LUKS vault stays decrypted indefinitely after boot.

**Implementation:**
- Idle detection daemon: `secure-ai-vault-watchdog.service`
  - Monitors last activity timestamp (updated on any API call, UI interaction,
    inference request)
  - Default lock timeout: **30 minutes** of inactivity (configurable)
  - On timeout: unmounts vault, closes LUKS, kills inference/diffusion workers
  - Re-opening requires passphrase entry via UI or console
- Activity tracker:
  - Lightweight — writes timestamp to `/run/secure-ai/last-activity`
  - Updated by UI middleware, inference worker, diffusion worker
- Lock states:
  - `unlocked` — normal operation
  - `locked` — vault encrypted, services stopped
  - `locked-emergency` — triggered by emergency wipe (M23)
- UI changes:
  - Lock icon in header showing vault state
  - Manual "Lock Now" button
  - Unlock dialog when accessing features that need the vault
- Grace period: 60-second warning before auto-lock (dismissable)

---

## Phase 2: Deep Sandboxing (M16–M18)

### M16 — Advanced Process Isolation

**Problem:** Current systemd sandboxing covers basics but lacks syscall filtering
and fine-grained filesystem access.

**Implementation:**
- Per-service seccomp-bpf profiles:
  - Inference worker: allow ML-related syscalls (mmap, ioctl for GPU), deny
    network, deny exec
  - Diffusion worker: same as inference + image write syscalls
  - Registry: allow network (localhost only), file I/O, deny exec
  - UI: allow network (localhost), file read, deny raw device access
  - Tool-firewall: allow network, deny file write outside audit logs
- Landlock LSM policies (kernel 5.13+):
  - Each service gets a filesystem access allowlist
  - Inference: read-only on `/var/lib/secure-ai/registry/`, write to
    `/var/lib/secure-ai/vault/outputs/`
  - Registry: read-write on `/var/lib/secure-ai/registry/`
  - Quarantine: read-write on quarantine dirs, read-only on registry
- Systemd hardening additions:
  - `MemoryDenyWriteExecute=true` on services that don't need JIT
  - `SystemCallFilter=@system-service` base + per-service allowlist
  - `RestrictNamespaces=true`
  - `RestrictRealtime=true`
  - `LockPersonality=true`
- Testing: automated test that each service starts successfully under the new
  restrictions

### M17 — Secure Boot Chain + Measured Boot

**Problem:** No verification that the OS itself hasn't been tampered with before
the vault is decrypted.

**Implementation:**
- UEFI Secure Boot with custom Machine Owner Key (MOK):
  - Generate MOK during image build
  - Sign bootloader and kernel with MOK
  - Include MOK enrollment in firstboot
- TPM2 integration:
  - Seal LUKS key to PCR values (PCR 0,2,4,7 — firmware, kernel, bootloader,
    secure boot state)
  - Vault only unlocks if boot chain is intact
  - Fallback: manual passphrase if PCR mismatch (allows recovery after
    legitimate updates)
- ostree + TPM2:
  - After `rpm-ostree upgrade`, re-seal LUKS key to new PCR values
  - Pre-flight: verify cosign signature on new ostree commit before reboot
- VM considerations:
  - VMs without vTPM: warn user, fall back to passphrase-only
  - VMs with vTPM (Hyper-V Gen2, libvirt + swtpm): full measured boot

### M18 — Memory Protection

**Problem:** Inference data, vault contents, and model weights live unprotected
in RAM.

**Implementation:**
- Kernel configuration:
  - `CONFIG_INIT_ON_FREE_DEFAULT_ON=1` — zero freed pages
  - `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=1` — zero allocated pages (performance
    trade-off, optional)
  - `init_on_free=1` kernel parameter in recipe.yml
- mlock for sensitive data:
  - Vault decryption keys: mlocked immediately after use
  - Session tokens: mlocked
  - Inference context: mlocked during active inference (freed promptly after)
- AMD SEV / Intel TDX (stretch):
  - Detect at boot, log capability
  - If running in SEV-SNP/TDX-enabled VM, verify attestation
  - Not required for bare-metal (already have physical access control)
- Swap prevention:
  - Already disabled in firstboot.sh (swapoff -a)
  - Add `vm.swappiness=0` to sysctl
  - Add `zswap.enabled=0` kernel parameter
- Core dump prevention:
  - `kernel.core_pattern=|/bin/false` in sysctl
  - `fs.suid_dumpable=0`
  - `LimitCORE=0` in all service units

---

## Phase 3: Network & Privacy Hardening (M19–M21)

### M19 — Network Traffic Analysis Protection

**Problem:** Even with Tor, traffic patterns (timing, volume) can correlate
searches with the user.

**Implementation:**
- Query timing randomization:
  - Random delay of 0.5–3 seconds before sending search queries
  - Jitter on all outbound Tor connections
- Circuit management:
  - New Tor circuit per search session (already have IsolateDestAddr)
  - Add `MaxCircuitDirtiness 30` (rotate faster under active use)
- Padding:
  - Enable Tor padding (`ConnectionPadding 1` in torrc)
  - Pad search queries to fixed-size buckets (256 / 512 / 1024 bytes)
- DNS leak verification:
  - Boot-time check: attempt DNS resolution, verify it routes through Tor
  - Periodic check every 60 minutes
  - Alert if DNS is leaking
- nftables hardening:
  - Block all DNS (port 53) except through Tor
  - Block all outbound except Tor SOCKS (when search is enabled)
  - Log and alert on any blocked connection attempts

### M20 — Differential Privacy for Search Queries

**Problem:** Even after PII stripping, specific queries can be identifying.

**Implementation:**
- Query generalization:
  - Before searching the specific query, first search a broader category term
  - e.g., "treatment for rare disease X" -> first search "medical conditions",
    then the specific query
  - Creates cover traffic that makes the real query harder to isolate
- Noise injection:
  - Add 1–2 decoy searches per real search (configurable)
  - Decoy queries drawn from a curated list of common/generic topics
  - Decoy results are discarded, never shown to user or LLM
- k-anonymity check:
  - If a query is highly unique (contains rare proper nouns, specific addresses),
    warn the user before sending
  - Configurable: auto-block, warn, or allow
- Batch timing:
  - Group searches into fixed time windows (every 5 seconds)
  - Multiple queries in a window are sent together, making timing analysis harder
- All configurable in `policy.yaml` under `search.differential_privacy`

### M21 — Clipboard Isolation

**Problem:** Clipboard can leak data between the AI environment and host (especially in VMs).

**Implementation:**
- VM clipboard blocking:
  - Detect spice-vdagent, vmware-user, VBoxClient --clipboard
  - On first boot in VM: disable clipboard sharing services
  - Log warning if clipboard agent detected
- Wayland clipboard isolation (bare metal):
  - If running on Wayland, use `wl-clipboard` restrictions
  - Prevent background clipboard access by non-UI processes
- UI-level protection:
  - Copy buttons in UI that explicitly put content on clipboard (user-initiated)
  - No automatic clipboard writes
  - Optional: clipboard clear after 60 seconds (configurable)
- Systemd isolation:
  - Services other than UI get `PrivateUsers=true` (no access to user's clipboard)

---

## Phase 4: Resilience & Recovery (M22–M24)

### M22 — Canary / Tripwire System

**Problem:** No early warning if someone gains filesystem access.

**Implementation:**
- Canary file placement:
  - Place canary files in sensitive directories:
    - `/var/lib/secure-ai/vault/.canary`
    - `/var/lib/secure-ai/registry/.canary`
    - `/var/lib/secure-ai/keys/.canary`
    - `/etc/secure-ai/.canary`
  - Each canary contains a unique token + creation timestamp
  - Tokens are hashed and stored in a separate integrity database
- Monitoring:
  - `secure-ai-canary.timer` — checks every **5 minutes**
  - Checks: file exists, content unchanged, permissions unchanged, ownership unchanged
  - Also monitors: mtime on critical config files, unexpected new files in
    sensitive dirs
- On tripwire trigger:
  - CRITICAL audit log entry (hash-chained)
  - Lock vault immediately
  - Kill all inference/diffusion workers
  - UI shows security alert banner
  - Optional: configurable webhook/notification (for advanced users)
- inotify watchers (real-time):
  - inotifywait on canary files and critical configs
  - Immediate detection, doesn't wait for timer
  - Falls back to timer-based if inotify is unavailable

### M23 — Emergency Wipe

**Problem:** No way to quickly destroy sensitive data under duress.

**Implementation:**
- Panic actions (configurable severity levels):
  - **Level 1 — Lock:** Lock vault, kill workers, require re-auth (reversible)
  - **Level 2 — Wipe keys:** Delete LUKS header backup, delete cosign keys,
    lock vault (data recoverable only with passphrase)
  - **Level 3 — Full wipe:** Re-encrypt vault with random key (data
    unrecoverable), zero inference memory, delete all logs, delete registry
- Trigger methods:
  - UI: "Emergency Lock" button (Level 1), "Emergency Wipe" (Level 2/3 with
    confirmation dialog + passphrase)
  - Console: `securectl panic [level]`
  - Keyboard shortcut: configurable (default: none, must be explicitly set)
  - USB dead-man switch: optional, remove a specific USB device to trigger
    (advanced users)
- Safety:
  - Level 2 and 3 require passphrase confirmation
  - 5-second countdown with cancel option
  - Audit log of panic event (written before wipe executes)
- Post-wipe state:
  - System boots to "factory reset" state
  - First boot setup runs again
  - No residual data accessible

### M24 — Update Verification + Auto-Rollback

**Problem:** A malicious or broken update could compromise the system.

**Implementation:**
- Pre-update verification:
  - Before `rpm-ostree upgrade`: fetch cosign signature for new commit
  - Verify signature against pinned public key
  - Reject unsigned or mis-signed updates
- Health checks after update:
  - `secure-ai-health-check.service` runs on first boot after update
  - Checks: all services start, registry accessible, integrity check passes,
    firewall rules loaded
  - Timeout: 5 minutes
- Auto-rollback:
  - If health check fails: `rpm-ostree rollback` + reboot
  - Maximum 2 rollback attempts before halting with error
  - Rollback event logged in audit chain
- Staged updates:
  - Download update in background
  - Stage (don't apply) until user confirms
  - Show changelog/diff in UI
  - "Apply & Reboot" button with confirmation
- Greenboot integration:
  - Use Fedora's greenboot framework for health-check-based rollback
  - Custom health check scripts in `/etc/greenboot/check/required.d/`

---

## Monitoring Frequency Summary

| Check | Default Interval | Configurable |
|---|---|---|
| Model integrity (hash verify) | Every 15 minutes | `monitoring.integrity_interval` |
| Audit log chain verification | Every 30 minutes | `monitoring.audit_interval` |
| Canary/tripwire check | Every 5 minutes | `monitoring.canary_interval` |
| DNS leak check | Every 60 minutes | `monitoring.dns_check_interval` |
| Vault idle auto-lock | 30 min inactivity | `vault.lock_timeout` |
| inotify canary (real-time) | Continuous | Always on |
| Post-update health check | On boot after update | N/A |

---

## Implementation Order (Suggested)

```
M12  Continuous Model Integrity Monitor     ← closes biggest gap
M13  Audit Log Integrity (Hash Chains)      ← needed by everything after
M14  Web UI Authentication                  ← gate before adding more features
M15  Vault Auto-Lock                        ← protects data at rest
 |
M16  Advanced Process Isolation             ← deep sandbox
M17  Secure Boot Chain                      ← tamper-proof boot
M18  Memory Protection                      ← protect runtime data
 |
M19  Network Traffic Analysis Protection    ← strengthen Tor usage
M20  Differential Privacy for Search        ← privacy beyond PII stripping
M21  Clipboard Isolation                    ← close data leak vector
 |
M22  Canary / Tripwire System              ← early breach detection
M23  Emergency Wipe                         ← last resort data protection
M24  Update Verification + Rollback         ← safe update pipeline
```

Milestones within each phase can be parallelized. Cross-phase dependencies are
minimal — only M13 (audit chains) should be done before M22 (canaries use
chained logging).

---

## Configuration (appliance.yaml additions)

```yaml
monitoring:
  integrity_interval: 15    # minutes between model hash checks
  audit_interval: 30        # minutes between audit chain verification
  canary_interval: 5        # minutes between canary checks
  dns_check_interval: 60    # minutes between DNS leak checks

vault:
  lock_timeout: 30          # minutes of inactivity before auto-lock
  grace_period: 60          # seconds warning before lock

auth:
  session_timeout: 30       # minutes idle before session expires
  max_failed_attempts: 5    # before first lockout
  lockout_duration: 60      # seconds for first lockout

emergency:
  # Trigger levels: lock (1), wipe-keys (2), full-wipe (3)
  # USB dead-man switch: set to USB device serial number, or empty to disable
  usb_deadman: ""

search:
  differential_privacy:
    enabled: false
    decoy_queries: 2
    query_delay_min: 0.5    # seconds
    query_delay_max: 3.0
    warn_unique_queries: true
```
