# Catalog jobs and sessions

The UI runtime supervises one Gunicorn master, one HTTP worker, one catalog
coordinator and at most one transfer attempt. HTTP worker recycling preserves
sessions and queued work. Multiple HTTP workers remain unsupported because the
UI audit writer has not been qualified for that configuration.

Downloads require a live session and an allowed current profile. The coordinator
checks cancellation, expiry and profile changes while the attempt runs; the
attempt checks the session, exact current catalog and profile before each Airlock
fetch and each progress chunk. Provider traffic still goes through Airlock.
Bearer tokens, credentials, URLs and response bodies are absent from job state.

## Session lifetime and revocation

The default idle timeout is 30 minutes; passive polling never refreshes it. The
default absolute ceiling is 12 hours (`SESSION_ABSOLUTE_TIMEOUT`, at most seven
days). Active authenticated cookie requests refresh the browser cookie only up
to the remaining idle and absolute lifetime. Logout and passphrase changes take
effect across HTTP workers and transfer processes after durable acceptance.
A persistence failure is an error, never a successful saved revocation.

Session, lockout and attempt lifetimes use the explicit Linux `CLOCK_BOOTTIME`
domain, including time spent suspended. The independent attempt timer uses the
same clock and an absolute deadline. It does not wake the host. Missing clock or
timer support fails closed; there is no silent fallback to an awake-only clock.
Short lock-acquisition and shutdown waits retain separate ordinary monotonic
timers. Wall-clock reversal cannot extend these authorization lifetimes.

Session state contains SHA-256 bearer digests and credential fingerprints.
Credential changes are serialized with issuance; an old KDF result cannot issue
a session after the credential generation changes. Reboot or container recreation
changes the protected runtime epoch and requires fresh authentication. A same-boot
native service restart retains that epoch when the tmpfiles directory survives.

## Durable job contract

`POST /api/catalog/download` accepts only the current pinned catalog identity and
persists admission before returning 202 and an opaque `job_id`. Repeating the same
live intent returns that job. Only a cancelled, never-started job can request retry; a different
identity under an existing filename conflicts. `GET /api/catalog/downloads`
returns minimized job phases and counters. It never extends session lifetime.

`POST /api/catalog/jobs/<id>/cancel` and `/retry` require an empty JSON object,
normal authentication and browser CSRF protection. Supported retry is limited to
a cancelled job that has never started an attempt and has no recorded objects.
It binds the current session/profile again. Started attempts require maintenance
and cannot use this retry route. Limits remain 16 active jobs, one running attempt
and 30 minutes per attempt; the persisted attempt-count validation ceiling remains 3. Admission stops at 256 total retained jobs; the loader has a
272-record ceiling and reserves 4 KiB per record within a 2 MiB snapshot. No
history is silently evicted. Existing terminal/cancellation transitions retain
logical space when admission is full. Disk errors remain possible and fail closed.
Artifact reservations retain the existing 2 GiB free-space margin and immutable
file/directory byte and file-count limits. Admission reads actual filesystem free
space, so retained partial bytes continue occupying capacity after cancellation;
no storage is reclaimed or credited through automatic cleanup.

Queued, running and verified jobs have not completed handoff. `publishing` means
verified publication intent was saved before publishing any source/manifest
sidecar. `quarantined` means the publication and directory sync completed; it
does not certify scanning, promotion or trusted runtime readiness. A missing
published artifact or interrupted publication becomes `handoff_unknown`. This
state cannot be retried automatically or cancelled into deletion. A matching
registry filename, successful resolution or missing quarantine file does not
prove the requested model outcome. Registry promotion/provenance reconciliation
is a separate boundary.

Prepublication interruption stops and reaps the attempt and records
`cleanup_required`. Partial bytes and the complete recorded inventory are retained
without pathname deletion, renaming or reclamation. Retry remains unavailable,
even after reauthentication, until a separately qualified maintenance mechanism
exists. An empty inventory after a started attempt is also conservatively treated
as cleanup-required: creation may have preceded its durable inventory record.
There is no implicit replay or range resume. Hidden staging names include both job ID and attempt number.
A crash in the small create-before-inode-record window may leave an unrecorded
empty partial. It is retained for reviewed maintenance, and a later attempt uses
a different name. Browser requests never remove suffix-matching orphan files.
Directory staging requests mode 0750 and inherits any setgid bit from its
provisioned parent; files remain 0660. The service does not explicitly set S_ISGID
on new staging directories. This is compatible with RestrictSUIDSGID and does
not grant permission for a later UID to delete retained content.

## State inventory and failure fencing

| Location | Purpose | Backup/restore treatment |
| --- | --- | --- |
| `/var/lib/secure-ai/auth/auth.json` | Sensitive portable credential material | Preserve only through approved encrypted credential handling; never publish |
| `/var/lib/secure-ai/auth/sessions.json` | Version 2 sessions, lockouts, epoch, clock domain | Exclude; never restore bearer authority |
| `/run/secure-ai-ui/session-state/epoch.json` | Version 2 runtime epoch and clock domain | Exclude all `/run` authority |
| `/var/lib/secure-ai/ui/catalog-jobs/jobs.json` | Version 2 operational queue and clock domain | Export sanitized history only after quiescence; never raw replay |
| `worker.json`, `worker.lock` in the job directory | Readiness and sole coordinator ownership | Exclude |

All three live schemas require `clock: "linux-boottime-v1"`. Experimental version1
records used an awake-only monotonic clock and are rejected, never reinterpreted
as current authority. This change performs no live migration or automatic repair.

Each bounded snapshot has a sibling `<name>.lock`, containing its device/inode
identity, and may have `<name>.pending`. Lock files must remain stable; replacing
or unlinking a lock requires recovery. Snapshot files are private regular
single-link files, mode 0660 (0600 accepted), with the containing directory's
group. Directory traversal rejects symlinks; the native 2730 runtime parent is
traversed with O_PATH and the final 2770 directory is opened for fsync.
Atomic publication temporarily creates `.<name>.<random>`. Credential publication
temporarily creates `.auth.<random>`. These are operational temporary files,
not independently valid snapshots or authority.

Before a write transaction permits credential or state mutation it creates and
syncs a `.pending` fence and its directory. It publishes and syncs the replacement
snapshot before removing and syncing the fence. A killed or failed writer leaves
a fence that both existing peers and restarted processes reject. An unexpected
exception after possible external mutation also preserves the fence. Explicit
prepublication admission conflicts and capacity refusals remove only their own
fence. A busy reader cannot remove a writer's fence.

If fence creation/sync itself fails, no subsequent mutation has been permitted;
the observing process latches unavailable. A cross-process durable failure record
cannot be promised when the device refuses the fence itself. If final fence
cleanup fails, the implementation attempts to restore the fence and latches the
observer; it does not claim that a failed device necessarily persisted that
attempt. A crash after snapshot sync and fence unlink can expose the already
committed snapshot, or leave a conservative fence after filesystem recovery.
Process-kill and injected-syscall tests do not constitute physical power-loss or
storage-controller durability certification.

Readiness (`/health`, HTTP 503 when unavailable) checks the session/job stores
and a recent coordinator heartbeat with its original held lock. The supervisor
exits when either component fails; Linux parent-death guards and bounded shutdown
stop attempts and HTTP workers. Readiness never silently initializes a corrupt
snapshot into an empty store. Inspect sanitized job state and service exit status;
raw upstream exceptions and secrets are deliberately absent from worker logs.

## Backup and recovery boundary

First stop new admission and stop/reap the supervisor, coordinator and attempt
processes at a known publication boundary. Prove that ownership is released and
no transfer can mutate the state. Preserve an evidence copy before any repair.
Do not clear `.pending` merely because JSON parses or because its timestamp is
old. Inspect whether credential replacement or artifact handoff
may already have happened. Uncertain publication requires reconciliation;
restoring old operational JSON must not authorize a redownload.

`ui.catalog_jobs.sanitized_history(snapshot)` is a pure export transformation.
The caller must establish the above quiescence itself. Output is
`{"version":1,"kind":"catalog-history","jobs":{...}}`, deliberately incompatible
with the live queue loader. It preserves job ID, filename, catalog digest,
immutable revision/content or manifest pins, size/progress, attempt count and
creation/update timestamps. Creation is a nanosecond ordering sequence; updates
are Unix seconds. Active states become historical `interrupted`; published or
ambiguous states become `handoff_unknown`. `requires_reconciliation` preserves
unresolved execution/handoff/owned-partial status. Session digests, credential and
runtime/profile generations, deadlines, cancellation controls, locks and owned
paths are omitted. There is no live-history import or replay API here.

Recovery must restore fresh authentication/runtime authority and supported
operational state through an approved recovery workflow. Automatic partial cleanup
and a qualified maintenance mechanism are currently unavailable. Do not edit live
job files or clear inventory to force retry. Unresolved retention/handoff records
and their data must not be silently discarded by backup or history maintenance.
Sanitized history alone does not back up the retained partial bytes; an approved
data inventory must preserve them or explicitly report that backup coverage is
incomplete. This implementation performs no real-state migration, credential
rotation, deployment or automatic repair and is not fully production-ready.

## Qualification limits

Synthetic tests cover concurrent admission, storage faults, crash fences,
recycling, browser sessions/CSRF, cancellation/revocation/expiry, process death,
retained bytes/inventory and capacity. Simulated suspend and backwards wall-clock cases
exercise the explicit clock domain; the host is not suspended. Native probes apply the configured syscall filter
before required Landlock and exercise nonroot shared-group DAC. Unit filters must
permit Landlock initialization; explicit syscall declarations make that dependency
auditable across systemd syscall-group versions and do not expand path rules.
The host systemd255 probe required the explicit declarations. A separate Fedora44
systemd259.8 Airlock probe started the original unit because that version's groups
already include those calls; the host result is compatibility evidence, not a
demonstrated Fedora44 startup defect. Production Fedora
systemd/SELinux boot, real storage power loss, real provider artifacts and physical
backup/restore remain separate qualification requirements.
