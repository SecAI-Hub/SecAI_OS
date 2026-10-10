# Durable audit storage and recovery

The airlock service requires a pre-existing audit directory and an absolute
`AUDIT_LOG_PATH` (default `/var/lib/secure-ai/logs/airlock-audit.jsonl`).
It opens a regular, single-link, mode-0600 file owned by its effective UID,
without following the final symlink, takes an exclusive nonblocking flock, and
validates the complete existing stream before serving requests. Parent symlinks
are rejected. The immediate directory must belong to root or the service UID;
a directory writable by other identities must have the sticky bit. Production
uses the existing root-owned 3770 `secure-ai-logs` directory and the stable
`secure-ai-airlock` account. The service creates a missing file; it never
repairs or changes an existing file's permissions or ownership.

Records are version-1 JSON objects with consecutive sequence numbers, timestamps,
event names and minimized data. This is **structured JSONL, not an authenticated
chain**. Digests bind request/policy fields without storing raw subjects, URLs,
query strings, bodies, header credentials or dynamic reason text. Hashes can
still reveal equality and permit guessing of low-entropy inputs. The stream
has an 8192-byte record bound and a 64 MiB total bound. Every accepted append
must complete a full write, file fsync and parent-directory fsync. Startup syncs
existing storage and durably records startup. Inode, mode, link count, owner,
size, modification/change time and immediate parent identity are rechecked.
These checks assume the service UID and root are trusted; they do not protect
against a malicious process with the same UID or a hostile storage/kernel.

An open/validation/sync/startup-write failure prevents listening. Runtime
write, short-write, sync, exhaustion or path-drift failures latch audit readiness
false for the process lifetime. `/health` then returns 503. A reload cannot clear
the latch or publish a new policy without its durable policy record. Denials
remain available and report `evidence_available:false`; new allows require
accepted durable evidence. A restart revalidates and syncs the entire stream;
it cannot repair an incomplete tail, reset sequences or adopt a malformed file.
A valid complete stream can reopen after an operator resolves a transient fault.

## Upgrade and recovery procedure

1. Stop the service before changing files, identity or ownership. Preserve an
   access-controlled byte-for-byte copy of its audit stream, directory metadata,
   any containment state, and the separate verifier enrollment/checkpoint state.
   Record source hashes and the tested service binary. Keep the previous binary
   and its matching files together for rollback. Do not downgrade against a new
   format or silently use mismatched verifier enrollment.
2. Review the reason for failure. Existing unversioned or mode-0640 logs from
   the earlier best-effort writer are intentionally rejected. This change does
   **not** supply or automatically perform a history conversion, permission
   migration, tail truncation, rotation, or verifier re-enrollment. Preserve the
   old evidence and obtain an explicitly reviewed offline conversion/ownership
   and continuity plan before upgrading an existing installation.
3. For an already valid version-1 stream, correct storage availability or the
   reviewed ownership/path issue while stopped. Restore the original intact
   evidence and its matching verifier state where that is the approved recovery.
   A rename/replacement/truncation can invalidate the verifier's independent
   inode/prefix enrollment even when this service can parse the resulting file.
   Do not delete or reset that enrollment to make a check pass.
4. Restart only after reviewing the preserved evidence and continuity outcome.
   Confirm `/health` is 200, a synthetic authenticated request records durable
   evidence, and the independent verifier still reports its actual assurance
   level. Keep failed/interrupted records in the recovery evidence, including
   whether an outbound action may already have happened.

Automatic rotation and bounded-retention continuity, authenticated chaining,
external rollback anchors, crash/power-loss storage behavior and installed
Fedora/systemd/Landlock/seccomp qualification remain open. At 64 MiB the service
fails closed; budget disk space and arrange reviewed offline rotation before
reaching that limit. Passing these tests does not certify production readiness.

## Fetch and containment semantics

Each HTTP transport attempt, including redirects, requires a durable
`fetch-intent` before DNS/dial. The intent identifies a request and hashes its
destination, method and the immutable policy snapshot. Headers/outcomes and a
bounded final forwarded-byte count are recorded separately. A transport error
is classified as possibly sent, because a remote side effect cannot be undone
by losing its response. The HTTP transport's internal retries are covered by
the encompassing attempt intent; they are not separately counted as socket
attempts. There is no exactly-once or cross-request idempotency claim.

If evidence fails before any attempt, no upstream call occurs. If it fails after
an attempt, the service reports evidence unavailable and may already have sent
bytes. If final audit sync fails after response headers/body were streamed, the
HTTP status cannot be changed: the `X-SecAI-Audit-Available: false` trailer and
subsequent failed readiness disclose the lost completion evidence. Existing
streams are not retrospectively cancelled by another request's audit failure.

Containment engages the in-memory restriction before state persistence/auditing.
The response independently reports `status:disabled`, `persisted`, and
`evidence_available`. An audit failure never rolls back the restriction. Failed
containment persistence returns HTTP 500 with the in-memory restriction still
active; it is not a claim of durability across restart. A persisted restriction
survives policy reload and restart. In-flight requests are not a claim of
instantaneous kernel network revocation. No real containment state is migrated
by this change.
