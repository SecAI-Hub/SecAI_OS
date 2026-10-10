# Main registry eligibility and verification

The main registry's path, hash, GGUF-manifest and verify-all routes share an
enrollment gate. The loaded enrollment must remain valid and match its original
file identity and digest, and the requested record must not be blocked. A path
response also requires a matching artifact size and SHA-256 digest. Successful
containment still removes the record and moves the artifact; a blocked record is
not an alternative containment implementation.

`GET /v1/models` and `GET /v1/model` remain diagnostic views, including blocked
records needed for recovery. Their metadata does not authorize use. A caller
must check the HTTP status of a verification/path response. `securectl path`
rejects every non-200 response and missing or invalid absolute paths.

## Limits and failure responses

Two shared slots admit verification, path resolution, enrollment health and
integrity-status work. An occupied slot is retained until its actual file I/O
and verifier process finish. Each admitted operation has a 10-second deadline,
shortened by the caller's context. This fits the current CLI's 15-second and
UI hash request's 30-second timeout. Large models that cannot finish inside this
budget are unavailable through this interface; no unbounded fallback is used.

| Condition | HTTP result |
| --- | --- |
| Missing record or artifact | 404 |
| Blocked record, changed artifact/generation, hash mismatch, verification failure | 409 |
| Caller cancellation | 408 when a response can still be delivered |
| Both slots occupied | 429, `Retry-After: 1` |
| Missing, invalid or replaced enrollment; unavailable protected verifier | 503 |
| Request/work deadline | 504 |

Error responses never include `safe_to_use: "true"`. A GGUF record without a
manifest produces a skipped response with `safe_to_use: "false"`. The health
endpoint represents any unavailable enrollment check as degraded HTTP 503.

Model hashing checks cancellation between bounded reads and directory batches.
Directory work retains the existing limits of 20,000 files, 25,000 entries,
4,096-byte paths, 50 GiB per file and 64 GiB total; verify-all applies its
inventory/byte bounds across the whole request. Observed metadata/name storage
is capped at 16 MiB, enrollment/sidecar inputs at 16 MiB, and the JSON result at
1 MiB. The verifier's combined stdout/stderr is capped at 64 KiB while it is
produced, and overflow cancels the child.

Only the fixed root-owned, executable, single-link, non-symlink and
non-group/world-writable `/usr/bin/gguf-guard` is selected in production. Its
opened executable descriptor is used for launch; requests cannot select commands.
The child receives a small fixed locale/PATH environment and canonical enrolled
input paths. The guard's own loaders require regular pathname inputs and reject
`/proc/self/fd` symlinks. Cancellation targets the exact child, which is waited
and reaped; no process-name or shared process-group cleanup is used.

## Concurrency and interpretation

Verification copies enrollment metadata under the manifest lock, then releases
it before slow file reads or child execution. Containment and other safety
mutations can acquire the lock while a verifier waits. Before success, the
registry rechecks file identities, metadata stamps (including Linux ctime),
source enrollment identity/digest and in-memory generation. Cancellation is
checked again even when a completed result is simultaneously available.

These are point-in-time checks. Returning a pathname does not bind a later
consumer open to the verified inode, and pre/post checks do not exclude every
transient pathname substitution. No broader consumer TOCTOU or file-lease
guarantee is made. The current trusted native verifier does not spawn descendant
processes; this completion contract does not cover arbitrary replacement tools.

Go cannot preempt a regular-file kernel read that stalls. The HTTP operation
can time out while at most two workers remain occupied until that I/O returns.
Such workers retain their slots and do not retain a manifest read lock. Tests
simulate a stalled read without hanging the host. They do not establish a hard
kernel-I/O completion deadline or qualify arbitrarily large model latency.

Verify-all publishes a bounded complete historical snapshot by atomic rename.
After publication it rechecks artifact and enrollment identity before responding.
`GET /v1/integrity/status` accepts a snapshot only for the current enrollment
revision and rejects blocked records; the revision includes a process epoch,
so a restart invalidates previous snapshots. The `historical_verification_snapshot`
scope and timestamp describe a past scan, not current runtime authority or a
fresh hash of every file. Missing, incomplete or stale cache data yields unknown.
This cache is not a durable transaction journal or an authority restoration path.

Synthetic tests cover blocked/corrupt/missing/replaced enrollment, persistent
artifact replacement, late block/containment, cancellation, deadline, admission,
output limits, retained I/O slots, stale history and protected executable checks.
A separate 80-byte synthetic GGUF fixture exercises the actual guard's regular
input interface through the registry. Installed service sandbox compatibility
and combined appliance qualification remain separate checks.
