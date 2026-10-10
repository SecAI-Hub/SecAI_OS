# Agent task history: privacy, retention and deletion

Agent history is an operational summary, separate from the signed execution authority and audit trail. Active tasks and their full successful results remain in the agent process's memory. The history file never stores raw intent, descriptions, paths/URLs, parameters, arbitrary keys, results, error text, capabilities, step signatures, credentials, or content hashes.

This metadata-only policy applies in every session mode, including sensitive sessions. The appliance's `logging.store_raw_prompts` and `logging.store_raw_responses` values must be actual booleans. They are checked at startup with safe false defaults, but setting either to true does **not** enable raw task history: general logging preferences cannot expand this separate history schema. Invalid types or an explicitly configured but unreadable/unsafe appliance configuration block saved history and degrade health. New work may continue in memory while history is unavailable.

The version-2 record whitelist contains generated task/step IDs, enum mode/status/action/risk, enum policy decisions, timestamps and bounded budget usage counters. Its schema is strict; a record with an unexpected content field is rejected rather than partially exposed. These metadata records do not prove audit authenticity and have no authority to run a task.

## Retention

Defaults are at most 500 persisted records and seven days. `AGENT_TASK_HISTORY_LIMIT` accepts an integer from 1 to 5000. `AGENT_TASK_HISTORY_TTL_SECONDS` accepts an integer from 60 to 2592000 (30 days). Invalid values do not silently fall back. Configuration is loaded at startup; changes require a service restart.

The age window starts at terminal completion, or at task creation for unfinished/recovery metadata. Active in-memory work is exempt from age/count eviction and deletion. A long-running task receives its full retention window after it finishes, so a short TTL does not immediately hide a new result. Historical expiry cannot be extended by restarting with a longer retention setting. Persisted history still has a strict count/byte bound, so it is not a durable record of every pending job.

Retention runs before history is exposed, during saves, at startup before restored records are returned, and every 60 seconds from the shipped agent entrypoint while the service runs. The service cannot physically prune files while it is stopped; expired records are removed before startup exposure. An external WSGI launcher must preserve the retention lifecycle or arrange equivalent periodic maintenance. Invalid clock values and large backward jumps degrade saved-history availability; a small backward correction cannot reduce the recorded time high-water mark. Completion before creation, completion on a nonterminal record, and timestamps later than their persisted observation are rejected. This is not protection against a privileged rollback of the system clock and all state.

The store maintains one canonical metadata file and an empty concurrency lock. It creates no backup or history index. Successful writes fsync the new file, atomically replace the canonical file and fsync its directory. Failed writes do not claim success. A process interrupted before replacement may leave a metadata-only temporary file; the next transaction removes validated version-2 temporary files under the same file lock. Unknown or legacy temporary files require explicit administrator review. Retention/deletion covers the canonical store and these managed temporary artifacts.

## Runtime API

All history and task endpoints require the existing UI task-control bearer credential. The separate incident-containment credential cannot delete history. The agent endpoint uses bearer authentication rather than browser cookies; the UI proxy must retain session authentication and CSRF protection for DELETE, approve and deny requests.

- `GET /v1/tasks` and `GET /v1/task/<id>` show current in-memory content/results when available. Restored records have `history_only:true`, `content_available:false`, empty content fields and no capability. All task responses identify `history_storage:"metadata_only"` and `history_expires_at` when established.
- `GET /v1/history/policy` reports the effective storage policy, count/age bounds, health, persistence availability, blocked-state indicator and restart behavior. `legacy_state_blocked` includes old, malformed or unsafe state and invalid privacy configuration; it indicates administrator review, not proof of a particular old schema version.
- `DELETE /v1/history/<id>` deletes a terminal record. It returns 409 for active work, 404 for an unknown record, and 503 if deletion cannot be committed. Cancellation is a separate action; deletion never cancels work.
- `DELETE /v1/history` removes terminal history and leaves active work untouched. Both DELETE endpoints accept **no body and no query parameters**. Success includes `deleted`, `active_remaining`, `external_backups_deleted:false` and `audit_evidence_deleted:false`.

History saves and deletes share a serialization boundary, so a save captured before a successful deletion cannot later restore the deleted record. Concurrent live work remains in memory. A failed deletion is not acknowledged as completed; if storage fails after a replacement, its physical outcome can be uncertain and requires a retry/review.

After a restart, unfinished tasks become `recovery_required`. Every restored task is historical metadata only, even if its prior status was completed. Approve, deny, cancel and execution entrypoints reject historical records. To do new work, submit a fresh intent and obtain a new signed capability. History is not a durable job queue or session-recovery mechanism.

## Explicit upgrade from raw version-1 history

The old format can contain raw user content under ordinary keys. The new service refuses to restore it **and refuses to overwrite it**. Merely restarting does not convert the old file. No production data migration or destructive conversion command is supplied or was executed by this change.

An administrator must review a maintenance operation that stops the agent, preserves any required old evidence in an appropriately protected location with a finite retention policy, and explicitly retires or relocates the old history file and any legacy history temporary files before starting a new metadata-only history store. The old file should not remain readable by the running service as an informal backup. Review its ownership, encrypted backup coverage and copies. Do not move or delete the agent's containment latch, credential material, audit logs or unrelated state along with task history.

Keep the prior software/configuration and protected old history if an approved rollback requires them, but understand that returning to the old history writer reintroduces raw-content retention. That is not a security-preserving rollback. The new service does not provide an automatic v1-to-v2 conversion, historical authorization recovery or a validated installed-appliance upgrade ceremony. No legacy records are presented to users before that privacy decision.

## Audit, exports and remaining boundaries

Deleting history does not delete the separate decision audit trail, including required task/policy/action evidence. That evidence has its own retention and authenticity requirements. The shipped `secai-backup.sh` path lists do not collect the agent task-history directory; this change adds no history export endpoint. Administrator-created archives, full filesystem images, browser downloads, copied API responses and external backups are outside these DELETE/TTL controls and need their own retention policy. A restored v2 history file is filtered by its original expiry; a restored v1/raw file is blocked.

This implementation does not claim secure erasure from SSDs, filesystem snapshots, backups, swap or RAM. Active content is kept in process memory and is not recoverable from history after restart. The service's existing process/isolation controls still require installed-system qualification. Multiple independent agent job owners, durable sessions/jobs, crash-safe resumption, external rollback anchors and broader audit/export privacy remain separate work.
