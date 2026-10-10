# Incident storage and GPU policy upgrade

The production remediation changes incident records from partial, unauthenticated checksums to versioned HMACs covering evidence, lifecycle and containment results. New installations need no history migration. Preserve the existing forensic HMAC credential with the incident history and recovery state; changing that key without a planned migration prevents old records from authenticating.

An existing legacy history is refused at startup rather than silently treated as trusted. The old checksum did not protect evidence or lifecycle fields, so a program cannot establish their historical authenticity. An operator must independently review that history before migration.

For an existing appliance, enter an authorized maintenance window, stop `secure-ai-incident-recorder.service`, and preserve a verified backup of the original incident history, recovery requirements and signing credential. Review the records and containment/recovery state against independent evidence. Use the new binary's offline conversion command, with flags before any positional arguments:

```text
incident-recorder migrate-history -in /path/to/reviewed-legacy.jsonl -out /path/to/new-authenticated.jsonl -key /path/to/existing-forensic-key -acknowledge-reviewed-history
```

The output must not already exist. Conversion validates the old checksums, signs the full reviewed records, syncs the output and preserves the original. Install the reviewed output as the configured incident store using its existing service ownership and restricted permissions. Restart the service and confirm health, authenticated history loading and pending recovery requirements. Retain the original backup; conversion is not proof that previously unauthenticated data was never modified. If independent review cannot establish trust, preserve the files for investigation and keep the appliance in recovery mode.

Storage or audit errors now produce HTTP 503 and a degraded health state. Emergency containment may still have executed even when the report cannot be durably acknowledged. Inspect the incident and recovery state before retrying a privileged workflow. Restore storage, preserve evidence and restart under supervision after resolving a latched storage fault. Capacity exhaustion never silently deletes an unresolved incident. Forensic exports explicitly identify their bounded audit-tail scope and fail if evidence cannot be read.

GPU monitoring credentials cannot enroll a baseline over HTTP. Enrollment must occur offline against independently approved model/driver evidence; existing model-file capture alone is not proof of approval. Live partial profile reload is disabled. Apply changes to probe cadence, weights and action destinations together through a supervised service restart. Missing required probes remain unknown, and every confirmed model change is a failure even when most other probes pass.

GPU shutdown HTTP responses are acknowledgments, not proof of termination. Verified containment remains the responsibility of the authenticated incident/containment path. Real appliance restart, storage-failure and hardware containment drills remain release qualification requirements.
