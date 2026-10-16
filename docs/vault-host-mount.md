# Runtime host vault mount control

Runtime lock/unlock asks PID1 to start/stop only
`var-lib-secure\x2dai-vault.mount`. The installed contract requires
`What=/dev/mapper/secure-ai-vault`, `Where=/var/lib/secure-ai/vault`, `Type=ext4`,
`SourcePath=/etc/fstab` and the normal `/run/systemd/generator/` fragment. Options
must include `nodev,nosuid,noexec` and cannot contain their unsafe opposites or
bind/remount/move operations; kernel option serialization is not assumed stable.
Missing configuration permits an absent/unconfigured state, never mounting an
archive-selected source or falling back to a direct mount command.

The watchdog keeps its filesystem and process hardening. Only its explicit vault
`ReadWritePaths` exception is removed. A service started before the vault mount
could otherwise retain a plaintext-directory bind and observe multiple target
mount rows after a host mount. Sandbox-local `findmnt` is no longer the authority
for host presence. PID1 must report jobless `active/mounted` or `inactive/dead`
with no control process. Unlock also runs the existing exact vault verifier afresh
and rechecks host state; a cached active oneshot is not verification.

Before unmount, fixed consumers are stopped and checked for no jobs/main process
and empty independently pinned cgroup subtrees, including surviving descendants.
Their private model/document/output binds can otherwise outlive host unmount.
The code rechecks consumers and host absence before mapper close, reports busy
mapper failures, and never uses forced/lazy unmount or forced mapper closure.

Normal request failure/timeout does not imply a PID1 job was cancelled. The helper
reconfirms each observed job ID against its fixed unit before cancellation, then
waits for job/control-process settling. Failed unlock stops/drains consumers and
the mount before closing a mapper opened by that unlock. Unconfirmed cleanup
retains the mapper and reports failure rather than claiming locked/unlocked.
Requests/draining use finite logical deadlines; an in-flight manager RPC may
overrun the remaining phase budget by its existing call timeout.

The development-host synthetic qualification uses private tmpfs/transient units,
an actual consumer/cgroup, and a queued-job timeout/cancel. It demonstrates the
changed helper's PID1 protocol and namespace behavior there. It substitutes the
transient metadata contract and does not qualify production Fedora's generated
unit, LUKS closure, SELinux, GPU/model processes, or hardware.

A separate guarded 64 MiB RAM-file fixture exercised an owned loop device,
LUKS2 mapper and ext4 mount through PID1 on the development host. PID1 preserved
the friendly `/dev/mapper/` source while its canonical path identified the same
virtual block device. Mount-job draining, mapper closure and loop detachment
completed before the key and backing file were removed. This supports keeping
the strict mapper-name contract; Fedora and physical-appliance qualification
remain required.

There is no persistent boot/producer admission policy in this change. Runtime
checks reject observed reactivation, but do not provide a race-free global fence
against external asynchronous activators or arbitrary root actions. An owner kill
can still leave work running until the next cooperating reconciliation.
PID1 jobs do not inherit the advisory operation flock. Unknown external namespace
pins can still keep the mapper busy; that remains an error requiring inspection,
not proof of successful encrypted relock or global quiescence.


## Interrupted runtime operations in the same boot

Before runtime lock/unlock first changes consumers, the mapper or the mount, the
watchdog atomically commits a non-secret `pending_operation` in the existing
`/run/secure-ai/vault-state` JSON record, syncing its file and parent directory.
The version-1 marker contains only the current kernel boot UUID, a generated
operation UUID, and the fixed action `lock` or `unlock`. It contains no passphrase,
device, path, unit or command. Error/status updates preserve the marker and cannot
advertise a completed locked/unlocked state. Only verified terminal completion
removes it; failed cleanup retains it, including when the mount is already absent.
A post-rename state sync failure reports failure, not rollback of that publication.

Under the existing operation flock, startup and every observation iteration check
for pending work before adopting a mount/status. A valid current-boot marker
requests the existing fixed consumer-drain/relock path, not replay of stored
commands. Unconfirmed cleanup leaves an error and pending marker for retry.
Explicit trusted manual unlock first settles an interrupted operation under the
same held flock, then performs the new requested unlock. It cannot skip cleanup
through the already-mounted shortcut.

Malformed, duplicate-key, oversized, unsupported-version and other-boot records
fail closed and require trusted local inspection; they are not silently cleared or
used as boot authorization. The daemon retains `ProcSubset=pid` and reads the
kernel boot UUID through its fixed read-only bind at
`/run/secure-ai-vault-boot-id`; console commands can read the normal proc path.
Available nonempty sources must agree; the zero-byte secondary target placeholder
left in the host namespace is unavailable, while the original kernel source stays
strict. Missing/empty tmpfiles records and legacy unmarked runtime status retain
ordinary fresh-boot/TPM mount adoption. No marker can identify an interruption
that occurred before this protocol was installed or after a root operator removed
its state.

This is runtime same-boot reconciliation, not persistent boot recovery, a change
to setup/TPM operation intent, producer admission or global fencing. It cannot
prevent a killed owner from leaving a PID1 job; it ensures cooperating observers
attempt fixed cleanup before claiming completion. Unknown external jobs, root
changes and namespace pins remain outside this guarantee. Tests simulate owner
loss and devices/jobs; no native Fedora LUKS/MAC or power-loss qualification is
claimed by those tests.
