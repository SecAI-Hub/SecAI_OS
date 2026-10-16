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
against external asynchronous activators, arbitrary root actions, or owner kills.
PID1 jobs do not inherit the advisory operation flock. Unknown external namespace
pins can still keep the mapper busy; that remains an error requiring inspection,
not proof of successful encrypted relock or global quiescence.
