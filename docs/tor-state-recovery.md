# Tor identity and existing state

The native Tor service uses the dedicated `secure-ai-tor` account and primary
group. The network controller matches that primary socket group. Fresh state
is created at `/var/lib/secure-ai/tor`, owned by that account and group with mode
0700. Systemd retains the service's private namespaces, filesystem restrictions,
0077 umask and IPC cleanup. Tor retains `Sandbox 1` and `NoExec 1`.

`IsolateDestAddr` and `IsolateDestPort` are SOCKS listener flags. They separate
destinations; they do not authenticate local callers or promise a fresh circuit
for each query. The loopback SOCKS policy permits local clients.

An upgrade does not recursively change ownership or discard Tor state. The
tmpfiles `d` entry updates the top-level directory only. State left by an older
UID can therefore keep Tor unavailable until an operator completes an offline
ownership recovery. Do not delete the directory, regenerate its contents, or
run a recursive chown while Tor is running.

For an existing installation:

1. Stop `secure-ai-tor.service`, close networking with the native network
   controller, and verify that Tor has no remaining process and that networking
   reports a verified offline scope. Keep the service stopped throughout recovery.
2. Preserve the existing directory and its metadata in the site's approved
   protected backup. Treat Tor state as private data; do not paste its contents
   into a terminal transcript or an incident report. Check available space and
   the backup's integrity before changing ownership.
3. Inventory the state on its original filesystem. Record each path, numeric
   UID/GID, mode, inode, link count and file digest. Stop for mount crossings,
   symlinks, hard links, special files, unexpected owners or a concurrent change.
   Establish the former service UID from installation records rather than
   assuming a historical dynamic UID still identifies Tor.
4. Create/verify the packaged static account with `systemd-sysusers`, then
   verify `id secure-ai-tor` and the packaged primary group. Review a finite list
   of the old account's Tor-state entries. While still offline, change ownership
   of only those reviewed entries to the new account and group, without following
   links. Set the top-level directory to 0700; retain existing private file modes.
   Preserve the original bytes and record every metadata change. Do not use a
   recursive live ownership operation or reset the data directory.
5. Restore the package's SELinux labels for the reviewed Tor paths and inspect
   them. Investigate any AVC denial; do not switch SELinux to permissive mode or
   install a broad local allow policy to make startup succeed.
6. Validate the packaged torrc as the service account. Note that Tor's
   `--verify-config` can adjust data-directory permissions; perform it after the
   backup and ownership review. Start the actual service while networking remains
   closed, and verify its primary group, private state, journal and SELinux status.
   Grant an explicit research lease only after the native checks pass.

If validation fails, keep Tor stopped and networking closed. Preserve the failed
state and diagnostics. Restore the reviewed prior ownership metadata only under
the site's rollback procedure; do not silently replace private state from a
different installation. A fresh VM startup test does not qualify an existing
device's state migration or a public Tor circuit.
