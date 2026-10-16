# Installed vault operation exclusion

The installed watchdog's lock, unlock and individual state-reconciliation
iterations, fresh vault setup, and TPM seal/reseal/unseal/wipe use one advisory
exclusive flock on `/run/secure-ai/vault-operation.lock`. Tmpfiles provisions
the empty, root-owned `0600` regular file. The helper never creates, truncates,
repairs, replaces or unlinks it. A missing, linked, unsafe or changed lock inode
fails closed. Live-environment setup requires this installed tmpfiles contract
to be provisioned first.

Acquisition uses a ten-second monotonic contention deadline, including another
installed operation. Acquisition busy/error returns failure before changing the
vault or its state. A final identity check can fail after an operation has already
changed the vault/state; failure does not claim rollback. The idle watchdog retries
on its next iteration; incident relock reports
failure through its existing broker result. The existing operation/subprocess
deadlines remain unchanged. The daemon does not hold exclusion while sleeping.

Unlock failure uses the already-held internal relock path rather than acquiring
another independent flock. The fixed setup entry execs only `setup-vault.sh`;
its validated inherited descriptor 9 retains exclusion through shell failure and
signal cleanup. No arbitrary command or caller-selected lock path is accepted.
Passphrases retain their existing terminal/in-memory transport and never enter
the lock, its arguments, or lock-error output. Linux local-filesystem flock uses
a read-only descriptor, so relock's sandbox needs no new writable file bind.
Concrete mapper, mount and cryptenroll children explicitly inherit the held OFD,
so a cooperating child can retain exclusion after its Python owner terminates.
This handoff is not native proof that every external executable retains inherited
descriptors; the regression exercises a private fake mutation child.

This serializes cooperating installed helpers. It does not stop arbitrary root
mount/cryptsetup commands, generated boot units or external asynchronous manager
jobs, close producer admission, or
establish global quiescence, native recovery, or a complete maintenance interlock.
Future callers must retain and revalidate the appropriate exclusions together.
Tests use real Linux flock with private fixture paths and mocked expected UID/GID
for ordinary-user runs; no real vault devices, mounts or systemd services run.
No native mount/relock, sandbox propagation, SELinux or hardware qualification
is established by this exclusion change.
