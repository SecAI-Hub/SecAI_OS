# Backup archive foundation

This implementation supports bounded encrypted export, verification, and inert
staging. Complete backup and active restore remain unavailable until the durable
maintenance transaction (B), producer adapters (C), historical evidence and fresh
enrollment (D), and rotation reconciliation (R) qualify. There is no bypass flag.
The old in-memory v2 `apply_restore` function remains only for historical
synthetic regression tests; the supported CLI cannot reach it.

The internal `secure-native-writer-scope.py` library coordinates a writer set
supplied by trusted installed code. It requires durable closed admission,
masks activation before stopping, and checks both manager jobs and pinned
kernel cgroups. Deadline expiry prevents further authorization or a successful
quiescence result; an already running manager call retains its bounded timeout.
This library does not supply a complete native writer policy, install startup
hooks, reopen services, or qualify native restore. Its current tests exercise
the coordinator with manager/cgroup fixtures and preserve the existing narrow
update-check admission tests. Native activation and recovery remain gated.

Its `documents_outputs_scope` factory fixes the installed agent, diffusion and
three activation services, plus their path/timer triggers. Trusted callers must
already exclude direct diffusion installation and vault setup, unlock, relock
or mount changes; both live exclusion predicates are mandatory and rechecked
during closure. The factory does not acquire those interlocks or provide startup
and fresh-boot admission. This selected scope cannot establish global quiescence
or authorize active restore.

The internal `secure-native-generation-metadata.py` planner keeps existing
generation metadata separate from incoming metadata. Existing ownership, modes
and SELinux labels are read from pinned descriptors without changing them.
Incoming documents and outputs resolve the installed inventory, local group
IDs and enforcing SELinux target policy; archive fields cannot choose these
values. It does not install metadata or enable a native recovery backend.

Trusted calling code can explicitly pair `NativeDataGate` and the journal's
`native_classes` argument for those two classes. This uses a separate version 2
plan binding the installed target contract and fingerprints of actual ownership,
modes and SELinux labels. Incoming metadata is checked again across staging,
publication and replay; even a matching supplied fingerprint cannot waive the
local contract. Old generation metadata is preserved rather than normalized.
Default B1 gates and plans retain their existing format and reject native plans.
Private filesystem fixtures exercise commit, rollback, replay and real Linux
ownership changes. SELinux lookups and labels are simulated in these tests;
native labeling, policy stability, complete writer admission, namespace mapping
and boot recovery still require qualification. The installed restore CLI remains
unavailable.

Trusted calling code can also supply the gate's `trusted_root_rebind` callback
for a historical root mount ID. Persistent device/inode, owner, mode, stable
locks and layout bytes must still match; the callback requires explicit approval
within its deadline. The journal separately requires a changed origin boot and
backend approval for component mount IDs. Neither path rewrites layout or opens
admission before verified recovery and release. Default callers remain strict.
Tests simulate changed mount IDs and a lost runtime readiness file; actual boot,
filesystem device rebinding and native startup integration remain unqualified.

The internal `secure-native-generation-stage.py` helper prepares a private
`incoming` document or output tree using the installed metadata contract. Its
root caller must supply pinned private directories and an already authenticated,
verified logical class tree; the v3 `objects/ID` envelope is not that tree.
The helper checks bounds, source stability, copied bytes and native metadata
before a no-clobber rename. A failure reports whether publication occurred or
is unknown and retains ambiguous work. It does not bind live paths or enable
restore. Tests cover real bytes, modes and Linux ownership in private trees;
SELinux is simulated; the archive-to-class entry point described below has
synthetic coverage and still requires native qualification.

The internal `materialize_archive_incoming` entry point now maps the v3 inert
object envelope to a selected documents or outputs tree through the same private
publisher. Its caller must retain the canonical manifest digest from independent
authenticated backup verification. It checks that digest, the installed inventory,
the complete envelope's paths, private metadata and object hashes, then checks
selected bytes again while copying. Logical Unicode names, empty directories and
zero-byte files are preserved; numbered objects and the manifest are not copied
as user files. The source and active generation remain unchanged. This supplies
no origin or freshness decision, live mount binding, writer admission or restore
CLI. Tests use real synthetic v3 export/extraction and simulated native SELinux.

## Format and metadata contract

Version 3 uses `format="secure-ai-backup"`, archive version 3 and inventory
version 1. The installed `backup-inventory.json` controls logical source classes,
byte adapters and local target metadata. The archive supplies no destination,
numeric owner, executable mode, ACL, capability, SELinux label or restoration
hook. Its inventory digest must match the selected local inventory. Unknown
versions and future schemas require a reviewed adapter.

Payload names are consecutive ASCII `objects/00000001` IDs. The bounded manifest
maps them to a class and relative UTF-8 filename. Every directory, including the
class root and empty directories, has an explicit record. Accepted Unicode bytes
and spaces are preserved exactly; names are never normalized or silently renamed.
Case-fold or NFC collisions within a class are rejected conservatively, even on
a Linux filesystem that could distinguish those names.

Native component names are at most **240 UTF-8 bytes**, relative paths at most
**2048 bytes**, and paths at most **32 components**. These fixed limits leave
room for local destination prefixes. Empty/dot/traversal components, backslashes,
control/format/surrogate characters and conflicting file ancestors are rejected.
This is a native Linux contract, not a Windows or sandbox-volume adapter.

Ordinary files and directories are supported. Source hardlinks, symlinks,
special objects, executable files, setuid files/directories, file setgid/sticky
bits, ACLs and non-SELinux xattrs fail export. Source directory setgid/sticky
bits do not become archived privilege metadata. SELinux xattrs are deliberately
omitted; only the target's installed policy may assign labels. Arbitrary POSIX
metadata preservation and executable backup are outside this adapter.

The inert object envelope is always caller-owned `0600` below a private `0700`
directory. This envelope is distinct from the class target contract: documents
use `root:secure-ai-vault-read`, `2750` directories and `0640` files; outputs use
`root:secure-ai-vault-write`, `2770` directories and `0640` files; inert policy
and configuration use local `root:root`/`0755`/`0644` planning rules. No ownership
or live namespace is installed by extraction. Metadata on unsupported classes
is a source planning reference; `local_policy` refuses a target DAC mapping for
those classes. The audit adapter must separately preserve the sticky source
directory and dedicated MCP/search/DynamicUser ownership rules rather than
falling back to a shared generic log mode/group.

Each installed class is present in the manifest. A selected byte class is
`included` or a verified existing `empty` root. `not_applicable` with
`not_selected_partial_export` means explicitly outside this partial selection,
not absent or irrelevant to full recovery. `unsupported_adapter_partial_export`
records a required future semantic adapter. `excluded_authority` is explicit
regeneration/reconciliation state. `reacquire` is reserved by the inventory
schema but rejected until a producer supplies verified immutable acquisition
pins. Missing selected roots fail. Unknown branches of managed native roots
fail classification; unsupported classes are never copied by a generic fallback.

Sessions and their lock/pending markers are excluded. `/run/secure-ai*` and
delivered credentials are excluded wholesale. Historical HMAC keys are distinct
named, unsupported evidence classes; runtime bearer/signing/session credentials
are explicitly excluded. Catalog job roots require a sanitized producer export;
raw operational jobs, worker locks/readiness, pending markers and old grants are
never exported by the byte adapter. A pending marker is not successful state.

The outputs byte adapter reserves `.agent-write-*` and `.diffusion-write-*`
path components for private producer work. Export fails before payload copying
if either is present, preserving the source for reconciliation. Archive
validation and private incoming materialization reject those names as well;
unfinished or ambiguously retained work cannot become completed user output.
Ordinary hidden output names and document filenames are unaffected. This does
not supply writer quiescence or automatically recover an interrupted producer.

## Resource and source boundaries

Default ceilings are 65 GiB ciphertext, 64 GiB compressed archive, 64 GiB payload,
16 GiB per file, 50,000 combined objects/directories, 8 MiB manifest, 64 levels of
JSON nesting, 3600 seconds and a 16 MiB free-space reserve. JSON rejects duplicate
keys, nonfinite numbers including exponent overflow, boolean counts and unknown
fields. The manifest allocation estimate is checked during metadata inventory,
before file bytes are copied. Tar framing and metadata/padding bytes have a
separate expanded ceiling. Ordinary disk errors and exhausted inodes fail.

The source walk uses pinned directory descriptors and no-follow opens. A class
root is explicitly selected; nested mounts are rejected using Linux mount IDs,
including bind mounts that share a device number. The native vault boundary is
an explicitly known mount namespace. Directory names and inode/change metadata
are checked before and after copying, and file identity/change metadata is
rechecked after capture. These checks detect normal concurrent changes; they
are not producer quiescence or protection from a malicious privileged filesystem.

The parser accepts one complete gzip stream and regular tar members only. It
rejects PAX/GNU extensions, sparse/link/device entries, duplicate payloads,
malformed late headers, bad/truncated gzip trailers, concatenated gzip members,
nonzero padding and trailing tar payload. Version 2 extraction now uses this
same strict parser in one pinned pass. It validates the exact staged hashes;
it never verifies one pathname and reopens it for unchecked extraction. Failed
input or stage validation removes the inert tree rather than returning success.

Space preflights reserve known bytes and metadata conservatively, with additional
checks while age writes and objects expand. They do not reserve filesystem quota
or make free space immune to other writers. The processing deadline is checked
between bounded reads/writes; the age child also has an enforced parent deadline
and is killed and reaped on failure. Filesystem syscalls that stall in the kernel
are not a hard real-time guarantee. Full multi-filesystem rollback reserves and
crash/power-loss recovery belong to B and are not yet implemented.

## Integrity, origin and recovery keys

Age provides header and payload integrity, including the final authenticated
chunk. Its public recipient interface also permits anyone holding that public
recipient to create a different valid ciphertext. Therefore decryption and an
unsigned content manifest cannot identify the source appliance. This follows
from the [age format](https://c2sp.org/age) and the
[official recipient/identity interface](https://github.com/FiloSottile/age/blob/main/doc/age.1.ronn).

`--transport-sidecar` checks only an adjacent SHA-256 record. In contrast,
`--trusted-sha256` is the exact ciphertext digest from a recovery receipt already
held independently of the writable backup medium. The helper compares that digest
to the pinned input, and hashes the exact bounded bytes sent to age again. Input
metadata/path replacement or differing stream bytes prevents publication. The
caller is responsible for independent receipt custody; supplying an attacker
sidecar as the trusted option does not establish origin. A matching digest is
reported as `trusted_receipt_match`, with freshness still `not_established`.

Partial export emits the ciphertext, backup ID and manifest/inventory digests as
a receipt candidate. It is `created_not_restore_verified` until an authorized
identity-based decryption and content validation run. External custody and a
latest accepted receipt/sequence must be established operationally before an
origin/freshness claim. No signature tool, signing key or custom signature scheme
has been introduced. Old audit keys can forge historical evidence and must never
be installed as live service credentials.

The bounded adapter supports a native X25519 public recipient and one private,
unencrypted native age identity file. It copies that small identity into a sealed
memory descriptor passed to the child; key bytes and identity paths are absent
from argv/environment/diagnostics. Passphrase, protected-identity, SSH and plugin
adapters are explicitly unavailable. Existing archives requiring those adapters
must wait for a qualified bounded implementation. Keep the recovery identity
outside the appliance; losing it is not repaired by an archive manifest.

## Synthetic rehearsal

Use generated fixture data and an ephemeral `age-keygen` identity inside a private
temporary root. Set a private output directory and separately controlled staging
directory. The following helper commands form the supported sequence; replace
each uppercase placeholder with the exact fixture value:

```text
secure-backup-archive.py export-inert --root FIXTURE_INSTALLATION --classes user-documents,user-outputs --release-sha256 FIXTURE_RELEASE_DIGEST --inventory LOCAL_INVENTORY --staging-root PRIVATE_STAGE --recipient FIXTURE_PUBLIC_RECIPIENT --output PRIVATE_OUTPUT/export.age
secure-backup-archive.py decrypt --archive PRIVATE_OUTPUT/export.age --identity PRIVATE_FIXTURE_IDENTITY --trusted-sha256 INDEPENDENTLY_RETAINED_DIGEST --output PRIVATE_STAGE/validated.tar.gz
secure-backup-archive.py inspect-v3 --archive PRIVATE_STAGE/validated.tar.gz --inventory LOCAL_INVENTORY
secure-backup-archive.py extract-v3 --archive PRIVATE_STAGE/validated.tar.gz --inventory LOCAL_INVENTORY --destination EMPTY_PRIVATE_OBJECT_DIRECTORY
```

The declared release digest is metadata; this foundation does not attest the
source release. Plaintext-only inspect/extract cannot reconstruct the trust
decision from a preceding decrypt invocation and reports origin unverified.
Retain the decrypt result and independent receipt alongside the content check.
`extract-v3` creates an inert object store; use the manifest to associate each
object's exact bytes with its logical name. It does not populate watched intake,
model promotion, credentials, live state or vault directories.

The tests exercise real age with ephemeral keys, adversarial tar/JSON, source and
staged mutations, bounded staging and child termination. They do not establish
storage encryption, an installed service gate, hardware enrollment, a complete
replacement-device restore, an RPO/RTO or external retention/deletion behavior.
No ordinary restore command can invoke the preserved destructive LUKS ceremony
while these recovery prerequisites remain missing.
