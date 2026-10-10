# Python advisory coverage contract

`.github/scripts/audit-python-deps.py` audits every entry selected from the
committed CI, Windows qualification, service, application and diffusion locks.
The gate validates exact package/version coverage before reporting success or
applying vulnerability waivers. A resolver's clean result is insufficient: the
previous resolving path omitted pip, setuptools, wheel and packaging from the
CI lock despite a successful exit.

Each artifact requirement must have a SHA256 hash and one exact version.
Unpinned requirements, wildcard versions, extras, URL requirements, recursive
requirements files, unsupported options and duplicate selected package names
fail. Artifact index/find-links lines are recognized but never sent to the
advisory tool. Actual locks and hashes remain unchanged.

Markers are evaluated for the lock generator's target, not the machine running
the audit: CPython 3.12.15 on Linux x86_64 for ordinary locks, CPython 3.14.8 for
`-py314.lock`, and CPython 3.12.15 on Windows AMD64 for the Windows qualification
lock. Kernel/release/version and optional-extra markers lack a fixed value in
this contract and fail explicitly. A new target or marker requirement needs a
reviewed target definition. A lock selecting no packages fails rather than
claiming vacuous coverage. The current locks contain no environment markers;
regression fixtures exercise target selection and exclusions.

The selected pairs are written to a private temporary advisory input containing
only `name==version` lines. `pip-audit --strict --no-deps --disable-pip` queries
those pairs without resolving or installing dependencies. This advisory-only
input intentionally omits artifact hashes; real artifact installation retains
its separate `--require-hashes` contract. Temporary inputs are removed after
success, tool failure or timeout.

Only the existing reviewed diffusion mappings remove PyTorch/torchvision local
version suffixes. ROCm's `triton-rocm` uses the corresponding upstream `triton`
version as an advisory proxy. Missing mappings and proxy-name collisions fail.
These proxy results do not attest backend artifact equivalence or scan native
code; the original backend wheels and their hashes remain independently pinned.

The JSON report must contain exactly one valid record per expected normalized
name and version. Missing, extra, duplicate, wrong-version, skipped or malformed
records fail. Duplicate JSON keys and non-JSON numeric constants also fail.
An empty/partial report cannot pass. Exit zero requires no vulnerability
findings; exit one requires findings; all other statuses fail. Vulnerability
records need valid, unique IDs. Existing unexpired waiver IDs apply only after
coverage and tool-status validation and cannot waive missing evidence.

The audit is an advisory database check at execution time, not proof that a
dependency has no undisclosed vulnerability. Network/tool failures are failures,
not clean results. Updating target definitions, mappings or waivers requires
review; this gate does not change dependencies automatically.
