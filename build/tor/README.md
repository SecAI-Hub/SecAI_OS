# Tor source contract

`source.lock.json` pins stable Tor 0.4.9.14 and its signed SHA256 manifest to the
previously reviewed ahf signing/primary identity. The Fedora 44 signed 0.4.9.11
SRPM supplies the packaging baseline. Small unchanged auxiliaries are committed
here, then compared to native extraction from that independently verified SRPM.
The derivative spec updates the upstream version/changelog and retains the
reviewed SIG_BLOCK patch. Neither a source archive nor a built RPM is committed.

Stage with `python3 scripts/stage-tor-inputs.py --output .source-prep/tor`.
`--offline-cache DIR` requires exact cached remote inputs and never falls back to
network. The deterministic `TOR_SOURCE_MANIFEST.json` binds every staged file.
CI binds that manifest and this contract into the global source-prep manifest.

Copy the committed `build/tor` tree to `/tmp/build/tor` and staged inputs to
`/tmp/tor-source` in the image build. Run
`/tmp/files/scripts/build-current-tor.sh` with network disabled before removing
build dependencies. Missing, changed, unsigned or wrong-version inputs and any
build/check/install failure abort; distribution Tor is never a build fallback.
The native builder limits compilation to two jobs and 3300 seconds, retains the
full upstream `make check`, validates the packaged ELF/config, installs only the
local main RPM with all DNF repositories disabled, and checks the installed
NEVRA and exact ELF bytes.
The external GNU timeout is 3600 seconds, leaving 300 seconds for failure
reporting and cleanup. Both finite limits count wall time, including pauses
imposed by the owning build's resource guardian.

The installed `/usr/share/secure-ai/integrity/tor-build.json` and
`tor-build-logs/` retain source/signature/native-artifact provenance and full
compiler diagnostics. Only the owned temporary build root is removed.

The retained private Fedora 44 build passed 32 wrappers with two established
skips, package hardening and bounded native startup. Independent source review
found no demonstrated daemon memory-safety blocker in the examined warning
paths. GCC16 partial-struct object-size/LTO compatibility remains a qualification
risk; warnings are retained and are not universally declared harmless. Fresh
image ABI, native boot/systemd, hardware and Tor circuits require qualification.
Source-date macros do not assert universal RPM bit reproducibility across
changed compilers or libraries.
