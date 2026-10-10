# Release source composition

This is a source and payload contract, not deployment approval or a claim that
local dirty changes have been published. Main appliance source means the exact
SecAI_OS checkout used by the build. A neighbouring helper working tree is never
an implicit input. A release must bind the reviewed checkout tree, including
uncommitted changes if any, before claiming those changes ship.

## Selected source matrix

| Component | Native image input | Sandbox input / context | Relationship to standalone helper |
|---|---|---|---|
| Airlock | `services/airlock` | Same directory, its Dockerfile | Embedded appliance implementation |
| Registry and registry CLI | `services/registry` | Same directory, its Dockerfile | Does not ship neighbouring `ai-model-registry` changes |
| Tool firewall | `services/tool-firewall` | Same directory, its Dockerfile | Does not ship neighbouring `agent-tool-firewall` changes |
| Policy engine | `services/policy-engine` | Same directory, its Dockerfile | Embedded appliance implementation |
| GPU watch, runtime attestor, integrity monitor, incident recorder | Respective `services/<name>` trees | Not in sandbox Compose | Native appliance services, no helper fallback |
| MCP firewall | `services/mcp-firewall`, verified against `UPSTREAM_SYNC.json` before Go compilation | Not in sandbox Compose | Explicit reviewed helper snapshot; base `77e3dbe2417637142989ddf45c0aa7589c4732ac` plus listed local changes |
| Quarantine watcher and scanner | `services/quarantine` installed as a local wheel | Root context, `services/quarantine/Dockerfile.sandbox`, copies embedded Python package | Does not ship neighbouring `ai-quarantine` |
| Common Python modules | `services/common` local wheel | Copied from main in each consumer Dockerfile | Includes current audit/auth/inference modules |
| Agent | `services/agent` local wheel | Root context, `services/agent/Dockerfile.sandbox` | Embedded package; no standalone source selection |
| UI | `services/ui` local wheel including templates | Root context, `services/ui/Dockerfile.sandbox`, copies package directory | Explicit package data now closes native template omission |
| Search mediator | `services/search-mediator` copied app/boundary/transport modules | Root context, its Dockerfile | Embedded appliance service |
| UI ingress | Native ingress comes from appliance packaging | `services/ui-ingress`, its Dockerfile | Sandbox Go ingress is an embedded implementation |
| GGUF Guard | Locked archive under `upstreams/gguf-guard` | No standalone GGUF Guard build in quarantine Dockerfile | Local helper HEAD matches pinned commit; its dirty compiler/CI/container metadata is not the native source archive |
| SearXNG | Locked source under `upstreams/searxng`, frozen version metadata, local installation | `deploy/sandbox/searxng`, published image plus settings/entrypoint changes | Source and published image are distinct build identities |
| Tor | Native recipe/package configuration | `deploy/sandbox/tor`, Alpine image plus repository `apk add tor` | No standalone helper |
| Inference | Verified llama.cpp source compiled locally with appliance options | Root context, `services/inference-worker/Dockerfile`, fixed published backend targets plus appliance launcher/auth preparer | Concrete native/CPU backend gap below |
| Diffusion | Embedded `services/diffusion-worker/app.py`, opt-in runtime installer and dependency locks | Root context, `services/diffusion-worker/Dockerfile.sandbox` | Optional runtime; no complete accelerator qualification implied |
| ModelScan, Fickling, ModelAudit | Hash-locked Python distribution wheels from application graph | Hash-locked quarantine requirements | Neighbouring scanner helper working trees are not installed |

The native source-selection script now accepts only embedded appliance paths for
appliance services, and only the staged locked path for GGUF Guard. Missing paths
cannot fall back to standalone helpers; reused destinations and symlink roots
fail. The previous upstream-first alternatives were **latent override paths**:
clean source prep currently downloads only GGUF Guard and SearXNG, so those
alternatives do not demonstrate that clean CI was shipping the wrong quarantine.

## Locks and handoff

`.upstreams.lock.yaml` currently has exactly two external source entries:

| Source | Commit | Archive SHA256 |
|---|---|---|
| GGUF Guard | `71cdf1f811ba9df8a4ba1e56e343aaabb5a4b65d` | `e0412557c129acc1f79a0d51cf25a4fafe65c2fbceb61a67ef0facba03d8c949` |
| SearXNG | `23e7e4da008fdc9ac5b27b2625faa9144d46f208` | `b6622bb036721540ee0e4c1f3570ac653af4527587f0cdc8d48ffd6f55a5b1a0` |

`.github/workflows/build.yml` verifies archives, vendors embedded Go modules,
stages the hash-locked wheelhouse and compiler/llama archives, and emits a
source-prep manifest bound to the workflow commit. Stage 2 uses a fresh checkout
and `.github/scripts/restore-source-prep.py`, which verifies the expected job
artifact digest, safe archive structure, checkout lock digests and payload
checksums before restoring. Restoration now additionally rejects undeclared
upstream roots and nested root declarations. This compares payload roots with
the authenticated preparation manifest; it does not add an independent signature
or reinterpret YAML using an ad hoc parser.

`recipes/recipe.yml` copies `services`, scripts, staged upstreams, wheelhouse,
locks and source-prep metadata into the build and invokes `build-services.sh`
with networking disabled. Embedded MCP hashes are now checked during the build,
not only by tests. The snapshot verifier rejects modified or missing listed
files, symlinks and added unreviewed files. Existing noninstalled sample JSON is
excluded; Go vendor contents remain under the separate source-prep contract.

Native scanner verification now expects ModelAudit **0.2.52**, matching the
reviewed application lock and quarantine metadata. The previous assertion of
0.2.42 would abort a build with the current locked graph. ModelScan remains
0.8.8 and Fickling 0.1.12; no scanner pin was changed by this work.

## Actual payload evidence and remaining boundaries

An offline wheel build before the packaging fix contained **zero UI templates**.
The source has eleven HTML templates and currently no static asset files.
Sandbox directory COPY included those templates. UI metadata now explicitly
packages only `ui` and its template/static data. Qualification builds the common
and UI wheels without indexes or build isolation, compares every packaged UI
file byte-for-byte with source, rejects unexpected package payloads, installs in
a private directory outside the checkout, compiles all templates, renders login,
models and security, and receives `/login` HTTP 200 with socket connections
blocked. This is not a complete native OS build.

The CI Python job now explicitly sets `SECAI_PACKAGING_PYTHON=python` and installs
setuptools84.0.0 and wheel0.48.0 from `requirements-ci.lock`. These are the exact
versions and artifact hashes already reviewed in the application lock; all
pre-existing CI lock entries and hashes were preserved. The existing CI graph
already supplies the UI rendering imports and wheel's packaging dependency, so
no separate application environment is needed. The explicit interpreter makes
missing build/runtime dependencies fail this test instead of taking its optional
local-development skip. A fresh private Python3.12 environment installed solely
from the resulting CI lock passed the real wheel/install/render test, including
with the same `python` command used by CI. This qualifies the local CI recipe;
no remote GitHub Actions run was performed.

The fixed published CPU image uses llama.cpp **0.3.0-dev, build 10795,
6703d7894**. Native source is **v0.4.0, build 10809,
5266f24da75dc449bd56cbed7addb9c8e4a6a73e**, archive SHA256
`9c2948aa9c79c92dd0e4c98e11ff5cf76dfdcaebdeb18e3e93409e9a98aefdab`.
Native options disable OpenSSL, subprocess support and built-in UI; runtime
launchers also disable UI and set an explicit model alias. Published CPU auth
and request qualification does not establish native compile-hardening parity.
The CPU upstream digest is
`fcca4dac388066ca93db561751e8caf5fc7d46d9df5f00a7422026db68468e31`.
Other fixed targets (CUDA, CUDA13, ROCm, Vulkan, Intel, OpenVINO) have independent
digests in the Dockerfile; they were not rebuilt or qualified here.

Sandbox SearXNG digest is
`e37c25170d9f5947b16713af33e0ab41f0e6e6e73685e19c30fc6bb63562f801`.
Digest-pinned base images do not freeze subsequent `apk add/upgrade` results.
The Tor and other sandbox Dockerfiles still resolve OS packages during their
builds. Do not infer byte reproducibility or source equivalence from a base
image pin alone. Native agent package metadata now names requests2.34.2, matching its requirements
and the installed application graph. The offline agent wheel check verifies its
actual `Requires-Dist` field against both agent locks and the application lock.

## ModelScan local patch boundary and proposal

The neighbouring helper is based at `c00d45c725701f69bcd2763496edcef393d33da1`.
Its current five changed implementation files are:

- `modelscan/cli.py`: explicit trusted settings rather than implicit current-directory settings.
- `modelscan/middlewares/format_via_extension.py`: format normalization and context merging.
- `modelscan/modelscan.py`: preserve partial issues, errors and skipped coverage.
- `modelscan/settings.py`: pickle resource bounds, unsafe globals and settings serialization.
- `modelscan/tools/picklescanner.py`: bounded, stricter pickle opcode analysis.

All five differ from the installed PyPI0.8.8 files. These are the current dirty
patch files, **not** a claim that replacing five files in the much older PyPI
wheel produces the reviewed helper tree. The helper has additional committed
architecture changes; patch dependencies require an explicit review.

The main single-file gate permits only structurally valid GGUF/safetensors and
runs before static scanning. Diffusion directory static scanning visits only
safetensors. The API invokes `ModelScan()` using built-in settings; API failures
fail closed. CLI is used only if API imports are unavailable, without an
operator settings argument. Ordinary synthetic GGUF/safetensors produce an
explicit `not_applicable` result, not claimed scanner coverage.

A bounded inert probe nevertheless demonstrated a reachable ZIP dispatch:
a 67,324,880-byte safetensors file used a valid 67,324,752-byte padded JSON header
whose little-endian length begins `PK\x03\x04`, with an inert ZIP stored as U8
tensor data. It passed the current structural format gate and PyPI ModelScan
statically inspected `inert.pkl` (PROTO2/NONE/STOP; never deserialized). Thus
extension restrictions alone do not establish that the pickle scanner and its
partial-result handling are unreachable. This is a format/scanner reachability
finding, not proof of full admission, payload execution or framework exploit.

The shared safetensors parser now rejects this exact initial ZIP magic before
reading the JSON header. Both file and directory format gates use that parser;
ordered direct and isolated-worker pipelines run format validation before static
scanning. Regression tests prove rejection before downstream scanners, ordinary
GGUF/safetensors acceptance, and that ZIP-like tensor data elsewhere remains
valid. Inspection of the installed detector confirms its complete dispatch rule
is exactly the initial four bytes `PK\x03\x04`; central-directory/end-record
signatures alone do not dispatch it. This deliberately rejects otherwise valid
safetensors with the ambiguous 67,324,752-byte header length (the only such
length under the current 100MiB cap), even if their tensor data is benign. The
original header-size cap is otherwise unchanged. The inert fixture still reaches
ModelScan if called directly, while appliance format validation rejects it. This
narrow contract correction avoids importing a fork for excluded formats. No ModelScan vendoring or lock
change is authorized by this document, and no helper CLI change is established
as necessary for the normal installed API path.

If a wider format contract later requires the reviewed helper, stage one exact
reviewed source artifact with a local version, source-file hashes, base revision,
full patch set and Apache-2.0 license/notice. Its current build backend requires
Poetry Core and Poetry Dynamic Versioning; select and hash-lock actual build
artifacts, rather than copying the helper's version ranges into production.
Build one wheel from that source offline, record its hash and install it in both
native and sandbox lock graphs. Verification must require that exact wheel and
reviewed implementation hashes, and fail if the ordinary PyPI wheel remains or
can replace it. A raw overlay of five files without dependency/RECORD review is
not proposed. Qualify bounded parser/ZIP tests plus real HDF5/Keras/TensorFlow/
NumPy/PyTorch coverage for any newly supported format, with explicit optional
framework dependencies and license review. Those broader acceptance tasks are
open; no framework execution was performed here.

## Inputs for a broader release manifest

A future release manifest must bind the complete main source tree; recipe and
native scripts, units/configuration; all Dockerfiles/contexts, Compose profiles
and `.dockerignore`; embedded service source and MCP snapshot; dependency locks,
wheel and Go vendor payloads; external source lock plus extracted archive
identities and prepared SearXNG metadata; compiler and llama source identities;
custom Python installer and CPython patches; selected backend image digest and
resulting image IDs; and optional diffusion/runtime installers and locks.
Record actual OS repository package resolution and target architecture too.
The source-prep manifest, SBOM, signing identity and final image digest must be
linked by the real release pipeline. Local hashes do not prove that CI used a
dirty working tree, that signing ran, or that a deployed appliance has this
payload. Full native image building, all sandbox targets, accelerator/runtime
parity, CI signing and deployment verification remain outside this bounded work.
