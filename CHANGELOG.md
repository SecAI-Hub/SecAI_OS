# Changelog

All notable changes to SecAI OS are tracked here.

This project follows semantic versioning for tagged releases. Dates use
YYYY-MM-DD.

## Unreleased

### Added

- Added repository-wide container pin validation for service, sandbox, and deploy
  Containerfiles, with expiring waivers for dynamic multi-variant image refs.
- Added full Python dependency-audit coverage for CI and runtime requirement
  files.
- Added cross-platform line-ending enforcement for shell, workflow, config, and
  documentation files.
- Added Dependabot coverage for GitHub Actions, Python services, Go modules,
  Dockerfiles, and sandbox images.
- Added GitHub issue and pull request templates.

### Changed

- Made quarantine scanner installation fail closed by default in production and
  sandbox Containerfiles.
- Made the OS image build fail closed when required quarantine, search mediator,
  or signing-policy material is missing.
- Pinned diffusion-worker Python runtime dependencies and sandbox base images.
- Refreshed documented test counts and fixed stale quarantine test references.
- Clarified PKCS#11 status as degraded-provider detection until hardware-backed
  signing and rotation are implemented.
