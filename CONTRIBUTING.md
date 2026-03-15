# Contributing to SecAI OS

Thank you for your interest in contributing to SecAI OS. This document explains
how to set up your development environment, run tests, and submit changes.

## Prerequisites

| Tool | Minimum Version | Purpose |
|---|---|---|
| Go | 1.25+ | Build Go services (9 services, see below) |
| Python | 3.11+ | Build Python services (quarantine, UI, search mediator) |
| shellcheck | Latest | Lint shell scripts |
| git | 2.x | Version control |

Optional but recommended:

- `gofmt` (included with Go) for formatting Go code.
- `pip` or a virtual-environment manager (`venv`, `uv`) for Python dependencies.
- `cosign` for verifying container image signatures.

## Local Development Setup

### 1. Clone the Repository

```bash
git clone https://github.com/SecAI-Hub/SecAI_OS.git
cd SecAI_OS
```

### 2. Build Go Services

```bash
for svc in airlock registry tool-firewall gpu-integrity-watch mcp-firewall \
           policy-engine runtime-attestor integrity-monitor incident-recorder; do
  (cd "services/$svc" && go build ./...)
done
```

### 3. Install Python Dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r services/quarantine/requirements.txt
pip install -r services/ui/requirements.txt
pip install -r services/search-mediator/requirements.txt
pip install pytest
```

### 4. Verify Shell Scripts

```bash
shellcheck files/system/usr/libexec/secure-ai/*.sh
```

## Running Tests

### Go Tests (402 tests across 9 services)

```bash
for svc in airlock registry tool-firewall gpu-integrity-watch mcp-firewall \
           policy-engine runtime-attestor integrity-monitor incident-recorder; do
  (cd "services/$svc" && go test -v -race ./...)
done
```

### Python Tests (739 tests)

```bash
pip install -r requirements-ci.txt
PYTHONPATH=services python -m pytest tests/ -v
```

### Type Checking (mypy)

```bash
pip install -r requirements-ci.txt
mypy --ignore-missing-imports \
  services/common/ services/agent/agent/ \
  services/quarantine/quarantine/ services/ui/ui/
```

### Shell Linting

```bash
shellcheck files/system/usr/libexec/secure-ai/*.sh files/scripts/*.sh
```

### Run Everything

```bash
# Go (9 services, 402 tests)
for svc in airlock registry tool-firewall gpu-integrity-watch mcp-firewall \
           policy-engine runtime-attestor integrity-monitor incident-recorder; do
  (cd "services/$svc" && go test -v -race ./...)
done

# Python (739 tests)
PYTHONPATH=services python -m pytest tests/ -v

# Type check
mypy --ignore-missing-imports \
  services/common/ services/agent/agent/ \
  services/quarantine/quarantine/ services/ui/ui/

# Lint
ruff check services/ tests/ --select E,F,W --ignore E501,E402

# Shell
shellcheck files/system/usr/libexec/secure-ai/*.sh files/scripts/*.sh
```

## Coding Standards

### Go

- Format all Go code with `gofmt`. CI will reject unformatted code.
- Follow standard Go conventions (effective Go, Go Code Review Comments).
- Export only what is necessary; keep package APIs minimal.

### Python

- Follow [PEP 8](https://peps.python.org/pep-0008/).
- Use type hints where practical.
- Keep functions focused and testable.

### Shell

- Target POSIX sh unless bash-specific features are required.
- All scripts must pass `shellcheck` with zero warnings.
- Use `set -euo pipefail` at the top of bash scripts.

### General

- Keep commits atomic -- one logical change per commit.
- Write clear, descriptive variable and function names.
- Add or update tests for any new functionality.

## Pull Request Process

1. **Branch from `main`.** Create a feature branch with a descriptive name:
   ```
   git checkout -b feat/short-description
   ```

2. **Make your changes.** Follow the coding standards above.

3. **Run all tests locally.** Ensure Go tests, Python tests, and shellcheck
   all pass before pushing.

4. **Sign your commits.** Use `git commit -s` to add a Signed-off-by line,
   or configure GPG/SSH signing.

5. **Push and open a PR.** Target the `main` branch.

6. **Describe your changes.** In the PR description, explain:
   - What the change does and why it is needed.
   - How it was tested.
   - Any relevant issue numbers (use `Closes #N` or `Fixes #N`).

7. **Wait for CI.** All checks must pass before a PR will be reviewed.

8. **Respond to review feedback.** Push additional commits to address review
   comments rather than force-pushing.

## Commit Message Format

Use the following format for commit messages:

```
<type>: <short summary>

<optional longer description>

Signed-off-by: Your Name <your.email@example.com>
```

Where `<type>` is one of:

| Type | Meaning |
|---|---|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `test` | Adding or updating tests |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `chore` | Build, CI, or tooling changes |
| `security` | Security-related change |

Example:

```
feat: add tensor-level scanning to quarantine pipeline

Scan individual tensors in GGUF files for anomalous shapes and
unexpected data types before promoting models to the trusted store.

Signed-off-by: Jane Doe <jane@example.com>
```

## Reporting Issues

- **Bugs:** Open a [GitHub Issue](https://github.com/SecAI-Hub/SecAI_OS/issues).
- **Security vulnerabilities:** See [SECURITY.md](SECURITY.md).
- **Questions:** Use [GitHub Discussions](https://github.com/SecAI-Hub/SecAI_OS/discussions).

## License

By contributing to SecAI OS, you agree that your contributions will be licensed
under the [Apache License 2.0](LICENSE).
