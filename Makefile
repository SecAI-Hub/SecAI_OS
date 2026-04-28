# SecAI OS — Developer Targets
# Usage: make help
#
# Thin wrappers around existing CI / verification commands.
# No build targets — image builds are handled by BlueBuild + release.yml.

.DEFAULT_GOAL := help
SHELL := /usr/bin/env bash

# ---------------------------------------------------------------------------
# Configuration (override via environment or make args)
# ---------------------------------------------------------------------------
IMAGE ?= ghcr.io/secai-hub/secai_os:latest

GO_SERVICES := airlock registry tool-firewall gpu-integrity-watch mcp-firewall \
               policy-engine runtime-attestor integrity-monitor incident-recorder

SCRIPTS_LIBEXEC := $(wildcard files/system/usr/libexec/secure-ai/*.sh)
SCRIPTS_FILES   := $(wildcard files/scripts/*.sh) $(wildcard .github/scripts/*.sh)

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

.PHONY: help
help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: verify-release
verify-release: ## Verify a release image (IMAGE=ghcr.io/...)
	@files/scripts/verify-release.sh "$(IMAGE)"

.PHONY: sandbox-vex
sandbox-vex: ## Generate local sandbox OpenVEX document (requires built sandbox images)
	python scripts/security/generate_custom_python_vex.py \
	  --image secai-sandbox-ui:latest \
	  --image secai-sandbox-agent:latest \
	  --image secai-sandbox-search-mediator:latest \
	  --image secai-sandbox-diffusion:latest \
	  --include-unicode-locale-glibc \
	  --output custom-python.vex.json

.PHONY: test
test: test-go test-python ## Run all tests (Go + Python)

.PHONY: test-go
test-go: ## Run Go service tests (all 9 services, -race)
	@for svc in $(GO_SERVICES); do \
	  echo "=== $${svc} ===" ; \
	  (cd services/$${svc} && go test -v -race -count=1 ./...) || exit 1 ; \
	done

.PHONY: test-python
test-python: ## Run Python tests (pytest tests/ -v)
	PYTHONPATH=services python -m pytest tests/ -v

.PHONY: shellcheck
shellcheck: ## Lint all shell scripts with shellcheck
	shellcheck -s bash $(SCRIPTS_LIBEXEC) $(SCRIPTS_FILES)

.PHONY: hadolint
hadolint: ## Lint Containerfiles and Dockerfiles with Hadolint
	.github/scripts/check-hadolint.sh

.PHONY: semgrep
semgrep: ## Run repo-owned Semgrep security rules
	.github/scripts/run-semgrep.sh

.PHONY: lint
lint: shellcheck hadolint semgrep ## Combined lint (shellcheck + hadolint + semgrep + ruff + go vet)
	ruff check services/ tests/ --select E,F,W --ignore E501,E402
	@for svc in $(GO_SERVICES); do \
	  echo "--- vet: $${svc} ---" ; \
	  (cd services/$${svc} && go vet ./...) || exit 1 ; \
	done
