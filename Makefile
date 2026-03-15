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
SCRIPTS_FILES   := $(wildcard files/scripts/*.sh)

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

.PHONY: lint
lint: shellcheck ## Combined lint (shellcheck + ruff + go vet)
	ruff check services/ tests/ --select E,F,W --ignore E501,E402
	@for svc in $(GO_SERVICES); do \
	  echo "--- vet: $${svc} ---" ; \
	  (cd services/$${svc} && go vet ./...) || exit 1 ; \
	done
