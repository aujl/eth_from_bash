SHELL := /usr/bin/env bash

.PHONY: check venv clean-venv deps lint

# Ensure required CLI tools exist
deps:
	@bash scripts/check_deps.sh

# Creates a local Python venv for development helpers.
venv:
	@bash scripts/ensure_venv.sh

# Runs the test suite.
check: deps
	@bash tests/run.sh

clean-venv:
	rm -rf .venv

# Lint shell scripts (best-effort locally; enforced in CI)
lint:
	@bash scripts/lint.sh
