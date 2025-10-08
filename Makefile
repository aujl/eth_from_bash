SHELL := /usr/bin/env bash

.PHONY: check venv clean-venv deps lint

# Ensure required CLI tools exist
deps:
	@bash scripts/check_deps.sh

# Creates a local Python venv with pycryptodome so Keccak tests can pass.
venv:
	@bash scripts/ensure_venv.sh

# Runs the test suite. If system Python lacks Keccak, uses a local venv.
check: deps
	@set -euo pipefail; \
	need_venv=0; \
	if ! python3 scripts/has_keccak.py >/dev/null 2>&1; then \
	  need_venv=1; \
	fi; \
	if ! python3 -c 'import ecdsa' >/dev/null 2>&1; then \
	  need_venv=1; \
	fi; \
	if [[ $$need_venv -eq 0 ]]; then \
	  echo "Using system Python crypto deps"; \
	  bash tests/run.sh; \
	else \
	  echo "Using local venv (.venv) for python deps"; \
	  if [[ ! -d .venv ]]; then $(MAKE) venv; fi; \
	  PATH=.venv/bin:$$PATH bash tests/run.sh; \
	fi

clean-venv:
	rm -rf .venv

# Lint shell scripts (best-effort locally; enforced in CI)
lint:
	@bash scripts/lint.sh
