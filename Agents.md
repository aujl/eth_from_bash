# Agents Guide

This repository is used with automated coding agents. To keep changes safe,
auditable, and reproducible, follow these conventions:

## Principles
- Prefer scripts over inline one‑liners: Do not embed large Bash, Python, or Perl
  blocks directly in Makefiles or CI steps. Put logic into files under `scripts/`
  and call them.
- Keep changes minimal and focused: Avoid unrelated refactors when fixing a task.
- Validate with `make check`: Always run the test suite locally before opening a PR.
- Be explicit about dependencies: Use the Makefile and CI to install or check deps.

## Layout
- `eth-from-bash.sh`: Main CLI that derives Ethereum keys/address from a mnemonic.
- `scripts/`: Helper scripts used by Make and tests (keccak detection, EIP‑55 helpers,
  dependency checks, venv setup, lint entrypoint).
- `tests/run.sh`: Test harness that shells out to the scripts/utilities.
- `Makefile`: Entry points for `check`, `venv`, `lint`.

## Common Tasks
- Run tests: `make check`
- Prepare Keccak if missing: `make venv` (installs `pycryptodome` into `.venv/`)
- Lint shell: `make lint` (requires `shellcheck`)

## CI Expectations
- GitHub Actions must pass on PRs: lint + tests.
- CI installs required system packages and executes `make lint` and `make check`.

## Style
- Bash: `set -euo pipefail`, use functions for readability, avoid unnecessary subshells.
- Python: Small, single‑purpose scripts with `#!/usr/bin/env python3` and `if __name__ == '__main__':` guards.
- Perl: Keep usage minimal and scoped to Keccak fallback.

## Security Notes
- Never commit secrets or real mnemonics.
- Avoid network access in tests; everything should run offline.

