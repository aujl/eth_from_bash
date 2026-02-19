# Agents Guide

Guidelines for automated contributors working in this repository.

## Scope and policy
- Keep runtime project features shell-native (Bash + standard CLI tools).
- Do not introduce new third-party runtime crypto dependencies for project features.
- Python is allowed in tests/tooling only.
- Keep changes minimal, focused, and auditable.

## Required local checks
- `make deps`
- `make lint` (best effort locally, enforced in CI)
- `UNSIGNED_TEST=1 make check` for unsigned regression runs
- `SIGNED_TEST=1 make check` when signing material is available

## Dependency baseline
Project scripts assume:
- `bash`
- `jq`
- `bc`
- `xxd`
- `awk`
- coreutils hash tools (`sha256sum`, `sha512sum`) when present

## Testing and signed fixtures
- Signed mode validates fixture authenticity/integrity and requires secret env vars documented in `README.md`.
- Unsigned mode is explicitly opt-in via `UNSIGNED_TEST=1`.
- Keep tests offline and deterministic.

## Coding style
- Use `set -euo pipefail` in shell scripts.
- Prefer reusable functions/modules under `scripts/lib/` over large inline snippets.
- Keep CLI entrypoints thin (`bin/`) and orchestration logic in `scripts/cli` + `scripts/lib/flows`.

## Security and hygiene
- Never commit secrets, real mnemonics, or private keys.
- Use restrictive file permissions for sensitive test artifacts.
- Avoid network-dependent tests.
