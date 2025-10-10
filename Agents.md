# Agents Guide

This repository is used with automated coding agents. To keep changes safe,
auditable, and reproducible, follow these conventions:

## Principles
- **Primitive policy**: All cryptographic primitives used in the CLI **must** come
  from the internal helper modules that live under `scripts/` (e.g., the
  maintained Keccak and EIP‑55 helpers). Introducing or depending on third-party
  crypto libraries (system packages or PyPI crates) is prohibited unless the
  policy is explicitly amended.
- Prefer scripts over inline one‑liners: Do not embed large Bash, Python, or
  Perl blocks directly in Makefiles or CI steps. Put logic into files under
  `scripts/` and call them.
- Keep changes minimal and focused: Avoid unrelated refactors when fixing a
  task.
- Validate with `make check`: Always run the test suite locally before opening a
  PR.
- Be explicit about dependencies: Use the Makefile and CI to install or check
  deps. Document any new internal helper script you add.

## Layout
- `eth-from-bash.sh`: Main CLI that derives Ethereum keys/address from a mnemonic.
- `scripts/`: Helper scripts used by Make and tests (keccak detection, EIP‑55 helpers,
  dependency checks, lint entrypoint).
- `tests/run.sh`: Test harness that shells out to the scripts/utilities.
- `Makefile`: Entry points for `check`, `deps`, `lint`.

## Common Tasks
- Bootstrap CLI dependencies first: run `make deps` and install any missing
  packages (e.g., `bc`, `xxd`, `jq`, `openssl`) using the system
  package manager when prompted.
- Run tests: `make check`
- Lint shell: `make lint` (requires `shellcheck`)

### Signed test workflow
- CI and local contributors must run the signed test harness by executing
  `SIGNED_TEST=1 make check`. When `SIGNED_TEST=1` is set, the harness verifies
  outputs against signed fixtures stored in `tests/fixtures/`.
- Required secrets:
  - `CORE_FLOW_FIXTURE_HMAC_KEY_B64`: Base64-encoded binary key used to authenticate `tests/fixtures/core_flow_vectors.json`.
  - `CORE_FLOW_FIXTURE_HMAC_B64`: Base64-encoded HMAC-SHA256 digest of the canonicalized core flow fixture.
  - `SIGNING_PUBKEY`: ASCII‑armored PGP public key for verification.
  - `SIGNING_CERT_SHA256`: Expected fingerprint used to guard against key
    substitution attacks.
  - `SECP256K1_VECTOR_SIG_B64`: Base64 detached signature over
    `tests/fixtures/secp256k1_vectors.json` signed by the key in
    `tests/fixtures/secp256k1_vectors_pub.pem`.
  - For maintainers regenerating fixtures, set `SIGNING_KEY_HANDLE` to the
    hardware token slot and export `SIGNING_KEY_PASSPHRASE` only in an isolated
    shell (never in CI).
- To execute the signed tests securely:
  1. `set -euo pipefail` before invoking `make check`.
  2. Ensure `gpg` and `openssl` are installed and configured to use restricted
     homes with permissions `700` where applicable.
  3. Load secrets via environment variables or a temporary file sourced with
     `set -o noclobber` enabled to prevent accidental overwrite.
  4. Unset all signing secrets immediately after tests complete.

### Obtaining temporary signatures (local development)
- Contributors without access to production tokens can run
  `scripts/dev-sign-fixtures.sh` to request a 24‑hour temporary signature from
  the maintainer-operated signing service. The script:
  1. Generates a new ephemeral keypair stored under `tests/dev-keys/` with
     permissions `700`.
  2. Uploads the public key over HTTPS (certificate pinned) and receives
     signatures scoped to the requested fixtures.
  3. Installs the returned signatures into `tests/fixtures/dev/`.
- All temporary keys **must** be deleted (`rm -rf tests/dev-keys/ tests/fixtures/dev/`)
  before committing changes. Never check in temporary signatures or keys.

## CI Expectations
- GitHub Actions must pass on PRs: lint + tests.
- CI installs required system packages and executes `make lint` and `make check`.

## Style
- Bash: `set -euo pipefail`, use functions for readability, avoid unnecessary subshells.
- Python: Small, single‑purpose scripts with `#!/usr/bin/env python3` and `if __name__ == '__main__':` guards.
- Perl: Avoid introducing new Perl dependencies.

## Security Notes
- Never commit secrets or real mnemonics.
- Avoid network access in tests; everything should run offline.

### Secret handling rules
- Never log or print decoded secrets, private keys, or mnemonic phrases.
- Always enable `set -o noclobber` in scripts that touch secret material or
  write to files derived from secrets, preventing accidental overwrite.
- Files containing secrets must be created with restrictive permissions (`chmod
  600` for files, `chmod 700` for directories). Scripts should verify and
  enforce these modes before use.

### Offline build expectations
- All build and test workflows must succeed without network access once
  dependencies are bootstrapped. Cache or vendor any data needed for tests.
- When adding tools, prefer ones already available in the base image or include
  an offline installation plan in the Makefile under a dedicated target.

### Signature verification checklist
- Before opening a PR:
  1. Run `make lint` and `SIGNED_TEST=1 make check` locally.
  2. Verify that no new third-party cryptography dependencies were introduced.
  3. Document any updates to internal crypto helper scripts in the PR
     description.
  4. For changes touching signed fixtures, attach the verification log showing
     `gpg --verify` success.
- Reviewers must confirm that CI executed the signed tests and that dependency
  prohibitions are still satisfied (no changes to `requirements.txt`, `pip` or
  package installs introducing crypto libs).

