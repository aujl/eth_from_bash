# Module Boundaries

The repository separates executable entrypoints from reusable library code to keep test harnesses and downstream scripts
composable:

- **CLI dispatchers (`bin/`)** – `bin/eth-from-bash` and `bin/crypto-sign` are the only user-facing entrypoints. They locate the
  repository root, export helper environment variables, and `exec` into the implementation shells. The legacy `eth-from-bash.sh`
  wrapper simply forwards to `bin/eth-from-bash` for backward compatibility.
- **Helper libraries (`scripts/lib/`)** – Mnemonic, derivation, ASN.1, and cryptographic helpers expose pure Bash functions.
  Tests can `source scripts/lib/*.sh` directly without invoking the CLI, which keeps deterministic fixtures free from subshell
  state.
- **Implementation scripts (`scripts/`)** – The libraries back `scripts/crypto_sign.sh`, `scripts/crypto_kdf.sh`,
  `scripts/bip39_seed.sh`, and other helpers. The CLI dispatchers delegate to these scripts once environment discovery completes.

When adding new helpers, prefer adding a module to `scripts/lib/` and surfacing it via a dispatcher in `bin/` so the test harness
and documentation remain consistent.
