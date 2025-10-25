# Module Boundaries

The repository separates executable entrypoints from reusable library code to keep test harnesses and downstream scripts
composable:

- **CLI dispatchers (`bin/`)** – `bin/eth-from-bash` now delegates to `scripts/cli/ethereum.sh`,
  `scripts/lib/common/bootstrap.sh`, and `scripts/lib/flows/ethereum.sh`, keeping the entrypoint small while exposing the
  shared functions. `bin/crypto-sign` continues to wrap the signing helpers, and the legacy `eth-from-bash.sh` wrapper forwards
  to the dispatcher for compatibility.
- **Helper libraries (`scripts/lib/`)** – Reusable functions are grouped by domain: BIP helpers live under
  `scripts/lib/bip/`, cryptographic primitives under `scripts/lib/crypto/`, and chain-specific logic under
  `scripts/lib/chains/` with encoders in `scripts/lib/encoding/`. Tests can source these modules directly without invoking the
  CLI, which keeps deterministic fixtures free from subshell state.
- **Implementation scripts (`scripts/`)** – Library modules continue to back `scripts/crypto_sign.sh`,
  `scripts/crypto_kdf.sh`, `scripts/bip39_seed.sh`, and related helpers. The CLI dispatchers now rely on
  `scripts/cli/` and `scripts/lib/flows/` to orchestrate argument parsing and derivation once bootstrap completes.

When adding new helpers, prefer adding a module to `scripts/lib/` and surfacing it via a dispatcher in `bin/` so the test harness
and documentation remain consistent.
