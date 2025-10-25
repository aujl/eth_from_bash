# Ethereum Keys from Bash

Deterministically derive an Ethereum private key and address from a BIP‑39 mnemonic using Bash with bundled helpers for Keccak, elliptic curve operations, and Bash PBKDF2/HMAC primitives implemented by the internal `bin/crypto-sign` dispatcher and `scripts/crypto_kdf.sh`.

This repo includes:
- `bin/eth-from-bash`: CLI entrypoint that wires argument parsing, helper discovery, and JSON output together.
- `bin/sol-from-bash`: Solana-focused CLI that derives SLIP-0010/Ed25519 key material and base58 addresses.
- `bin/crypto-sign`: Dispatcher for the signing/entropy helper backed by the modules in `scripts/lib/`.
- `eth-from-bash.sh`: Compatibility wrapper that forwards to `bin/eth-from-bash` for existing automation.
- `scripts/lib/bip39.sh`: BIP‑39 entropy helpers (validation, generation, mnemonic assembly, and wordlist guards).
- `scripts/lib/bip32.sh`: secp256k1 constants, big-number helpers, and BIP‑32 derivation routines used by the CLI and tests.
- `scripts/lib/solana_slip10.sh`: SLIP‑0010 hardened derivation helpers for Ed25519 chains (used by the Solana CLI/tests).
- `scripts/lib/ed25519.sh`: Pure Bash Ed25519 scalar/point helpers backed by `bc` for public key derivation.
- `scripts/lib/base58.sh`: Bitcoin-alphabet base58 encoder used for Solana address formatting.
- `scripts/crypto_kdf.sh`: Bash PBKDF2/HMAC helper reused by the CLI, tests, and dependency checks.
- `english_bip-39.txt`: Standard 2048‑word English BIP‑39 wordlist.
- `tests/run.sh`: Modular sanity tests for BIP‑39 flow, environment guards, and Keccak vectors.
- `tests/load_secrets.sh`: Helper that materializes signature/HMAC secrets for the test harness.


## Features
- BIP‑39 mnemonic generation (128‑bit entropy) or import via `--mnemonic`.
- Seed derivation via PBKDF2-HMAC-SHA512 (2048 iters) powered by the Bash helpers in `bin/crypto-sign` and `scripts/crypto_kdf.sh`.
- BIP‑32 derivation with guards: skips invalid `IL >= n` or child key = 0.
- SLIP‑0010 hardened derivation for Solana Ed25519 accounts (`m/44'/501'/…`).
- Ethereum address: Keccak‑256 of uncompressed pubkey (no prefix), EIP‑55 checksum.
- Non-blocking entropy sourced from the Bash helper (`bin/crypto-sign random-bytes`) with `/dev/urandom` fallback.
- Quiet mode for scriptable JSON output.

## Requirements
- Bash, `awk`, `bc`, `xxd` (from `vim-common`), `jq`.

On Debian/Ubuntu:
```
sudo apt update && sudo apt install -y jq bc vim-common
```

## Usage

- Generate a new mnemonic and derive address (JSON only):
```
./bin/eth-from-bash -q english_bip-39.txt
```

- Use an existing mnemonic (e.g. from MetaMask) and include the seed:
```
./bin/eth-from-bash -q --include-seed --mnemonic "abandon abandon ... about" english_bip-39.txt [optional passphrase]
```

- Only derive keys/seed (skip address if Keccak is unavailable):
```
./bin/eth-from-bash -q --no-address english_bip-39.txt
```

- Override entropy or mnemonics via environment variables:
```
ENT_HEX=00000000000000000000000000000000 ./bin/eth-from-bash -q english_bip-39.txt
MNEMONIC="abandon abandon ... about" ./bin/eth-from-bash -q --include-seed english_bip-39.txt TREZOR
```
  - `ENT_HEX` must be 32 hexadecimal characters (128 bits).
  - `MNEMONIC` must contain valid BIP-39 words (multiples of three). When set, `--mnemonic` is rejected in favor of the environment.

Output JSON fields:
- `mnemonic`: 12 words (space‑separated)
- `path`: Fixed `m/44'/60'/0'/0/0`
- `privateKey`: 32‑byte hex with `0x` prefix
- `address`: EIP‑55 checksummed `0x…` (empty `0x` if `--no-address`)
- `seed`: 64‑byte seed hex (only when `--include-seed` is used)

## Solana from Bash

`bin/sol-from-bash` mirrors the Ethereum workflow but targets Solana’s Ed25519-based accounts. It reuses the BIP‑39 helper,
derives hardened SLIP‑0010 keys, expands them into Ed25519 public keys using the bundled `bc` arithmetic helpers, and exports the
address in base58 form.

- Derive the first Solana account for a mnemonic and include the seed:
  ```
  ./bin/sol-from-bash -q --include-seed --mnemonic "urge pulp usage sister evidence arrest palm math please chief egg abuse" english_bip-39.txt
  ```

- Override the derivation path (only hardened segments are supported):
  ```
  ./bin/sol-from-bash -q --path "m/44'/501'/1'/0'" english_bip-39.txt
  ```

The Solana CLI JSON mirrors the Ethereum fields where possible and adds Solana-specific artifacts:

- `mnemonic`: Normalized BIP‑39 words
- `path`: Hardened SLIP‑0010 path (default `m/44'/501'/0'/0'`)
- `privateKey`: 32‑byte Ed25519 seed (hex)
- `publicKey`: 32‑byte compressed Ed25519 public key (hex)
- `secretKey`: 64‑byte secret key (seed concatenated with public key)
- `chainCode`: SLIP‑0010 chain code (hex)
- `address`: Base58-encoded public key (Solana address)
- `seed`: Optional 64‑byte BIP‑39 seed when `--include-seed` is set

The helper respects `MNEMONIC`/`ENT_HEX` overrides just like the Ethereum CLI and requires only `bash`, `bc`, and `xxd`.

Helper environment variables exported by `eth-from-bash.sh` (available to tests and downstream scripts):
- `BIP39_HELPER`: Bash wrapper around PBKDF2 seed derivation.
- `CRYPTO_KDF_HELPER`: Bash CLI for PBKDF2 and HMAC primitives.
- `CRYPTO_SIGN_HELPER`: Shell signing utility with entropy helpers (e.g., `bin/crypto-sign random-bytes`).
- `SECP256K1_HELPER`, `KECCAK_HELPER`, `EIP55_HELPER`: Existing secp256k1, Keccak-256, and EIP-55 utilities.

### Library layout

`bin/eth-from-bash` sources the reusable helpers under `scripts/lib/` and exports their public shell functions so tests or
downstream scripts can source the same modules. The sibling dispatcher `bin/crypto-sign` wires the RSA, ECDSA, and HMAC commands
to the same shared libraries so callers can choose between a CLI or `source`-based workflow:

- `bip39_hex_to_bits`, `bip39_validate_entropy_hex`, `bip39_generate_entropy_hex`, `bip39_build_mnemonic_from_entropy`, and
  related helpers live in `scripts/lib/bip39.sh`.
- `bip32_master_from_seed`, `bip32_derive_path_segments`, the `bip32_bn_*` arithmetic helpers, and secp256k1 public key
  utilities live in `scripts/lib/bip32.sh`.
- The Solana flow is powered by `scripts/lib/solana_slip10.sh`, `scripts/lib/ed25519.sh`, and `scripts/lib/base58.sh`, which can be
  sourced in isolation for advanced automation.
- The crypto-sign helpers live in `scripts/lib/asn1.sh`, `scripts/lib/hmac.sh`, `scripts/lib/rsa.sh`, and
  `scripts/lib/ecdsa.sh`; tests can source these modules directly without invoking the CLI dispatcher.

All helpers are standard Bash functions that can be consumed by tests via `source scripts/lib/bip39.sh` or
`source scripts/lib/bip32.sh`; the CLI exports them with `export -f` to preserve compatibility for subprocesses and the
crypto-sign dispatcher keeps the low-level primitives available for sourcing when needed.

## Tests

`make check` enforces signed fixtures by default. Provide the following secrets as base64-encoded environment variables before running the suite:

- `CORE_FLOW_FIXTURE_HMAC_KEY_B64`: binary key used for the HMAC guard over `tests/fixtures/core_flow_vectors.json`.
- `CORE_FLOW_FIXTURE_HMAC_B64`: expected HMAC digest for the canonicalized core flow fixture.
- `KECCAK_VECTOR_SIG_B64`: detached signature for `tests/fixtures/keccak_vectors.json` produced by the maintainer key shipped in `tests/fixtures/keccak_reference_pub.pem`.
- `SECP256K1_VECTOR_SIG_B64`: detached signature for `tests/fixtures/secp256k1_vectors.json` produced by `tests/fixtures/secp256k1_vectors_pub.pem`.

Run all tests:
```
make check
```
To perform an unsigned local run (skipping fixture verification), explicitly opt in:
```
UNSIGNED_TEST=1 make check
```
What is covered:
- Core CLI flow vectors, environment guard rails, and fixture HMAC verification.
- Deterministic Keccak-256 primitives, vector regeneration, and detached signature verification.
- secp256k1 primitive self-test, vector verification, and detached signature validation.
- Solana SLIP‑0010/Ed25519 derivation regression tests and base58 formatting vectors.

## Maintainer signing workflow
Maintainers can refresh the signing material entirely offline. The workflow produces fresh maintainer keypairs, regenerates the fixture HMAC/signatures, and exports environment assignments that `tests/load_secrets.sh` understands.

1. Generate or rotate maintainer keys (RSA for Keccak fixtures, secp256k1 for elliptic-curve fixtures). Private keys are stored under `~/.config/eth_from_bash/maintainer` by default and public keys are written back into `tests/fixtures/`.
   ```bash
   tests/generate_maintainer_keys.sh
   ```
2. Recreate the signed artifacts. The script canonicalizes the fixtures, derives a random HMAC key for the core flow bundle, and emits the secrets as export statements. Capture the output in the current shell or write it to a file sourced only for the test session.
   ```bash
   eval "$(tests/recreate_signed_artifacts.sh)"
   ```
3. Run the signed test suite to confirm the regenerated artifacts validate end-to-end.
   ```bash
   SIGNED_TEST=1 make check
   ```
4. When finished, unset the exported secrets and secure the private key directory (the scripts enforce `chmod 700` for the directory and `chmod 400` for key files).

If an alternate location for the private keys or fixtures is required, set `PRIVATE_KEY_DIR` or `FIX` before invoking the scripts.

### Development
- Lint shell scripts:
```
make lint
```
- Ensure CLI dependencies are available:
```
make deps
```

- `bin/check-deps`: Deterministically self-tests CLI dependencies (`jq`, `bc`, `xxd`, `awk`) and verifies the built-in SHA-256/SHA-512 helper alongside the bundled `bin/crypto-sign` HMAC helper against known vectors.
- `scripts/keccak256.sh`: Constant-time Keccak-256 helpers and CLI.
- `scripts/secp256k1_pub.sh`: Derive secp256k1 public keys via on-repo bc helpers.
- `scripts/eip55_checksum.sh`: Recompute EIP‑55 checksum for an address.
- `scripts/rsa_prime_churn.sh`: Profile `bin/crypto-sign rsa-generate` to inspect bc usage.

### RSA helper tuning

`bin/crypto-sign rsa-generate` accepts `--bits` (default `2048`) and
`--exponent` (`65537`) to control key size and public exponent selection. The
helper enforces odd exponents ≥ 3 and regenerates primes until the Euler
totient is coprime to the chosen exponent. Prime candidates are sieved against
all primes < 1000 before feeding a long-lived `bc` coprocess that keeps the
Miller–Rabin helpers resident. The number of Miller–Rabin rounds is automatically
chosen from the key size (override with `CRYPTO_SIGN_RSA_MR_ROUNDS`) and the
minimum size gate can be tuned with `CRYPTO_SIGN_RSA_MIN_BITS`.

The companion script `scripts/rsa_prime_churn.sh` runs the generator under
`CRYPTO_SIGN_TRACE_CHURN=1` and reports the number of `bc` calls and prime
candidates processed per keypair alongside wall-clock duration. This is useful
when validating performance changes without touching the main CLI. Reusing the
same `bc` session allows churn comparisons before/after tuning without noisy
process-spawn overhead. See [`docs/rsa_prime_churn_baseline.md`](docs/rsa_prime_churn_baseline.md)
for the current baseline results and notes on reproducing the measurements.

For bigint microbenchmarks, `scripts/dev_compare_bigint.sh` compares the
resident `bc` helpers against a standalone shell reference that performs the
same calculations with bc primitives. Randomized test vectors are replayable by
seed, and the benchmark now runs entirely on the repository's Bash/bc toolchain
with no Python dependency.

## Notes on Keccak vs SHA‑3
Ethereum uses Keccak‑256 (pre‑NIST) for addresses, not SHA3‑256. This repository ships a constant-time, Bash-based Keccak-256 implementation in `scripts/keccak256.sh`, so no external cryptography packages are required.

## Security
- This is a demo/reference script. Do not use on untrusted machines.
- Never paste real seed phrases into terminals on shared environments.
- Consider air‑gapped usage and review the code before production use.
To audit only the secp256k1 primitive helper:
```
scripts/secp256k1_pub.sh selftest
```

