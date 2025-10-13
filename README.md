# Ethereum Keys from Bash

Deterministically derive an Ethereum private key and address from a BIP‑39 mnemonic using Bash with bundled helpers for Keccak, elliptic curve operations, and Bash PBKDF2/HMAC primitives backed by the Perl Digest::SHA module.

This repo includes:
- `eth-from-bash.sh`: BIP‑39 seed (PBKDF2), BIP‑32 (secp256k1) derivation for `m/44'/60'/0'/0/0`, public key → Ethereum address (Keccak‑256 + EIP‑55).
- `scripts/crypto_kdf.sh`: Shell PBKDF2/HMAC helper backed by the Perl `Digest::SHA` module for the CLI and tests.
- `english_bip-39.txt`: Standard 2048‑word English BIP‑39 wordlist.
- `tests/run.sh`: Modular sanity tests for BIP‑39 flow, environment guards, and Keccak vectors.
- `tests/load_secrets.sh`: Helper that materializes signature/HMAC secrets for the test harness.

## Features
- BIP‑39 mnemonic generation (128‑bit entropy) or import via `--mnemonic`.
- Seed derivation via PBKDF2-HMAC-SHA512 (2048 iters) powered by Perl Digest::SHA HMAC primitives.
- BIP‑32 derivation with guards: skips invalid `IL >= n` or child key = 0.
- Ethereum address: Keccak‑256 of uncompressed pubkey (no prefix), EIP‑55 checksum.
- Non-blocking entropy sourced from the Bash helper (`scripts/crypto_sign.sh random-bytes`) with `/dev/urandom` fallback.
- Quiet mode for scriptable JSON output.

## Requirements
- Bash, `awk`, `bc`, `xxd` (from `vim-common`), `jq`, `sha256sum`, `sha512sum`, `perl` (core `Digest::SHA`).

On Debian/Ubuntu:
```
sudo apt update && sudo apt install -y jq bc vim-common
```

## Usage

- Generate a new mnemonic and derive address (JSON only):
```
bash eth-from-bash.sh -q english_bip-39.txt
```

- Use an existing mnemonic (e.g. from MetaMask) and include the seed:
```
bash eth-from-bash.sh -q --include-seed --mnemonic "abandon abandon ... about" english_bip-39.txt [optional passphrase]
```

- Only derive keys/seed (skip address if Keccak is unavailable):
```
bash eth-from-bash.sh -q --no-address english_bip-39.txt
```

- Override entropy or mnemonics via environment variables:
```
ENT_HEX=00000000000000000000000000000000 bash eth-from-bash.sh -q english_bip-39.txt
MNEMONIC="abandon abandon ... about" bash eth-from-bash.sh -q --include-seed english_bip-39.txt TREZOR
```
  - `ENT_HEX` must be 32 hexadecimal characters (128 bits).
  - `MNEMONIC` must contain valid BIP-39 words (multiples of three). When set, `--mnemonic` is rejected in favor of the environment.

Output JSON fields:
- `mnemonic`: 12 words (space‑separated)
- `path`: Fixed `m/44'/60'/0'/0/0`
- `privateKey`: 32‑byte hex with `0x` prefix
- `address`: EIP‑55 checksummed `0x…` (empty `0x` if `--no-address`)
- `seed`: 64‑byte seed hex (only when `--include-seed` is used)

Helper environment variables exported by `eth-from-bash.sh` (available to tests and downstream scripts):
- `BIP39_HELPER`: Bash wrapper around PBKDF2 seed derivation.
- `CRYPTO_KDF_HELPER`: Bash CLI for PBKDF2 and HMAC primitives.
- `CRYPTO_SIGN_HELPER`: Shell signing utility with entropy helpers (e.g., `random-bytes`).
- `SECP256K1_HELPER`, `KECCAK_HELPER`, `EIP55_HELPER`: Existing secp256k1, Keccak-256, and EIP-55 utilities.

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

- `scripts/check_deps.sh`: Verify CLI dependencies (`jq`, `bc`, `xxd`, `awk`, `sha256sum`, `sha512sum`, `perl`).
- `scripts/keccak256.sh`: Constant-time Keccak-256 helpers and CLI.
- `scripts/secp256k1_pub.sh`: Derive secp256k1 public keys via OpenSSL tooling.
- `scripts/eip55_checksum.sh`: Recompute EIP‑55 checksum for an address.
- `scripts/rsa_prime_churn.sh`: Profile `crypto_sign.sh rsa-generate` to inspect bc usage.

### RSA helper tuning

`scripts/crypto_sign.sh rsa-generate` accepts `--bits` (default `2048`) and
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
resident `bc` helpers against a Python backend using the same randomized test
vectors. On Debian bookworm (bc 1.07.1, Python 3.11) the script observed bc
spending ~9.9 s total (~0.40 s/op) on `modexp` while Python needed ~0.49 s
(~0.02 s/op), but `gcd`/`modinv` remained within a few hundred milliseconds for
both backends. Those numbers suggest future work could embed Python to offload
expensive exponentiations while leaving the lightweight arithmetic inside the
existing bc coprocess.

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

