# Ethereum Keys from Bash

Deterministically derive an Ethereum private key and address from a BIP‑39 mnemonic using plain Bash with OpenSSL and Python for Keccak.

This repo includes:
- `eth-from-bash.sh`: BIP‑39 seed (PBKDF2), BIP‑32 (secp256k1) derivation for `m/44'/60'/0'/0/0`, public key → Ethereum address (Keccak‑256 + EIP‑55).
- `english_bip-39.txt`: Standard 2048‑word English BIP‑39 wordlist.
- `tests/run.sh`: Modular sanity tests for BIP‑39 flow, environment guards, and Keccak vectors.

## Features
- BIP‑39 mnemonic generation (128‑bit entropy) or import via `--mnemonic`.
- Seed derivation via OpenSSL 3 PBKDF2 (HMAC‑SHA512, 2048 iters).
- BIP‑32 derivation with guards: skips invalid `IL >= n` or child key = 0.
- Ethereum address: Keccak‑256 of uncompressed pubkey (no prefix), EIP‑55 checksum.
- Non-blocking entropy via `openssl rand -hex 16` with `/dev/urandom` fallback.
- Quiet mode for scriptable JSON output.

## Requirements
- Bash, `awk`, `bc`, `xxd` (from `vim-common`), `openssl` (v3+).
- Python 3 (stdlib only) for deterministic Keccak-256 and elliptic curve helpers.

On Debian/Ubuntu:
```
sudo apt update && sudo apt install -y jq bc vim-common openssl python3 python3-pip
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

## Tests

Run all tests:
```
make check
```
What is covered:
- BIP‑39 seed vector (known mnemonic + passphrase `TREZOR`).
- Generated mnemonic checksum roundtrip.
- Environment overrides and guard rails.
- Deterministic Keccak-256 primitives, vector regeneration, and signature verification (when signature secret provided).
- secp256k1 primitive self-test and signed public key vectors.

When available, export `KECCAK_VECTOR_SIG_B64` (base64 signature issued by the maintainer key in `tests/fixtures/keccak_reference_pub.pem`) to enforce fixture signing checks.
Set `SECP256K1_VECTOR_SIG_B64` to the base64-encoded detached signature produced by the maintainer key stored in `tests/fixtures/secp256k1_vectors_pub.pem` to validate the secp256k1 bundle.

### Development
- Lint shell scripts:
```
make lint
```
- Ensure dependencies and venv:
```
make deps
make venv
```

### Scripts
- `scripts/check_deps.sh`: Verify CLI dependencies.
- `scripts/ensure_venv.sh`: Create `.venv` for local tooling.
- `scripts/keccak_primitives.py`: Constant-time Keccak-256 helpers and CLI.
- `scripts/has_keccak.py`: Sanity-check the internal Keccak primitive.
- `scripts/eip55_recompute.py`: Recompute EIP‑55 checksum for an address.
- `scripts/keccak256.py`: Keccak‑256 of stdin bytes to hex via internal primitive.

## Notes on Keccak vs SHA‑3
Ethereum uses Keccak‑256 (pre‑NIST) for addresses, not SHA3‑256. This repository ships a constant-time, pure-Python Keccak-256 implementation in `scripts/keccak_primitives.py`, so no external cryptography packages are required.

## Security
- This is a demo/reference script. Do not use on untrusted machines.
- Never paste real seed phrases into terminals on shared environments.
- Consider air‑gapped usage and review the code before production use.
To audit only the secp256k1 primitive helper:
```
python3 scripts/derive_seed_and_pub.py selftest
```

