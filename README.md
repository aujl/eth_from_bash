# Ethereum Keys from Bash

Deterministically derive an Ethereum private key and address from a BIP‑39 mnemonic using plain Bash with OpenSSL and Python for Keccak.

This repo includes:
- `eth-from-bash.sh`: BIP‑39 seed (PBKDF2), BIP‑32 (secp256k1) derivation for `m/44'/60'/0'/0/0`, public key → Ethereum address (Keccak‑256 + EIP‑55).
- `english_bip-39.txt`: Standard 2048‑word English BIP‑39 wordlist.
- `tests/run.sh`: Sanity tests for BIP‑39 seed vector, mnemonic checksum, and EIP‑55.

## Features
- BIP‑39 mnemonic generation (128‑bit entropy) or import via `--mnemonic`.
- Seed derivation via OpenSSL 3 PBKDF2 (HMAC‑SHA512, 2048 iters).
- BIP‑32 derivation with guards: skips invalid `IL >= n` or child key = 0.
- Ethereum address: Keccak‑256 of uncompressed pubkey (no prefix), EIP‑55 checksum.
- Non-blocking entropy via `openssl rand -hex 16` with `/dev/urandom` fallback.
- Quiet mode for scriptable JSON output.

## Requirements
- Bash, `awk`, `bc`, `xxd` (from `vim-common`), `openssl` (v3+), `perl`.
- Python 3 with `pycryptodome` for Keccak‑256 (recommended):
  - Ubuntu/Debian: `sudo apt install python3-pycryptodome`
  - Or via pip: `pip install pycryptodome`
- Optional fallback: Perl `Digest::Keccak` if Python Keccak is missing.

On Debian/Ubuntu:
```
sudo apt update && sudo apt install -y jq bc vim-common openssl perl python3 python3-pip python3-pycryptodome
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
- Keccak provider presence and EIP‑55 validation (when Keccak is available).

If your system Python lacks Keccak, `make check` will create a local virtualenv in `.venv/` and install `pycryptodome` there automatically, then run the tests using that environment.

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
- `scripts/ensure_venv.sh`: Create `.venv` and install `pycryptodome`.
- `scripts/has_keccak.py`: Detect Python Keccak provider.
- `scripts/has_perl_keccak.pl`: Detect Perl Keccak provider.
- `scripts/eip55_recompute.py|.pl`: Recompute EIP‑55 checksum for an address.
- `scripts/keccak256.py`: Keccak‑256 of stdin bytes to hex.

## Notes on Keccak vs SHA‑3
Ethereum uses Keccak‑256 (pre‑NIST) for addresses, not SHA3‑256. The script prefers Python `pycryptodome` (`Crypto.Hash.keccak`) to compute Keccak‑256. If no Keccak provider is installed, use `--no-address` or install one of:
- `pip install pycryptodome` (recommended)
- `sudo apt install libdigest-keccak-perl`

## Security
- This is a demo/reference script. Do not use on untrusted machines.
- Never paste real seed phrases into terminals on shared environments.
- Consider air‑gapped usage and review the code before production use.
