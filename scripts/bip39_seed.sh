#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: bip39_seed.sh --mnemonic "<mnemonic>" [--passphrase "<passphrase>"]

Derive a 64-byte BIP-39 seed using OpenSSL's PBKDF2 implementation.
Outputs lowercase hexadecimal without trailing whitespace.
USAGE
}

mnemonic=""
passphrase=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mnemonic)
      shift
      if [[ $# -eq 0 ]]; then
        echo "--mnemonic requires a value" >&2
        exit 2
      fi
      mnemonic="${1}"
      shift
      ;;
    --passphrase)
      shift
      if [[ $# -eq 0 ]]; then
        echo "--passphrase requires a value" >&2
        exit 2
      fi
      passphrase="${1}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${mnemonic}" ]]; then
  echo "Mnemonic is required" >&2
  usage >&2
  exit 2
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl command not found" >&2
  exit 1
fi

derive_with_openssl() {
  local salt="mnemonic${passphrase}"
  local output
  if ! output="$(
    openssl kdf -keylen 64 \
      -kdfopt digest:SHA512 \
      -kdfopt iter:2048 \
      -kdfopt "pass:${mnemonic}" \
      -kdfopt "salt:${salt}" \
      PBKDF2 2>/dev/null
  )"; then
    return 1
  fi
  output="${output//[$'\n\r\t ']/}"
  output="${output//:/}"
  printf '%s' "${output}"
}

derive_with_python() {
  python3 - "$mnemonic" "$passphrase" <<'PY'
import sys
import binascii
import hashlib
import unicodedata

if len(sys.argv) != 3:
    raise SystemExit("expected mnemonic and passphrase")

mnemonic = unicodedata.normalize("NFKD", sys.argv[1])
passphrase = unicodedata.normalize("NFKD", sys.argv[2])
salt = "mnemonic" + passphrase
seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), salt.encode(), 2048, dklen=64)
print(binascii.hexlify(seed).decode())
PY
}

openssl_supports_kdf() {
  openssl kdf -keylen 1 -kdfopt pass:x -kdfopt salt:y PBKDF2 >/dev/null 2>&1
}

seed_hex=""
if openssl_supports_kdf; then
  seed_hex="$(derive_with_openssl || true)"
fi

if [[ -z "${seed_hex}" ]]; then
  if ! command -v python3 >/dev/null 2>&1; then
    echo "Unable to derive seed: openssl kdf unsupported and python3 missing" >&2
    exit 1
  fi
  if ! seed_hex="$(derive_with_python)"; then
    echo "Failed to derive seed with python fallback" >&2
    exit 1
  fi
fi

seed_hex="${seed_hex//[$'\n\r\t ']/}"

if [[ ${#seed_hex} -ne 128 ]]; then
  echo "Unexpected seed length" >&2
  exit 1
fi

printf '%s\n' "${seed_hex,,}"
