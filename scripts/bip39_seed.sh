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

if ! command -v xxd >/dev/null 2>&1; then
  echo "xxd command not found" >&2
  exit 1
fi

salt="mnemonic${passphrase}"

seed_hex="$(
  openssl kdf -binary -keylen 64 \
    -kdfopt digest:SHA512 \
    -kdfopt iter:2048 \
    -kdfopt kdf:PBKDF2 \
    -kdfopt "pass:${mnemonic}" \
    -kdfopt "salt:${salt}" \
    2>/dev/null | \
    xxd -p -c 1000
)"

if [[ -z "${seed_hex}" ]]; then
  echo "Failed to derive seed with openssl" >&2
  exit 1
fi

seed_hex="${seed_hex//[$'\n\r\t ']/}"

if [[ ${#seed_hex} -ne 128 ]]; then
  echo "Unexpected seed length from openssl" >&2
  exit 1
fi

printf '%s\n' "${seed_hex,,}"
