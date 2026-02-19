#!/usr/bin/env bash
set -euo pipefail

resolve_path() {
  local target="$1"
  local dir base
  dir="$(cd "$(dirname "${target}")" && pwd -P)"
  base="$(basename "${target}")"
  printf '%s/%s\n' "${dir}" "${base}"
}

SCRIPT_PATH="$(resolve_path "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname "${SCRIPT_PATH}")"
DEFAULT_KDF_HELPER="${SCRIPT_DIR}/crypto_kdf.sh"
CRYPTO_KDF_HELPER="${CRYPTO_KDF_HELPER:-${DEFAULT_KDF_HELPER}}"
CRYPTO_KDF_HELPER="$(resolve_path "${CRYPTO_KDF_HELPER}")"

if [[ "${CRYPTO_KDF_HELPER}" == "${SCRIPT_PATH}" ]]; then
  CRYPTO_KDF_HELPER="${DEFAULT_KDF_HELPER}"
fi

usage() {
  cat <<'USAGE'
Usage: bip39_seed.sh --mnemonic "<mnemonic>" [--passphrase "<passphrase>"]

Derive a 64-byte BIP-39 seed using PBKDF2-HMAC-SHA512.
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

if [[ ! -x "${CRYPTO_KDF_HELPER}" ]]; then
  echo "PBKDF2 helper '${CRYPTO_KDF_HELPER}' not executable" >&2
  exit 1
fi

seed_hex="$(
  "${CRYPTO_KDF_HELPER}" pbkdf2 \
    --mnemonic "${mnemonic}" \
    --passphrase "${passphrase}" \
    || true
)"

if [[ -z "${seed_hex}" ]]; then
  echo "Failed to derive seed with PBKDF2 helper." >&2
  exit 1
fi

seed_hex="${seed_hex//[$'\n\r\t ']/}"

if [[ ${#seed_hex} -ne 128 ]]; then
  echo "Unexpected seed length" >&2
  exit 1
fi

printf '%s\n' "${seed_hex,,}"
