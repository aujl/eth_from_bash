# shellcheck shell=bash

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "scripts/lib/common/bootstrap.sh must be sourced" >&2
  exit 1
fi

eth_from_bash::source_relative() {
  local repo_root="$1"
  shift || true
  local rel
  for rel in "$@"; do
    local path="${repo_root}/${rel}"
    [[ -r "${path}" ]] || continue
    # shellcheck source=/dev/null
    source "${path}"
  done
}

eth_from_bash::ensure_executable() {
  local path="$1" label="$2"
  if [[ ! -x "${path}" ]]; then
    echo "${label} '${path}' not executable" >&2
    return 1
  fi
}

eth_from_bash::require_commands() {
  local missing=0
  local cmd
  for cmd in "$@"; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
      echo "Required tool '${cmd}' missing" >&2
      missing=1
    fi
  done
  if (( missing )); then
    return 1
  fi
}

eth_from_bash::set_helper_defaults() {
  local repo_root="$1"
  BIP39_HELPER="${BIP39_HELPER:-${repo_root}/scripts/bip39_seed.sh}"
  CRYPTO_KDF_HELPER="${CRYPTO_KDF_HELPER:-${repo_root}/scripts/crypto_kdf.sh}"
  SECP256K1_HELPER="${SECP256K1_HELPER:-${repo_root}/scripts/secp256k1_pub.sh}"
  KECCAK_HELPER="${KECCAK_HELPER:-${repo_root}/scripts/keccak256.sh}"
  EIP55_HELPER="${EIP55_HELPER:-${repo_root}/scripts/eip55_checksum.sh}"
  CRYPTO_SIGN_HELPER="${CRYPTO_SIGN_HELPER:-${repo_root}/bin/crypto-sign}"
  export BIP39_HELPER
  export CRYPTO_KDF_HELPER
  export SECP256K1_HELPER
  export KECCAK_HELPER
  export EIP55_HELPER
  export CRYPTO_SIGN_HELPER
}

eth_from_bash::ensure_helper_executables() {
  eth_from_bash::ensure_executable "${BIP39_HELPER}" "Seed helper" || return 1
  eth_from_bash::ensure_executable "${CRYPTO_KDF_HELPER}" "Crypto helper" || return 1
  eth_from_bash::ensure_executable "${SECP256K1_HELPER}" "secp256k1 helper" || return 1
  eth_from_bash::ensure_executable "${KECCAK_HELPER}" "Keccak helper" || return 1
  eth_from_bash::ensure_executable "${EIP55_HELPER}" "EIP-55 helper" || return 1
}

eth_from_bash::bootstrap_cli_environment() {
  local repo_root="$1"
  eth_from_bash::source_relative "${repo_root}" \
    "scripts/lib/bip/bip39.sh" \
    "scripts/lib/bip/bip32.sh" \
    "scripts/lib/crypto/sha2.sh"
  eth_from_bash::set_helper_defaults "${repo_root}"
  eth_from_bash::ensure_helper_executables
}
