#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/crypto/sha2.sh
source "${SCRIPT_DIR}/lib/crypto/sha2.sh"

export LC_ALL=C

usage() {
  cat <<'USAGE'
Usage: crypto_kdf.sh <command> [options]

Commands:
  pbkdf2         Derive PBKDF2-HMAC-SHA512 seed (BIP-39 semantics)
  hmac-sha512    Compute HMAC-SHA512 over hex-encoded inputs
  hmac-sha256    Compute HMAC-SHA256 over hex-encoded inputs
USAGE
}

error() {
  local message=$1
  echo "${message}" >&2
}

validate_hex() {
  local label=$1
  local value=$2
  local trimmed
  trimmed=${value//$'\t\r\n '/}
  if [[ -z ${trimmed} ]]; then
    error "${label} must be non-empty hex"
    return 2
  fi
  if (( ${#trimmed} % 2 != 0 )); then
    error "${label} must have an even number of characters"
    return 2
  fi
  if [[ ! ${trimmed} =~ ^[0-9A-Fa-f]+$ ]]; then
    error "${label} must be hexadecimal"
    return 2
  fi
  printf '%s' "${trimmed,,}"
}

ascii_to_hex() {
  local input=$1
  if [[ -z ${input} ]]; then
    printf ''
    return
  fi
  printf '%s' "${input}" | xxd -p -c 256 | tr -d '\n'
}

hex_to_raw() {
  local hex=${1:-}
  if [[ -z ${hex} ]]; then
    return 0
  fi
  local formatted=""
  local i=0
  while (( i < ${#hex} )); do
    formatted+="\\x${hex:i:2}"
    i=$((i + 2))
  done
  printf '%b' "${formatted}"
}

pad_hex_to_block() {
  local hex=${1:-}
  local block_bytes=$2
  local target_length=$((block_bytes * 2))
  while (( ${#hex} < target_length )); do
    hex+="00"
  done
  printf '%s' "${hex:0:target_length}"
}

xor_hex_with_byte() {
  local hex=${1:-}
  local byte=${2:-00}
  local result=""
  local i=0
  local chunk value
  while (( i < ${#hex} )); do
    chunk=${hex:i:2}
    if [[ ${#chunk} -ne 2 ]]; then
      chunk+="0"
    fi
    value=$((16#${chunk} ^ 16#${byte}))
    result+=$(printf '%02x' "${value}")
    i=$((i + 2))
  done
  printf '%s' "${result}"
}

xor_hex_strings() {
  local left=$1
  local right=$2
  local result=""
  local i=0
  local a b value
  local max_len=${#left}
  while (( i < max_len )); do
    a=${left:i:2}
    b=${right:i:2}
    value=$((16#${a} ^ 16#${b}))
    result+=$(printf '%02x' "${value}")
    i=$((i + 2))
  done
  printf '%s' "${result}"
}

be32_hex() {
  local value=$1
  printf '%08x' "${value}"
}

hmac_hex() {
  local algo=$1
  local key_hex=$2
  local data_hex=$3
  local block_size
  local hash_func
  case ${algo} in
    sha256)
      block_size=64
      hash_func=sha256_hex_from_stream
      ;;
    sha512)
      block_size=128
      hash_func=sha512_hex_from_stream
      ;;
    *)
      error "unsupported hmac algo: ${algo}"
      return 2
      ;;
  esac

  key_hex=${key_hex,,}
  data_hex=${data_hex,,}

  local key_len_bytes=$(( ${#key_hex} / 2 ))
  if (( key_len_bytes > block_size )); then
    key_hex="$(hex_to_raw "${key_hex}" | "${hash_func}")"
    key_len_bytes=$(( ${#key_hex} / 2 ))
  fi

  local block_hex
  block_hex="$(pad_hex_to_block "${key_hex}" "${block_size}")"

  local ipad_hex opad_hex
  ipad_hex="$(xor_hex_with_byte "${block_hex}" "36")"
  opad_hex="$(xor_hex_with_byte "${block_hex}" "5c")"

  local inner_digest outer_digest
  inner_digest="$({
    hex_to_raw "${ipad_hex}"
    hex_to_raw "${data_hex}"
  } | "${hash_func}")"
  outer_digest="$({
    hex_to_raw "${opad_hex}"
    hex_to_raw "${inner_digest}"
  } | "${hash_func}")"

  printf '%s' "${outer_digest}"
}

pbkdf2_hmac_sha512() {
  local password_hex=$1
  local salt_hex=$2
  local iterations=$3
  local dk_len_bytes=64
  if (( iterations <= 0 )); then
    error "iterations must be positive"
    return 2
  fi
  local hlen=64
  local block_count=$(( (dk_len_bytes + hlen - 1) / hlen ))
  local derived=""
  local block=1
  while (( block <= block_count )); do
    local block_hex
    block_hex="$(be32_hex "${block}")"
    local u
    u="$(hmac_hex sha512 "${password_hex}" "${salt_hex}${block_hex}")"
    local t="${u}"
    local i=2
    while (( i <= iterations )); do
      u="$(hmac_hex sha512 "${password_hex}" "${u}")"
      t="$(xor_hex_strings "${t}" "${u}")"
      ((i++))
    done
    derived+="${t}"
    ((block++))
  done
  printf '%s' "${derived:0:$((dk_len_bytes * 2))}"
}

pbkdf2_hmac_sha512_openssl() {
  local password_hex=$1
  local salt_hex=$2
  local iterations=$3

  command -v openssl >/dev/null 2>&1 || return 1

  openssl kdf \
    -keylen 64 \
    -kdfopt digest:sha512 \
    -kdfopt "hexpass:${password_hex}" \
    -kdfopt "hexsalt:${salt_hex}" \
    -kdfopt "iter:${iterations}" \
    PBKDF2 2>/dev/null \
    | tr -d '[:space:]:' \
    | tr 'A-F' 'a-f'
}

command_hmac_sha512() {
  local key_hex=""
  local data_hex=""
  while [[ $# -gt 0 ]]; do
    case $1 in
      --key-hex)
        shift
        if [[ $# -eq 0 ]]; then
          error "--key-hex requires a value"
          exit 2
        fi
        key_hex=$(validate_hex "key" "$1") || exit 2
        shift
        ;;
      --data-hex)
        shift
        if [[ $# -eq 0 ]]; then
          error "--data-hex requires a value"
          exit 2
        fi
        data_hex=$(validate_hex "data" "$1") || exit 2
        shift
        ;;
      *)
        error "Unknown argument: $1"
        exit 2
        ;;
    esac
  done
  printf '%s\n' "$(hmac_hex sha512 "${key_hex}" "${data_hex}")"
}

command_hmac_sha256() {
  local key_hex=""
  local data_hex=""
  while [[ $# -gt 0 ]]; do
    case $1 in
      --key-hex)
        shift
        if [[ $# -eq 0 ]]; then
          error "--key-hex requires a value"
          exit 2
        fi
        key_hex=$(validate_hex "key" "$1") || exit 2
        shift
        ;;
      --data-hex)
        shift
        if [[ $# -eq 0 ]]; then
          error "--data-hex requires a value"
          exit 2
        fi
        data_hex=$(validate_hex "data" "$1") || exit 2
        shift
        ;;
      *)
        error "Unknown argument: $1"
        exit 2
        ;;
    esac
  done
  printf '%s\n' "$(hmac_hex sha256 "${key_hex}" "${data_hex}")"
}

command_pbkdf2() {
  local mnemonic=""
  local passphrase=""
  local iterations=2048
  while [[ $# -gt 0 ]]; do
    case $1 in
      --mnemonic)
        shift
        if [[ $# -eq 0 ]]; then
          error "--mnemonic requires a value"
          exit 2
        fi
        mnemonic=$1
        shift
        ;;
      --passphrase)
        shift
        if [[ $# -eq 0 ]]; then
          error "--passphrase requires a value"
          exit 2
        fi
        passphrase=$1
        shift
        ;;
      --iterations)
        shift
        if [[ $# -eq 0 ]]; then
          error "--iterations requires a value"
          exit 2
        fi
        iterations=$1
        shift
        ;;
      *)
        error "Unknown argument: $1"
        exit 2
        ;;
    esac
  done
  if [[ -z ${mnemonic} ]]; then
    error "Mnemonic is required"
    exit 2
  fi
  if [[ ! ${iterations} =~ ^[0-9]+$ ]]; then
    error "Iterations must be a positive integer"
    exit 2
  fi
  if (( iterations <= 0 )); then
    error "Iterations must be greater than zero"
    exit 2
  fi
  local salt="mnemonic${passphrase}"
  local mnemonic_hex
  mnemonic_hex=$(ascii_to_hex "${mnemonic}")
  local salt_hex
  salt_hex=$(ascii_to_hex "${salt}")
  local derived
  if ! derived="$(pbkdf2_hmac_sha512_openssl "${mnemonic_hex}" "${salt_hex}" "${iterations}")"; then
    derived="$(pbkdf2_hmac_sha512 "${mnemonic_hex}" "${salt_hex}" "${iterations}")"
  fi
  printf '%s\n' "${derived}"
}

main() {
  if [[ $# -eq 0 ]]; then
    usage >&2
    exit 2
  fi
  local command=$1
  shift || true
  case ${command} in
    pbkdf2)
      command_pbkdf2 "$@"
      ;;
    hmac-sha512)
      command_hmac_sha512 "$@"
      ;;
    hmac-sha256)
      command_hmac_sha256 "$@"
      ;;
    -h|--help)
      usage
      ;;
    *)
      error "Unknown command: ${command}"
      usage >&2
      exit 2
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
