#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: crypto_sign.sh <command> [options]

Commands:
  hmac-sha256    Compute HMAC-SHA256 digest
  random-bytes   Generate random bytes from /dev/urandom

Run "crypto_sign.sh <command> --help" for command-specific flags.
USAGE
}

usage_hmac() {
  cat <<'USAGE'
Usage: crypto_sign.sh hmac-sha256 --key <path|-> --message <path|-> [--output hex|base64|raw]
USAGE
}

usage_random() {
  cat <<'USAGE'
Usage: crypto_sign.sh random-bytes --count <n> [--output hex|base64|raw]
USAGE
}

read_bytes() {
  local path="$1"
  if [[ "${path}" == "-" ]]; then
    cat
  else
    cat "${path}"
  fi
}

read_hex() {
  local path="$1"
  if [[ "${path}" == "-" ]]; then
    od -An -tx1 -v | tr -d ' \n'
  else
    od -An -tx1 -v "${path}" | tr -d ' \n'
  fi
}

hex_to_raw() {
  local hex="$1"
  if [[ -z "${hex}" ]]; then
    return 0
  fi
  local formatted
  formatted="$(printf '%s' "${hex}" | sed 's/../\\x&/g')"
  printf '%b' "${formatted}"
}

pad_hex_to_block() {
  local hex="$1"
  local block_bytes="$2"
  local target=$((block_bytes * 2))
  while (( ${#hex} < target )); do
    hex+="00"
  done
  printf '%s' "${hex:0:target}"
}

xor_hex_with_byte() {
  local hex="$1"
  local byte="$2"
  local result=""
  local i=0
  local chunk value
  while (( i < ${#hex} )); do
    chunk="${hex:i:2}"
    if [[ ${#chunk} -ne 2 ]]; then
      chunk+="0"
    fi
    value=$((16#${chunk} ^ 16#${byte}))
    result+=$(printf '%02x' "${value}")
    i=$((i + 2))
  done
  printf '%s' "${result}"
}

sha256_hex_from_stream() {
  sha256sum | cut -d' ' -f1
}

cmd_hmac_sha256() {
  local key_path=""
  local message_path=""
  local output_format="hex"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --key)
        [[ $# -lt 2 ]] && { usage_hmac >&2; return 1; }
        key_path="$2"
        shift 2
        ;;
      --message)
        [[ $# -lt 2 ]] && { usage_hmac >&2; return 1; }
        message_path="$2"
        shift 2
        ;;
      --output)
        [[ $# -lt 2 ]] && { usage_hmac >&2; return 1; }
        output_format="$2"
        shift 2
        ;;
      --help)
        usage_hmac
        return 0
        ;;
      *)
        echo "Unknown option for hmac-sha256: $1" >&2
        usage_hmac >&2
        return 1
        ;;
    esac
  done

  if [[ -z "${key_path}" || -z "${message_path}" ]]; then
    usage_hmac >&2
    return 1
  fi

  local key_hex block_hex ipad_hex opad_hex
  key_hex="$(read_hex "${key_path}")"

  local block_size=64
  local key_len_bytes=$(( ${#key_hex} / 2 ))
  if (( key_len_bytes > block_size )); then
    key_hex="$(hex_to_raw "${key_hex}" | sha256_hex_from_stream)"
  fi
  block_hex="$(pad_hex_to_block "${key_hex}" "${block_size}")"
  ipad_hex="$(xor_hex_with_byte "${block_hex}" "36")"
  opad_hex="$(xor_hex_with_byte "${block_hex}" "5c")"

  local inner_digest outer_digest
  inner_digest="$({
    hex_to_raw "${ipad_hex}"
    read_bytes "${message_path}"
  } | sha256_hex_from_stream)"

  outer_digest="$({
    hex_to_raw "${opad_hex}"
    hex_to_raw "${inner_digest}"
  } | sha256_hex_from_stream)"

  case "${output_format}" in
    hex)
      printf '%s\n' "${outer_digest}"
      ;;
    base64)
      hex_to_raw "${outer_digest}" | base64 | tr -d '\n'
      printf '\n'
      ;;
    raw)
      hex_to_raw "${outer_digest}"
      ;;
    *)
      echo "Invalid output format: ${output_format}" >&2
      return 1
      ;;
  esac
}

cmd_random_bytes() {
  local count=""
  local output_format="hex"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --count)
        [[ $# -lt 2 ]] && { usage_random >&2; return 1; }
        count="$2"
        shift 2
        ;;
      --output)
        [[ $# -lt 2 ]] && { usage_random >&2; return 1; }
        output_format="$2"
        shift 2
        ;;
      --help)
        usage_random
        return 0
        ;;
      *)
        echo "Unknown option for random-bytes: $1" >&2
        usage_random >&2
        return 1
        ;;
    esac
  done

  if [[ -z "${count}" ]]; then
    usage_random >&2
    return 1
  fi
  if ! [[ "${count}" =~ ^[0-9]+$ ]] || (( count < 0 )); then
    echo "--count must be a non-negative integer" >&2
    return 1
  fi

  case "${output_format}" in
    hex)
      dd if=/dev/urandom bs=1 count="${count}" status=none | od -An -tx1 -v | tr -d ' \n'
      printf '\n'
      ;;
    base64)
      dd if=/dev/urandom bs=1 count="${count}" status=none | base64 | tr -d '\n'
      printf '\n'
      ;;
    raw)
      dd if=/dev/urandom bs=1 count="${count}" status=none
      ;;
    *)
      echo "Invalid output format: ${output_format}" >&2
      return 1
      ;;
  esac
}

main() {
  if [[ $# -eq 0 ]]; then
    usage >&2
    return 1
  fi
  local command="$1"
  shift
  case "${command}" in
    hmac-sha256)
      cmd_hmac_sha256 "$@"
      ;;
    random-bytes)
      cmd_random_bytes "$@"
      ;;
    --help|-h)
      usage
      ;;
    *)
      echo "Unknown command: ${command}" >&2
      usage >&2
      return 1
      ;;
  esac
}

main "$@"
