# shellcheck shell=bash
# Base58 encoding utilities (Bitcoin alphabet)

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  echo "scripts/lib/encoding/base58.sh must be sourced" >&2
  exit 1
fi

readonly BASE58_ALPHABET="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

base58__require_bc() {
  if ! command -v bc >/dev/null 2>&1; then
    echo "bc is required for base58 encoding" >&2
    return 1
  fi
}

base58_hex_normalize() {
  local hex="${1,,}"
  hex="${hex//[^0-9a-f]/}"
  if (( ${#hex} % 2 == 1 )); then
    hex="0${hex}"
  fi
  printf '%s' "${hex}"
}

base58_bc_eval() {
  local expr="$1"
  bc <<<"${expr}" | tr -d ' \n'
}

base58_encode_hex() {
  base58__require_bc || return 1
  local input_hex
  input_hex="$(base58_hex_normalize "${1:-}")"
  if [[ -z "${input_hex}" ]]; then
    printf ''
    return 0
  fi

  local leading_zero_bytes=0
  local value_hex="${input_hex}"
  while [[ ${#value_hex} -gt 0 && ${value_hex:0:2} == "00" ]]; do
    value_hex="${value_hex:2}"
    ((leading_zero_bytes++))
  done

  local result=""
  local dec="0"
  if [[ -n "${value_hex}" ]]; then
    dec="$(base58_bc_eval "ibase=16; ${value_hex}")"
    if [[ -z "${dec}" ]]; then
      dec="0"
    fi
  fi

  while [[ "${dec}" != "0" ]]; do
    local remainder
    remainder="$(base58_bc_eval "${dec} % 58")"
    dec="$(base58_bc_eval "${dec} / 58")"
    if [[ -z "${remainder}" ]]; then
      remainder="0"
    fi
    local idx=$((10#${remainder}))
    local ch="${BASE58_ALPHABET:idx:1}"
    result="${ch}${result}"
  done

  local prefix=""
  if (( leading_zero_bytes > 0 )); then
    printf -v prefix '%*s' "${leading_zero_bytes}" ''
    prefix=${prefix// /1}
  fi

  if [[ -n "${result}" ]]; then
    printf '%s%s' "${prefix}" "${result}"
  else
    if [[ -n "${prefix}" ]]; then
      printf '%s' "${prefix}"
    else
      printf '1'
    fi
  fi
}

export -f base58_encode_hex
