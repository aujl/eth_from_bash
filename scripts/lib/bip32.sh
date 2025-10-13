# shellcheck shell=bash
# BIP-32 (secp256k1) helper primitives for eth-from-bash.

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  echo "scripts/lib/bip32.sh must be sourced, not executed" >&2
  exit 1
fi

readonly BIP32_SECP256K1_N_HEX="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
readonly BIP32_SEED_KEY_HEX="426974636F696E2073656564"

bip32__debug(){
  if declare -F debug >/dev/null 2>&1; then
    debug "$@"
  elif [[ ${BIP32_DEBUG:-0} -eq 1 ]]; then
    echo "$@" >&2
  fi
}

bip32_bn_add_mod_n(){
  local a="$1" b="$2"
  a="${a^^}"
  b="${b^^}"
  local sum
  sum="$(bc <<<"obase=16; ibase=16; ( ${a} + ${b} ) % ${BIP32_SECP256K1_N_HEX}")"
  sum="${sum^^}"
  printf "%064s" "${sum}" | tr ' ' 0
}

bip32_bn_ge(){
  local a="${1^^}" b="${2^^}"
  bc <<<"obase=10; ibase=16; ${a} >= ${b}"
}

bip32_bn_is_zero(){
  local a="${1^^}"
  [[ "${a}" =~ ^0+$ ]] && { echo 1; return; }
  echo 0
}

bip32_validate_private_scalar(){
  local candidate="$1"
  local label="${2:-scalar}"
  if [[ ! "${candidate}" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    echo "Invalid ${label}: must be 64 hex characters" >&2
    return 1
  fi
  local ge_result
  ge_result="$(bip32_bn_ge "${candidate}" "${BIP32_SECP256K1_N_HEX}")"
  if [[ "${ge_result}" -eq 1 ]]; then
    echo "Invalid ${label}: value >= curve order" >&2
    return 1
  fi
  local zero_result
  zero_result="$(bip32_bn_is_zero "${candidate}")"
  if [[ "${zero_result}" -eq 1 ]]; then
    echo "Invalid ${label}: zero" >&2
    return 1
  fi
}

bip32_hmac_sha512(){
  local key_hex="$1" data_hex="$2"
  local helper="${CRYPTO_KDF_HELPER:-}"
  if [[ -z "${helper}" || ! -x "${helper}" ]]; then
    echo "Crypto helper '${helper}' not executable" >&2
    return 1
  fi
  "${helper}" hmac-sha512 --key-hex "${key_hex}" --data-hex "${data_hex}"
}

bip32_master_from_seed(){
  local seed_hex="$1"
  local imaster
  imaster="$(bip32_hmac_sha512 "${BIP32_SEED_KEY_HEX}" "${seed_hex}")"
  local il="${imaster:0:64}"
  local ir="${imaster:64:64}"
  bip32_validate_private_scalar "${il}" "master IL" || return 1
  printf '%s %s\n' "${il}" "${ir}"
}

bip32_pub_from_private(){
  local khex="$1"
  local helper="${SECP256K1_HELPER:-}"
  if [[ -z "${helper}" || ! -x "${helper}" ]]; then
    echo "secp256k1 helper '${helper}' not executable" >&2
    return 1
  fi
  "${helper}" pub --priv-hex "${khex}"
}

bip32_pub_compressed_from_priv_hex(){
  local khex="$1"
  local comp
  read -r comp _ < <(bip32_pub_from_private "${khex}")
  printf '%s' "${comp}"
}

bip32_derive_hardened(){
  local kpar="$1" cpar="$2" index="$3"
  local idx="${index}"
  while :; do
    local i_hex
    printf -v i_hex "%08X" $((idx | 0x80000000))
    local data="00${kpar}${i_hex}"
    local I
    I="$(bip32_hmac_sha512 "${cpar}" "${data}")" || return 1
    local ILc="${I:0:64}" IRc="${I:64:64}"
    local child_k
    child_k="$(bip32_bn_add_mod_n "${ILc}" "${kpar}")"
    local ge
    ge="$(bip32_bn_ge "${ILc}" "${BIP32_SECP256K1_N_HEX}")"
    local iz
    iz="$(bip32_bn_is_zero "${child_k}")"
    if [[ "${ge}" -eq 1 ]] || [[ "${iz}" -eq 1 ]]; then
      bip32__debug "hardened idx ${idx} invalid (IL>=n or child=0), trying $((idx+1))"
      idx=$((idx+1))
      continue
    fi
    printf '%s %s\n' "${child_k}" "${IRc}"
    break
  done
}

bip32_derive_normal(){
  local kpar="$1" cpar="$2" index="$3"
  local idx="${index}"
  while :; do
    local i_hex
    printf -v i_hex "%08X" "${idx}"
    local Kpar_comp
    Kpar_comp="$(bip32_pub_compressed_from_priv_hex "${kpar}")" || return 1
    local data="${Kpar_comp}${i_hex}"
    local I
    I="$(bip32_hmac_sha512 "${cpar}" "${data}")" || return 1
    local ILc="${I:0:64}" IRc="${I:64:64}"
    local child_k
    child_k="$(bip32_bn_add_mod_n "${ILc}" "${kpar}")"
    local ge
    ge="$(bip32_bn_ge "${ILc}" "${BIP32_SECP256K1_N_HEX}")"
    local iz
    iz="$(bip32_bn_is_zero "${child_k}")"
    if [[ "${ge}" -eq 1 ]] || [[ "${iz}" -eq 1 ]]; then
      bip32__debug "normal idx ${idx} invalid (IL>=n or child=0), trying $((idx+1))"
      idx=$((idx+1))
      continue
    fi
    printf '%s %s\n' "${child_k}" "${IRc}"
    break
  done
}

bip32_derive_path_segments(){
  local k="$1" c="$2"
  shift 2 || true
  local segment
  for segment in "$@"; do
    if [[ "${segment}" =~ ^([0-9]+)\'$ ]]; then
      read -r k c < <(bip32_derive_hardened "${k}" "${c}" "${BASH_REMATCH[1]}") || return 1
    elif [[ "${segment}" =~ ^[0-9]+$ ]]; then
      read -r k c < <(bip32_derive_normal "${k}" "${c}" "${segment}") || return 1
    else
      echo "Invalid path segment '${segment}'" >&2
      return 1
    fi
    bip32_validate_private_scalar "${k}" "derived ${segment} private key" || return 1
  done
  printf '%s %s\n' "${k}" "${c}"
}

export -f bip32_bn_add_mod_n
export -f bip32_bn_ge
export -f bip32_bn_is_zero
export -f bip32_validate_private_scalar
export -f bip32_hmac_sha512
export -f bip32_master_from_seed
export -f bip32_pub_from_private
export -f bip32_pub_compressed_from_priv_hex
export -f bip32_derive_hardened
export -f bip32_derive_normal
export -f bip32_derive_path_segments
