#!/usr/bin/env bash
# eth-from-bash-perl-keccak.sh
# Like before, but uses libdigest-sha3-perl for the final Keccak / SHA3 step
# deps: bash, xxd, bc, awk, sha256sum, openssl, Perl with Digest::SHA3

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIP39_HELPER="${SCRIPT_DIR}/scripts/bip39_seed.sh"
SECP256K1_HELPER="${SCRIPT_DIR}/scripts/secp256k1_pub.sh"
KECCAK_HELPER="${SCRIPT_DIR}/scripts/keccak256.sh"
EIP55_HELPER="${SCRIPT_DIR}/scripts/eip55_checksum.sh"
PYTHON_BIN="${PYTHON_BIN:-python3}"

hex_to_bits() {
  local hex=${1:-}
  local upper=${hex^^}
  local -i i
  local char
  local result=""
  for ((i = 0; i < ${#upper}; i++)); do
    char=${upper:i:1}
    case "${char}" in
      0) result+=0000 ;;
      1) result+=0001 ;;
      2) result+=0010 ;;
      3) result+=0011 ;;
      4) result+=0100 ;;
      5) result+=0101 ;;
      6) result+=0110 ;;
      7) result+=0111 ;;
      8) result+=1000 ;;
      9) result+=1001 ;;
      A) result+=1010 ;;
      B) result+=1011 ;;
      C) result+=1100 ;;
      D) result+=1101 ;;
      E) result+=1110 ;;
      F) result+=1111 ;;
      "") ;;
      *)
        echo "Invalid hex character '${char}'" >&2
        return 1
        ;;
    esac
  done
  printf '%s' "${result}"
}


ENT_HEX_ENV="${ENT_HEX-}"
MNEMONIC_ENV="${MNEMONIC-}"

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  echo "Python interpreter '${PYTHON_BIN}' not found" >&2
  exit 1
fi

if [[ ! -x "${BIP39_HELPER}" ]]; then
  echo "Seed helper '${BIP39_HELPER}' not executable" >&2
  exit 1
fi

if [[ ! -x "${SECP256K1_HELPER}" ]]; then
  echo "secp256k1 helper '${SECP256K1_HELPER}' not executable" >&2
  exit 1
fi

if [[ ! -x "${KECCAK_HELPER}" ]]; then
  echo "Keccak helper '${KECCAK_HELPER}' not executable" >&2
  exit 1
fi

if [[ ! -x "${EIP55_HELPER}" ]]; then
  echo "EIP-55 helper '${EIP55_HELPER}' not executable" >&2
  exit 1
fi

# options: -q|--quiet to print only JSON
#          --mnemonic "w1 ... w12" to use provided phrase
#          --include-seed to include seed hex in JSON
QUIET=0
INCLUDE_SEED=0
USER_MNEMONIC=""
NO_ADDRESS=0
USE_ENV_MNEMONIC=0

if [[ -n "${MNEMONIC_ENV}" ]]; then
  USER_MNEMONIC="${MNEMONIC_ENV}"
  USE_ENV_MNEMONIC=1
fi

if [[ "${USE_ENV_MNEMONIC}" -eq 0 ]]; then
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -q|--quiet)
        QUIET=1; shift ;;
      --include-seed)
        INCLUDE_SEED=1; shift ;;
      --mnemonic)
        shift
        USER_MNEMONIC="${1-}"
        if [[ -z "${USER_MNEMONIC}" ]]; then echo "--mnemonic requires a value" >&2; exit 2; fi
        shift ;;
      --no-address)
        NO_ADDRESS=1; shift ;;
      --)
        shift; break ;;
      -*)
        echo "Unknown option: $1" >&2; exit 2 ;;
      *)
        break ;;
    esac
  done
else
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -q|--quiet)
        QUIET=1; shift ;;
      --include-seed)
        INCLUDE_SEED=1; shift ;;
      --no-address)
        NO_ADDRESS=1; shift ;;
      --mnemonic)
        echo "MNEMONIC environment variable is set; remove --mnemonic" >&2
        exit 2 ;;
      --)
        shift; break ;;
      -*)
        echo "Unknown option: $1" >&2; exit 2 ;;
      *)
        break ;;
    esac
  done
fi

debug(){ if [[ "${QUIET}" -eq 0 ]]; then echo "$@" >&2; fi }

WLIST="${1:?path to english.txt}"
shift || true
# Use remaining args as passphrase (may contain spaces)
PASSPHRASE="${*:-}"

# validate wordlist
[[ -r "${WLIST}" ]] || { echo "wordlist missing" >&2; exit 1; }
[[ "$(wc -l < "${WLIST}")" -eq 2048 ]] || { echo "wordlist must have 2048 lines" >&2; exit 1; }

# check dependencies
for cmd in xxd bc awk sha256sum openssl python3; do
  command -v "${cmd}" >/dev/null || { echo "need ${cmd}" >&2; exit 1; }
done

N_HEX="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"

bn_add_mod_n(){
  local a="$1" b="$2"
  # bc treats lowercase a-f as variables; force uppercase for hex digits
  a="${a^^}"
  b="${b^^}"
  # Important: set obase before ibase in bc. Otherwise obase=16 would be
  # interpreted in the new base (0x16 = 22), yielding spaced, non-hex output.
  local sum
  sum="$(bc <<<"obase=16; ibase=16; ( ${a} + ${b} ) % ${N_HEX}")"
  sum="${sum^^}"
  printf "%064s" "${sum}" | tr ' ' 0
}

# Return 1 if a >= b (hex), else 0
bn_ge(){
  local a="${1^^}" b="${2^^}"
  bc <<<"obase=10; ibase=16; ${a} >= ${b}"
}

bn_is_zero(){
  local a="${1^^}"
  # quick check for 64 zeros
  [[ "${a}" =~ ^0+$ ]] && { echo 1; return; }
  echo 0
}

validate_private_scalar(){
  local candidate="$1"
  local label="${2:-scalar}"
  if [[ ! "${candidate}" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    echo "Invalid ${label}: must be 64 hex characters" >&2
    exit 1
  fi
  local ge_result
  ge_result="$(bn_ge "${candidate}" "${N_HEX}")"
  if [[ "${ge_result}" -eq 1 ]]; then
    echo "Invalid ${label}: value >= curve order" >&2
    exit 1
  fi
  local zero_result
  zero_result="$(bn_is_zero "${candidate}")"
  if [[ "${zero_result}" -eq 1 ]]; then
    echo "Invalid ${label}: zero" >&2
    exit 1
  fi
}


# Use provided mnemonic if any; else generate new 128-bit entropy phrase
validate_entropy_hex(){
  local candidate="$1"
  if [[ ! "${candidate}" =~ ^[0-9a-fA-F]{32}$ ]]; then
    echo "ENT_HEX must be 32 hexadecimal characters" >&2
    exit 2
  fi
  printf '%s' "${candidate,,}"
}

generate_entropy_hex(){
  local hex
  if command -v openssl >/dev/null 2>&1; then
    if hex="$(openssl rand -hex 16 2>/dev/null)"; then
      if [[ "${hex}" =~ ^[0-9a-fA-F]{32}$ ]]; then
        printf '%s' "${hex,,}"
        return 0
      fi
    fi
    debug "openssl rand failed, falling back to /dev/urandom"
  fi
  if [[ -r /dev/urandom ]]; then
    hex="$(head -c 16 /dev/urandom | xxd -p -c 16 | tr -d '\n')"
    if [[ "${hex}" =~ ^[0-9a-fA-F]{32}$ ]]; then
      printf '%s' "${hex,,}"
      return 0
    fi
  fi
  echo "Unable to produce entropy: openssl rand failed and /dev/urandom unavailable" >&2
  exit 1
}

ENT_HEX_VALUE=""
if [[ -n "${ENT_HEX_ENV}" ]]; then
  ENT_HEX_VALUE="$(validate_entropy_hex "${ENT_HEX_ENV}")"
fi

if [[ -z "${USER_MNEMONIC}" ]]; then
  if [[ -z "${ENT_HEX_VALUE}" ]]; then
    ENT_HEX_VALUE="$(generate_entropy_hex)"
  fi
else
  ENT_HEX_VALUE=""
fi

if [[ -n "${ENT_HEX_VALUE}" ]]; then
  CS_NIB_HEX="$(printf "%s" "${ENT_HEX_VALUE}" | xxd -r -p | sha256sum | cut -c1)"
  # sanitize CS_NIB_HEX
  CS_NIB_HEX_clean="$(echo "${CS_NIB_HEX}" | tr -cd '0-9A-Fa-f')"
  CS_BITS_BIN="$(echo "obase=2; ibase=16; ${CS_NIB_HEX_clean^^}" | bc)"
  CS_BITS="$(printf "%04s" "${CS_BITS_BIN}" | tr ' ' 0)"
fi
if [[ -n "${ENT_HEX_VALUE}" ]]; then
  BIN_ENT="$(hex_to_bits "${ENT_HEX_VALUE}")"
fi

if [[ -n "${ENT_HEX_VALUE}" ]]; then
  BIN_ALL="${BIN_ENT}${CS_BITS}"
fi

if [[ -n "${ENT_HEX_VALUE}" ]]; then
  debug "checksum bits: ${CS_BITS}"
  debug "checksum nib_hex: ${CS_NIB_HEX}"
  debug "binary entropy: ${BIN_ENT}"
  debug "${BIN_ALL}"
fi

mapfile -t WORDS < "${WLIST}"

declare -A WORD_SET=()
for word in "${WORDS[@]}"; do
  WORD_SET["${word}"]=1
done

if [[ -z "${USER_MNEMONIC}" ]]; then
  mnemonic=()
  for i in {0..11}; do
    idx_bits="${BIN_ALL:$((i*11)):11}"
    if [[ ! "${idx_bits}" =~ ^[01]{11}$ ]]; then
      echo "Bad bit chunk: '${idx_bits}'" >&2
      exit 1
    fi
    idx=$((2#${idx_bits}))
    mnemonic+=( "${WORDS[${idx}]}" )
    debug "idx: ${idx}, word: ${mnemonic[-1]}"
  done
  MNEMONIC="${mnemonic[*]}"
else
  if [[ -z "${USER_MNEMONIC// }" ]]; then
    echo "Provided mnemonic is empty" >&2
    exit 2
  fi
  read -r -a mnemonic_words <<<"${USER_MNEMONIC}"
  if (( ${#mnemonic_words[@]} == 0 )); then
    echo "Provided mnemonic is empty" >&2
    exit 2
  fi
  if (( ${#mnemonic_words[@]} % 3 != 0 )); then
    echo "Mnemonic word count must be a multiple of 3" >&2
    exit 2
  fi
  for w in "${mnemonic_words[@]}"; do
    if [[ -z "${WORD_SET[${w}]+x}" ]]; then
      echo "Mnemonic word '${w}' not in wordlist" >&2
      exit 2
    fi
  done
  MNEMONIC="${USER_MNEMONIC}"
fi

# Derive seed using Bash helper (PBKDF2-HMAC-SHA512)
SEED_HEX="$(
  "${BIP39_HELPER}" \
    --mnemonic "${MNEMONIC}" \
    --passphrase "${PASSPHRASE}"
)"

debug "Hex Seed: ${SEED_HEX}"
# master I, IL, IR
I_MASTER="$(printf "%s" "${SEED_HEX}" | xxd -r -p | openssl dgst -sha512 -mac HMAC -macopt key:"Bitcoin seed" -binary | xxd -p -c 1000)"
IL="${I_MASTER:0:64}"; IR="${I_MASTER:64:64}"

debug "I_MASTER: ${I_MASTER}"
debug "IL: ${IL}"
debug "IR: ${IR}"
validate_private_scalar "${IL}" "master IL"

derive_hardened(){
  local kpar="$1" cpar="$2" index="$3"
  local idx="${index}"
  while :; do
    local i_hex; printf -v i_hex "%08X" $((idx | 0x80000000))
    local data="00${kpar}${i_hex}"
    local I
    I="$(printf "%s" "${data}" | xxd -r -p | openssl dgst -sha512 -mac HMAC -macopt "hexkey:${cpar}" -binary | xxd -p -c 1000)"
    local ILc="${I:0:64}" IRc="${I:64:64}"
    local child_k
    child_k="$(bn_add_mod_n "${ILc}" "${kpar}")"
    # Guards: if IL >= n or child_k == 0, increment index and retry
    local ge
    ge="$(bn_ge "${ILc}" "${N_HEX}")"
    local iz
    iz="$(bn_is_zero "${child_k}")"
    if [[ "${ge}" -eq 1 ]] || [[ "${iz}" -eq 1 ]]; then
      debug "hardened idx ${idx} invalid (IL>=n or child=0), trying $((idx+1))"
      idx=$((idx+1))
      continue
    fi
    printf "%s %s\n" "${child_k}" "${IRc}"
    break
  done
}

pub_compressed_from_priv_hex(){
  local khex="$1"
  local comp
  read -r comp _ <<<"$("${SECP256K1_HELPER}" pub --priv-hex "${khex}")"
  printf "%s" "${comp}"
}

derive_normal(){
  local kpar="$1" cpar="$2" index="$3"
  local idx="${index}"
  while :; do
    local i_hex; printf -v i_hex "%08X" "${idx}"
    local Kpar_comp
    Kpar_comp="$(pub_compressed_from_priv_hex "${kpar}")"
    local data="${Kpar_comp}${i_hex}"
    local I
    I="$(printf "%s" "${data}" | xxd -r -p | openssl dgst -sha512 -mac HMAC -macopt "hexkey:${cpar}" -binary | xxd -p -c 1000)"
    local ILc="${I:0:64}" IRc="${I:64:64}"
    local child_k
    child_k="$(bn_add_mod_n "${ILc}" "${kpar}")"
    local ge
    ge="$(bn_ge "${ILc}" "${N_HEX}")"
    local iz
    iz="$(bn_is_zero "${child_k}")"
    if [[ "${ge}" -eq 1 ]] || [[ "${iz}" -eq 1 ]]; then
      debug "normal idx ${idx} invalid (IL>=n or child=0), trying $((idx+1))"
      idx=$((idx+1))
      continue
    fi
    printf "%s %s\n" "${child_k}" "${IRc}"
    break
  done
}

# path m/44'/60'/0'/0/0
k="${IL}"; c="${IR}"

validate_private_scalar "${k}" "m master private key"

debug "before derivation"
read -r next_k c < <(derive_hardened "${k}" "${c}" 44)
validate_private_scalar "${next_k}" "m/44' private key"
k="${next_k}"
read -r next_k c < <(derive_hardened "${k}" "${c}" 60)
validate_private_scalar "${next_k}" "m/44'/60' private key"
k="${next_k}"
read -r next_k c < <(derive_hardened "${k}" "${c}" 0)
validate_private_scalar "${next_k}" "m/44'/60'/0' private key"
k="${next_k}"

debug "after derive hardened"

read -r next_k c < <(derive_normal   "${k}" "${c}" 0)
validate_private_scalar "${next_k}" "m/44'/60'/0'/0 private key"
k="${next_k}"
read -r next_k c < <(derive_normal   "${k}" "${c}" 0)
validate_private_scalar "${next_k}" "m/44'/60'/0'/0/0 private key"
k="${next_k}"
debug "after derive normal"

validate_private_scalar "${k}" "final private key"
PRIV_HEX="${k}"

debug "PK_HEX k : ${k} "

ADDR_EIP55="0x"
if [[ "${NO_ADDRESS}" -eq 0 ]]; then
  read -r PUB_COMP_HEX PUB_UNCOMP_HEX <<<"$("${SECP256K1_HELPER}" pub --priv-hex "${PRIV_HEX}")"
  debug "PUB_COMP_HEX: ${PUB_COMP_HEX}"
  PUB_XY_HEX="${PUB_UNCOMP_HEX:2}"
  debug "PUB_XY_HEX: ${PUB_XY_HEX}"
fi

eth_keccak256_hex(){
  "${KECCAK_HELPER}" keccak256-hex
}

if [[ "${NO_ADDRESS}" -eq 0 ]]; then
  # Compute hash from pubkey XY using Keccak-256
  HASH="$(printf "%s" "${PUB_XY_HEX}" | xxd -r -p | eth_keccak256_hex)"
  ADDR_HEX="${HASH:24}"
  ADDR_LC="${ADDR_HEX,,}"
  H2="$(printf "%s" "${ADDR_LC}" | eth_keccak256_hex)"
  debug "EIP55 base: ${ADDR_LC}"
  debug "EIP55 h:    ${H2}"
  ADDR_EIP55="$("${EIP55_HELPER}" "${ADDR_HEX}")"
fi

if [[ "${INCLUDE_SEED}" -eq 1 ]]; then
  printf '{"mnemonic":"%s","path":"m/44'\''/60'\''/0'\''/0/0","privateKey":"0x%s","address":"%s","seed":"%s"}\n' \
    "${MNEMONIC}" "${PRIV_HEX}" "${ADDR_EIP55}" "${SEED_HEX}"
else
  printf '{"mnemonic":"%s","path":"m/44'\''/60'\''/0'\''/0/0","privateKey":"0x%s","address":"%s"}\n' \
    "${MNEMONIC}" "${PRIV_HEX}" "${ADDR_EIP55}"
fi
