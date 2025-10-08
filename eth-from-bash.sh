#!/usr/bin/env bash
# eth-from-bash-perl-keccak.sh
# Like before, but uses libdigest-sha3-perl for the final Keccak / SHA3 step
# deps: bash, xxd, bc, awk, sha256sum, openssl, Perl with Digest::SHA3

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_HELPER="${SCRIPT_DIR}/scripts/derive_seed_and_pub.py"
PYTHON_BIN="${PYTHON_BIN:-python3}"

ENT_HEX_ENV="${ENT_HEX-}"
MNEMONIC_ENV="${MNEMONIC-}"

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  echo "Python interpreter '${PYTHON_BIN}' not found" >&2
  exit 1
fi

if ! "${PYTHON_BIN}" -c 'import ecdsa' >/dev/null 2>&1; then
  if [[ -x "${SCRIPT_DIR}/.venv/bin/python3" ]]; then
    PYTHON_BIN="${SCRIPT_DIR}/.venv/bin/python3"
  fi
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
for cmd in xxd bc awk sha256sum openssl perl python3; do
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
  if ! sum="$(bc <<<"obase=16; ibase=16; ( ${a} + ${b} ) % ${N_HEX}")"; then
    echo "Failed to run bc for modular addition" >&2
    exit 1
  fi
  sum="${sum^^}"
  if [[ -z "${sum}" || ! "${sum}" =~ ^[0-9A-F]+$ ]]; then
    echo "bc produced invalid output for modular addition" >&2
    exit 1
  fi
  printf "%064s" "${sum}" | tr ' ' 0
}

# Return 1 if a >= b (hex), else 0
bn_ge(){
  local a="${1^^}" b="${2^^}"
  local out
  if ! out="$(bc <<<"obase=10; ibase=16; ${a} >= ${b}")"; then
    echo "Failed to run bc for comparison" >&2
    exit 1
  fi
  if [[ ! "${out}" =~ ^[01]$ ]]; then
    echo "bc produced invalid comparison output" >&2
    exit 1
  fi
  printf "%s" "${out}"
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
  BIN_ENT="$(
    printf "%s" "${ENT_HEX_VALUE}" | xxd -r -p | \
    xxd -b -g 0 -c 16 | \
    awk '{ for(i=2; i < NF; i++) printf "%s", $i }'
  )"
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

# Derive seed using Python helper (PBKDF2-HMAC-SHA512)
SEED_HEX="$(
  "${PYTHON_BIN}" "${PYTHON_HELPER}" seed \
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
  read -r comp _ <<<"$("${PYTHON_BIN}" "${PYTHON_HELPER}" pub --priv-hex "${khex}")"
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
  read -r PUB_COMP_HEX PUB_UNCOMP_HEX <<<"$("${PYTHON_BIN}" "${PYTHON_HELPER}" pub --priv-hex "${PRIV_HEX}")"
  debug "PUB_COMP_HEX: ${PUB_COMP_HEX}"
  PUB_XY_HEX="${PUB_UNCOMP_HEX:2}"
  debug "PUB_XY_HEX: ${PUB_XY_HEX}"
fi

eth_keccak256_hex(){
  # Primary: Python (pycryptodome) Keccak-256; read from stdin
  if command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
    if "${PYTHON_BIN}" -c '
import sys
try:
    from Crypto.Hash import keccak
except Exception:
    sys.exit(1)
data = sys.stdin.buffer.read()
k = keccak.new(digest_bits=256)
k.update(data)
sys.stdout.write(k.hexdigest())
' ; then
      return
    fi
  fi
  if [[ "${PYTHON_BIN}" != "python3" ]] && command -v python3 >/dev/null 2>&1; then
    if python3 -c '
import sys
try:
    from Crypto.Hash import keccak
except Exception:
    sys.exit(1)
data = sys.stdin.buffer.read()
k = keccak.new(digest_bits=256)
k.update(data)
sys.stdout.write(k.hexdigest())
' ; then
      return
    fi
  fi
  # Secondary: Perl Digest::Keccak if available
  if perl -MDigest::Keccak=keccak_256_hex -e '1' 2>/dev/null; then
    perl -MDigest::Keccak=keccak_256_hex -0777 -ne 'print keccak_256_hex($_)'
    return
  fi
  echo "ERROR: Keccak-256 provider not found. Install python3-pycryptodome (apt) or pycryptodome (pip), or libdigest-keccak-perl." >&2
  exit 1
}

if [[ "${NO_ADDRESS}" -eq 0 ]]; then
  # Compute hash from pubkey XY using Keccak-256
  HASH="$(printf "%s" "${PUB_XY_HEX}" | xxd -r -p | eth_keccak256_hex)"
  ADDR_HEX="${HASH:24}"
  ADDR_LC="${ADDR_HEX,,}"
# EIP-55 checksum: keccak256 of ASCII lowercase hex string
H2="$(printf "%s" "${ADDR_LC}" | eth_keccak256_hex)"
debug "EIP55 base: ${ADDR_LC}"
debug "EIP55 h:    ${H2}"
  CHK=""
  for i in $(seq 0 39); do
    ch="${ADDR_LC:${i}:1}"
    hd="${H2:${i}:1}"
    if [[ "${ch}" =~ [a-f] ]] && (( 0x${hd} >= 8 )); then
      CHK+="${ch^^}"
    else
      CHK+="${ch}"
    fi
  done
  ADDR_EIP55="0x${CHK}"
fi

if [[ "${INCLUDE_SEED}" -eq 1 ]]; then
  printf '{"mnemonic":"%s","path":"m/44'\''/60'\''/0'\''/0/0","privateKey":"0x%s","address":"%s","seed":"%s"}\n' \
    "${MNEMONIC}" "${PRIV_HEX}" "${ADDR_EIP55}" "${SEED_HEX}"
else
  printf '{"mnemonic":"%s","path":"m/44'\''/60'\''/0'\''/0/0","privateKey":"0x%s","address":"%s"}\n' \
    "${MNEMONIC}" "${PRIV_HEX}" "${ADDR_EIP55}"
fi
