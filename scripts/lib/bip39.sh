# shellcheck shell=bash
# BIP-39 helper primitives shared across the CLI and tests.

BIP39_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if ! declare -F sha256_hex_from_stream >/dev/null 2>&1; then
  # shellcheck source=scripts/lib/sha2.sh
  source "${BIP39_LIB_DIR}/sha2.sh"
fi

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  echo "scripts/lib/bip39.sh must be sourced, not executed" >&2
  exit 1
fi

bip39__debug(){
  if declare -F debug >/dev/null 2>&1; then
    debug "$@"
  elif [[ ${BIP39_DEBUG:-0} -eq 1 ]]; then
    echo "$@" >&2
  fi
}

bip39_hex_to_bits(){
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

bip39_validate_entropy_hex(){
  local candidate="$1"
  if [[ ! "${candidate}" =~ ^[0-9a-fA-F]{32}$ ]]; then
    echo "ENT_HEX must be 32 hexadecimal characters" >&2
    return 1
  fi
  printf '%s' "${candidate,,}"
}

bip39_generate_entropy_hex(){
  local crypto_helper="${CRYPTO_SIGN_HELPER:-}"
  local hex
  if [[ -n "${crypto_helper}" ]]; then
    if command -v "${crypto_helper}" >/dev/null 2>&1; then
      if hex="$(${crypto_helper} random-bytes --count 16 --output hex 2>/dev/null | tr -d '\r\n')"; then
        if [[ "${hex}" =~ ^[0-9a-fA-F]{32}$ ]]; then
          printf '%s' "${hex,,}"
          return 0
        fi
      fi
      bip39__debug "crypto_sign random-bytes failed, falling back to /dev/urandom"
    else
      bip39__debug "Random helper '${crypto_helper}' unavailable; falling back to /dev/urandom"
    fi
  fi
  if [[ -r /dev/urandom ]]; then
    hex="$(head -c 16 /dev/urandom | xxd -p -c 16 | tr -d '\n')"
    if [[ "${hex}" =~ ^[0-9a-fA-F]{32}$ ]]; then
      printf '%s' "${hex,,}"
      return 0
    fi
  fi
  echo "Unable to produce entropy: crypto_sign random-bytes failed and /dev/urandom unavailable" >&2
  return 1
}

bip39_checksum_bits(){
  local entropy_hex="$1"
  local digest
  digest="$(printf "%s" "${entropy_hex}" | xxd -r -p | sha256_hex_from_stream)"
  local digest_bits
  digest_bits="$(bip39_hex_to_bits "${digest}")"
  local checksum_bit_len=$(( (${#entropy_hex} * 4) / 32 ))
  printf '%s' "${digest_bits:0:${checksum_bit_len}}"
}

bip39_entropy_bits(){
  local entropy_hex="$1"
  bip39_hex_to_bits "${entropy_hex}"
}

bip39_entropy_with_checksum_bits(){
  local entropy_hex="$1"
  local ent_bits
  ent_bits="$(bip39_entropy_bits "${entropy_hex}")"
  local cs_bits
  cs_bits="$(bip39_checksum_bits "${entropy_hex}")"
  printf '%s%s' "${ent_bits}" "${cs_bits}"
}

bip39_load_wordlist(){
  local wordlist_path="$1"
  if [[ ! -r "${wordlist_path}" ]]; then
    echo "wordlist missing" >&2
    return 1
  fi
  mapfile -t BIP39_WORDS < "${wordlist_path}"
  if [[ ${#BIP39_WORDS[@]} -ne 2048 ]]; then
    echo "wordlist must have 2048 lines" >&2
    return 1
  fi
  declare -gA BIP39_WORD_SET=()
  local word
  for word in "${BIP39_WORDS[@]}"; do
    BIP39_WORD_SET["${word}"]=1
  done
  declare -gx BIP39_WORDLIST_PATH="${wordlist_path}"
}

bip39_build_mnemonic_from_entropy(){
  local entropy_hex="$1"
  if [[ -z "${entropy_hex}" ]]; then
    echo "Entropy hex required" >&2
    return 1
  fi
  if [[ -z "${BIP39_WORDS+x}" ]]; then
    echo "BIP39 wordlist not loaded" >&2
    return 1
  fi
  local combined_bits
  combined_bits="$(bip39_entropy_with_checksum_bits "${entropy_hex}")"
  local bits_per_word=11
  local total_words=$(( ${#combined_bits} / bits_per_word ))
  local words=()
  local idx_bits
  local idx
  local i
  for ((i = 0; i < total_words; i++)); do
    idx_bits="${combined_bits:$((i*bits_per_word)):bits_per_word}"
    if [[ ! "${idx_bits}" =~ ^[01]{11}$ ]]; then
      echo "Bad bit chunk: '${idx_bits}'" >&2
      return 1
    fi
    idx=$((2#${idx_bits}))
    words+=("${BIP39_WORDS[idx]}")
  done
  printf '%s' "${words[*]}"
}

bip39_validate_mnemonic(){
  local phrase="$1"
  if [[ -z "${phrase// }" ]]; then
    echo "Provided mnemonic is empty" >&2
    return 1
  fi
  local word_set_ref_name=""
  local -A _bip39_tmp_set=()
  if [[ -n "${BIP39_WORD_SET+x}" ]]; then
    word_set_ref_name="BIP39_WORD_SET"
  elif [[ -n "${BIP39_WORDLIST_PATH:-}" && -r "${BIP39_WORDLIST_PATH}" ]]; then
    while IFS= read -r _bip39_word; do
      _bip39_tmp_set["${_bip39_word}"]=1
    done < "${BIP39_WORDLIST_PATH}"
    word_set_ref_name="_bip39_tmp_set"
  else
    echo "BIP39 wordlist not loaded" >&2
    return 1
  fi
  local -n word_set_ref="${word_set_ref_name}"
  read -r -a mnemonic_words <<<"${phrase}"
  if (( ${#mnemonic_words[@]} == 0 )); then
    echo "Provided mnemonic is empty" >&2
    return 1
  fi
  if (( ${#mnemonic_words[@]} % 3 != 0 )); then
    echo "Mnemonic word count must be a multiple of 3" >&2
    return 1
  fi
  local w
  for w in "${mnemonic_words[@]}"; do
    if [[ -z "${word_set_ref[${w}]+x}" ]]; then
      echo "Mnemonic word '${w}' not in wordlist" >&2
      return 1
    fi
  done
  printf '%s' "${mnemonic_words[*]}"
}

bip39_mnemonic_to_words(){
  local phrase="$1"
  read -r -a BIP39_LAST_MNEMONIC_WORDS <<<"${phrase}"
  printf '%s\n' "${BIP39_LAST_MNEMONIC_WORDS[@]}"
}

bip39_checksum_nibble_hex(){
  local entropy_hex="$1"
  printf "%s" "${entropy_hex}" | xxd -r -p | sha256_hex_from_stream | cut -c1
}

export -f bip39_hex_to_bits
export -f bip39_validate_entropy_hex
export -f bip39_generate_entropy_hex
export -f bip39_checksum_bits
export -f bip39_entropy_bits
export -f bip39_entropy_with_checksum_bits
export -f bip39_load_wordlist
export -f bip39_build_mnemonic_from_entropy
export -f bip39_validate_mnemonic
export -f bip39_mnemonic_to_words
export -f bip39_checksum_nibble_hex
