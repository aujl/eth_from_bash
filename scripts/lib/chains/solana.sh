# shellcheck shell=bash
# SLIP-0010 helpers for Ed25519 (Solana-specific derivation)

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  echo "scripts/lib/chains/solana.sh must be sourced" >&2
  exit 1
fi

readonly SOLANA_SLIP10_SEED_KEY_HEX="656432353531392073656564"

solana_slip10_hmac_sha512() {
  local key_hex="$1" data_hex="$2"
  local helper="${CRYPTO_KDF_HELPER:-}"
  if [[ -z "${helper}" ]]; then
    local repo_root="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
    helper="${repo_root}/scripts/crypto_kdf.sh"
  fi
  if [[ ! -x "${helper}" ]]; then
    echo "Crypto helper '${helper}' not executable" >&2
    return 1
  fi
  "${helper}" hmac-sha512 --key-hex "${key_hex}" --data-hex "${data_hex}" | tr -d '\n'
}

solana_slip10_master_from_seed() {
  local seed_hex="${1,,}"
  local I
  I="$(solana_slip10_hmac_sha512 "${SOLANA_SLIP10_SEED_KEY_HEX}" "${seed_hex}")" || return 1
  local il="${I:0:64}"
  local ir="${I:64:64}"
  printf '%s %s\n' "${il}" "${ir}"
}

solana_slip10_derive_hardened() {
  local key_hex="${1,,}"
  local chain_hex="${2,,}"
  local index="$3"
  if [[ ! "${index}" =~ ^[0-9]+$ ]]; then
    echo "invalid index '${index}'" >&2
    return 1
  fi
  local hardened=$((index | 0x80000000))
  printf -v index_hex '%08x' "${hardened}"
  local data="00${key_hex}${index_hex}"
  local I
  I="$(solana_slip10_hmac_sha512 "${chain_hex}" "${data}")" || return 1
  local il="${I:0:64}"
  local ir="${I:64:64}"
  printf '%s %s\n' "${il}" "${ir}"
}

solana_slip10_derive_path_segments() {
  local key_hex="$1" chain_hex="$2"
  shift 2 || true
  local segment
  for segment in "$@"; do
    if [[ "${segment}" =~ ^([0-9]+)\'$ ]]; then
      read -r key_hex chain_hex < <(solana_slip10_derive_hardened "${key_hex}" "${chain_hex}" "${BASH_REMATCH[1]}") || return 1
    else
      echo "invalid path segment '${segment}'" >&2
      return 1
    fi
  done
  printf '%s %s\n' "${key_hex}" "${chain_hex}"
}

solana_slip10_parse_path() {
  local path="$1"
  if [[ -z "${path}" ]]; then
    echo "";
    return 0
  fi
  if [[ "${path}" == "m" ]]; then
    echo ""
    return 0
  fi
  if [[ ! "${path}" =~ ^m(/[^/]+)+$ ]]; then
    echo "invalid path '${path}'" >&2
    return 1
  fi
  local segment
  local remainder="${path#m/}"
  local -a result=()
  IFS='/' read -r -a segments <<<"${remainder}"
  local numeric
  for segment in "${segments[@]}"; do
    if [[ -z "${segment}" ]]; then
      echo "invalid empty path segment" >&2
      return 1
    fi
    if [[ ${segment: -1} != "'" ]]; then
      echo "Solana derivation requires hardened segments (' indexes)" >&2
      return 1
    fi
    numeric="${segment%?}"
    if [[ -z "${numeric}" || ! "${numeric}" =~ ^[0-9]+$ ]]; then
      echo "invalid path segment '${segment}'" >&2
      return 1
    fi
    result+=("${segment}")
  done
  printf '%s\n' "${result[@]}"
}

solana_slip10_derive_path() {
  local seed_hex="$1" path="$2"
  local key chain
  read -r key chain < <(solana_slip10_master_from_seed "${seed_hex}") || return 1
  local -a segments=()
  mapfile -t segments < <(solana_slip10_parse_path "${path}") || return 1
  if (( ${#segments[@]} > 0 )); then
    read -r key chain < <(solana_slip10_derive_path_segments "${key}" "${chain}" "${segments[@]}") || return 1
  fi
  printf '%s %s\n' "${key}" "${chain}"
}

export -f solana_slip10_master_from_seed
export -f solana_slip10_derive_hardened
export -f solana_slip10_derive_path_segments
export -f solana_slip10_parse_path
export -f solana_slip10_derive_path
