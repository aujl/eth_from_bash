# shellcheck shell=bash

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "scripts/lib/flows/ethereum.sh must be sourced" >&2
  exit 1
fi

ethereum_flow_run() {
  local wordlist=""
  local passphrase=""
  local mnemonic=""
  local entropy_hex=""
  local include_seed=0
  local quiet=0
  local no_address=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --wordlist)
        shift
        wordlist="${1-}"
        shift || true
        ;;
      --passphrase)
        shift
        passphrase="${1-}"
        shift || true
        ;;
      --mnemonic)
        shift
        mnemonic="${1-}"
        shift || true
        ;;
      --entropy-hex)
        shift
        entropy_hex="${1-}"
        shift || true
        ;;
      --include-seed)
        shift
        include_seed="${1:-0}"
        shift || true
        ;;
      --quiet)
        shift
        quiet="${1:-0}"
        shift || true
        ;;
      --no-address)
        shift
        no_address="${1:-0}"
        shift || true
        ;;
      *)
        echo "Unknown flow argument: $1" >&2
        return 2
        ;;
    esac
  done

  if [[ -z "${wordlist}" ]]; then
    echo "Wordlist path is required" >&2
    return 2
  fi

  if [[ ! -r "${wordlist}" ]]; then
    echo "Wordlist '${wordlist}' not readable" >&2
    return 1
  fi

  bip39_load_wordlist "${wordlist}"

  local ethereum_flow_debug
  ethereum_flow_debug() {
    if [[ "${quiet}" -eq 0 ]]; then
      echo "$*" >&2
    fi
  }

  local entropy_value=""
  if [[ -n "${entropy_hex}" ]]; then
    if ! entropy_value="$(bip39_validate_entropy_hex "${entropy_hex}")"; then
      return 2
    fi
  fi

  if [[ -z "${mnemonic}" ]]; then
    if [[ -z "${entropy_value}" ]]; then
      if ! entropy_value="$(bip39_generate_entropy_hex)"; then
        return 1
      fi
    fi
  else
    entropy_value=""
  fi

  if [[ -n "${entropy_value}" ]]; then
    local cs_nib_hex cs_bits bin_ent bin_all
    cs_nib_hex="$(bip39_checksum_nibble_hex "${entropy_value}")"
    cs_bits="$(bip39_checksum_bits "${entropy_value}")"
    bin_ent="$(bip39_entropy_bits "${entropy_value}")"
    bin_all="$(bip39_entropy_with_checksum_bits "${entropy_value}")"
    ethereum_flow_debug "checksum bits: ${cs_bits}"
    ethereum_flow_debug "checksum nib_hex: ${cs_nib_hex}"
    ethereum_flow_debug "binary entropy: ${bin_ent}"
    ethereum_flow_debug "${bin_all}"
  fi

  local effective_mnemonic
  if [[ -z "${mnemonic}" ]]; then
    effective_mnemonic="$(bip39_build_mnemonic_from_entropy "${entropy_value}")"
  else
    if ! effective_mnemonic="$(bip39_validate_mnemonic "${mnemonic}")"; then
      return 2
    fi
  fi

  local seed_hex
  seed_hex="$(${BIP39_HELPER} --mnemonic "${effective_mnemonic}" --passphrase "${passphrase}")"
  ethereum_flow_debug "Hex Seed: ${seed_hex}"

  local k c
  read -r k c < <(bip32_master_from_seed "${seed_hex}")

  local -a path_segments=("44'" "60'" "0'" "0" "0")
  local derivation_path_display="m/44'/60'/0'/0/0"
  read -r k c < <(bip32_derive_path_segments "${k}" "${c}" "${path_segments[@]}")

  bip32_validate_private_scalar "${k}" "final private key" || return 1
  local priv_hex="${k}"

  ethereum_flow_debug "PK_HEX k : ${k}"

  local addr_eip55="0x"
  local pub_xy_hex=""
  if [[ "${no_address}" -eq 0 ]]; then
    local pub_comp_hex pub_uncomp_hex
    read -r pub_comp_hex pub_uncomp_hex < <(bip32_pub_from_private "${priv_hex}")
    ethereum_flow_debug "PUB_COMP_HEX: ${pub_comp_hex}"
    pub_xy_hex="${pub_uncomp_hex:2}"
    ethereum_flow_debug "PUB_XY_HEX: ${pub_xy_hex}"
  fi

  ethereum_flow_keccak256_hex() {
    "${KECCAK_HELPER}" keccak256-hex
  }

  if [[ "${no_address}" -eq 0 ]]; then
    local hash addr_hex addr_lc h2
    hash="$(printf "%s" "${pub_xy_hex}" | xxd -r -p | ethereum_flow_keccak256_hex)"
    addr_hex="${hash:24}"
    addr_lc="${addr_hex,,}"
    h2="$(printf "%s" "${addr_lc}" | ethereum_flow_keccak256_hex)"
    ethereum_flow_debug "EIP55 base: ${addr_lc}"
    ethereum_flow_debug "EIP55 h:    ${h2}"
    addr_eip55="$("${EIP55_HELPER}" "${addr_hex}")"
  fi

  if [[ "${include_seed}" -eq 1 ]]; then
    printf '{"mnemonic":"%s","path":"%s","privateKey":"0x%s","address":"%s","seed":"%s"}\n' \
      "${effective_mnemonic}" "${derivation_path_display}" "${priv_hex}" "${addr_eip55}" "${seed_hex}"
  else
    printf '{"mnemonic":"%s","path":"%s","privateKey":"0x%s","address":"%s"}\n' \
      "${effective_mnemonic}" "${derivation_path_display}" "${priv_hex}" "${addr_eip55}"
  fi
}
