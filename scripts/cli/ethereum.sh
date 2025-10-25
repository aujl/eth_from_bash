# shellcheck shell=bash

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "scripts/cli/ethereum.sh must be sourced" >&2
  exit 1
fi

ethereum_cli_reset_state() {
  ETHEREUM_CLI_QUIET=0
  ETHEREUM_CLI_INCLUDE_SEED=0
  ETHEREUM_CLI_NO_ADDRESS=0
  ETHEREUM_CLI_MNEMONIC=""
  ETHEREUM_CLI_WORDLIST=""
  ETHEREUM_CLI_PASSPHRASE=""
  ETHEREUM_CLI_USE_ENV_MNEMONIC=0
  ETHEREUM_CLI_ENTROPY_HEX="${ENT_HEX-}"
}

ethereum_cli_usage() {
  cat <<'USAGE'
Usage: eth-from-bash [options] <wordlist> [passphrase]

Options:
  -q, --quiet          Emit only JSON output
  --include-seed       Include the BIP39 seed in JSON output
  --mnemonic PHRASE    Use the provided mnemonic phrase
  --no-address         Skip public key/address derivation
USAGE
}

ethereum_cli_parse_args() {
  ethereum_cli_reset_state

  if [[ -n "${MNEMONIC-}" ]]; then
    ETHEREUM_CLI_MNEMONIC="${MNEMONIC}"
    ETHEREUM_CLI_USE_ENV_MNEMONIC=1
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -q|--quiet)
        ETHEREUM_CLI_QUIET=1
        shift
        ;;
      --include-seed)
        ETHEREUM_CLI_INCLUDE_SEED=1
        shift
        ;;
      --no-address)
        ETHEREUM_CLI_NO_ADDRESS=1
        shift
        ;;
      --mnemonic)
        if (( ETHEREUM_CLI_USE_ENV_MNEMONIC )); then
          echo "MNEMONIC environment variable is set; remove --mnemonic" >&2
          return 2
        fi
        shift
        ETHEREUM_CLI_MNEMONIC="${1-}"
        if [[ -z "${ETHEREUM_CLI_MNEMONIC}" ]]; then
          echo "--mnemonic requires a value" >&2
          return 2
        fi
        shift
        ;;
      --help|-h)
        ethereum_cli_usage
        return 1
        ;;
      --)
        shift
        break
        ;;
      -*)
        echo "Unknown option: $1" >&2
        return 2
        ;;
      *)
        break
        ;;
    esac
  done

  if [[ $# -lt 1 ]]; then
    ethereum_cli_usage >&2
    return 2
  fi

  ETHEREUM_CLI_WORDLIST="$1"
  shift || true
  ETHEREUM_CLI_PASSPHRASE="${*:-}"

  return 0
}

ethereum_cli_main() {
  local repo_root="$1"
  shift || true

  eth_from_bash::bootstrap_cli_environment "${repo_root}"

  if ! ethereum_cli_parse_args "$@"; then
    local status=$?
    if (( status == 1 )); then
      return 0
    fi
    return ${status}
  fi

  if ! eth_from_bash::require_commands xxd bc awk; then
    return 1
  fi

  ethereum_flow_run \
    --wordlist "${ETHEREUM_CLI_WORDLIST}" \
    --passphrase "${ETHEREUM_CLI_PASSPHRASE}" \
    --mnemonic "${ETHEREUM_CLI_MNEMONIC}" \
    --entropy-hex "${ETHEREUM_CLI_ENTROPY_HEX}" \
    --include-seed "${ETHEREUM_CLI_INCLUDE_SEED}" \
    --quiet "${ETHEREUM_CLI_QUIET}" \
    --no-address "${ETHEREUM_CLI_NO_ADDRESS}"
}
