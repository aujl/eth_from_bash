#!/usr/bin/env bash
# Common helpers for eth_from_bash tests

ROOT_DIR="$(readlink -f "$(dirname "${BASH_SOURCE[0]}")/..")"
# shellcheck disable=SC2034  # referenced by sourced test scripts
SCRIPT="${ROOT_DIR}/bin/eth-from-bash"
# shellcheck disable=SC2034  # referenced by sourced test scripts
WLIST="${ROOT_DIR}/english_bip-39.txt"

pass() {
  printf 'PASS: %s\n' "$1"
}

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

