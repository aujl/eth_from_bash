#!/usr/bin/env bash
# Common helpers for eth_from_bash tests

ROOT_DIR="$(readlink -f "$(dirname "${BASH_SOURCE[0]}")/..")"
SCRIPT="${ROOT_DIR}/eth-from-bash.sh"
WLIST="${ROOT_DIR}/english_bip-39.txt"

pass() {
  printf 'PASS: %s\n' "$1"
}

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

