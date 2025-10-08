#!/usr/bin/env bash
# Common helpers for eth_from_bash tests

ROOT_DIR="$(readlink -f "$(dirname "${BASH_SOURCE[0]}")/..")"
SCRIPT="${ROOT_DIR}/eth-from-bash.sh"
WLIST="${ROOT_DIR}/english_bip-39.txt"
PYTHON_BIN="${PYTHON_BIN:-python3}"

pass() {
  printf 'PASS: %s\n' "$1"
}

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

require_python_module() {
  local module="$1"
  if ! "${PYTHON_BIN}" -c "import ${module}" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}
