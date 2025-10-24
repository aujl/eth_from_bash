#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/sha2.sh
source "${SCRIPT_DIR}/lib/sha2.sh"

eth_from_bash::check_result() {
  local binary="$1"
  local expected="$2"
  local status="$3"
  local actual="$4"

  if (( status != 0 )); then
    echo "Dependency self-test failed for ${binary}: command execution failed" >&2
    return 1
  fi

  if [[ "${actual}" != "${expected}" ]]; then
    echo "Dependency self-test failed for ${binary}: expected '${expected}', got '${actual}'" >&2
    return 1
  fi

  return 0
}

eth_from_bash::check_deps() {
  local missing=0
  local deps=(jq bc xxd awk)

  for cmd in "${deps[@]}"; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
      echo "Missing dependency: ${cmd}" >&2
      missing=1
    fi
  done

  if [[ ${missing} -eq 1 ]]; then
    echo "Install missing dependencies and retry." >&2
    return 1
  fi

  local failures=0
  local status
  local actual

  set +e
  actual="$(printf 'eth-from-bash' | sha256_hex_from_stream)"
  status=$?
  set -e
  if ! eth_from_bash::check_result "sha256 helper" \
    "c880132ead8ce984fc8df9a0a84f884aaf04c078c345c07fb6909501d4fdf6ef" "${status}" "${actual}"; then
    failures=1
  fi

  set +e
  actual="$(printf 'eth-from-bash' | sha512_hex_from_stream)"
  status=$?
  set -e
  if ! eth_from_bash::check_result "sha512 helper" \
    "a8806ef666a5967a8b035cb9dcb9b21ebf53fc4988f82e8076f881a9df2bc5ce2dfec68e1683bc22f69eaacb05df3b873ca42901059a5ababf111a6a6eb91021" "${status}" "${actual}"; then
    failures=1
  fi

  local crypto_sign_bin
  if crypto_sign_bin="$(command -v crypto-sign 2>/dev/null)" && [[ -n "${crypto_sign_bin}" ]]; then
    :
  else
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    crypto_sign_bin="$(cd "${script_dir}/.." && pwd)/bin/crypto-sign"
  fi

  local key_file message_file
  key_file="$(mktemp)"
  message_file="$(mktemp)"
  printf 'supersecret' >"${key_file}"
  printf 'eth-from-bash' >"${message_file}"

  set +e
  actual="$("${crypto_sign_bin}" hmac-sha256 --key "${key_file}" --message "${message_file}" --output hex)"
  status=$?
  set -e

  rm -f "${key_file}" "${message_file}"

  if ! eth_from_bash::check_result "crypto-sign hmac-sha256" \
    "463c16069cd606850e43c4a2c045e4270c46054df1bae28d31803fc5fdabd6a5" "${status}" "${actual}"; then
    failures=1
  fi

  set +e
  actual="$(printf '{"nested": {"value": [1,2,3]}}' | jq -c '.nested.value[1]')"
  status=$?
  set -e
  if ! eth_from_bash::check_result "jq" "2" "${status}" "${actual}"; then
    failures=1
  fi

  set +e
  actual="$(printf 'scale=5; 7/19\n' | bc)"
  status=$?
  set -e
  if ! eth_from_bash::check_result "bc" ".36842" "${status}" "${actual}"; then
    failures=1
  fi

  set +e
  actual="$(printf 'eth' | xxd -p -c 256)"
  status=$?
  set -e
  if ! eth_from_bash::check_result "xxd" "657468" "${status}" "${actual}"; then
    failures=1
  fi

  set +e
  actual="$(printf '3 4\n' | awk '{print $1 * $2}')"
  status=$?
  set -e
  if ! eth_from_bash::check_result "awk" "12" "${status}" "${actual}"; then
    failures=1
  fi

  if (( failures == 1 )); then
    echo "One or more CLI dependencies failed deterministic self-tests." >&2
    return 1
  fi

  echo "All required CLI deps passed deterministic self-tests: jq JSON query, bc division, xxd hex encode, awk arithmetic, built-in SHA-256/SHA-512 helper digests, crypto-sign HMAC."
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  eth_from_bash::check_deps "$@"
fi
