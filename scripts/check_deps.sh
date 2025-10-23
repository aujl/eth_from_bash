#!/usr/bin/env bash
set -euo pipefail

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
  local deps=(jq bc xxd awk sha256sum sha512sum openssl)

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
  actual="$(printf 'eth-from-bash' | sha256sum | awk '{print $1}')"
  status=$?
  set -e
  if ! eth_from_bash::check_result "sha256sum" \
    "c880132ead8ce984fc8df9a0a84f884aaf04c078c345c07fb6909501d4fdf6ef" "${status}" "${actual}"; then
    failures=1
  fi

  set +e
  actual="$(printf 'eth-from-bash' | sha512sum | awk '{print $1}')"
  status=$?
  set -e
  if ! eth_from_bash::check_result "sha512sum" \
    "a8806ef666a5967a8b035cb9dcb9b21ebf53fc4988f82e8076f881a9df2bc5ce2dfec68e1683bc22f69eaacb05df3b873ca42901059a5ababf111a6a6eb91021" "${status}" "${actual}"; then
    failures=1
  fi

  set +e
  actual="$(printf 'verify' | openssl dgst -sha256 -mac HMAC -macopt hexkey:00112233445566778899aabbccddeeff | awk '{print $NF}')"
  status=$?
  set -e
  if ! eth_from_bash::check_result "openssl" \
    "c4138406480be28241a2d976c7eae49d78c9960e16a2b71518ff97b9ae376821" "${status}" "${actual}"; then
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

  echo "All required CLI deps passed deterministic self-tests: jq JSON query, bc division, xxd hex encode, awk arithmetic, sha256sum/sha512sum known digests, openssl HMAC."
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  eth_from_bash::check_deps "$@"
fi
