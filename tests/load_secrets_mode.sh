#!/usr/bin/env bash
set -euo pipefail

TEST_DIR="$(cd "$(dirname "$0")" && pwd)"

assert_unsigned_ci_allowed() {
  if ! CI=1 UNSIGNED_TEST=1 TEST_SECRETS_INITIALIZED=0 bash -c 'set -euo pipefail; source "$1"' bash "${TEST_DIR}/load_secrets.sh" >/dev/null 2>&1; then
    echo "Expected UNSIGNED_TEST=1 to succeed when CI=1" >&2
    exit 1
  fi
}

assert_unsigned_signed_conflict() {
  set +e
  local output
  output=$(CI=1 UNSIGNED_TEST=1 SIGNED_TEST=1 TEST_SECRETS_INITIALIZED=0 bash -c 'set -euo pipefail; source "$1"' bash "${TEST_DIR}/load_secrets.sh" 2>&1)
  local status=$?
  set -e
  if (( status == 0 )); then
    echo "Expected UNSIGNED_TEST=1 SIGNED_TEST=1 to fail" >&2
    exit 1
  fi
  if [[ "${output}" != *"UNSIGNED_TEST=1 conflicts with SIGNED_TEST=1"* ]]; then
    echo "Conflict error message missing" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
}

assert_unsigned_ci_allowed
assert_unsigned_signed_conflict
