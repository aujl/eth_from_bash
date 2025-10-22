#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=tests/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

HELPER="${ROOT_DIR}/scripts/crypto_kdf.sh"

if [[ ! -r "${HELPER}" ]]; then
  fail "crypto_kdf helper missing: ${HELPER}"
fi

# shellcheck source=scripts/crypto_kdf.sh
source "${HELPER}"

test_validate_hex_success() {
  local output
  output="$(validate_hex test "0A0b")"
  if [[ "${output}" != "0a0b" ]]; then
    fail "validate_hex lowercases input"
  fi
  pass "validate_hex lowercases input"
}

test_validate_hex_rejects_invalid() {
  local status
  set +e
  validate_hex test "zz" >/dev/null 2>&1
  status=$?
  set -e
  if (( status != 2 )); then
    fail "validate_hex rejects non-hex input"
  fi
  pass "validate_hex rejects non-hex input"
}

test_ascii_to_hex_roundtrip() {
  local output
  output="$(ascii_to_hex "Hi")"
  if [[ "${output}" != "4869" ]]; then
    fail "ascii_to_hex encodes ASCII input"
  fi
  pass "ascii_to_hex encodes ASCII input"
}

test_hmac_hex_sha256() {
  local key="0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
  local data="4869205468657265"
  local expected="b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
  local output
  output="$(hmac_hex sha256 "${key}" "${data}")"
  if [[ "${output}" != "${expected}" ]]; then
    fail "hmac_hex sha256 vector"
  fi
  pass "hmac_hex sha256 vector"
}

test_hmac_hex_sha512() {
  local key="0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
  local data="4869205468657265"
  local expected="87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
  local output
  output="$(hmac_hex sha512 "${key}" "${data}")"
  if [[ "${output}" != "${expected}" ]]; then
    fail "hmac_hex sha512 vector"
  fi
  pass "hmac_hex sha512 vector"
}

test_pbkdf2_small_iterations() {
  local password_hex
  password_hex="$(ascii_to_hex "pass")"
  local salt_hex
  salt_hex="$(ascii_to_hex "salt")"
  local expected="b38deb857ea637081cfe61e4965722c36ee58dc40f53b80e42a4315795c39470480bf86c81e90a4f1c142aabc7273ee0c5a095fbab225ddea60a3d328c15cf03"
  local output
  output="$(pbkdf2_hmac_sha512 "${password_hex}" "${salt_hex}" 2)"
  if [[ "${output}" != "${expected}" ]]; then
    fail "pbkdf2_hmac_sha512 minimal iterations"
  fi
  pass "pbkdf2_hmac_sha512 minimal iterations"
}

test_pbkdf2_rejects_zero_iterations() {
  local password_hex
  password_hex="$(ascii_to_hex "pass")"
  local salt_hex
  salt_hex="$(ascii_to_hex "salt")"
  local status
  set +e
  pbkdf2_hmac_sha512 "${password_hex}" "${salt_hex}" 0 >/dev/null 2>&1
  status=$?
  set -e
  if (( status != 2 )); then
    fail "pbkdf2_hmac_sha512 rejects zero iterations"
  fi
  pass "pbkdf2_hmac_sha512 rejects zero iterations"
}

test_cli_hmac_sha256() {
  local key="0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
  local data="4869205468657265"
  local expected="b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
  local output
  output="$("${HELPER}" hmac-sha256 --key-hex "${key}" --data-hex "${data}")"
  if [[ "${output}" != "${expected}" ]]; then
    fail "crypto_kdf hmac-sha256 command"
  fi
  pass "crypto_kdf hmac-sha256 command"
}

test_cli_hmac_sha512() {
  local key="0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
  local data="4869205468657265"
  local expected="87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
  local output
  output="$("${HELPER}" hmac-sha512 --key-hex "${key}" --data-hex "${data}")"
  if [[ "${output}" != "${expected}" ]]; then
    fail "crypto_kdf hmac-sha512 command"
  fi
  pass "crypto_kdf hmac-sha512 command"
}

test_cli_pbkdf2_iterations_flag() {
  local expected="acc2626cbdcc2f66e4b490696a2687da4bd7807af9daab87d3408e390d562f1898000d1e4145427a6f360d679685a244258823f160ac1afb0ce9d1627c15ba40"
  local output
  output="$("${HELPER}" pbkdf2 --mnemonic test --passphrase 1 --iterations 2)"
  if [[ "${output}" != "${expected}" ]]; then
    fail "crypto_kdf pbkdf2 command iterations"
  fi
  pass "crypto_kdf pbkdf2 command iterations"
}

main() {
  test_validate_hex_success
  test_validate_hex_rejects_invalid
  test_ascii_to_hex_roundtrip
  test_hmac_hex_sha256
  test_hmac_hex_sha512
  test_pbkdf2_small_iterations
  test_pbkdf2_rejects_zero_iterations
  test_cli_hmac_sha256
  test_cli_hmac_sha512
  test_cli_pbkdf2_iterations_flag
}

main "$@"
