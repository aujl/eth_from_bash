#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=tests/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

HELPER="${ROOT_DIR}/scripts/crypto_kdf.sh"

if [[ ! -x "${HELPER}" ]]; then
  fail "crypto_kdf helper missing: ${HELPER}"
fi

run_pbkdf2_vector() {
  local mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  local passphrase="TREZOR"
  local expected="c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
  local output
  output="$("${HELPER}" pbkdf2 --mnemonic "${mnemonic}" --passphrase "${passphrase}")"
  if [[ "${output}" != "${expected}" ]]; then
    echo "Expected PBKDF2: ${expected}" >&2
    echo "Got:            ${output}" >&2
    fail "PBKDF2-HMAC-SHA512 vector"
  fi
  pass "PBKDF2-HMAC-SHA512 vector"
}

run_hmac_sha512_vector() {
  local key_hex="0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
  local data_hex="4869205468657265"
  local expected="87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
  local output
  output="$("${HELPER}" hmac-sha512 --key-hex "${key_hex}" --data-hex "${data_hex}")"
  if [[ "${output}" != "${expected}" ]]; then
    echo "Expected HMAC-SHA512: ${expected}" >&2
    echo "Got:                  ${output}" >&2
    fail "HMAC-SHA512 vector"
  fi
  pass "HMAC-SHA512 vector"
}

run_hmac_sha256_vector() {
  local key_hex="0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
  local data_hex="4869205468657265"
  local expected="b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
  local output
  output="$("${HELPER}" hmac-sha256 --key-hex "${key_hex}" --data-hex "${data_hex}")"
  if [[ "${output}" != "${expected}" ]]; then
    echo "Expected HMAC-SHA256: ${expected}" >&2
    echo "Got:                  ${output}" >&2
    fail "HMAC-SHA256 vector"
  fi
  pass "HMAC-SHA256 vector"
}

main() {
  run_pbkdf2_vector
  run_hmac_sha512_vector
  run_hmac_sha256_vector
}

main "$@"
