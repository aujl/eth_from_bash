#!/usr/bin/env bash
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/common.sh
source "${TESTS_DIR}/common.sh"
# shellcheck source=tests/load_secrets.sh
source "${TESTS_DIR}/load_secrets.sh"

SOL_SCRIPT="${ROOT_DIR}/bin/sol-from-bash"
if [[ ! -x "${SOL_SCRIPT}" ]]; then
  fail "sol-from-bash entrypoint missing"
fi

# shellcheck source=scripts/lib/crypto/sha2.sh
source "${ROOT_DIR}/scripts/lib/crypto/sha2.sh"
# shellcheck source=scripts/lib/chains/solana.sh
source "${ROOT_DIR}/scripts/lib/chains/solana.sh"
# shellcheck source=scripts/lib/crypto/ed25519.sh
source "${ROOT_DIR}/scripts/lib/crypto/ed25519.sh"
# shellcheck source=scripts/lib/encoding/base58.sh
source "${ROOT_DIR}/scripts/lib/encoding/base58.sh"

expect_eq() {
  local actual="$1" expected="$2" message="$3"
  if [[ "${actual}" != "${expected}" ]]; then
    printf 'FAIL: %s\nExpected: %s\nActual:   %s\n' "${message}" "${expected}" "${actual}" >&2
    exit 1
  fi
}

test_slip10_vectors() {
  local seed="000102030405060708090a0b0c0d0e0f"
  local exp_master_key="2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
  local exp_master_chain="90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"
  local exp_child_key="68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"
  local exp_child_chain="8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69"

  read -r master_key master_chain < <(solana_slip10_master_from_seed "${seed}")
  expect_eq "${master_key}" "${exp_master_key}" "SLIP-0010 master key"
  expect_eq "${master_chain}" "${exp_master_chain}" "SLIP-0010 master chain"

  read -r child_key child_chain < <(solana_slip10_derive_path "${seed}" "m/0'")
  expect_eq "${child_key}" "${exp_child_key}" "SLIP-0010 child key m/0'"
  expect_eq "${child_chain}" "${exp_child_chain}" "SLIP-0010 child chain m/0'"
  pass "SLIP-0010 ed25519 reference vectors"
}

test_base58_vectors() {
  local zero_one
  zero_one="$(base58_encode_hex "00")"
  expect_eq "${zero_one}" "1" "Base58 encode 0x00"
  local two_bytes
  two_bytes="$(base58_encode_hex "0001")"
  expect_eq "${two_bytes}" "12" "Base58 encode 0x0001"
  local pub_hex="c047b4f3846cb97c5a956c84ad16a7922bdf7b659c17ff3b366f2d8f4a37f499"
  local addr
  addr="$(base58_encode_hex "${pub_hex}")"
  expect_eq "${addr}" "DwahMtMFiaySBMpNgRzDgwwAejoPM7ZgggMEhj3Yr2AL" "Base58 encode known public key"
  pass "Base58 encoding vectors"
}

test_cli_known_vector() {
  local mnemonic="urge pulp usage sister evidence arrest palm math please chief egg abuse"
  local expected_seed="fc8366fb892d2e9e30d56e72daf7585ee80482310a3c58936094e8d4dcdb1693d48cfc8b7d36d5de56ca244444ba2cd533c2ea4a533ab65de04303579395182d"
  local expected_priv="284e86df61965c35e2a5488d66dbbec5d58ab79305b695d064900351ec72c05f"
  local expected_pub="d9cc61f26972232bb9a429a83d56b2cb651e5313a3aa082f400c15d204d8abbd"
  local expected_secret64="${expected_priv}${expected_pub}"
  local expected_chain="b3c52f8deb70df13f951cd82c4a78c456bcd8ebdb989246ddba7bd2a5c9aa8bd"
  local expected_address="FfCEC4bh9hCuo2nANx7n8MVSumz7YqxT21sJ92YcTprg"

  local output
  output="$("${SOL_SCRIPT}" -q --include-seed --mnemonic "${mnemonic}" "${WLIST}")"

  parse_json() {
    local key="$1"
    jq -r --arg k "$key" '.[$k] // ""'
  }

  local priv pub secret64 chain addr seed
  priv="$(printf '%s' "${output}" | parse_json privateKey)"
  pub="$(printf '%s' "${output}" | parse_json publicKey)"
  secret64="$(printf '%s' "${output}" | parse_json secretKey)"
  chain="$(printf '%s' "${output}" | parse_json chainCode)"
  addr="$(printf '%s' "${output}" | parse_json address)"
  seed="$(printf '%s' "${output}" | parse_json seed)"

  expect_eq "${priv}" "${expected_priv}" "CLI private key"
  expect_eq "${pub}" "${expected_pub}" "CLI public key"
  expect_eq "${secret64}" "${expected_secret64}" "CLI secret 64"
  expect_eq "${chain}" "${expected_chain}" "CLI chain code"
  expect_eq "${addr}" "${expected_address}" "CLI base58 address"
  expect_eq "${seed}" "${expected_seed}" "CLI BIP39 seed"
  pass "sol-from-bash known mnemonic"
}

main() {
  test_slip10_vectors
  test_base58_vectors
  test_cli_known_vector
}

main "$@"
