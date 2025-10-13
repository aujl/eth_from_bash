#!/usr/bin/env bash
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/common.sh
source "${TEST_DIR}/common.sh"
# shellcheck source=/dev/null
source "${ROOT_DIR}/scripts/lib/bip39.sh"

bip39_load_wordlist "${WLIST}"

entropy_hex="00000000000000000000000000000000"
validated="$(bip39_validate_entropy_hex "${entropy_hex}")"
if [[ "${validated}" != "${entropy_hex}" ]]; then
  fail "validate entropy returned ${validated}"
fi

entropy_bits="$(bip39_entropy_bits "${entropy_hex}")"
if [[ ${#entropy_bits} -ne 128 ]]; then
  fail "entropy bits length ${#entropy_bits} != 128"
fi

checksum_bits="$(bip39_checksum_bits "${entropy_hex}")"
if [[ "${checksum_bits}" != "0011" ]]; then
  fail "checksum bits ${checksum_bits}"
fi

checksum_nibble="$(bip39_checksum_nibble_hex "${entropy_hex}")"
if [[ "${checksum_nibble}" != "3" ]]; then
  fail "checksum nibble ${checksum_nibble}"
fi

mnemonic="$(bip39_build_mnemonic_from_entropy "${entropy_hex}")"
expected_mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
if [[ "${mnemonic}" != "${expected_mnemonic}" ]]; then
  fail "mnemonic mismatch: ${mnemonic}"
fi

validated_phrase="$(bip39_validate_mnemonic "${mnemonic}")"
if [[ "${validated_phrase}" != "${expected_mnemonic}" ]]; then
  fail "validated mnemonic mismatch"
fi

random_entropy="$(bip39_generate_entropy_hex)"
if [[ ! "${random_entropy}" =~ ^[0-9a-f]{32}$ ]]; then
  fail "generated entropy invalid: ${random_entropy}"
fi

pass "bip39 library helpers"
