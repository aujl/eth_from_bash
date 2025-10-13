#!/usr/bin/env bash
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/common.sh
source "${TEST_DIR}/common.sh"

CRYPTO_KDF_HELPER="${ROOT_DIR}/scripts/crypto_kdf.sh"
SECP256K1_HELPER="${ROOT_DIR}/scripts/secp256k1_pub.sh"
export CRYPTO_KDF_HELPER
export SECP256K1_HELPER

# shellcheck source=/dev/null
source "${ROOT_DIR}/scripts/lib/bip32.sh"

seed_hex="c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
read -r master_k master_c < <(bip32_master_from_seed "${seed_hex}")
if [[ "${master_k,,}" != "cbedc75b0d6412c85c79bc13875112ef912fd1e756631b5a00330866f22ff184" ]]; then
  fail "unexpected master private key"
fi
if [[ "${master_c,,}" != "a3fa8c983223306de0f0f65e74ebb1e98aba751633bf91d5fb56529aa5c132c1" ]]; then
  fail "unexpected master chain code"
fi

segments=("44'" "60'" "0'" "0" "0")
read -r final_k final_c < <(bip32_derive_path_segments "${master_k}" "${master_c}" "${segments[@]}")
expected_priv="62f1d86b246c81bdd8f6c166d56896a4a5e1eddbcaebe06480e5c0bc74c28224"
if [[ "${final_k,,}" != "${expected_priv}" ]]; then
  fail "unexpected derived private key"
fi

bip32_validate_private_scalar "${final_k}" "final private key" || fail "private key validation failed"

read -r comp_pub uncompressed_pub < <(bip32_pub_from_private "${final_k}")
if [[ ${#comp_pub} -ne 66 || ! "${comp_pub}" =~ ^0[23] ]]; then
  fail "compressed public key invalid"
fi
if [[ ${#uncompressed_pub} -ne 130 || "${uncompressed_pub:0:2}" != "04" ]]; then
  fail "uncompressed public key invalid"
fi

if [[ ! "${final_c}" =~ ^[0-9A-Fa-f]{64}$ ]]; then
  fail "derived chain code malformed"
fi

pass "bip32 library helpers"
