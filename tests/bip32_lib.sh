#!/usr/bin/env bash
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/common.sh
source "${TEST_DIR}/common.sh"

CRYPTO_KDF_HELPER="${ROOT_DIR}/scripts/crypto_kdf.sh"
SECP256K1_HELPER="${ROOT_DIR}/scripts/secp256k1_pub.sh"
if [[ ! -x "${CRYPTO_KDF_HELPER}" ]]; then
  fail "crypto_kdf helper missing at ${CRYPTO_KDF_HELPER}"
fi
if [[ ! -x "${SECP256K1_HELPER}" ]]; then
  fail "secp256k1 helper missing at ${SECP256K1_HELPER}"
fi
export CRYPTO_KDF_HELPER
export SECP256K1_HELPER

# shellcheck source=/dev/null
source "${ROOT_DIR}/scripts/lib/bip/bip32.sh"

add_result="$(bip32_bn_add_mod_n "0000000000000000000000000000000000000000000000000000000000000001" \
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")"
if [[ "${add_result}" != "0000000000000000000000000000000000000000000000000000000000000000" ]]; then
  fail "bn_add_mod_n failed modular wrap"
fi

if [[ "$(bip32_bn_ge "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141" \
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")" -ne 1 ]]; then
  fail "bn_ge equality check failed"
fi
if [[ "$(bip32_bn_ge "0000000000000000000000000000000000000000000000000000000000000001" \
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")" -ne 0 ]]; then
  fail "bn_ge ordering check failed"
fi

if [[ "$(bip32_bn_is_zero "0000000000000000000000000000000000000000000000000000000000000000")" -ne 1 ]]; then
  fail "bn_is_zero failed for zero"
fi
if [[ "$(bip32_bn_is_zero "0000000000000000000000000000000000000000000000000000000000000001")" -ne 0 ]]; then
  fail "bn_is_zero misidentified non-zero"
fi

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

comp_helper="$(bip32_pub_compressed_from_priv_hex "${final_k}")"
if [[ "${comp_helper}" != "${comp_pub}" ]]; then
  fail "compressed pub helper mismatch"
fi

if [[ ! "${final_c}" =~ ^[0-9A-Fa-f]{64}$ ]]; then
  fail "derived chain code malformed"
fi

if bip32_validate_private_scalar "0000000000000000000000000000000000000000000000000000000000000000" "zero" 2>/dev/null; then
  fail "zero scalar erroneously accepted"
fi

pass "bip32 library helpers"
