#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=tests/common.sh
source "$(dirname "$0")/common.sh"

if ! require_python_module ecdsa; then
  echo "WARNING: python module 'ecdsa' missing; using pure-Python secp256k1 fallback." >&2
fi

run_seed_vector(){
  local mn="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  local expected="c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
  local out seed
  out=$(bash "${SCRIPT}" -q --include-seed --no-address --mnemonic "${mn}" "${WLIST}" TREZOR)
  seed=$(jq -r .seed <<<"${out}")
  if [[ "${seed}" == "${expected}" ]]; then
    pass "BIP39 PBKDF2 seed vector"
  else
    echo "Got:      ${seed}"
    echo "Expected: ${expected}"
    fail "BIP39 PBKDF2 seed vector"
  fi
}

run_python_helper_pub(){
  local helper="${ROOT_DIR}/scripts/derive_seed_and_pub.py"
  local out comp uncomp
  out=$(python3 "${helper}" pub --priv-hex 0000000000000000000000000000000000000000000000000000000000000001)
  read -r comp uncomp <<<"${out}"
  local expected_comp="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
  local expected_uncomp="0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
  if [[ "${comp}" == "${expected_comp}" && "${uncomp}" == "${expected_uncomp}" ]]; then
    pass "Python helper secp256k1 derivation"
  else
    echo "comp:      ${comp}"
    echo "expected:  ${expected_comp}"
    echo "uncomp:    ${uncomp}"
    echo "expected:  ${expected_uncomp}"
    fail "Python helper secp256k1 derivation"
  fi
}

run_mnemonic_checksum(){
  local out mn
  out=$(bash "${SCRIPT}" -q --include-seed "${WLIST}")
  mn=$(jq -r .mnemonic <<<"${out}")
  local bits="" idx
  local -a words=()
  read -r -a words <<<"${mn}"
  for w in "${words[@]}"; do
    idx=$(awk -v w="${w}" 'BEGIN{found=0} $0==w {print NR; found=1; exit} END{if(!found) exit 1}' "${WLIST}" || true)
    if [[ -z "${idx}" ]]; then
      fail "word ${w} not found"
    fi
    idx=$((idx-1))
    local b
    b=$(echo "obase=2; ${idx}" | bc)
    b=$(printf "%011s" "${b}" | tr ' ' 0)
    bits+="${b}"
  done
  local ent_bits=${bits:0:128}
  local cs_bits=${bits:128:4}
  local ent_hex=""
  local i=0
  while (( i < 128 )); do
    local byte=${ent_bits:${i}:8}
    local val
    val=$(echo "ibase=2; ${byte}" | bc)
    ent_hex+=$(printf "%02x" "${val}")
    i=$((i+8))
  done
  local cs_nib cs_bin
  cs_nib=$(printf "%s" "${ent_hex}" | xxd -r -p | sha256sum | cut -c1)
  cs_bin=$(echo "obase=2; ibase=16; ${cs_nib^^}" | bc)
  cs_bin=$(printf "%04s" "${cs_bin}" | tr ' ' 0)
  if [[ "${cs_bin}" == "${cs_bits}" ]]; then
    pass "BIP39 mnemonic checksum"
  else
    echo "mnemonic: ${mn}"
    echo "ent_hex:  ${ent_hex}"
    echo "cs_bits:  ${cs_bits}"
    echo "calc_cs:  ${cs_bin}"
    fail "BIP39 mnemonic checksum"
  fi
}

main(){
  run_seed_vector
  run_python_helper_pub
  run_mnemonic_checksum
}

main "$@"
