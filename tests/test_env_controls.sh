#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=tests/common.sh
source "$(dirname "$0")/common.sh"

run_env_entropy_override(){
  local ent="00000000000000000000000000000000"
  local expected_mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  local out mn
  out=$(ENT_HEX="${ent}" bash "${SCRIPT}" -q --include-seed --no-address "${WLIST}")
  mn=$(jq -r .mnemonic <<<"${out}")
  if [[ "${mn}" == "${expected_mnemonic}" ]]; then
    pass "ENT_HEX environment override"
  else
    echo "Expected: ${expected_mnemonic}"
    echo "Got:      ${mn}"
    fail "ENT_HEX environment override"
  fi
}

run_env_entropy_invalid(){
  if ENT_HEX="zz" bash "${SCRIPT}" -q "${WLIST}" >/dev/null 2>&1; then
    fail "ENT_HEX invalid input rejected"
  else
    pass "ENT_HEX invalid input rejected"
  fi
}

run_env_mnemonic_override(){
  local mn="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  local expected_seed="c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
  local out seed
  out=$(MNEMONIC="${mn}" bash "${SCRIPT}" -q --include-seed --no-address "${WLIST}" TREZOR)
  seed=$(jq -r .seed <<<"${out}")
  if [[ "${seed}" == "${expected_seed}" ]]; then
    pass "MNEMONIC environment override"
  else
    echo "Expected: ${expected_seed}"
    echo "Got:      ${seed}"
    fail "MNEMONIC environment override"
  fi
}

run_env_mnemonic_invalid(){
  if MNEMONIC="foo bar" bash "${SCRIPT}" -q "${WLIST}" >/dev/null 2>&1; then
    fail "MNEMONIC invalid input rejected"
  else
    pass "MNEMONIC invalid input rejected"
  fi
}

run_master_il_guard(){
  local real_openssl
  real_openssl="$(command -v openssl)"
  local path_override="${ROOT_DIR}/tests/fixtures:${PATH}"
  if OPENSSL_REAL="${real_openssl}" \
    ETH_FROM_BASH_TEST_SCENARIO="master_il_zero" \
    PATH="${path_override}" \
    MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
    bash "${SCRIPT}" -q --include-seed --no-address "${WLIST}" TREZOR >/dev/null 2>&1; then
    fail "master IL zero guard"
  else
    pass "master IL zero guard"
  fi
}

main(){
  run_env_entropy_override
  run_env_entropy_invalid
  run_env_mnemonic_override
  run_env_mnemonic_invalid
  run_master_il_guard
}

main "$@"
