#!/usr/bin/env bash
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/common.sh
source "${TESTS_DIR}/common.sh"

CRYPTO_SIGN="${ROOT_DIR}/scripts/crypto_sign.sh"
FIXTURE_DIR="${ROOT_DIR}/tests/fixtures/crypto_sign"
MESSAGE_FILE="${FIXTURE_DIR}/message.txt"

RSA_PRIV="${FIXTURE_DIR}/test_rsa_priv.pem"
RSA_PUB="${FIXTURE_DIR}/test_rsa_pub.pem"
RSA_SIG_B64_FILE="${FIXTURE_DIR}/test_rsa_sig.b64"

ECDSA_PRIV="${FIXTURE_DIR}/test_ecdsa_priv.pem"
ECDSA_PUB="${FIXTURE_DIR}/test_ecdsa_pub.pem"
ECDSA_SIG_B64_FILE="${FIXTURE_DIR}/test_ecdsa_sig.b64"

require_fixture() {
  local path="$1"
  local label="$2"
  if [[ ! -f "${path}" ]]; then
    echo "Missing ${label}: ${path}" >&2
    exit 1
  fi
}

ensure_permissions() {
  local path="$1"
  local mode="$2"
  if [[ $(stat -c '%a' "${path}") != "${mode}" ]]; then
    chmod "${mode}" "${path}"
  fi
}

run_with_status() {
  local __out_var="$1"
  shift
  set +e
  local __output
  __output="$("$@" 2>&1)"
  local __status=$?
  set -e
  printf -v "${__out_var}" '%s' "${__output}"
  return "${__status}"
}

main() {
  require_fixture "${MESSAGE_FILE}" "message fixture"
  require_fixture "${RSA_PRIV}" "RSA private key"
  require_fixture "${RSA_PUB}" "RSA public key"
  require_fixture "${RSA_SIG_B64_FILE}" "RSA signature"
  require_fixture "${ECDSA_PRIV}" "secp256k1 private key"
  require_fixture "${ECDSA_PUB}" "secp256k1 public key"
  require_fixture "${ECDSA_SIG_B64_FILE}" "secp256k1 signature"

  ensure_permissions "${RSA_PRIV}" 400
  ensure_permissions "${ECDSA_PRIV}" 400
  ensure_permissions "${RSA_PUB}" 444
  ensure_permissions "${ECDSA_PUB}" 444

  local expected observed
  expected="$(tr -d '\n' <"${RSA_SIG_B64_FILE}")"
  local shell_expected
  shell_expected="$("${CRYPTO_SIGN}" rsa-sign --key "${RSA_PRIV}" --message "${MESSAGE_FILE}" --output base64)"
  shell_expected="${shell_expected//[$'\n\r']/}"
  if [[ "${shell_expected}" != "${expected}" ]]; then
    echo "FAIL: RSA signing regression mismatch" >&2
    exit 1
  fi
  pass "RSA signing regression matches fixture"
  local rsa_verify_output
  if ! run_with_status rsa_verify_output "${CRYPTO_SIGN}" rsa-verify --key "${RSA_PUB}" --message "${MESSAGE_FILE}" \
    --signature <(base64 -d "${RSA_SIG_B64_FILE}"); then
    echo "FAIL: crypto_sign.sh rsa-verify missing; RSA support pending" >&2
    printf '%s\n' "${rsa_verify_output}" >&2
    exit 1
  fi
  pass "RSA verification accepts fixture signature"

  local temp_dir
  temp_dir="$(mktemp -d)"
  trap 'rm -rf "'"${temp_dir}"'"' EXIT

  local fixture_pub_out="${temp_dir}/fixture_pub.pem"
  "${CRYPTO_SIGN}" rsa-public --key "${RSA_PRIV}" --output "${fixture_pub_out}"
  if cmp -s "${fixture_pub_out}" "${RSA_PUB}"; then
    pass "rsa-public reproduces fixture SPKI"
  else
    echo "FAIL: rsa-public output mismatch for fixture" >&2
    exit 1
  fi

  local generated_priv="${temp_dir}/generated_priv.pem"
  local generated_pub="${temp_dir}/generated_pub.pem"
  "${CRYPTO_SIGN}" rsa-generate --bits 512 --private-out "${generated_priv}" --public-out "${generated_pub}"
  if [[ $(stat -c '%a' "${generated_priv}") != "600" ]]; then
    echo "FAIL: rsa-generate did not set private key permissions to 600" >&2
    exit 1
  fi
  if [[ $(stat -c '%a' "${generated_pub}") != "644" ]]; then
    echo "FAIL: rsa-generate did not set public key permissions to 644" >&2
    exit 1
  fi
  pass "rsa-generate creates keypair with expected permissions"

  local custom_priv="${temp_dir}/generated_priv_e3.pem"
  local custom_pub="${temp_dir}/generated_pub_e3.pem"
  if ! "${CRYPTO_SIGN}" rsa-generate --bits 512 --exponent 3 --private-out "${custom_priv}" --public-out "${custom_pub}"; then
    echo "FAIL: rsa-generate rejected custom exponent" >&2
    exit 1
  fi
  if [[ $(stat -c '%a' "${custom_priv}") != "600" ]]; then
    echo "FAIL: rsa-generate --exponent 3 private key permissions" >&2
    exit 1
  fi
  if [[ $(stat -c '%a' "${custom_pub}") != "644" ]]; then
    echo "FAIL: rsa-generate --exponent 3 public key permissions" >&2
    exit 1
  fi
  pass "rsa-generate supports custom exponent"

  local churn_script="${ROOT_DIR}/scripts/rsa_prime_churn.sh"
  local churn_output
  churn_output="$(CRYPTO_SIGN_RSA_MIN_BITS=32 CRYPTO_SIGN_RSA_MR_ROUNDS=1 "${churn_script}" --bits 96 --exponent 3)"
  if [[ "${churn_output}" != *"bc_simple="* || "${churn_output}" != *"bc_eval_common="* || "${churn_output}" != *"generate_prime_dec="* ]]; then
    echo "FAIL: rsa_prime_churn.sh output missing bc counters" >&2
    printf '%s\n' "${churn_output}" >&2
    exit 1
  fi
  pass "rsa_prime_churn.sh reports bc counters"

  local derived_pub="${temp_dir}/derived_pub.pem"
  "${CRYPTO_SIGN}" rsa-public --key "${generated_priv}" --output "${derived_pub}"
  if cmp -s "${derived_pub}" "${generated_pub}"; then
    pass "rsa-public round-trips generated private key"
  else
    echo "FAIL: rsa-public output mismatched generated public key" >&2
    exit 1
  fi

  expected="$(tr -d '\n' <"${ECDSA_SIG_B64_FILE}")"
  local ecdsa_sign_output
  if ! run_with_status ecdsa_sign_output "${CRYPTO_SIGN}" ecdsa-sign --key "${ECDSA_PRIV}" --message "${MESSAGE_FILE}" --output base64; then
    echo "FAIL: crypto_sign.sh ecdsa-sign missing" >&2
    printf '%s\n' "${ecdsa_sign_output}" >&2
    exit 1
  fi
  observed="${ecdsa_sign_output//[$'\n\r']/}"
  observed="${observed//[$'\n\r']/}"
  if [[ "${observed}" != "${expected}" ]]; then
    echo "FAIL: secp256k1 signing regression mismatch" >&2
    exit 1
  fi
  pass "secp256k1 signing regression matches fixture"

  if "${CRYPTO_SIGN}" ecdsa-verify --key "${ECDSA_PUB}" --message "${MESSAGE_FILE}" \
    --signature <(base64 -d "${ECDSA_SIG_B64_FILE}") >/dev/null; then
    pass "secp256k1 verification accepts fixture signature"
  else
    echo "FAIL: secp256k1 verification rejected fixture" >&2
    exit 1
  fi

  local derived_pub="${temp_dir}/ecdsa_pub.pem"
  if ! "${CRYPTO_SIGN}" ecdsa-public --key "${ECDSA_PRIV}" --output "${derived_pub}"; then
    echo "FAIL: ecdsa-public missing" >&2
    exit 1
  fi
  if cmp -s "${derived_pub}" "${ECDSA_PUB}"; then
    pass "ecdsa-public reproduces fixture"
  else
    echo "FAIL: ecdsa-public output mismatch" >&2
    exit 1
  fi

  local generated_ecdsa_priv="${temp_dir}/gen_ecdsa_priv.pem"
  local generated_ecdsa_pub="${temp_dir}/gen_ecdsa_pub.pem"
  if ! "${CRYPTO_SIGN}" ecdsa-generate --private-out "${generated_ecdsa_priv}" --public-out "${generated_ecdsa_pub}"; then
    echo "FAIL: ecdsa-generate missing" >&2
    exit 1
  fi
  if [[ $(stat -c '%a' "${generated_ecdsa_priv}") != "600" ]]; then
    echo "FAIL: ecdsa-generate private key mode incorrect" >&2
    exit 1
  fi
  if [[ $(stat -c '%a' "${generated_ecdsa_pub}") != "644" ]]; then
    echo "FAIL: ecdsa-generate public key mode incorrect" >&2
    exit 1
  fi
  if ! "${CRYPTO_SIGN}" ecdsa-verify --key "${generated_ecdsa_pub}" --message "${MESSAGE_FILE}" \
    --signature <("${CRYPTO_SIGN}" ecdsa-sign --key "${generated_ecdsa_priv}" --message "${MESSAGE_FILE}"); then
    echo "FAIL: generated secp256k1 keypair failed sign/verify round-trip" >&2
    exit 1
  fi
  pass "ecdsa-generate round-trip verified"
}

main "$@"
