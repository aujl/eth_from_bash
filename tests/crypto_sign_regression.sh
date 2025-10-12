#!/usr/bin/env bash
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/common.sh
source "${TESTS_DIR}/common.sh"

CRYPTO_SIGN="${ROOT_DIR}/scripts/crypto_sign.sh"
CRYPTO_SIGN_ECDSA="${ROOT_DIR}/scripts/crypto_sign.py"
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
  local rsa_sign_output
  if ! run_with_status rsa_sign_output "${CRYPTO_SIGN}" rsa-sign --key "${RSA_PRIV}" --message "${MESSAGE_FILE}" --output base64; then
    echo "FAIL: crypto_sign.sh rsa-sign missing; RSA support pending" >&2
    printf '%s\n' "${rsa_sign_output}" >&2
    exit 1
  fi
  observed="${rsa_sign_output//[$'\n\r']/}"
  if [[ "${observed}" != "${expected}" ]]; then
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

  expected="$(tr -d '\n' <"${ECDSA_SIG_B64_FILE}")"
  observed="$("${CRYPTO_SIGN_ECDSA}" ecdsa-sign --key "${ECDSA_PRIV}" --message "${MESSAGE_FILE}" --output base64)"
  observed="${observed//[$'\n\r']/}"
  if [[ "${observed}" != "${expected}" ]]; then
    echo "FAIL: secp256k1 signing regression mismatch" >&2
    exit 1
  fi
  pass "secp256k1 signing regression matches fixture"

  if "${CRYPTO_SIGN_ECDSA}" ecdsa-verify --key "${ECDSA_PUB}" --message "${MESSAGE_FILE}" \
    --signature <(base64 -d "${ECDSA_SIG_B64_FILE}") >/dev/null; then
    pass "secp256k1 verification accepts fixture signature"
  else
    echo "FAIL: secp256k1 verification rejected fixture" >&2
    exit 1
  fi
}

main "$@"
