#!/usr/bin/env bash
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/common.sh
source "${TESTS_DIR}/common.sh"
# shellcheck source=tests/load_secrets.sh
source "${TESTS_DIR}/load_secrets.sh"

FIXTURE_JSON="${ROOT_DIR}/tests/fixtures/secp256k1_vectors.json"
FIXTURE_PUB="${ROOT_DIR}/tests/fixtures/secp256k1_vectors_pub.pem"
SECP_HELPER="${ROOT_DIR}/scripts/secp256k1_pub.sh"
CRYPTO_SIGN="${ROOT_DIR}/scripts/crypto_sign.py"

verify_signature() {
  local sig_file="${SECP256K1_VECTOR_SIG_B64_FILE-}"
  if [[ -z "${sig_file}" ]]; then
    if (( TEST_SIGNED_MODE == 1 )); then
      echo "Missing secp256k1 signature artifact" >&2
      exit 1
    fi
    echo "INFO: secp256k1 signature unavailable; skipping verification" >&2
    return
  fi

  ensure_secret_file_mode "${sig_file}" "secp256k1 fixture signature"

  if "${CRYPTO_SIGN}" ecdsa-verify --key "${FIXTURE_PUB}" --message "${FIXTURE_JSON}" --signature "${sig_file}" >/dev/null; then
    pass "secp256k1 vector signature verified"
  else
    echo "FAIL: secp256k1 vector signature verification failed" >&2
    exit 1
  fi
}

run_vectors() {
  if [[ ! -x "${SECP_HELPER}" ]]; then
    echo "FAIL: secp256k1 helper not executable" >&2
    exit 1
  fi

  local vector_count=0
  while IFS=$'\t' read -r name priv expected_comp expected_uncomp; do
    if [[ -z "${name}" ]]; then
      echo "FAIL: empty vector entry" >&2
      exit 1
    fi
    local comp uncomp
    if ! read -r comp uncomp <<<"$("${SECP_HELPER}" pub --priv-hex "${priv}")"; then
      echo "FAIL: helper failed for vector ${name}" >&2
      exit 1
    fi
    if [[ "${comp}" != "${expected_comp}" || "${uncomp}" != "${expected_uncomp}" ]]; then
      echo "FAIL: Vector ${name} mismatch" >&2
      exit 1
    fi
    vector_count=$((vector_count + 1))
  done < <(
    jq -r '.vectors[] | [.name, .private_hex, .compressed_hex, .uncompressed_hex] | @tsv' "${FIXTURE_JSON}"
  )

  if (( vector_count == 0 )); then
    echo "FAIL: Fixture bundle missing vectors" >&2
    exit 1
  fi

  pass "secp256k1 vectors verified"
}

check_edge_cases() {
  local expected_comp="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
  local expected_uncomp="0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
  local comp uncomp
  if ! read -r comp uncomp <<<"$("${SECP_HELPER}" pub --priv-hex 0000000000000000000000000000000000000000000000000000000000000001)"; then
    echo "FAIL: helper refused generator scalar" >&2
    exit 1
  fi
  if [[ "${comp}" != "${expected_comp}" || "${uncomp}" != "${expected_uncomp}" ]]; then
    echo "FAIL: generator scalar mismatch" >&2
    exit 1
  fi

  if "${SECP_HELPER}" pub --priv-hex 0000000000000000000000000000000000000000000000000000000000000000 >/dev/null 2>&1; then
    echo "FAIL: zero scalar accepted" >&2
    exit 1
  fi

  if "${SECP_HELPER}" pub --priv-hex ffffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 >/dev/null 2>&1; then
    echo "FAIL: order scalar accepted" >&2
    exit 1
  fi

  pass "secp256k1 edge cases rejected"
}

main() {
  "${SECP_HELPER}" selftest >/dev/null
  pass "secp256k1 primitive self-test"
  verify_signature
  run_vectors
  check_edge_cases
}

main "$@"
