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

  if openssl dgst -sha256 -verify "${FIXTURE_PUB}" -signature "${sig_file}" "${FIXTURE_JSON}" >/dev/null 2>&1; then
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

main() {
  "${SECP_HELPER}" selftest >/dev/null
  pass "secp256k1 primitive self-test"
  verify_signature
  run_vectors
}

main "$@"
