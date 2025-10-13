#!/usr/bin/env bash
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/common.sh
source "${TESTS_DIR}/common.sh"

CRYPTO_SIGN="${ROOT_DIR}/scripts/crypto_sign.sh"

check_miller_rabin_rounds() {
  local bits expected actual
  for bits in 256 384 512 1024 2048 4096; do
    case "${bits}" in
      256)
        expected=12
        ;;
      384)
        expected=10
        ;;
      512)
        expected=8
        ;;
      1024)
        expected=7
        ;;
      2048)
        expected=5
        ;;
      4096)
        expected=3
        ;;
      *)
        fail "Unexpected bit size ${bits} in test harness"
        ;;
    esac
    actual="$(miller_rabin_rounds_for_bits "${bits}")"
    if [[ "${actual}" != "${expected}" ]]; then
      fail "miller_rabin_rounds_for_bits ${bits} => ${actual}, expected ${expected}"
    fi
  done
  pass "miller_rabin_rounds_for_bits matches documented thresholds"
}

verify_small_prime_sieve_trace() {
  local trace_file
  trace_file="$(mktemp -t crypto_sign_trace_test.XXXXXX)"
  trap 'if [[ -n "${trace_file:-}" ]]; then rm -f "${trace_file}"; fi' RETURN

  local status
  set +e
  CRYPTO_SIGN_TRACE_CHURN=1 CRYPTO_SIGN_TRACE_FILE_PATH="${trace_file}" \
    is_probable_prime_dec 15 8 0f
  status=$?
  set -e
  if [[ ${status} -eq 0 ]]; then
    fail "is_probable_prime_dec incorrectly accepted composite 15"
  fi

  if grep -q '^bc_simple$' "${trace_file}"; then
    fail "Trace recorded bc_simple for small composite"
  fi
  if grep -q '^bc_eval_common$' "${trace_file}"; then
    fail "Trace recorded bc_eval_common for small composite"
  fi
  pass "small-prime sieve short-circuits composites without bc trials"
}

run_primality_checks() {
  check_miller_rabin_rounds
  verify_small_prime_sieve_trace
}

main() {
  (
    set -- --help
    {
      # shellcheck source=scripts/crypto_sign.sh
      source "${CRYPTO_SIGN}"
    } >/dev/null
    run_primality_checks
  )
}

main "$@"
