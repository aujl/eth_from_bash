#!/usr/bin/env bash
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/common.sh
source "${TESTS_DIR}/common.sh"

CRYPTO_SIGN="${ROOT_DIR}/scripts/crypto_sign.sh"

main() {
  local trace_file
  trace_file="$(mktemp -u -t crypto_sign_cache.XXXXXX)"
  trap '[[ -n "${trace_file:-}" && -e "${trace_file}" ]] && rm -f "${trace_file}"' EXIT

  local subshell_output
  if ! subshell_output="$(
    (
      set -euo pipefail
      export CRYPTO_SIGN_TRACE_CHURN=1
      export CRYPTO_SIGN_TRACE_FILE_PATH="${trace_file}"
      set -- --help
      # shellcheck source=scripts/crypto_sign.sh
      source "${CRYPTO_SIGN}"
      set --
      : >| "${CRYPTO_SIGN_TRACE_FILE_PATH}"
      hex_value="00ff"
      dec_tmp="$(mktemp -u -t crypto_sign_cache_dec.XXXXXX)"
      hex_tmp="$(mktemp -u -t crypto_sign_cache_hex.XXXXXX)"
      hex_to_dec "${hex_value}" >"${dec_tmp}"
      IFS= read -r dec_value <"${dec_tmp}"
      first_hex_count="$(grep -c '^bc_simple$' "${CRYPTO_SIGN_TRACE_FILE_PATH}" 2>/dev/null || true)"
      hex_to_dec "${hex_value}" >/dev/null
      second_hex_count="$(grep -c '^bc_simple$' "${CRYPTO_SIGN_TRACE_FILE_PATH}" 2>/dev/null || true)"
      dec_to_hex "${dec_value}" >"${hex_tmp}"
      first_dec_count="$(grep -c '^bc_simple$' "${CRYPTO_SIGN_TRACE_FILE_PATH}" 2>/dev/null || true)"
      dec_to_hex "${dec_value}" >/dev/null
      second_dec_count="$(grep -c '^bc_simple$' "${CRYPTO_SIGN_TRACE_FILE_PATH}" 2>/dev/null || true)"
      printf 'counts %s %s %s %s\n' "${first_hex_count}" "${second_hex_count}" "${first_dec_count}" "${second_dec_count}"
      rm -f "${dec_tmp}" "${hex_tmp}"
    ) 2>&1
  )"; then
    printf '%s\n' "${subshell_output}" >&2
    fail "crypto_sign cache subshell execution failed"
  fi

  if [[ ! -f "${trace_file}" ]]; then
    printf '%s\n' "${subshell_output}" >&2
    fail "crypto_sign trace file was not created"
  fi

  local counts_line prefix first_hex second_hex first_dec second_dec
  counts_line="$(printf '%s\n' "${subshell_output}" | grep '^counts ' || true)"
  if [[ -z "${counts_line}" ]]; then
    printf '%s\n' "${subshell_output}" >&2
    fail "missing cache hit counters from crypto_sign subshell"
  fi
  IFS=' ' read -r prefix first_hex second_hex first_dec second_dec <<<"${counts_line}"
  if [[ "${first_hex}" != "1" || "${second_hex}" != "1" ]]; then
    printf '%s\n' "${subshell_output}" >&2
    fail "expected hex_to_dec to trigger bc_simple once, counts were ${first_hex} -> ${second_hex}"
  fi
  if [[ "${first_dec}" != "2" || "${second_dec}" != "2" ]]; then
    printf '%s\n' "${subshell_output}" >&2
    fail "expected dec_to_hex to trigger bc_simple once, counts were ${first_dec} -> ${second_dec}"
  fi

  local bc_simple_count
  bc_simple_count="$(grep -c '^bc_simple$' "${trace_file}" 2>/dev/null || true)"
  if [[ "${bc_simple_count}" -ne 2 ]]; then
    echo "Trace contents:" >&2
    cat "${trace_file}" >&2
    printf '%s\n' "${subshell_output}" >&2
    fail "expected bc_simple to run exactly twice (once per conversion direction); got ${bc_simple_count}"
  fi

  if [[ "${subshell_output}" != *"trace:bc_simple=2"* ]]; then
    printf '%s\n' "${subshell_output}" >&2
    fail "trace summary missing bc_simple=2"
  fi

  pass "crypto_sign caches repeated base conversions"
}

main "$@"
