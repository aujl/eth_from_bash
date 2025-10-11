#!/usr/bin/env bash
set -euo pipefail

real_bin="${CRYPTO_KDF_REAL:-}"
if [[ "${ETH_FROM_BASH_TEST_SCENARIO:-}" == "master_il_zero" && "${1-}" == "hmac-sha512" ]]; then
  printf '0%.0s' {1..128}
  printf '\n'
  exit 0
fi

if [[ -z "${real_bin}" ]]; then
  echo "CRYPTO_KDF_REAL not set" >&2
  exit 1
fi

exec "${real_bin}" "$@"
