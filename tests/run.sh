#!/usr/bin/env bash
set -euo pipefail

TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/load_secrets.sh
source "${TEST_DIR}/load_secrets.sh"

SCRIPTS=(
  load_secrets_mode.sh
  bip39_lib.sh
  bip32_lib.sh
  core_flow.sh
  crypto_kdf_unit.sh
  crypto_kdf_vectors.sh
  crypto_sign_regression.sh
  crypto_sign_cache.sh
  crypto_sign_primality_tuning.sh
  keccak_primitive.sh
  secp256k1_primitive.sh
)

for script in "${SCRIPTS[@]}"; do
  echo "==> Running ${script}"
  start_ts=$(date +%s)
  bash "${TEST_DIR}/${script}"
  end_ts=$(date +%s)
  duration=$((end_ts - start_ts))
  max_duration=${TEST_TIMEOUT:-60}
  echo "-- ${script} completed in ${duration}s"
  if (( duration > max_duration )); then
    echo "FAIL: ${script} exceeded ${max_duration} seconds (took ${duration}s)" >&2
    exit 1
  fi
  echo
done
