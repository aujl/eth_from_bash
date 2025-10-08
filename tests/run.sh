#!/usr/bin/env bash
set -euo pipefail

TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS=(
  test_cli_core.sh
  test_env_controls.sh
  test_keccak.sh
)

for script in "${SCRIPTS[@]}"; do
  echo "==> Running ${script}"
  start_ts=$(date +%s)
  bash "${TEST_DIR}/${script}"
  end_ts=$(date +%s)
  duration=$((end_ts - start_ts))
  echo "-- ${script} completed in ${duration}s"
  if (( duration > 20 )); then
    echo "FAIL: ${script} exceeded 20 seconds (took ${duration}s)" >&2
    exit 1
  fi
  echo
done
