#!/usr/bin/env bash
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/common.sh
source "${TESTS_DIR}/common.sh"
# shellcheck source=tests/load_secrets.sh
source "${TESTS_DIR}/load_secrets.sh"

KECCAK_SCRIPT="${ROOT_DIR}/scripts/keccak_primitives.py"
VECTORS_FILE="${ROOT_DIR}/tests/fixtures/keccak_vectors.json"
REFERENCE_PUB="${ROOT_DIR}/tests/fixtures/keccak_reference_pub.pem"

run_keccak_self_test() {
  if "${PYTHON_BIN}" "${KECCAK_SCRIPT}" self-test >/dev/null; then
    pass "Keccak primitive internal self-test"
  else
    echo "FAIL: Keccak primitive internal self-test" >&2
    exit 1
  fi
}

run_cli_digests() {
  local empty abc
  empty=$(printf '' | "${PYTHON_BIN}" "${KECCAK_SCRIPT}" keccak256-hex)
  abc=$(printf 'abc' | "${PYTHON_BIN}" "${KECCAK_SCRIPT}" keccak256-hex)
  if [[ "${empty}" == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" ]]; then
    pass "Keccak-256 hex digest (empty string)"
  else
    echo "FAIL: Keccak-256 hex digest (empty string)" >&2
    exit 1
  fi
  if [[ "${abc}" == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45" ]]; then
    pass "Keccak-256 hex digest ('abc')"
  else
    echo "FAIL: Keccak-256 hex digest ('abc')" >&2
    exit 1
  fi
}

run_cli_eip55() {
  local out addr recomputed
  out=$(bash "${SCRIPT}" -q --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" "${WLIST}")
  addr=$(jq -r .address <<<"${out}")
  recomputed=$("${PYTHON_BIN}" "${ROOT_DIR}/scripts/eip55_recompute.py" "${addr}")
  if [[ "${recomputed}" == "${addr}" ]]; then
    pass "EIP-55 checksum matches"
  else
    echo "FAIL: EIP-55 checksum" >&2
    exit 1
  fi
}

verify_vectors_drift() {
  if ! "${PYTHON_BIN}" - <<'PY' "${KECCAK_SCRIPT}" "${VECTORS_FILE}"; then
import json
import subprocess
import sys
from pathlib import Path

script = Path(sys.argv[1])
fixture_path = Path(sys.argv[2])
regen = subprocess.check_output([sys.executable, str(script), "vectors"], text=True).strip()
fixture_text = fixture_path.read_text().strip()
canonical = json.dumps(json.loads(fixture_text), separators=(",", ":"), sort_keys=True)
if regen != canonical:
    print("Regenerated vectors diverge from fixture", file=sys.stderr)
    import difflib
    diff = difflib.unified_diff([canonical + "\n"], [fixture_text + "\n"], fromfile="regen", tofile=str(fixture_path))
    for line in diff:
        sys.stderr.write(line)
    sys.exit(1)
PY
    echo "FAIL: Keccak vector fixture drift" >&2
    exit 1
  fi
  pass "Keccak vector fixture up-to-date"
}

verify_signature() {
  local sig_file="${KECCAK_VECTOR_SIG_B64_FILE-}"
  if [[ -z "${sig_file}" ]]; then
    if (( TEST_SIGNED_MODE == 1 )); then
      echo "Missing keccak signature artifact" >&2
      exit 1
    fi
    echo "INFO: Keccak signature unavailable; skipping verification" >&2
    return
  fi

  ensure_secret_file_mode "${sig_file}" "keccak fixture signature"

  if openssl dgst -sha256 -verify "${REFERENCE_PUB}" -signature "${sig_file}" "${VECTORS_FILE}" >/dev/null 2>&1; then
    pass "Keccak vector signature verified"
  else
    echo "FAIL: Keccak vector signature verification failed" >&2
    exit 1
  fi
}

main() {
  run_keccak_self_test
  run_cli_digests
  run_cli_eip55
  verify_vectors_drift
  verify_signature
}

main "$@"
