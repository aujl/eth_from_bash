#!/usr/bin/env bash
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/common.sh
source "${TESTS_DIR}/common.sh"
# shellcheck source=tests/load_secrets.sh
source "${TESTS_DIR}/load_secrets.sh"

FIXTURE_JSON="${ROOT_DIR}/tests/fixtures/secp256k1_vectors.json"
FIXTURE_PUB="${ROOT_DIR}/tests/fixtures/secp256k1_vectors_pub.pem"

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
  python3 - "${ROOT_DIR}" <<'PY'
import json
import pathlib
import sys

ROOT = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(ROOT / "scripts"))
from derive_seed_and_pub import derive_pubkeys  # pylint: disable=import-error

fixture_path = ROOT / "tests" / "fixtures" / "secp256k1_vectors.json"
with fixture_path.open("r", encoding="utf-8") as handle:
    payload = json.load(handle)

vectors = payload.get("vectors", [])
if not vectors:
    raise SystemExit("Fixture bundle missing vectors")

for vector in vectors:
    name = vector.get("name", "<unnamed>")
    priv = vector["private_hex"]
    expected_comp = vector["compressed_hex"]
    expected_uncomp = vector["uncompressed_hex"]
    comp, uncomp = derive_pubkeys(priv)
    if comp != expected_comp or uncomp != expected_uncomp:
        raise SystemExit(
            f"Vector {name} mismatch: {comp=} {uncomp=}"
        )
PY
  pass "secp256k1 vectors verified"
}

main() {
  python3 "${ROOT_DIR}/scripts/derive_seed_and_pub.py" selftest >/dev/null
  pass "secp256k1 primitive self-test"
  verify_signature
  run_vectors
}

main "$@"
