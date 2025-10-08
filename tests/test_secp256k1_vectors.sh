#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=tests/common.sh
source "$(dirname "$0")/common.sh"

FIXTURE_JSON="${ROOT_DIR}/tests/fixtures/secp256k1_vectors.json"
FIXTURE_PUB="${ROOT_DIR}/tests/fixtures/secp256k1_vectors_pub.pem"
SIG_B64="${SECP256K1_VECTOR_SIG_B64-}"

if [[ -z "${SIG_B64}" ]]; then
  echo "SECP256K1_VECTOR_SIG_B64 must be set to the base64 signature for ${FIXTURE_JSON}" >&2
  exit 1
fi

tmp_sig="$(mktemp)"
trap 'rm -f "${tmp_sig}"' EXIT
printf '%s' "${SIG_B64}" | tr -d '\n' | base64 -d >"${tmp_sig}"

openssl dgst -sha256 -verify "${FIXTURE_PUB}" -signature "${tmp_sig}" "${FIXTURE_JSON}" >/dev/null

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

echo "PASS: secp256k1 vectors verified"
