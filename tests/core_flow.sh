#!/usr/bin/env bash
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/common.sh
source "${TESTS_DIR}/common.sh"
# shellcheck source=tests/load_secrets.sh
source "${TESTS_DIR}/load_secrets.sh"

CORE_FIXTURE="${ROOT_DIR}/tests/fixtures/core_flow_vectors.json"

load_fixture_values() {
  if [[ ! -f "${CORE_FIXTURE}" ]]; then
    echo "Missing core flow fixture" >&2
    exit 1
  fi

  local jq_bin
  jq_bin="$(command -v jq)"
  if [[ -z "${jq_bin}" ]]; then
    echo "jq binary not found" >&2
    exit 1
  fi

  SEED_VECTOR_MNEMONIC="$(${jq_bin} -r '.seed_vector.mnemonic' "${CORE_FIXTURE}")"
  SEED_VECTOR_EXPECTED_SEED="$(${jq_bin} -r '.seed_vector.expected_seed' "${CORE_FIXTURE}")"
  SEED_VECTOR_PASSPHRASE="$(${jq_bin} -r '.seed_vector.passphrase' "${CORE_FIXTURE}")"

  PYTHON_PRIV_HEX="$(${jq_bin} -r '.python_helper.priv_hex' "${CORE_FIXTURE}")"
  PYTHON_EXPECTED_COMP="$(${jq_bin} -r '.python_helper.compressed_hex' "${CORE_FIXTURE}")"
  PYTHON_EXPECTED_UNCOMP="$(${jq_bin} -r '.python_helper.uncompressed_hex' "${CORE_FIXTURE}")"

  ENTROPY_HEX_OVERRIDE="$(${jq_bin} -r '.env_overrides.entropy_hex' "${CORE_FIXTURE}")"
  ENTROPY_EXPECTED_MNEMONIC="$(${jq_bin} -r '.env_overrides.expected_mnemonic' "${CORE_FIXTURE}")"
  MNEMONIC_OVERRIDE_VALUE="$(${jq_bin} -r '.env_overrides.mnemonic_override' "${CORE_FIXTURE}")"
  MNEMONIC_OVERRIDE_EXPECTED_SEED="$(${jq_bin} -r '.env_overrides.expected_seed' "${CORE_FIXTURE}")"
  INVALID_ENTROPY_VALUE="$(${jq_bin} -r '.env_overrides.invalid_entropy' "${CORE_FIXTURE}")"
  INVALID_MNEMONIC_VALUE="$(${jq_bin} -r '.invalid_mnemonic' "${CORE_FIXTURE}")"

  for value in \
    SEED_VECTOR_MNEMONIC SEED_VECTOR_EXPECTED_SEED SEED_VECTOR_PASSPHRASE \
    PYTHON_PRIV_HEX PYTHON_EXPECTED_COMP PYTHON_EXPECTED_UNCOMP \
    ENTROPY_HEX_OVERRIDE ENTROPY_EXPECTED_MNEMONIC MNEMONIC_OVERRIDE_VALUE \
    MNEMONIC_OVERRIDE_EXPECTED_SEED INVALID_ENTROPY_VALUE INVALID_MNEMONIC_VALUE; do
    if [[ -z "${!value}" || "${!value}" == "null" ]]; then
      echo "Fixture ${value} missing" >&2
      exit 1
    fi
  done
}

verify_core_fixture_integrity() {
  local key_file="${CORE_FLOW_FIXTURE_HMAC_KEY_B64_FILE-}"
  local expected_file="${CORE_FLOW_FIXTURE_HMAC_B64_FILE-}"

  if [[ -z "${key_file}" || -z "${expected_file}" ]]; then
    if (( TEST_SIGNED_MODE == 1 )); then
      echo "Core flow fixture HMAC artifacts missing" >&2
      exit 1
    fi
    echo "INFO: Core flow HMAC artifacts unavailable; skipping integrity check" >&2
    return
  fi

  ensure_secret_file_mode "${key_file}" "core flow HMAC key"
  ensure_secret_file_mode "${expected_file}" "core flow HMAC digest"

  local expected_hex computed_hex
  expected_hex="$(xxd -p -c 1000 "${expected_file}")"

  computed_hex="$(
    python3 - <<'PY' "${CORE_FIXTURE}" "${key_file}"
import hashlib
import hmac
import json
import pathlib
import sys

fixture = pathlib.Path(sys.argv[1])
key_path = pathlib.Path(sys.argv[2])
payload = json.loads(fixture.read_text())
canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
key = key_path.read_bytes()
digest = hmac.new(key, canonical, hashlib.sha256).hexdigest()
print(digest)
PY
  )"

  expected_hex="${expected_hex//[$'\n\r']/}"
  computed_hex="${computed_hex//[$'\n\r']/}"

  if [[ "${computed_hex}" == "${expected_hex}" ]]; then
    echo "PASS: Core flow fixture integrity verified"
  else
    echo "FAIL: Core flow fixture integrity mismatch" >&2
    exit 1
  fi
}

run_seed_vector() {
  local helper="${ROOT_DIR}/scripts/bip39_seed.sh"
  local helper_seed
  helper_seed=$("${helper}" --mnemonic "${SEED_VECTOR_MNEMONIC}" --passphrase "${SEED_VECTOR_PASSPHRASE}")
  if [[ "${helper_seed}" != "${SEED_VECTOR_EXPECTED_SEED}" ]]; then
    echo "FAIL: BIP39 PBKDF2 seed vector (helper)" >&2
    exit 1
  fi

  local out seed
  out=$(bash "${SCRIPT}" -q --include-seed --no-address --mnemonic "${SEED_VECTOR_MNEMONIC}" "${WLIST}" "${SEED_VECTOR_PASSPHRASE}")
  seed=$(jq -r .seed <<<"${out}")
  if [[ "${seed}" != "${SEED_VECTOR_EXPECTED_SEED}" ]]; then
    echo "FAIL: BIP39 PBKDF2 seed vector (cli)" >&2
    exit 1
  fi

  pass "BIP39 PBKDF2 seed vector"
}

run_secp_helper_pub() {
  local helper="${ROOT_DIR}/scripts/secp256k1_pub.sh"
  local comp uncomp
  if ! read -r comp uncomp <<<"$("${helper}" pub --priv-hex "${PYTHON_PRIV_HEX}")"; then
    echo "FAIL: secp256k1 helper execution" >&2
    exit 1
  fi
  if [[ "${comp}" == "${PYTHON_EXPECTED_COMP}" && "${uncomp}" == "${PYTHON_EXPECTED_UNCOMP}" ]]; then
    pass "secp256k1 helper derivation"
  else
    echo "FAIL: secp256k1 helper derivation" >&2
    exit 1
  fi
}

run_mnemonic_checksum() {
  local out mn bits idx
  out=$(bash "${SCRIPT}" -q --include-seed "${WLIST}")
  mn=$(jq -r .mnemonic <<<"${out}")
  local -a words=()
  read -r -a words <<<"${mn}"
  bits=""
  for w in "${words[@]}"; do
    idx=$(awk -v w="${w}" 'BEGIN{found=0} $0==w {print NR; found=1; exit} END{if(!found) exit 1}' "${WLIST}" || true)
    if [[ -z "${idx}" ]]; then
      echo "FAIL: word ${w} not found" >&2
      exit 1
    fi
    idx=$((idx-1))
    local b
    b=$(echo "obase=2; ${idx}" | bc)
    b=$(printf "%011s" "${b}" | tr ' ' 0)
    bits+="${b}"
  done
  local ent_bits=${bits:0:128}
  local cs_bits=${bits:128:4}
  local ent_hex=""
  local i=0
  while (( i < 128 )); do
    local byte=${ent_bits:${i}:8}
    local val
    val=$(echo "ibase=2; ${byte}" | bc)
    ent_hex+=$(printf "%02x" "${val}")
    i=$((i+8))
  done
  local cs_nib cs_bin
  cs_nib=$(printf "%s" "${ent_hex}" | xxd -r -p | sha256sum | cut -c1)
  cs_bin=$(echo "obase=2; ibase=16; ${cs_nib^^}" | bc)
  cs_bin=$(printf "%04s" "${cs_bin}" | tr ' ' 0)
  if [[ "${cs_bin}" == "${cs_bits}" ]]; then
    pass "BIP39 mnemonic checksum"
  else
    echo "FAIL: BIP39 mnemonic checksum" >&2
    exit 1
  fi
}

run_env_entropy_override() {
  local out mn
  out=$(ENT_HEX="${ENTROPY_HEX_OVERRIDE}" bash "${SCRIPT}" -q --include-seed --no-address "${WLIST}")
  mn=$(jq -r .mnemonic <<<"${out}")
  if [[ "${mn}" == "${ENTROPY_EXPECTED_MNEMONIC}" ]]; then
    pass "ENT_HEX environment override"
  else
    echo "FAIL: ENT_HEX environment override" >&2
    exit 1
  fi
}

run_env_entropy_invalid() {
  if ENT_HEX="${INVALID_ENTROPY_VALUE}" bash "${SCRIPT}" -q "${WLIST}" >/dev/null 2>&1; then
    echo "FAIL: ENT_HEX invalid input rejected" >&2
    exit 1
  fi
  pass "ENT_HEX invalid input rejected"
}

run_env_mnemonic_override() {
  local out seed
  out=$(MNEMONIC="${MNEMONIC_OVERRIDE_VALUE}" bash "${SCRIPT}" -q --include-seed --no-address "${WLIST}" "${SEED_VECTOR_PASSPHRASE}")
  seed=$(jq -r .seed <<<"${out}")
  if [[ "${seed}" == "${MNEMONIC_OVERRIDE_EXPECTED_SEED}" ]]; then
    pass "MNEMONIC environment override"
  else
    echo "FAIL: MNEMONIC environment override" >&2
    exit 1
  fi
}

run_env_mnemonic_invalid() {
  if MNEMONIC="${INVALID_MNEMONIC_VALUE}" bash "${SCRIPT}" -q "${WLIST}" >/dev/null 2>&1; then
    echo "FAIL: MNEMONIC invalid input rejected" >&2
    exit 1
  fi
  pass "MNEMONIC invalid input rejected"
}

run_master_il_guard() {
  local real_openssl
  real_openssl="$(command -v openssl)"
  local path_override="${ROOT_DIR}/tests/fixtures:${PATH}"
  if OPENSSL_REAL="${real_openssl}" \
    ETH_FROM_BASH_TEST_SCENARIO="master_il_zero" \
    PATH="${path_override}" \
    MNEMONIC="${SEED_VECTOR_MNEMONIC}" \
    bash "${SCRIPT}" -q --include-seed --no-address "${WLIST}" "${SEED_VECTOR_PASSPHRASE}" >/dev/null 2>&1; then
    echo "FAIL: master IL zero guard" >&2
    exit 1
  fi
  pass "master IL zero guard"
}

main() {
  load_fixture_values
  verify_core_fixture_integrity
  run_seed_vector
  run_secp_helper_pub
  run_mnemonic_checksum
  run_env_entropy_override
  run_env_entropy_invalid
  run_env_mnemonic_override
  run_env_mnemonic_invalid
  run_master_il_guard
}

main "$@"
