#!/usr/bin/env bash
# Recreate signed artifacts as base64 env vars for tests/load_secrets.sh.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURES_DIR="${FIX:-$ROOT_DIR/tests/fixtures}"

CORE_JSON="${CORE_JSON:-$FIXTURES_DIR/core_flow_vectors.json}"
KECCAK_JSON="${KECCAK_JSON:-$FIXTURES_DIR/keccak_vectors.json}"
SECP_JSON="${SECP_JSON:-$FIXTURES_DIR/secp256k1_vectors.json}"

PRIVATE_KEY_DIR="${PRIVATE_KEY_DIR:-$HOME/.config/eth_from_bash/maintainer}"
KECCAK_PRIV="${KECCAK_PRIV:-$PRIVATE_KEY_DIR/keccak_reference_priv.pem}"
SECP_PRIV="${SECP_PRIV:-$PRIVATE_KEY_DIR/secp256k1_vectors_priv.pem}"

CRYPTO_SIGN="${ROOT_DIR}/scripts/crypto_sign.py"
CRYPTO_KDF="${ROOT_DIR}/scripts/crypto_kdf.py"

current_mode() {
  stat -c '%a' "$1"
}

for path in "${CORE_JSON}" "${KECCAK_JSON}" "${SECP_JSON}" "${KECCAK_PRIV}" "${SECP_PRIV}"; do
  if [[ ! -f "${path}" ]]; then
    echo "Missing: ${path}" >&2
    exit 1
  fi
  if [[ "${path}" == "${KECCAK_PRIV}" || "${path}" == "${SECP_PRIV}" ]]; then
    mode="$(current_mode "${path}")"
    if [[ "${mode}" != "400" ]]; then
      echo "Private key must be mode 400: ${path}" >&2
      exit 1
    fi
  fi
done

b64() {
  base64 | tr -d '\n'
}

cleanup_files=()
cleanup() {
  local f
  for f in "${cleanup_files[@]}"; do
    if [[ -n "${f}" && -e "${f}" ]]; then
      rm -f -- "${f}"
    fi
  done
}
trap cleanup EXIT

mktemp_file() {
  local tmp
  tmp="$(mktemp)"
  cleanup_files+=("${tmp}")
  printf '%s' "${tmp}"
}

TMP_KEY="$(mktemp_file)"
"${CRYPTO_SIGN}" random-bytes --count 32 --output raw >"${TMP_KEY}"

canonical="$(jq -cS '.' "${CORE_JSON}")"
key_hex="$(xxd -p "${TMP_KEY}" | tr -d '\n')"
canonical_hex="$(printf '%s' "${canonical}" | xxd -p | tr -d '\n')"
if [[ -z "${canonical}" || -z "${key_hex}" || -z "${canonical_hex}" ]]; then
  echo "Unable to prepare canonical fixture or key material" >&2
  exit 1
fi

CORE_FLOW_FIXTURE_HMAC_B64="$(
  "${CRYPTO_KDF}" hmac-sha256 --key-hex "${key_hex}" --data-hex "${canonical_hex}" \
    | xxd -r -p \
    | b64
)"

CORE_FLOW_FIXTURE_HMAC_KEY_B64="$(b64 <"${TMP_KEY}")"

KECCAK_VECTOR_SIG_B64="$("${CRYPTO_SIGN}" rsa-sign --key "${KECCAK_PRIV}" --message "${KECCAK_JSON}" --output base64)"
SECP256K1_VECTOR_SIG_B64="$("${CRYPTO_SIGN}" ecdsa-sign --key "${SECP_PRIV}" --message "${SECP_JSON}" --output base64)"

printf "export CORE_FLOW_FIXTURE_HMAC_KEY_B64='%s'\n" "${CORE_FLOW_FIXTURE_HMAC_KEY_B64}"
printf "export CORE_FLOW_FIXTURE_HMAC_B64='%s'\n" "${CORE_FLOW_FIXTURE_HMAC_B64}"
printf "export KECCAK_VECTOR_SIG_B64='%s'\n" "${KECCAK_VECTOR_SIG_B64}"
printf "export SECP256K1_VECTOR_SIG_B64='%s'\n" "${SECP256K1_VECTOR_SIG_B64}"
