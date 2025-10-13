#!/usr/bin/env bash
# Generate maintainer signing keys (RSA for keccak vectors, secp256k1 for secp vectors).
# Private keys are stored outside the repo inside a git-ignored directory.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PRIVATE_KEY_DIR="${PRIVATE_KEY_DIR:-$HOME/.config/eth_from_bash/maintainer}"
FIXTURES_DIR="${FIX:-$ROOT_DIR/tests/fixtures}"

mkdir -p "${PRIVATE_KEY_DIR}"
chmod 700 "${PRIVATE_KEY_DIR}"
mkdir -p "${FIXTURES_DIR}"

KECCAK_PRIV="${PRIVATE_KEY_DIR}/keccak_reference_priv.pem"
KECCAK_PUB="${FIXTURES_DIR}/keccak_reference_pub.pem"

SECP_PRIV="${PRIVATE_KEY_DIR}/secp256k1_vectors_priv.pem"
SECP_PUB="${FIXTURES_DIR}/secp256k1_vectors_pub.pem"

CRYPTO_SIGN_SH="${ROOT_DIR}/scripts/crypto_sign.sh"
CRYPTO_SIGN_RSA="${CRYPTO_SIGN_RSA:-${CRYPTO_SIGN_SH}}"
CRYPTO_SIGN_ECDSA="${CRYPTO_SIGN_ECDSA:-${CRYPTO_SIGN_SH}}"

current_mode() {
  stat -c '%a' "$1"
}

ensure_mode() {
  local path="$1"
  local desired="$2"
  local label="$3"

  if [[ ! -e "${path}" ]]; then
    echo "Missing ${label}: ${path}" >&2
    exit 1
  fi

  local mode
  mode="$(current_mode "${path}")"
  if [[ "${mode}" != "${desired}" ]]; then
    chmod "${desired}" "${path}"
    mode="$(current_mode "${path}")"
    if [[ "${mode}" != "${desired}" ]]; then
      echo "${label} must have mode ${desired}: ${path}" >&2
      exit 1
    fi
  fi
}

run_rsa_command() {
  local description="$1"
  shift
  set +e
  "$@"
  local status=$?
  set -e
  if (( status != 0 )); then
    echo "ERROR: ${description} requires crypto_sign.sh RSA support (pending implementation)" >&2
    exit 1
  fi
}

if [[ ! -f "${KECCAK_PRIV}" ]]; then
  run_rsa_command "Generating RSA maintainer keypair" "${CRYPTO_SIGN_RSA}" rsa-generate --bits 2048 --private-out "${KECCAK_PRIV}" --public-out "${KECCAK_PUB}"
else
  ensure_mode "${KECCAK_PRIV}" 400 "private key"
  run_rsa_command "Deriving RSA public key" "${CRYPTO_SIGN_RSA}" rsa-public --key "${KECCAK_PRIV}" --output "${KECCAK_PUB}"
fi
chmod 400 "${KECCAK_PRIV}"

if [[ ! -f "${SECP_PRIV}" ]]; then
  "${CRYPTO_SIGN_ECDSA}" ecdsa-generate --private-out "${SECP_PRIV}" --public-out "${SECP_PUB}"
else
  ensure_mode "${SECP_PRIV}" 400 "private key"
  "${CRYPTO_SIGN_ECDSA}" ecdsa-public --key "${SECP_PRIV}" --output "${SECP_PUB}"
fi
chmod 400 "${SECP_PRIV}"

ensure_mode "${KECCAK_PUB}" 444 "RSA public key"
ensure_mode "${SECP_PUB}" 444 "secp256k1 public key"

cat <<EON
Wrote keys:
  RSA private : ${KECCAK_PRIV}
  RSA public  : ${KECCAK_PUB}
  secp256k1 private : ${SECP_PRIV}
  secp256k1 public  : ${SECP_PUB}

Private keys are stored in: ${PRIVATE_KEY_DIR}
Ensure this directory is git-ignored and access is restricted (chmod 700).
EON
