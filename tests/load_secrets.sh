#!/usr/bin/env bash
# Materialize signing artifacts for the test harness.
set -euo pipefail
set -o noclobber

if [[ "${TEST_SECRETS_INITIALIZED:-0}" == "1" ]]; then
  # Already loaded in the current shell.
  return 0
fi

readonly TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT_DIR="$(readlink -f "${TESTS_DIR}/..")"

SIGNED_TEST="${SIGNED_TEST:-0}"
UNSIGNED_TEST="${UNSIGNED_TEST:-0}"

if [[ "${UNSIGNED_TEST}" == "1" && ( "${SIGNED_TEST}" == "1" || -n "${CI-}" ) ]]; then
  echo "UNSIGNED_TEST=1 conflicts with CI or SIGNED_TEST=1" >&2
  exit 1
fi

REQUIRE_SIGNED=1
if [[ "${UNSIGNED_TEST}" == "1" ]]; then
  REQUIRE_SIGNED=0
fi

export TEST_SIGNED_MODE="${REQUIRE_SIGNED}"

SECRET_WORKDIR="${TEST_SECRET_WORKDIR:-}"
SECRET_EPHEMERAL=0
if [[ -z "${SECRET_WORKDIR}" ]]; then
  SECRET_WORKDIR="$(mktemp -d "${TESTS_DIR}/.materialized.XXXXXX")"
  SECRET_EPHEMERAL=1
fi

mkdir -p "${SECRET_WORKDIR}"
chmod 700 "${SECRET_WORKDIR}"

cleanup_secrets() {
  if [[ "${SECRET_EPHEMERAL}" == "1" && -d "${SECRET_WORKDIR}" ]]; then
    rm -rf -- "${SECRET_WORKDIR}"
  fi
}

trap cleanup_secrets EXIT

declare -Ag TEST_SECRET_FILES=()
declare -ag TEST_SECRET_MISSING=()
declare -ag TEST_SECRET_INVALID=()

decode_secret() {
  local env_var="$1"
  local dest_name="$2"

  local value="${!env_var-}"
  local dest_path="${SECRET_WORKDIR}/${dest_name}"

  TEST_SECRET_FILES["${env_var}"]=""

  if [[ -z "${value}" ]]; then
    TEST_SECRET_MISSING+=("${env_var}")
    return 0
  fi

  umask 077
  if printf '%s' "${value}" | tr -d '\n' | base64 -d >"${dest_path}" 2>/dev/null; then
    chmod 400 "${dest_path}"
    TEST_SECRET_FILES["${env_var}"]="${dest_path}"
    export "${env_var}_FILE=${dest_path}"
    return 0
  fi

  rm -f -- "${dest_path}"
  TEST_SECRET_INVALID+=("${env_var}")
  return 0
}

ensure_secret_file_mode() {
  local path="$1"
  local label="$2"
  if [[ ! -f "${path}" ]]; then
    echo "Missing ${label} artifact" >&2
    exit 1
  fi
  local mode
  mode="$(stat -c '%a' "${path}")"
  if [[ "${mode}" != "400" ]]; then
    chmod 400 "${path}"
    mode="$(stat -c '%a' "${path}")"
    if [[ "${mode}" != "400" ]]; then
      echo "${label} artifact must be read-only" >&2
      exit 1
    fi
  fi
}

ensure_secret_artifact() {
  local var_name="$1"
  local label="$2"
  local path="${!var_name-}"

  if [[ -z "${path}" ]]; then
    return 1
  fi

  ensure_secret_file_mode "${path}" "${label}"
  return 0
}

decode_secret SECP256K1_VECTOR_SIG_B64 secp256k1_vectors.sig
decode_secret KECCAK_VECTOR_SIG_B64 keccak_vectors.sig
decode_secret CORE_FLOW_FIXTURE_HMAC_KEY_B64 core_flow_fixture.key
decode_secret CORE_FLOW_FIXTURE_HMAC_B64 core_flow_fixture.hmac

if (( ${#TEST_SECRET_INVALID[@]} > 0 )); then
  printf 'Unable to decode secrets: %s\n' "${TEST_SECRET_INVALID[*]}" >&2
  exit 1
fi

if (( REQUIRE_SIGNED == 1 )); then
  # Determine which secrets are mandatory in signed mode.
  required=(
    SECP256K1_VECTOR_SIG_B64
    KECCAK_VECTOR_SIG_B64
    CORE_FLOW_FIXTURE_HMAC_KEY_B64
    CORE_FLOW_FIXTURE_HMAC_B64
  )
  missing_required=()
  for key in "${required[@]}"; do
    if [[ -z "${TEST_SECRET_FILES["${key}"]}" ]]; then
      missing_required+=("${key}")
    fi
  done
  if (( ${#missing_required[@]} > 0 )); then
    printf 'Required secrets are missing: %s\n' "${missing_required[*]}" >&2
    echo "Set UNSIGNED_TEST=1 to run without fixture verification." >&2
    exit 1
  fi
fi

export TEST_SECRET_WORKDIR="${SECRET_WORKDIR}"
export TEST_SECRETS_INITIALIZED=1

# Export helpers for test scripts.
export -f ensure_secret_artifact
export -f ensure_secret_file_mode
export -f decode_secret
