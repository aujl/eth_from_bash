#!/usr/bin/env bash
set -euo pipefail

CURVE_ORDER="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
ASN1_OFFSET=23
COMPRESSED_LEN=33
UNCOMPRESSED_LEN=65

usage() {
  cat <<'USAGE'
Usage: secp256k1_pub.sh <command> [options]

Commands:
  pub --priv-hex HEX     Derive compressed and uncompressed public keys
  selftest               Run internal validation checks
USAGE
}

err() {
  printf '%s\n' "$1" >&2
}

tmp_files=()
cleanup() {
  if (( ${#tmp_files[@]} > 0 )); then
    rm -f "${tmp_files[@]}"
  fi
}
trap cleanup EXIT

make_tmp() {
  local tmp
  tmp="$(mktemp)"
  tmp_files+=("${tmp}")
  printf '%s\n' "${tmp}"
}

require_tools() {
  for tool in openssl xxd; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
      err "Required tool '${tool}' not found"
      exit 1
    fi
  done
}

validate_scalar() {
  local candidate="$1"
  if [[ ! "${candidate}" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    err "Private key must be 32-byte hex"
    return 1
  fi
  local upper="${candidate^^}"
  if [[ "${upper}" == "${CURVE_ORDER}" ]] || [[ "${upper}" > "${CURVE_ORDER}" ]]; then
    err "Private key scalar out of range"
    return 1
  fi
  if [[ -z "${upper//0/}" ]]; then
    err "Private key scalar out of range"
    return 1
  fi
  printf '%s\n' "${candidate,,}"
}

build_der() {
  local priv_hex="$1"
  local der_hex
  der_hex="302e0201010420${priv_hex}a00706052b8104000a"
  local der_file
  der_file="$(make_tmp)"
  printf '%s' "${der_hex}" | xxd -r -p >"${der_file}"
  printf '%s\n' "${der_file}"
}

extract_pub() {
  local der_file="$1" form="$2" length="$3"
  local pub_der raw_file err_file
  pub_der="$(make_tmp)"
  raw_file="$(make_tmp)"
  err_file="$(make_tmp)"

  if ! openssl ec -inform DER -in "${der_file}" -pubout -conv_form "${form}" -outform DER >"${pub_der}" 2>"${err_file}"; then
    cat "${err_file}" >&2 || true
    err "openssl failed to derive public key"
    exit 1
  fi

  openssl asn1parse -inform DER -in "${pub_der}" -offset "${ASN1_OFFSET}" -length "${length}" -out "${raw_file}" -noout >/dev/null
  xxd -p -c 1000 "${raw_file}" | tr -d '\n'
}

derive_pubkeys() {
  local priv_input="$1"
  require_tools
  local priv_hex=""
  if ! priv_hex="$(validate_scalar "${priv_input}")"; then
    return 1
  fi
  local der_file=""
  if ! der_file="$(build_der "${priv_hex}")"; then
    return 1
  fi
  local comp="" uncomp=""
  if ! comp="$(extract_pub "${der_file}" compressed "${COMPRESSED_LEN}")"; then
    return 1
  fi
  if ! uncomp="$(extract_pub "${der_file}" uncompressed "${UNCOMPRESSED_LEN}")"; then
    return 1
  fi
  printf '%s %s\n' "${comp}" "${uncomp}"
}

run_selftest() {
  local expected_comp="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
  local expected_uncomp="0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
  local comp uncomp
  read -r comp uncomp < <(derive_pubkeys "0000000000000000000000000000000000000000000000000000000000000001")
  if [[ "${comp}" != "${expected_comp}" || "${uncomp}" != "${expected_uncomp}" ]]; then
    err "Self-test failed: generator mismatch"
    exit 1
  fi

  if derive_pubkeys "0000000000000000000000000000000000000000000000000000000000000000" >/dev/null 2>&1; then
    err "Self-test failed: zero scalar accepted"
    exit 1
  fi
  if derive_pubkeys "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141" >/dev/null 2>&1; then
    err "Self-test failed: order scalar accepted"
    exit 1
  fi
  printf 'secp256k1 self-test passed\n'
}

main() {
  if [[ $# -lt 1 ]]; then
    usage >&2
    exit 1
  fi

  local cmd="$1"
  shift || true

  case "${cmd}" in
    pub)
      local priv_hex=""
      while [[ $# -gt 0 ]]; do
        case "$1" in
          --priv-hex)
            shift
            priv_hex="${1-}"
            if [[ -z "${priv_hex}" ]]; then
              err "--priv-hex requires a value"
              exit 1
            fi
            shift
            ;;
          *)
            usage >&2
            exit 1
            ;;
        esac
      done
      if [[ -z "${priv_hex}" ]]; then
        err "--priv-hex is required"
        exit 1
      fi
      derive_pubkeys "${priv_hex}"
      ;;
    selftest)
      run_selftest
      ;;
    -h|--help)
      usage
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
}

main "$@"
