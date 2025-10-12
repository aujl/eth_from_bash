#!/usr/bin/env bash
set -euo pipefail

die() {
  echo "crypto_sign.sh: $*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage: crypto_sign.sh <command> [options]

Commands:
  hmac-sha256    Compute HMAC-SHA256 digest
  random-bytes   Generate random bytes from /dev/urandom
  rsa-sign       Sign message with RSA PKCS#1 v1.5
  rsa-verify     Verify RSA PKCS#1 v1.5 signature

Run "crypto_sign.sh <command> --help" for command-specific flags.
USAGE
}

usage_hmac() {
  cat <<'USAGE'
Usage: crypto_sign.sh hmac-sha256 --key <path|-> --message <path|-> [--output hex|base64|raw]
USAGE
}

usage_random() {
  cat <<'USAGE'
Usage: crypto_sign.sh random-bytes --count <n> [--output hex|base64|raw]
USAGE
}

usage_rsa_sign() {
  cat <<'USAGE'
Usage: crypto_sign.sh rsa-sign --key <path> --message <path|-> [--hash sha256] [--output hex|base64|raw]
USAGE
}

usage_rsa_verify() {
  cat <<'USAGE'
Usage: crypto_sign.sh rsa-verify --key <path> --message <path|-> --signature <path|-> [--hash sha256]
USAGE
}

read_bytes() {
  local path="$1"
  if [[ "${path}" == "-" ]]; then
    cat
  else
    cat "${path}"
  fi
}

read_hex() {
  local path="$1"
  if [[ "${path}" == "-" ]]; then
    od -An -tx1 -v | tr -d ' \n'
  else
    od -An -tx1 -v "${path}" | tr -d ' \n'
  fi
}

hex_to_raw() {
  local hex="$1"
  if [[ -z "${hex}" ]]; then
    return 0
  fi
  local formatted
  formatted="$(printf '%s' "${hex}" | sed 's/../\\x&/g')"
  printf '%b' "${formatted}"
}

pad_hex_to_block() {
  local hex="$1"
  local block_bytes="$2"
  local target=$((block_bytes * 2))
  while (( ${#hex} < target )); do
    hex+="00"
  done
  printf '%s' "${hex:0:target}"
}

xor_hex_with_byte() {
  local hex="$1"
  local byte="$2"
  local result=""
  local i=0
  local chunk value
  while (( i < ${#hex} )); do
    chunk="${hex:i:2}"
    if [[ ${#chunk} -ne 2 ]]; then
      chunk+="0"
    fi
    value=$((16#${chunk} ^ 16#${byte}))
    result+=$(printf '%02x' "${value}")
    i=$((i + 2))
  done
  printf '%s' "${result}"
}

sha256_hex_from_stream() {
  sha256sum | cut -d' ' -f1
}

normalize_hex() {
  local hex="${1,,}"
  hex="${hex//[^0-9a-f]/}"
  while [[ ${#hex} -gt 2 && ${hex:0:2} == "00" ]]; do
    hex="${hex:2}"
  done
  if [[ -z "${hex}" ]]; then
    hex="00"
  elif (( ${#hex} % 2 == 1 )); then
    hex="0${hex}"
  fi
  printf '%s' "${hex}"
}

pad_hex_left() {
  local hex="$1"
  local width="$2"
  while (( ${#hex} < width )); do
    hex="0${hex}"
  done
  printf '%s' "${hex}"
}

repeat_hex_byte() {
  local byte="$1"
  local count="$2"
  local result=""
  while (( count > 0 )); do
    result+="${byte}"
    ((count--))
  done
  printf '%s' "${result}"
}

hex_to_dec() {
  local hex
  hex="$(normalize_hex "$1")"
  if [[ "${hex}" == "00" ]]; then
    printf '0\n'
    return 0
  fi
  printf '%s\n' "$(printf 'ibase=16;%s\n' "${hex^^}" | bc | tr -d '\n\\')"
}

dec_to_hex() {
  local dec="$1"
  local hex
  hex="$(printf 'obase=16;%s\n' "${dec}" | bc | tr -d '\n\\')"
  if [[ -z "${hex}" ]]; then
    hex="0"
  fi
  printf '%s\n' "${hex,,}"
}

modexp_bc() {
  local base="$1"
  local exponent="$2"
  local modulus="$3"
  bc <<BC
define modexp(a,b,n){
  a%=n;
  res=1;
  while(b>0){
    if(b%2==1) res=(res*a)%n;
    a=(a*a)%n;
    b/=2;
  }
  return res;
}
scale=0
modexp(${base}, ${exponent}, ${modulus})
BC
}

pem_block_to_hex() {
  local path="$1"
  local label="$2"
  local base64_data
  if ! base64_data="$(awk -v start="-----BEGIN ${label}-----" -v end="-----END ${label}-----" '
    $0 == start { in_block=1; next }
    $0 == end { in_block=0; exit }
    in_block { print }
  ' "${path}" | tr -d '\n\r')"; then
    return 1
  fi
  if [[ -z "${base64_data}" ]]; then
    return 1
  fi
  printf '%s' "${base64_data}" | base64 -d | od -An -tx1 -v | tr -d ' \n'
}

der_read_tlv() {
  local hex="${1,,}"
  local offset="$2"
  local expected_tag="${3,,}"
  local total_len=${#hex}
  local index=$((offset * 2))
  (( index < total_len )) || die "DER: unexpected end of data"
  local tag="${hex:index:2}"
  [[ "${tag}" == "${expected_tag}" ]] || die "DER: expected tag ${expected_tag}"
  index=$((index + 2))
  (( index + 2 <= total_len )) || die "DER: truncated length"
  local length_byte_hex="${hex:index:2}"
  index=$((index + 2))
  local length_byte=$((16#${length_byte_hex^^}))
  local length=0
  if (( length_byte < 0x80 )); then
    length=${length_byte}
  else
    local nbytes=$((length_byte & 0x7f))
    (( nbytes > 0 )) || die "DER: invalid length"
    local len_hex="${hex:index:nbytes*2}"
    (( ${#len_hex} == nbytes * 2 )) || die "DER: truncated length"
    index=$((index + nbytes * 2))
    length=$((16#${len_hex^^}))
  fi
  local value_index=${index}
  local value_hex="${hex:value_index:length*2}"
  (( ${#value_hex} == length * 2 )) || die "DER: truncated value"
  DER_VALUE="${value_hex}"
  DER_NEXT_OFFSET=$(((value_index + length * 2) / 2))
}

der_read_sequence() {
  der_read_tlv "$1" "$2" "30"
  DER_SEQUENCE_HEX="${DER_VALUE}"
}

der_read_integer() {
  der_read_tlv "$1" "$2" "02"
  local value="${DER_VALUE,,}"
  while [[ ${#value} -gt 2 && ${value:0:2} == "00" ]]; do
    value="${value:2}"
  done
  if [[ -z "${value}" ]]; then
    value="00"
  elif (( ${#value} % 2 == 1 )); then
    value="0${value}"
  fi
  DER_INTEGER_HEX="${value}"
}

der_read_octet_string() {
  der_read_tlv "$1" "$2" "04"
  DER_OCTET_HEX="${DER_VALUE}"
}

der_read_bit_string() {
  der_read_tlv "$1" "$2" "03"
  local value="${DER_VALUE}"
  (( ${#value} >= 2 )) || die "DER: invalid BIT STRING"
  local unused_bits=$((16#${value:0:2}))
  (( unused_bits == 0 )) || die "DER: unsupported BIT STRING"
  DER_BITSTRING_HEX="${value:2}"
}

der_read_object_identifier() {
  der_read_tlv "$1" "$2" "06"
  local raw="${DER_VALUE,,}"
  [[ -n "${raw}" ]] || die "DER: invalid OID"
  local first_byte=$((16#${raw:0:2}))
  local oid=""
  local comp0=$((first_byte / 40))
  local comp1=$((first_byte % 40))
  oid="${comp0}.${comp1}"
  local value=0
  local i=2
  while (( i < ${#raw} )); do
    local byte=$((16#${raw:i:2}))
    value=$(((value << 7) | (byte & 0x7f)))
    if (( (byte & 0x80) == 0 )); then
      oid+=".${value}"
      value=0
    fi
    i=$((i + 2))
  done
  (( value == 0 )) || die "DER: truncated OID"
  DER_OBJECT_IDENTIFIER="${oid}"
}

der_expect_eof() {
  local hex="$1"
  local offset="$2"
  local total_bytes=$(( ${#hex} / 2 ))
  (( offset == total_bytes )) || die "DER: unexpected trailing data"
}

parse_rsa_algorithm_identifier() {
  local hex="$1"
  local offset=0
  der_read_object_identifier "${hex}" "${offset}"
  local oid="${DER_OBJECT_IDENTIFIER}"
  [[ "${oid}" == "1.2.840.113549.1.1.1" ]] || die "DER: not an RSA key"
  offset="${DER_NEXT_OFFSET}"
  if (( offset * 2 < ${#hex} )); then
    der_read_tlv "${hex}" "${offset}" "05"
    [[ -z "${DER_VALUE}" ]] || die "DER: unexpected RSA parameters"
    offset="${DER_NEXT_OFFSET}"
  fi
  der_expect_eof "${hex}" "${offset}"
}

parse_rsa_private_pkcs1() {
  local hex="$1"
  der_read_sequence "${hex}" 0
  local seq_hex="${DER_SEQUENCE_HEX}"
  local offset=0
  der_read_integer "${seq_hex}" "${offset}"
  local version_hex="${DER_INTEGER_HEX}"
  offset="${DER_NEXT_OFFSET}"
  local version
  version="$(hex_to_dec "${version_hex}")"
  if [[ "${version}" != "0" && "${version}" != "1" ]]; then
    die "DER: unsupported RSA private key version"
  fi
  der_read_integer "${seq_hex}" "${offset}"
  local n_hex="${DER_INTEGER_HEX}"
  offset="${DER_NEXT_OFFSET}"
  der_read_integer "${seq_hex}" "${offset}"
  local e_hex="${DER_INTEGER_HEX}"
  offset="${DER_NEXT_OFFSET}"
  der_read_integer "${seq_hex}" "${offset}"
  local d_hex="${DER_INTEGER_HEX}"
  offset="${DER_NEXT_OFFSET}"
  # Consume remaining CRT parameters to ensure structure validity.
  local i
  for i in 1 2 3 4 5; do
    der_read_integer "${seq_hex}" "${offset}"
    offset="${DER_NEXT_OFFSET}"
  done
  der_expect_eof "${seq_hex}" "${offset}"
  RSA_PRIV_N="${n_hex}"
  RSA_PRIV_E="${e_hex}"
  RSA_PRIV_D="${d_hex}"
}

parse_rsa_private_pkcs8() {
  local hex="$1"
  der_read_sequence "${hex}" 0
  local seq_hex="${DER_SEQUENCE_HEX}"
  local offset=0
  der_read_integer "${seq_hex}" "${offset}"
  local version="$(hex_to_dec "${DER_INTEGER_HEX}")"
  offset="${DER_NEXT_OFFSET}"
  [[ "${version}" == "0" ]] || die "DER: unsupported PKCS#8 version"
  der_read_sequence "${seq_hex}" "${offset}"
  local alg_hex="${DER_SEQUENCE_HEX}"
  offset="${DER_NEXT_OFFSET}"
  parse_rsa_algorithm_identifier "${alg_hex}"
  der_read_octet_string "${seq_hex}" "${offset}"
  local private_hex="${DER_OCTET_HEX}"
  offset="${DER_NEXT_OFFSET}"
  der_expect_eof "${seq_hex}" "${offset}"
  parse_rsa_private_pkcs1 "${private_hex}"
}

parse_rsa_public_spki() {
  local hex="$1"
  der_read_sequence "${hex}" 0
  local seq_hex="${DER_SEQUENCE_HEX}"
  local offset=0
  der_read_sequence "${seq_hex}" "${offset}"
  local alg_hex="${DER_SEQUENCE_HEX}"
  offset="${DER_NEXT_OFFSET}"
  parse_rsa_algorithm_identifier "${alg_hex}"
  der_read_bit_string "${seq_hex}" "${offset}"
  local bit_hex="${DER_BITSTRING_HEX}"
  offset="${DER_NEXT_OFFSET}"
  der_expect_eof "${seq_hex}" "${offset}"
  der_read_sequence "${bit_hex}" 0
  local key_seq="${DER_SEQUENCE_HEX}"
  local key_offset=0
  der_read_integer "${key_seq}" "${key_offset}"
  local n_hex="${DER_INTEGER_HEX}"
  key_offset="${DER_NEXT_OFFSET}"
  der_read_integer "${key_seq}" "${key_offset}"
  local e_hex="${DER_INTEGER_HEX}"
  key_offset="${DER_NEXT_OFFSET}"
  der_expect_eof "${key_seq}" "${key_offset}"
  RSA_PUB_N="${n_hex}"
  RSA_PUB_E="${e_hex}"
}

load_rsa_private_key() {
  local path="$1"
  local der_hex
  if der_hex="$(pem_block_to_hex "${path}" "PRIVATE KEY" 2>/dev/null)"; then
    parse_rsa_private_pkcs8 "${der_hex}"
    return 0
  fi
  if der_hex="$(pem_block_to_hex "${path}" "RSA PRIVATE KEY" 2>/dev/null)"; then
    parse_rsa_private_pkcs1 "${der_hex}"
    return 0
  fi
  die "Failed to load RSA private key from ${path}"
}

load_rsa_public_key() {
  local path="$1"
  local der_hex
  if ! der_hex="$(pem_block_to_hex "${path}" "PUBLIC KEY" 2>/dev/null)"; then
    die "Failed to load RSA public key from ${path}"
  fi
  parse_rsa_public_spki "${der_hex}"
}

rsa_digest_info_hex() {
  local hash_name="$1"
  local digest_hex="$2"
  case "${hash_name}" in
    sha256)
      printf '%s' "3031300d060960864801650304020105000420${digest_hex}"
      ;;
    *)
      die "Unsupported hash: ${hash_name}"
      ;;
  esac
}

cmd_hmac_sha256() {
  local key_path=""
  local message_path=""
  local output_format="hex"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --key)
        [[ $# -lt 2 ]] && { usage_hmac >&2; return 1; }
        key_path="$2"
        shift 2
        ;;
      --message)
        [[ $# -lt 2 ]] && { usage_hmac >&2; return 1; }
        message_path="$2"
        shift 2
        ;;
      --output)
        [[ $# -lt 2 ]] && { usage_hmac >&2; return 1; }
        output_format="$2"
        shift 2
        ;;
      --help)
        usage_hmac
        return 0
        ;;
      *)
        echo "Unknown option for hmac-sha256: $1" >&2
        usage_hmac >&2
        return 1
        ;;
    esac
  done

  if [[ -z "${key_path}" || -z "${message_path}" ]]; then
    usage_hmac >&2
    return 1
  fi

  local key_hex block_hex ipad_hex opad_hex
  key_hex="$(read_hex "${key_path}")"

  local block_size=64
  local key_len_bytes=$(( ${#key_hex} / 2 ))
  if (( key_len_bytes > block_size )); then
    key_hex="$(hex_to_raw "${key_hex}" | sha256_hex_from_stream)"
  fi
  block_hex="$(pad_hex_to_block "${key_hex}" "${block_size}")"
  ipad_hex="$(xor_hex_with_byte "${block_hex}" "36")"
  opad_hex="$(xor_hex_with_byte "${block_hex}" "5c")"

  local inner_digest outer_digest
  inner_digest="$({
    hex_to_raw "${ipad_hex}"
    read_bytes "${message_path}"
  } | sha256_hex_from_stream)"

  outer_digest="$({
    hex_to_raw "${opad_hex}"
    hex_to_raw "${inner_digest}"
  } | sha256_hex_from_stream)"

  case "${output_format}" in
    hex)
      printf '%s\n' "${outer_digest}"
      ;;
    base64)
      hex_to_raw "${outer_digest}" | base64 | tr -d '\n'
      printf '\n'
      ;;
    raw)
      hex_to_raw "${outer_digest}"
      ;;
    *)
      echo "Invalid output format: ${output_format}" >&2
      return 1
      ;;
  esac
}

cmd_random_bytes() {
  local count=""
  local output_format="hex"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --count)
        [[ $# -lt 2 ]] && { usage_random >&2; return 1; }
        count="$2"
        shift 2
        ;;
      --output)
        [[ $# -lt 2 ]] && { usage_random >&2; return 1; }
        output_format="$2"
        shift 2
        ;;
      --help)
        usage_random
        return 0
        ;;
      *)
        echo "Unknown option for random-bytes: $1" >&2
        usage_random >&2
        return 1
        ;;
    esac
  done

  if [[ -z "${count}" ]]; then
    usage_random >&2
    return 1
  fi
  if ! [[ "${count}" =~ ^[0-9]+$ ]] || (( count < 0 )); then
    echo "--count must be a non-negative integer" >&2
    return 1
  fi

  case "${output_format}" in
    hex)
      dd if=/dev/urandom bs=1 count="${count}" status=none | od -An -tx1 -v | tr -d ' \n'
      printf '\n'
      ;;
    base64)
      dd if=/dev/urandom bs=1 count="${count}" status=none | base64 | tr -d '\n'
      printf '\n'
      ;;
    raw)
      dd if=/dev/urandom bs=1 count="${count}" status=none
      ;;
    *)
      echo "Invalid output format: ${output_format}" >&2
      return 1
      ;;
  esac
}

cmd_rsa_sign() {
  local key_path=""
  local message_path=""
  local hash_name="sha256"
  local output_format="raw"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --key)
        [[ $# -lt 2 ]] && { usage_rsa_sign >&2; return 1; }
        key_path="$2"
        shift 2
        ;;
      --message)
        [[ $# -lt 2 ]] && { usage_rsa_sign >&2; return 1; }
        message_path="$2"
        shift 2
        ;;
      --hash)
        [[ $# -lt 2 ]] && { usage_rsa_sign >&2; return 1; }
        hash_name="$2"
        shift 2
        ;;
      --output)
        [[ $# -lt 2 ]] && { usage_rsa_sign >&2; return 1; }
        output_format="$2"
        shift 2
        ;;
      --help)
        usage_rsa_sign
        return 0
        ;;
      *)
        echo "Unknown option for rsa-sign: $1" >&2
        usage_rsa_sign >&2
        return 1
        ;;
    esac
  done

  if [[ -z "${key_path}" || -z "${message_path}" ]]; then
    usage_rsa_sign >&2
    return 1
  fi

  load_rsa_private_key "${key_path}"

  local digest_hex
  case "${hash_name}" in
    sha256)
      if [[ "${message_path}" == "-" ]]; then
        digest_hex="$(cat | sha256_hex_from_stream)"
      else
        digest_hex="$(sha256sum "${message_path}" | cut -d' ' -f1)"
      fi
      ;;
    *)
      die "Unsupported hash: ${hash_name}"
      ;;
  esac

  local digest_info_hex
  digest_info_hex="$(rsa_digest_info_hex "${hash_name}" "${digest_hex}")"

  local n_hex="$(normalize_hex "${RSA_PRIV_N}")"
  local d_hex="$(normalize_hex "${RSA_PRIV_D}")"
  local k_bytes=$(( ${#n_hex} / 2 ))
  local digest_len_bytes=$(( ${#digest_info_hex} / 2 ))
  local padding_len=$((k_bytes - digest_len_bytes - 3))
  if (( padding_len < 8 )); then
    die "RSA modulus too short for digest"
  fi

  local padding_hex
  padding_hex="$(repeat_hex_byte "ff" "${padding_len}")"
  local em_hex="0001${padding_hex}00${digest_info_hex}"

  local em_dec d_dec n_dec signature_dec signature_hex
  em_dec="$(hex_to_dec "${em_hex}")"
  d_dec="$(hex_to_dec "${d_hex}")"
  n_dec="$(hex_to_dec "${n_hex}")"
  signature_dec="$(modexp_bc "${em_dec}" "${d_dec}" "${n_dec}")"
  signature_hex="$(dec_to_hex "${signature_dec}")"
  signature_hex="${signature_hex,,}"
  signature_hex="$(pad_hex_left "${signature_hex}" $((k_bytes * 2)))"

  case "${output_format}" in
    hex)
      printf '%s\n' "${signature_hex}"
      ;;
    base64)
      hex_to_raw "${signature_hex}" | base64 | tr -d '\n'
      printf '\n'
      ;;
    raw)
      hex_to_raw "${signature_hex}"
      ;;
    *)
      echo "Invalid output format: ${output_format}" >&2
      return 1
      ;;
  esac
}

cmd_rsa_verify() {
  local key_path=""
  local message_path=""
  local signature_path=""
  local hash_name="sha256"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --key)
        [[ $# -lt 2 ]] && { usage_rsa_verify >&2; return 1; }
        key_path="$2"
        shift 2
        ;;
      --message)
        [[ $# -lt 2 ]] && { usage_rsa_verify >&2; return 1; }
        message_path="$2"
        shift 2
        ;;
      --signature)
        [[ $# -lt 2 ]] && { usage_rsa_verify >&2; return 1; }
        signature_path="$2"
        shift 2
        ;;
      --hash)
        [[ $# -lt 2 ]] && { usage_rsa_verify >&2; return 1; }
        hash_name="$2"
        shift 2
        ;;
      --help)
        usage_rsa_verify
        return 0
        ;;
      *)
        echo "Unknown option for rsa-verify: $1" >&2
        usage_rsa_verify >&2
        return 1
        ;;
    esac
  done

  if [[ -z "${key_path}" || -z "${message_path}" || -z "${signature_path}" ]]; then
    usage_rsa_verify >&2
    return 1
  fi

  load_rsa_public_key "${key_path}"

  local digest_hex
  case "${hash_name}" in
    sha256)
      if [[ "${message_path}" == "-" ]]; then
        digest_hex="$(cat | sha256_hex_from_stream)"
      else
        digest_hex="$(sha256sum "${message_path}" | cut -d' ' -f1)"
      fi
      ;;
    *)
      die "Unsupported hash: ${hash_name}"
      ;;
  esac

  local expected_digest_info
  expected_digest_info="$(rsa_digest_info_hex "${hash_name}" "${digest_hex}")"
  local n_hex="$(normalize_hex "${RSA_PUB_N}")"
  local e_hex="$(normalize_hex "${RSA_PUB_E}")"
  local k_bytes=$(( ${#n_hex} / 2 ))

  local signature_hex
  signature_hex="$(read_hex "${signature_path}")"
  if [[ -z "${signature_hex}" ]]; then
    echo "verification failed" >&2
    return 1
  fi
  if (( ${#signature_hex} / 2 != k_bytes )); then
    echo "verification failed" >&2
    return 1
  fi

  local sig_dec n_dec e_dec em_dec em_hex
  sig_dec="$(hex_to_dec "${signature_hex}")"
  n_dec="$(hex_to_dec "${n_hex}")"
  e_dec="$(hex_to_dec "${e_hex}")"
  em_dec="$(modexp_bc "${sig_dec}" "${e_dec}" "${n_dec}")"
  em_hex="$(dec_to_hex "${em_dec}")"
  em_hex="${em_hex,,}"
  em_hex="$(pad_hex_left "${em_hex}" $((k_bytes * 2)))"

  if [[ "${em_hex:0:4}" != "0001" ]]; then
    echo "verification failed" >&2
    return 1
  fi
  local em_body="${em_hex:4}"
  local pos=0
  local body_len=${#em_body}
  while (( pos < body_len )); do
    local byte="${em_body:pos:2}"
    if [[ "${byte}" == "00" ]]; then
      break
    fi
    if [[ "${byte}" != "ff" ]]; then
      echo "verification failed" >&2
      return 1
    fi
    pos=$((pos + 2))
  done
  if (( pos >= body_len )); then
    echo "verification failed" >&2
    return 1
  fi
  if (( (pos / 2) < 8 )); then
    echo "verification failed" >&2
    return 1
  fi
  local digest_info_hex="${em_body:pos+2}"
  if [[ "${digest_info_hex,,}" != "${expected_digest_info}" ]]; then
    echo "verification failed" >&2
    return 1
  fi
  return 0
}

main() {
  if [[ $# -eq 0 ]]; then
    usage >&2
    return 1
  fi
  local command="$1"
  shift
  case "${command}" in
    hmac-sha256)
      cmd_hmac_sha256 "$@"
      ;;
    random-bytes)
      cmd_random_bytes "$@"
      ;;
    rsa-sign)
      cmd_rsa_sign "$@"
      ;;
    rsa-verify)
      cmd_rsa_verify "$@"
      ;;
    --help|-h)
      usage
      ;;
    *)
      echo "Unknown command: ${command}" >&2
      usage >&2
      return 1
      ;;
  esac
}

main "$@"
