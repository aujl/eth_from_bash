# shellcheck shell=bash

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

usage_rsa_generate() {
  cat <<'USAGE'
Usage: crypto_sign.sh rsa-generate --bits <n> --private-out <path> --public-out <path> [--exponent <value>]
USAGE
}

usage_rsa_public() {
  cat <<'USAGE'
Usage: crypto_sign.sh rsa-public --key <path> --output <path|->
USAGE
}

SMALL_PRIME_SIEVE=(
  3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59 61 67 71 73 79 83 89 97
  101 103 107 109 113 127 131 137 139 149 151 157 163 167 173 179 181 191
  193 197 199 211 223 227 229 233 239 241 251 257 263 269 271 277 281 283
  293 307 311 313 317 331 337 347 349 353 359 367 373 379 383 389 397 401
  409 419 421 431 433 439 443 449 457 461 463 467 479 487 491 499 503 509
  521 523 541 547 557 563 569 571 577 587 593 599 601 607 613 617 619 631
  641 643 647 653 659 661 673 677 683 691 701 709 719 727 733 739 743 751
  757 761 769 773 787 797 809 811 821 823 827 829 839 853 857 859 863 877
  881 883 887 907 911 919 929 937 941 947 953 967 971 977 983 991 997
)

RSA_OID="1.2.840.113549.1.1.1"
SHA256_OID="2.16.840.1.101.3.4.2.1"

parse_rsa_algorithm_identifier() {
  local hex="${1,,}"
  local seq_hex
  if [[ "${hex:0:2}" == "30" ]]; then
    der_read_sequence "${hex}" 0
    seq_hex="${DER_SEQUENCE_HEX}"
  else
    seq_hex="${hex}"
  fi
  local offset=0
  der_read_object_identifier "${seq_hex}" "${offset}"
  local oid="${DER_OBJECT_IDENTIFIER}"
  offset="${DER_NEXT_OFFSET}"
  [[ "${oid}" == "${RSA_OID}" ]] || die "Algorithm identifier is not RSA"
  if (( offset * 2 < ${#seq_hex} )); then
    der_read_tlv "${seq_hex}" "${offset}" "05"
    local value="${DER_VALUE}"
    [[ -z "${value}" ]] || die "Unexpected parameters in RSA algorithm identifier"
    offset="${DER_NEXT_OFFSET}"
  fi
  der_expect_eof "${seq_hex}" "${offset}"
}

parse_rsa_private_pkcs1() {
  local hex="$1"
  der_read_sequence "${hex}" 0
  local seq_hex="${DER_SEQUENCE_HEX}"
  local offset=0
  der_read_integer "${seq_hex}" "${offset}"
  local version
  version="$(hex_to_dec "${DER_INTEGER_HEX}")"
  offset="${DER_NEXT_OFFSET}"
  [[ "${version}" == "0" ]] || die "DER: unsupported RSA private key version"
  der_read_integer "${seq_hex}" "${offset}"
  RSA_PRIV_N="${DER_INTEGER_HEX}"
  offset="${DER_NEXT_OFFSET}"
  der_read_integer "${seq_hex}" "${offset}"
  RSA_PRIV_E="${DER_INTEGER_HEX}"
  offset="${DER_NEXT_OFFSET}"
  der_read_integer "${seq_hex}" "${offset}"
  RSA_PRIV_D="${DER_INTEGER_HEX}"
  offset="${DER_NEXT_OFFSET}"
  der_read_integer "${seq_hex}" "${offset}"
  RSA_PRIV_P="${DER_INTEGER_HEX}"
  offset="${DER_NEXT_OFFSET}"
  der_read_integer "${seq_hex}" "${offset}"
  RSA_PRIV_Q="${DER_INTEGER_HEX}"
  offset="${DER_NEXT_OFFSET}"
  der_read_integer "${seq_hex}" "${offset}"
  RSA_PRIV_DP="${DER_INTEGER_HEX}"
  offset="${DER_NEXT_OFFSET}"
  der_read_integer "${seq_hex}" "${offset}"
  RSA_PRIV_DQ="${DER_INTEGER_HEX}"
  offset="${DER_NEXT_OFFSET}"
  der_read_integer "${seq_hex}" "${offset}"
  RSA_PRIV_QI="${DER_INTEGER_HEX}"
  offset="${DER_NEXT_OFFSET}"
  der_expect_eof "${seq_hex}" "${offset}"
}

parse_rsa_private_pkcs8() {
  local hex="$1"
  der_read_sequence "${hex}" 0
  local seq_hex="${DER_SEQUENCE_HEX}"
  local offset=0
  der_read_integer "${seq_hex}" "${offset}"
  local version
  version="$(hex_to_dec "${DER_INTEGER_HEX}")"
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
  RSA_PUB_N="${DER_INTEGER_HEX}"
  key_offset="${DER_NEXT_OFFSET}"
  der_read_integer "${key_seq}" "${key_offset}"
  RSA_PUB_E="${DER_INTEGER_HEX}"
  key_offset="${DER_NEXT_OFFSET}"
  der_expect_eof "${key_seq}" "${key_offset}"
}

load_rsa_private_key() {
  local path="$1"
  local der_hex
  RSA_PRIV_N=""
  RSA_PRIV_D=""
  RSA_PRIV_E=""
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

rsa_algorithm_identifier_hex() {
  der_encode_sequence_hex \
    "$(der_encode_object_identifier_hex "${RSA_OID}")" \
    "$(der_encode_null_hex)"
}

sha256_algorithm_identifier_hex() {
  der_encode_sequence_hex \
    "$(der_encode_object_identifier_hex "${SHA256_OID}")" \
    "$(der_encode_null_hex)"
}

rsa_digest_info_hex() {
  local hash_name="$1"
  local digest_hex
  digest_hex="$(normalize_hex "$2")"
  case "${hash_name}" in
    sha256)
      local alg
      alg="$(sha256_algorithm_identifier_hex)"
      printf '%s' "$(der_encode_sequence_hex "${alg}" "$(der_encode_octet_string_hex "${digest_hex}")")"
      ;;
    *)
      die "Unsupported hash: ${hash_name}"
      ;;
  esac
}

rsa_private_to_pkcs1_hex() {
  local n_hex
  n_hex="$(normalize_hex "$1")"
  local e_hex
  e_hex="$(normalize_hex "$2")"
  local d_hex
  d_hex="$(normalize_hex "$3")"
  local p_hex
  p_hex="$(normalize_hex "$4")"
  local q_hex
  q_hex="$(normalize_hex "$5")"
  local dp_hex
  dp_hex="$(normalize_hex "$6")"
  local dq_hex
  dq_hex="$(normalize_hex "$7")"
  local qi_hex
  qi_hex="$(normalize_hex "$8")"
  der_encode_sequence_hex \
    "$(der_encode_integer_hex "00")" \
    "$(der_encode_integer_hex "${n_hex}")" \
    "$(der_encode_integer_hex "${e_hex}")" \
    "$(der_encode_integer_hex "${d_hex}")" \
    "$(der_encode_integer_hex "${p_hex}")" \
    "$(der_encode_integer_hex "${q_hex}")" \
    "$(der_encode_integer_hex "${dp_hex}")" \
    "$(der_encode_integer_hex "${dq_hex}")" \
    "$(der_encode_integer_hex "${qi_hex}")"
}

rsa_private_to_pkcs8_hex() {
  local pkcs1_hex="$1"
  der_encode_sequence_hex \
    "$(der_encode_integer_hex "00")" \
    "$(rsa_algorithm_identifier_hex)" \
    "$(der_encode_octet_string_hex "${pkcs1_hex}")"
}

rsa_public_to_spki_hex() {
  local n_hex
  n_hex="$(normalize_hex "$1")"
  local e_hex
  e_hex="$(normalize_hex "$2")"
  local public_seq
  public_seq="$(der_encode_sequence_hex "$(der_encode_integer_hex "${n_hex}")" "$(der_encode_integer_hex "${e_hex}")")"
  der_encode_sequence_hex \
    "$(rsa_algorithm_identifier_hex)" \
    "$(der_encode_bit_string_hex "${public_seq}")"
}

random_decimal_for_bits() {
  local bits="$1"
  local bytes=$(( (bits + 7) / 8 ))
  local hex
  hex="$(random_hex_bytes "${bytes}")"
  if [[ -z "${hex}" ]]; then
    hex="00"
  fi
  hex_to_dec "${hex}"
}

miller_rabin_rounds_for_bits() {
  local bits="$1"
  if (( bits >= 4096 )); then
    printf '3\n'
  elif (( bits >= 3072 )); then
    printf '4\n'
  elif (( bits >= 2048 )); then
    printf '5\n'
  elif (( bits >= 1536 )); then
    printf '6\n'
  elif (( bits >= 1024 )); then
    printf '7\n'
  elif (( bits >= 768 )); then
    printf '7\n'
  elif (( bits >= 512 )); then
    printf '8\n'
  elif (( bits >= 384 )); then
    printf '10\n'
  elif (( bits >= 256 )); then
    printf '12\n'
  else
    printf '16\n'
  fi
}

effective_miller_rabin_rounds() {
  local bits="$1"
  local override="${CRYPTO_SIGN_RSA_MR_ROUNDS:-}"
  if [[ -n "${override}" ]]; then
    if [[ "${override}" =~ ^[0-9]+$ ]] && (( override > 0 )); then
      printf '%s\n' "${override}"
      return 0
    fi
    die "CRYPTO_SIGN_RSA_MR_ROUNDS must be a positive integer"
  fi
  miller_rabin_rounds_for_bits "${bits}"
}

generate_candidate_hex() {
  local bits="$1"
  local bytes=$(( (bits + 7) / 8 ))
  local hex
  hex="$(random_hex_bytes "${bytes}")"
  if [[ -z "${hex}" ]]; then
    hex="00"
  fi
  hex="${hex,,}"
  local first_byte_hex="${hex:0:2}"
  local first_byte=$((16#${first_byte_hex^^}))
  local msb_mod=$(( bits % 8 ))
  if (( msb_mod == 0 )); then
    first_byte=$((first_byte | 0x80))
  else
    local mask=$(( (0xFF << (8 - msb_mod)) & 0xFF ))
    first_byte=$((first_byte & mask))
    first_byte=$((first_byte | 0x80))
  fi
  first_byte_hex=$(printf '%02x' "${first_byte}")
  hex="${first_byte_hex}${hex:2}"
  local last_index=$(( ${#hex} - 2 ))
  local last_byte=$((16#${hex:last_index:2} ))
  last_byte=$((last_byte | 0x01))
  local last_hex
  last_hex=$(printf '%02x' "${last_byte}")
  hex="${hex:0:last_index}${last_hex}"
  printf '%s\n' "${hex}"
}

is_probable_prime_dec() {
  local candidate="$1"
  local bits="$2"
  local candidate_hex="${3:-}"
  if [[ "${candidate}" == "2" || "${candidate}" == "3" ]]; then
    return 0
  fi
  if [[ "${candidate}" == "" ]]; then
    return 1
  fi
  if [[ -z "${candidate_hex}" ]]; then
    candidate_hex="$(dec_to_hex "${candidate}")"
  fi
  candidate_hex="${candidate_hex,,}"
  local last_nibble="${candidate_hex: -1}"
  case "${last_nibble}" in
    0|2|4|6|8|a|c|e)
      return 1
      ;;
  esac
  if [[ "${candidate_hex}" == "" ]]; then
    return 1
  fi
  local prime mod
  for prime in "${SMALL_PRIME_SIEVE[@]}"; do
    if [[ "${candidate}" == "${prime}" ]]; then
      return 0
    fi
    mod="$(hex_mod_small_prime "${candidate_hex}" "${prime}")"
    if [[ "${mod}" == "0" ]]; then
      return 1
    fi
  done
  if (( bits <= 2 )); then
    return 1
  fi
  ensure_bc_common_session
  local rounds
  rounds="$(effective_miller_rabin_rounds "${bits}")"
  local i
  for (( i = 0; i < rounds; i++ )); do
    local random_dec
    random_dec="$(random_decimal_for_bits "${bits}")"
    if [[ -z "${random_dec}" ]]; then
      random_dec=2
    fi
    local result
    result="$(prime_session_mr_trial "${candidate}" "${random_dec}")"
    if [[ "${result}" != "1" ]]; then
      return 1
    fi
  done
  return 0
}

generate_prime_dec() {
  local bits="$1"
  crypto_sign_trace_increment generate_prime_dec
  ensure_bc_common_session
  while true; do
    local candidate_hex
    candidate_hex="$(generate_candidate_hex "${bits}")"
    local candidate
    candidate="$(hex_to_dec "${candidate_hex}")"
    if [[ -z "${candidate}" || "${candidate}" == "0" ]]; then
      continue
    fi
    if ! is_probable_prime_dec "${candidate}" "${bits}" "${candidate_hex}"; then
      continue
    fi
    printf '%s\n' "${candidate}"
    return 0
  done
}

cmd_rsa_generate() {
  local bits=2048
  local private_out=""
  local public_out=""
  local exponent=65537
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --bits)
        [[ $# -lt 2 ]] && { usage_rsa_generate >&2; return 1; }
        bits="$2"
        shift 2
        ;;
      --private-out)
        [[ $# -lt 2 ]] && { usage_rsa_generate >&2; return 1; }
        private_out="$2"
        shift 2
        ;;
      --public-out)
        [[ $# -lt 2 ]] && { usage_rsa_generate >&2; return 1; }
        public_out="$2"
        shift 2
        ;;
      --exponent)
        [[ $# -lt 2 ]] && { usage_rsa_generate >&2; return 1; }
        exponent="$2"
        shift 2
        ;;
      --help)
        usage_rsa_generate
        return 0
        ;;
      *)
        echo "Unknown option for rsa-generate: $1" >&2
        usage_rsa_generate >&2
        return 1
        ;;
    esac
  done

  if [[ -z "${private_out}" || -z "${public_out}" ]]; then
    usage_rsa_generate >&2
    return 1
  fi

  if ! [[ "${bits}" =~ ^[0-9]+$ ]]; then
    echo "--bits must be a positive integer" >&2
    return 1
  fi
  local min_bits="${CRYPTO_SIGN_RSA_MIN_BITS:-256}"
  if (( bits < min_bits )); then
    echo "--bits must be at least ${min_bits}" >&2
    return 1
  fi

  if ! [[ "${exponent}" =~ ^[0-9]+$ ]]; then
    echo "--exponent must be a positive integer" >&2
    return 1
  fi
  if (( exponent < 3 || exponent % 2 == 0 )); then
    echo "--exponent must be an odd integer >= 3" >&2
    return 1
  fi

  if [[ -e "${private_out}" ]]; then
    echo "Refusing to overwrite existing file: ${private_out}" >&2
    return 1
  fi
  if [[ -e "${public_out}" ]]; then
    echo "Refusing to overwrite existing file: ${public_out}" >&2
    return 1
  fi

  ensure_bc_common_session

  local half_bits=$(( bits / 2 ))
  local other_bits=$(( bits - half_bits ))
  local p_dec q_dec n_dec phi_dec d_dec dp_dec dq_dec qi_dec gcd_val

  while true; do
    p_dec="$(generate_prime_dec "${half_bits}")"
    q_dec="$(generate_prime_dec "${other_bits}")"
    if [[ "${p_dec}" == "${q_dec}" ]]; then
      continue
    fi
    n_dec="$(bc_simple "(${p_dec}) * (${q_dec})")"
    phi_dec="$(bc_simple "(${p_dec} - 1) * (${q_dec} - 1)")"
    gcd_val="$(bc_eval_common "gcd(${exponent}, ${phi_dec})")"
    if [[ "${gcd_val}" != "1" ]]; then
      continue
    fi
    d_dec="$(bc_eval_common "modinv(${exponent}, ${phi_dec})")"
    dp_dec="$(bc_simple "${d_dec} % (${p_dec} - 1)")"
    dq_dec="$(bc_simple "${d_dec} % (${q_dec} - 1)")"
    qi_dec="$(bc_eval_common "modinv(${q_dec}, ${p_dec})")"
    break
  done

  local n_hex d_hex p_hex q_hex dp_hex dq_hex qi_hex e_hex
  n_hex="$(dec_to_hex "${n_dec}")"; n_hex="${n_hex,,}"
  d_hex="$(dec_to_hex "${d_dec}")"; d_hex="${d_hex,,}"
  p_hex="$(dec_to_hex "${p_dec}")"; p_hex="${p_hex,,}"
  q_hex="$(dec_to_hex "${q_dec}")"; q_hex="${q_hex,,}"
  dp_hex="$(dec_to_hex "${dp_dec}")"; dp_hex="${dp_hex,,}"
  dq_hex="$(dec_to_hex "${dq_dec}")"; dq_hex="${dq_hex,,}"
  qi_hex="$(dec_to_hex "${qi_dec}")"; qi_hex="${qi_hex,,}"
  e_hex="$(dec_to_hex "${exponent}")"; e_hex="${e_hex,,}"

  local pkcs1_hex pkcs8_hex spki_hex
  pkcs1_hex="$(rsa_private_to_pkcs1_hex "${n_hex}" "${e_hex}" "${d_hex}" "${p_hex}" "${q_hex}" "${dp_hex}" "${dq_hex}" "${qi_hex}")"
  pkcs8_hex="$(rsa_private_to_pkcs8_hex "${pkcs1_hex}")"
  spki_hex="$(rsa_public_to_spki_hex "${n_hex}" "${e_hex}")"

  local priv_pem pub_pem
  priv_pem="$(pem_wrap_hex "PRIVATE KEY" "${pkcs8_hex}")"
  pub_pem="$(pem_wrap_hex "PUBLIC KEY" "${spki_hex}")"

  ( umask 077; printf '%s\n' "${priv_pem}" > "${private_out}" )
  chmod 600 "${private_out}"
  ( umask 022; printf '%s\n' "${pub_pem}" > "${public_out}" )
  chmod 644 "${public_out}"
}

cmd_rsa_public() {
  local key_path=""
  local output_path=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --key)
        [[ $# -lt 2 ]] && { usage_rsa_public >&2; return 1; }
        key_path="$2"
        shift 2
        ;;
      --output)
        [[ $# -lt 2 ]] && { usage_rsa_public >&2; return 1; }
        output_path="$2"
        shift 2
        ;;
      --help)
        usage_rsa_public
        return 0
        ;;
      *)
        echo "Unknown option for rsa-public: $1" >&2
        usage_rsa_public >&2
        return 1
        ;;
    esac
  done

  if [[ -z "${key_path}" || -z "${output_path}" ]]; then
    usage_rsa_public >&2
    return 1
  fi

  load_rsa_private_key "${key_path}"

  local spki_hex
  spki_hex="$(rsa_public_to_spki_hex "${RSA_PRIV_N}" "${RSA_PRIV_E}")"
  local pem
  pem="$(pem_wrap_hex "PUBLIC KEY" "${spki_hex}")"

  if [[ "${output_path}" == "-" ]]; then
    printf '%s\n' "${pem}"
    return 0
  fi

  if [[ -e "${output_path}" ]]; then
    echo "Refusing to overwrite existing file: ${output_path}" >&2
    return 1
  fi

  ( umask 022; printf '%s\n' "${pem}" > "${output_path}" )
  chmod 644 "${output_path}"
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

  local n_hex d_hex
  n_hex="$(normalize_hex "${RSA_PRIV_N}")"
  d_hex="$(normalize_hex "${RSA_PRIV_D}")"
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
  signature_hex="$(pad_hex_left "${signature_hex}" ${#n_hex})"

  case "${output_format}" in
    raw)
      hex_to_raw "${signature_hex}"
      ;;
    hex)
      printf '%s\n' "${signature_hex}"
      ;;
    base64)
      hex_to_raw "${signature_hex}" | base64 | tr -d '\n'
      printf '\n'
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
        digest_hex="$(sha256_hex_from_stream <&0)"
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

  local signature_hex
  signature_hex="$(read_hex "${signature_path}")"
  if [[ -z "${signature_hex}" ]]; then
    echo "verification failed" >&2
    return 1
  fi

  local n_hex
  n_hex="$(normalize_hex "${RSA_PUB_N}")"
  local e_hex
  e_hex="$(normalize_hex "${RSA_PUB_E}")"
  local sig_hex
  sig_hex="$(normalize_hex "${signature_hex}")"
  local sig_dec
  sig_dec="$(hex_to_dec "${sig_hex}")"
  local n_dec
  n_dec="$(hex_to_dec "${n_hex}")"
  local e_dec
  e_dec="$(hex_to_dec "${e_hex}")"
  local em_dec
  em_dec="$(modexp_bc "${sig_dec}" "${e_dec}" "${n_dec}")"
  local em_hex
  em_hex="$(dec_to_hex "${em_dec}")"
  em_hex="$(pad_hex_left "${em_hex}" ${#n_hex})"

  local em_len=${#em_hex}
  if (( em_len < 4 )) || [[ ${em_hex:0:4} != "0001" ]]; then
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
