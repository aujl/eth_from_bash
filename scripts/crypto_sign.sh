#!/usr/bin/env bash
set -euo pipefail
set -o noclobber

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
  rsa-generate   Generate RSA keypair (PKCS#8 private + SPKI public)
  rsa-public     Derive RSA public key from private key

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

read -r -d '' BC_COMMON_FUNCS <<'BC_FUNCS' || true
define modexp(a,b,n){
  if(n==1) return 0;
  a%=n;
  res=1;
  while(b>0){
    if(b%2==1) res=(res*a)%n;
    a=(a*a)%n;
    b/=2;
  }
  return res;
}
define gcd(a,b){
  auto t;
  while(b!=0){
    t=b;
    b=a%b;
    a=t;
  }
  if(a<0) a=-a;
  return a;
}
define modinv(a,m){
  auto m0,t,q,x0,x1;
  m0=m;
  x0=0;
  x1=1;
  if(m==1) return 0;
  while(a>1){
    q=a/m;
    t=m;
    m=a%m;
    a=t;
    t=x0;
    x0=x1-q*x0;
    x1=t;
  }
  if(x1<0) x1+=m0;
  x1%=m0;
  if(x1<0) x1+=m0;
  return x1;
}
define lcm(a,b){
  return (a/gcd(a,b))*b;
}
define miller_rabin(n,a){
  if(a<=1||a>=n) return 0;
  if(n%a==0) return (a==n);
  d=n-1;
  s=0;
  while(d%2==0){
    d/=2;
    s+=1;
  }
  x=modexp(a,d,n);
  if(x==1||x==n-1) return 1;
  for(r=1;r<s;r++){
    x=(x*x)%n;
    if(x==n-1) return 1;
  }
  return 0;
}
BC_FUNCS

bc_eval_common() {
  local expr="$1"
  bc <<BC
${BC_COMMON_FUNCS}
scale=0
${expr}
BC
}

bc_mod() {
  local a="$1"
  local b="$2"
  printf 'scale=0; (%s) %% (%s)\n' "${a}" "${b}" | bc
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

RSA_OID="1.2.840.113549.1.1.1"
SHA256_OID="2.16.840.1.101.3.4.2.1"

der_encode_length_hex() {
  local length="$1"
  if (( length < 0 )); then
    die "DER: negative length"
  fi
  if (( length < 0x80 )); then
    printf '%02x' "${length}"
    return
  fi
  local hex
  hex="$(printf '%x' "${length}")"
  if (( ${#hex} % 2 == 1 )); then
    hex="0${hex}"
  fi
  local nbytes=$(( ${#hex} / 2 ))
  printf '%02x%s' $((0x80 | nbytes)) "${hex}"
}

der_encode_tlv_hex() {
  local tag_hex="$1"
  shift
  local content=""
  local part
  for part in "$@"; do
    content+="${part}"
  done
  local length=$(( ${#content} / 2 ))
  local len_hex
  len_hex="$(der_encode_length_hex "${length}")"
  printf '%s%s%s' "${tag_hex}" "${len_hex}" "${content}"
}

der_encode_integer_hex() {
  local value
  value="$(normalize_hex "${1}")"
  if [[ -z "${value}" ]]; then
    value="00"
  fi
  while [[ ${#value} > 2 && ${value:0:2} == "00" && $((16#${value:2:2})) < 0x80 ]]; do
    value="${value:2}"
  done
  if (( 16#${value:0:2} >= 0x80 )); then
    value="00${value}"
  fi
  der_encode_tlv_hex "02" "${value}"
}

der_encode_octet_string_hex() {
  local content
  content="$(normalize_hex "${1}")"
  der_encode_tlv_hex "04" "${content}"
}

der_encode_bit_string_hex() {
  local content
  content="$(normalize_hex "${1}")"
  der_encode_tlv_hex "03" "00${content}"
}

der_encode_sequence_hex() {
  der_encode_tlv_hex "30" "$@"
}

der_encode_object_identifier_hex() {
  local oid="$1"
  local IFS='.'
  read -r -a parts <<<"${oid}" || die "DER: invalid OID"
  if (( ${#parts[@]} < 2 )); then
    die "DER: invalid OID"
  fi
  local first_component=$((10#${parts[0]}))
  local second_component=$((10#${parts[1]}))
  local encoded
  encoded=$(printf '%02x' $((first_component * 40 + second_component)))
  local component
  for component in "${parts[@]:2}"; do
    local value=$((10#${component}))
    if (( value == 0 )); then
      encoded+="00"
      continue
    fi
    local -a stack=()
    while (( value > 0 )); do
      stack+=( "$(printf '%02x' $((value & 0x7f)))" )
      value=$(( value >> 7 ))
    done
    local idx
    for (( idx=${#stack[@]}-1; idx>=0; idx-- )); do
      local byte=$((16#${stack[idx]}))
      if (( idx > 0 )); then
        byte=$((byte | 0x80))
      fi
      encoded+="$(printf '%02x' "${byte}")"
    done
  done
  der_encode_tlv_hex "06" "${encoded}"
}

der_encode_null_hex() {
  printf '%s' "0500"
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
  digest_hex="$(normalize_hex "${2}")"
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
  local n_hex="$(normalize_hex "$1")"
  local e_hex="$(normalize_hex "$2")"
  local d_hex="$(normalize_hex "$3")"
  local p_hex="$(normalize_hex "$4")"
  local q_hex="$(normalize_hex "$5")"
  local dp_hex="$(normalize_hex "$6")"
  local dq_hex="$(normalize_hex "$7")"
  local qi_hex="$(normalize_hex "$8")"
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
  local n_hex="$(normalize_hex "$1")"
  local e_hex="$(normalize_hex "$2")"
  local public_seq
  public_seq="$(der_encode_sequence_hex "$(der_encode_integer_hex "${n_hex}")" "$(der_encode_integer_hex "${e_hex}")")"
  der_encode_sequence_hex \
    "$(rsa_algorithm_identifier_hex)" \
    "$(der_encode_bit_string_hex "${public_seq}")"
}

pem_wrap_hex() {
  local label="$1"
  local data_hex="$2"
  local base64_body
  base64_body="$(hex_to_raw "${data_hex}" | base64 | tr -d '\n')"
  local folded
  folded="$(printf '%s' "${base64_body}" | fold -w 64)"
  printf '%s\n' "-----BEGIN ${label}-----"
  if [[ -n "${folded}" ]]; then
    printf '%s\n' "${folded}"
  fi
  printf '%s\n' "-----END ${label}-----"
}

random_hex_bytes() {
  local bytes="$1"
  if (( bytes <= 0 )); then
    return 0
  fi
  od -An -N "${bytes}" -tx1 /dev/urandom | tr -d ' \n'
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
  local last_hex=$(printf '%02x' "${last_byte}")
  hex="${hex:0:last_index}${last_hex}"
  echo "${hex}"
}

random_decimal_for_bits() {
  local bits="$1"
  local bytes=$(( (bits + 7) / 8 ))
  local hex
  hex="$(random_hex_bytes "${bytes}")"
  if [[ -z "${hex}" ]]; then
    hex="00"
  fi
  printf 'ibase=16;%s\n' "${hex^^}" | bc
}

is_probable_prime_dec() {
  local candidate="$1"
  local bits="$2"
  if [[ "${candidate}" == "2" || "${candidate}" == "3" ]]; then
    return 0
  fi
  if [[ "${candidate}" == "" ]]; then
    return 1
  fi
  if [[ "$(bc_mod "${candidate}" 2)" == "0" ]]; then
    return 1
  fi
  local small_primes=(3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59 61 67 71 73 79 83 89 97)
  local prime mod
  for prime in "${small_primes[@]}"; do
    if [[ "${candidate}" == "${prime}" ]]; then
      return 0
    fi
    mod="$(bc_mod "${candidate}" "${prime}")"
    if [[ "${mod}" == "0" ]]; then
      return 1
    fi
  done
  if (( bits <= 2 )); then
    return 1
  fi
  local rounds=4
  local i
  for (( i = 0; i < rounds; i++ )); do
    local random_dec
    random_dec="$(random_decimal_for_bits "${bits}")"
    if [[ -z "${random_dec}" ]]; then
      random_dec=2
    fi
    local expr
    read -r -d '' expr <<EOF || true
n=${candidate}
rand=${random_dec}
if (n <= 3) {
  if (n == 2 || n == 3) {
    print 1
  } else {
    print 0
  }
} else {
  if (n % 2 == 0) {
    print 0
  } else {
    if (rand <= 1 || rand >= n - 1) rand = (rand % (n - 3)) + 2;
    print miller_rabin(n, rand)
  }
}
EOF
    local result
    result="$(bc_eval_common "${expr}")"
    if [[ "${result}" != "1" ]]; then
      return 1
    fi
  done
  return 0
}

generate_prime_dec() {
  local bits="$1"
  while true; do
    local candidate_hex
    candidate_hex="$(generate_candidate_hex "${bits}")"
    local candidate
    candidate="$(printf 'ibase=16;%s\n' "${candidate_hex^^}" | bc)"
    if [[ -z "${candidate}" || "${candidate}" == "0" ]]; then
      continue
    fi
    if ! is_probable_prime_dec "${candidate}" "${bits}"; then
      continue
    fi
    echo "${candidate}"
    return 0
  done
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
  if (( bits < 256 )); then
    echo "--bits must be at least 256" >&2
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

  local half_bits=$(( bits / 2 ))
  local other_bits=$(( bits - half_bits ))
  local p_dec q_dec n_dec phi_dec d_dec dp_dec dq_dec qi_dec gcd_val

  while true; do
    p_dec="$(generate_prime_dec "${half_bits}")"
    q_dec="$(generate_prime_dec "${other_bits}")"
    if [[ "${p_dec}" == "${q_dec}" ]]; then
      continue
    fi
    n_dec="$(printf 'scale=0; (%s) * (%s)\n' "${p_dec}" "${q_dec}" | bc)"
    phi_dec="$(printf 'scale=0; (%s - 1) * (%s - 1)\n' "${p_dec}" "${q_dec}" | bc)"
    gcd_val="$(bc_eval_common "gcd(${exponent}, ${phi_dec})")"
    if [[ "${gcd_val}" != "1" ]]; then
      continue
    fi
    d_dec="$(bc_eval_common "modinv(${exponent}, ${phi_dec})")"
    dp_dec="$(printf 'scale=0; %s %% (%s - 1)\n' "${d_dec}" "${p_dec}" | bc)"
    dq_dec="$(printf 'scale=0; %s %% (%s - 1)\n' "${d_dec}" "${q_dec}" | bc)"
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
  local n_hex e_hex
  n_hex="$(normalize_hex "${RSA_PUB_N}")"
  e_hex="$(normalize_hex "${RSA_PUB_E}")"
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
    rsa-generate)
      cmd_rsa_generate "$@"
      ;;
    rsa-public)
      cmd_rsa_public "$@"
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
