# shellcheck shell=bash

usage_ecdsa_sign() {
  cat <<'USAGE'
Usage: crypto_sign.sh ecdsa-sign --key <path> --message <path|-> [--hash sha256] [--output hex|base64|raw]
USAGE
}

usage_ecdsa_verify() {
  cat <<'USAGE'
Usage: crypto_sign.sh ecdsa-verify --key <path> --message <path|-> --signature <path|-> [--hash sha256]
USAGE
}

usage_ecdsa_generate() {
  cat <<'USAGE'
Usage: crypto_sign.sh ecdsa-generate --private-out <path> --public-out <path>
USAGE
}

usage_ecdsa_public() {
  cat <<'USAGE'
Usage: crypto_sign.sh ecdsa-public --key <path> --output <path|->
USAGE
}

SECP256K1_P_HEX="fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
SECP256K1_N_HEX="fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
SECP256K1_GX_HEX="79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
SECP256K1_GY_HEX="483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
SECP256K1_OID="1.3.132.0.10"
EC_PUBLIC_OID="1.2.840.10045.2.1"

SECP256K1_N_DEC="$(hex_to_dec "${SECP256K1_N_HEX}")"
SECP256K1_HALF_N_DEC="$(bc_simple "${SECP256K1_N_DEC} / 2")"

read -r -d '' BC_SECP_FUNCS <<'BC_FUNCS' || true
define modp(x) {
  auto r;
  r = x % p;
  if (r < 0) r += p;
  return r;
}

define madd(a, b) {
  return modp(a + b);
}

define msub(a, b) {
  auto r;
  r = a - b;
  r = r % p;
  if (r < 0) r += p;
  return r;
}

define mmul(a, b) {
  return modp(a * b);
}

define msqr(a) {
  return modp(a * a);
}

define minv(a) {
  auto t0, t1, r0, r1, q0, u0;
  a = modp(a);
  if (a == 0) return 0;
  t0 = 0;
  t1 = 1;
  r0 = p;
  r1 = a;
  while (r1 != 0) {
    q0 = r0 / r1;
    u0 = t1;
    t1 = t0 - q0 * t1;
    t0 = u0;
    u0 = r1;
    r1 = r0 - q0 * r1;
    r0 = u0;
  }
  if (r0 != 1) return 0;
  while (t0 < 0) t0 += p;
  return t0 % p;
}

define pdouble(px, py) {
  auto s0, n0, d0;
  if (py == 0) {
    t[0] = 0;
    t[1] = 0;
    return 1;
  }
  n0 = mmul(3, msqr(px));
  d0 = mmul(2, py);
  d0 = minv(d0);
  if (d0 == 0) {
    t[0] = 0;
    t[1] = 0;
    return 1;
  }
  s0 = mmul(n0, d0);
  t[0] = msub(msub(msqr(s0), px), px);
  t[1] = msub(mmul(s0, msub(px, t[0])), py);
  return 0;
}

define padd(ax, ay, bx, by) {
  auto s0, d0;
  if (ax == bx) {
    if (madd(ay, by) == 0) {
      t[0] = 0;
      t[1] = 0;
      return 1;
    }
    return pdouble(ax, ay);
  }
  d0 = msub(bx, ax);
  d0 = minv(d0);
  if (d0 == 0) {
    t[0] = 0;
    t[1] = 0;
    return 1;
  }
  s0 = mmul(msub(by, ay), d0);
  t[0] = msub(msub(msqr(s0), ax), bx);
  t[1] = msub(mmul(s0, msub(ax, t[0])), ay);
  return 0;
}

define pmul(k, px, py) {
  r[0] = 0;
  r[1] = 0;
  r[2] = 1;
  q[0] = px;
  q[1] = py;
  q[2] = 0;
  while (k > 0) {
    if (k % 2 == 1) {
      if (r[2] == 1) {
        if (q[2] == 1) {
          r[0] = 0;
          r[1] = 0;
          r[2] = 1;
        } else {
          r[0] = q[0];
          r[1] = q[1];
          r[2] = 0;
        }
      } else if (q[2] == 0) {
        if (padd(r[0], r[1], q[0], q[1]) == 1) {
          r[0] = 0;
          r[1] = 0;
          r[2] = 1;
        } else {
          r[0] = t[0];
          r[1] = t[1];
          r[2] = 0;
        }
      }
    }
    if (q[2] == 0) {
      if (pdouble(q[0], q[1]) == 1) {
        q[0] = 0;
        q[1] = 0;
        q[2] = 1;
      } else {
        q[0] = t[0];
        q[1] = t[1];
      }
    }
    k = k / 2;
  }
  if (r[2] == 1) {
    pmul_inf = 1;
  } else {
    pmul_inf = 0;
    pmul_x = r[0];
    pmul_y = r[1];
  }
}
BC_FUNCS

secp_point_mul() {
  local scalar_hex="${1^^}"
  local base_x_hex="${2^^}"
  local base_y_hex="${3^^}"
  scalar_hex="${scalar_hex//[^0-9A-F]/}"
  base_x_hex="${base_x_hex//[^0-9A-F]/}"
  base_y_hex="${base_y_hex//[^0-9A-F]/}"
  if [[ -z "${scalar_hex}" ]]; then
    scalar_hex="0"
  fi
  local bc_output
  bc_output="$(bc <<BC
scale=0
ibase=16
p=${SECP256K1_P_HEX^^}
bx=${base_x_hex}
by=${base_y_hex}
k=${scalar_hex}
ibase=10
${BC_SECP_FUNCS}
dummy = pmul(k, bx, by)
if (pmul_inf == 1) {
  print "INF\n";
} else {
  pmul_x;
  pmul_y;
}
BC
)"
  bc_output="${bc_output//$'\r'/}"
  bc_output="${bc_output%%$'\n'}"
  if [[ "${bc_output}" == "INF" ]]; then
    printf 'INF\n'
    return 0
  fi
  local -a coords=()
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    coords+=("${line}")
  done <<<"${bc_output}"
  if (( ${#coords[@]} != 2 )); then
    return 1
  fi
  local x_hex
  x_hex="$(dec_to_hex "${coords[0]}")"
  local y_hex
  y_hex="$(dec_to_hex "${coords[1]}")"
  x_hex="${x_hex,,}"
  y_hex="${y_hex,,}"
  printf '%s %s\n' "${x_hex}" "${y_hex}"
}

secp_point_add() {
  local ax_hex="${1,,}"
  local ay_hex="${2,,}"
  local bx_hex="${3,,}"
  local by_hex="${4,,}"
  if [[ "${ax_hex}" == "0" && "${ay_hex}" == "0" ]]; then
    printf '%s %s\n' "${bx_hex}" "${by_hex}"
    return 0
  fi
  if [[ "${bx_hex}" == "0" && "${by_hex}" == "0" ]]; then
    printf '%s %s\n' "${ax_hex}" "${ay_hex}"
    return 0
  fi
  local bc_output
  bc_output="$(bc <<BC
scale=0
ibase=16
p=${SECP256K1_P_HEX^^}
ax=${ax_hex^^}
ay=${ay_hex^^}
bx=${bx_hex^^}
by=${by_hex^^}
ibase=10
${BC_SECP_FUNCS}
if (padd(ax, ay, bx, by) == 1) {
  print "INF\n";
} else {
  t[0];
  t[1];
}
BC
)"
  bc_output="${bc_output//$'\r'/}"
  bc_output="${bc_output%%$'\n'}"
  if [[ "${bc_output}" == "INF" ]]; then
    printf '0 0\n'
    return 0
  fi
  local -a coords=()
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    coords+=("${line}")
  done <<<"${bc_output}"
  if (( ${#coords[@]} != 2 )); then
    return 1
  fi
  local x_hex
  x_hex="$(dec_to_hex "${coords[0]}")"
  local y_hex
  y_hex="$(dec_to_hex "${coords[1]}")"
  x_hex="${x_hex,,}"
  y_hex="${y_hex,,}"
  printf '%s %s\n' "${x_hex}" "${y_hex}"
}

secp_int2octets() {
  local value_hex
  value_hex="$(normalize_hex "$1")"
  value_hex="${value_hex,,}"
  printf '%064s\n' "${value_hex}" | tr ' ' '0'
}

secp_bits2octets() {
  local digest_hex
  digest_hex="$(normalize_hex "$1")"
  local digest_dec
  digest_dec="$(hex_to_dec "${digest_hex}")"
  local mod_dec
  mod_dec="$(bc_simple "(${digest_dec}) % (${SECP256K1_N_DEC})")"
  local mod_hex
  mod_hex="$(dec_to_hex "${mod_dec}")"
  mod_hex="${mod_hex,,}"
  printf '%064s\n' "${mod_hex}" | tr ' ' '0'
}

rfc6979_generate_k() {
  local priv_hex
  priv_hex="$(secp_int2octets "$1")"
  local digest_hex
  digest_hex="$(normalize_hex "$2")"
  local h1_hex
  h1_hex="$(secp_bits2octets "${digest_hex}")"
  local V
  V="$(printf '01%.0s' {1..32})"
  local K
  K="$(printf '00%.0s' {1..32})"
  local message
  message="${V}00${priv_hex}${h1_hex}"
  K="$(hmac_sha256_hex_internal "${K}" "${message}")"
  V="$(hmac_sha256_hex_internal "${K}" "${V}")"
  message="${V}01${priv_hex}${h1_hex}"
  K="$(hmac_sha256_hex_internal "${K}" "${message}")"
  V="$(hmac_sha256_hex_internal "${K}" "${V}")"
  while true; do
    V="$(hmac_sha256_hex_internal "${K}" "${V}")"
    local T="${V}"
    local k_dec
    k_dec="$(hex_to_dec "${T}")"
    if [[ $(bc_simple "(${k_dec} > 0) && (${k_dec} < ${SECP256K1_N_DEC})") -eq 1 ]]; then
      local k_hex
      k_hex="$(dec_to_hex "${k_dec}")"
      k_hex="${k_hex,,}"
      printf '%064s\n' "${k_hex}" | tr ' ' '0'
      return 0
    fi
    message="${V}00"
    K="$(hmac_sha256_hex_internal "${K}" "${message}")"
    V="$(hmac_sha256_hex_internal "${K}" "${V}")"
  done
}

ec_algorithm_identifier_hex() {
  der_encode_sequence_hex \
    "$(der_encode_object_identifier_hex "${EC_PUBLIC_OID}")" \
    "$(der_encode_object_identifier_hex "${SECP256K1_OID}")"
}

ec_private_to_der_hex() {
  local priv_hex
  priv_hex="$(normalize_hex "$1")"
  priv_hex="$(printf '%064s' "${priv_hex}" | tr ' ' '0')"
  local pub_x
  pub_x="$(normalize_hex "$2")"
  pub_x="$(printf '%064s' "${pub_x}" | tr ' ' '0')"
  local pub_y
  pub_y="$(normalize_hex "$3")"
  pub_y="$(printf '%064s' "${pub_y}" | tr ' ' '0')"
  local params
  params="$(der_encode_tlv_hex "a0" "$(der_encode_object_identifier_hex "${SECP256K1_OID}")")"
  local pub_point="04${pub_x}${pub_y}"
  local pub
  pub="$(der_encode_tlv_hex "a1" "$(der_encode_bit_string_hex "${pub_point}")")"
  der_encode_sequence_hex \
    "$(der_encode_integer_hex "01")" \
    "$(der_encode_octet_string_hex "${priv_hex}")" \
    "${params}" \
    "${pub}"
}

ec_public_to_spki_hex() {
  local pub_x
  pub_x="$(normalize_hex "$1")"
  pub_x="$(printf '%064s' "${pub_x}" | tr ' ' '0')"
  local pub_y
  pub_y="$(normalize_hex "$2")"
  pub_y="$(printf '%064s' "${pub_y}" | tr ' ' '0')"
  local alg
  alg="$(ec_algorithm_identifier_hex)"
  local point_hex="04${pub_x}${pub_y}"
  der_encode_sequence_hex \
    "${alg}" \
    "$(der_encode_bit_string_hex "${point_hex}")"
}

parse_ecdsa_private_der() {
  local hex="$1"
  der_read_sequence "${hex}" 0
  local seq_hex="${DER_SEQUENCE_HEX}"
  local offset=0
  der_read_integer "${seq_hex}" "${offset}"
  local version
  version="$(hex_to_dec "${DER_INTEGER_HEX}")"
  offset="${DER_NEXT_OFFSET}"
  [[ "${version}" == "1" ]] || die "DER: unsupported EC private key version"
  der_read_octet_string "${seq_hex}" "${offset}"
  local priv_hex="${DER_OCTET_HEX,,}"
  offset="${DER_NEXT_OFFSET}"
  priv_hex="$(printf '%064s' "${priv_hex}" | tr ' ' '0')"
  local priv_dec
  priv_dec="$(hex_to_dec "${priv_hex}")"
  if [[ $(bc_simple "(${priv_dec} <= 0) || (${priv_dec} >= ${SECP256K1_N_DEC})") -eq 1 ]]; then
    die "EC private key scalar out of range"
  fi
  local pub_x=""
  local pub_y=""
  local params_seen=0
  while (( offset * 2 < ${#seq_hex} )); do
    local tag="${seq_hex:offset*2:2}"
    case "${tag,,}" in
      a0)
        der_read_explicit "${seq_hex}" "${offset}" "a0"
        local explicit_next="${DER_NEXT_OFFSET}"
        local param_hex="${DER_EXPLICIT_HEX}"
        local param_offset=0
        der_read_object_identifier "${param_hex}" "${param_offset}"
        local oid="${DER_OBJECT_IDENTIFIER}"
        param_offset="${DER_NEXT_OFFSET}"
        der_expect_eof "${param_hex}" "${param_offset}"
        [[ "${oid}" == "${SECP256K1_OID}" ]] || die "EC key is not secp256k1"
        params_seen=1
        offset="${explicit_next}"
        ;;
      a1)
        der_read_explicit "${seq_hex}" "${offset}" "a1"
        local explicit_pub_next="${DER_NEXT_OFFSET}"
        local pub_hex="${DER_EXPLICIT_HEX}"
        local pub_offset=0
        der_read_bit_string "${pub_hex}" "${pub_offset}"
        local bit_hex="${DER_BITSTRING_HEX,,}"
        pub_offset="${DER_NEXT_OFFSET}"
        der_expect_eof "${pub_hex}" "${pub_offset}"
        [[ ${#bit_hex} -ge 130 && ${bit_hex:0:2} == "04" ]] || die "Unsupported EC public key format"
        pub_x="${bit_hex:2:64}"
        pub_y="${bit_hex:66:64}"
        offset="${explicit_pub_next}"
        ;;
      *)
        die "Unexpected field in EC private key"
        ;;
    esac
  done
  local derived_x derived_y
  read -r derived_x derived_y < <(secp_point_mul "${priv_hex}" "${SECP256K1_GX_HEX}" "${SECP256K1_GY_HEX}")
  [[ -n "${derived_x}" && "${derived_x}" != "INF" ]] || die "Failed to derive EC public key"
  derived_x="$(printf '%064s' "${derived_x}" | tr ' ' '0')"
  derived_y="$(printf '%064s' "${derived_y}" | tr ' ' '0')"
  if [[ -n "${pub_x}" ]]; then
    pub_x="$(printf '%064s' "${pub_x}" | tr ' ' '0')"
    pub_y="$(printf '%064s' "${pub_y}" | tr ' ' '0')"
    if [[ "${pub_x,,}" != "${derived_x,,}" || "${pub_y,,}" != "${derived_y,,}" ]]; then
      die "EC private key public point mismatch"
    fi
  else
    pub_x="${derived_x}"
    pub_y="${derived_y}"
  fi
  if [[ ${params_seen} -eq 0 ]]; then
    :
  fi
  ECDSA_PRIV_SCALAR_HEX="${priv_hex,,}"
  ECDSA_PRIV_PUB_X_HEX="${pub_x,,}"
  ECDSA_PRIV_PUB_Y_HEX="${pub_y,,}"
}

parse_ecdsa_public_spki() {
  local hex="$1"
  der_read_sequence "${hex}" 0
  local seq_hex="${DER_SEQUENCE_HEX}"
  local offset=0
  der_read_sequence "${seq_hex}" "${offset}"
  local alg_hex="${DER_SEQUENCE_HEX}"
  offset="${DER_NEXT_OFFSET}"
  local alg_offset=0
  der_read_object_identifier "${alg_hex}" "${alg_offset}"
  local alg_oid="${DER_OBJECT_IDENTIFIER}"
  [[ "${alg_oid}" == "${EC_PUBLIC_OID}" ]] || die "Public key is not EC"
  alg_offset="${DER_NEXT_OFFSET}"
  der_read_object_identifier "${alg_hex}" "${alg_offset}"
  local curve_oid="${DER_OBJECT_IDENTIFIER}"
  alg_offset="${DER_NEXT_OFFSET}"
  der_expect_eof "${alg_hex}" "${alg_offset}"
  [[ "${curve_oid}" == "${SECP256K1_OID}" ]] || die "EC key is not secp256k1"
  der_read_bit_string "${seq_hex}" "${offset}"
  local bit_hex="${DER_BITSTRING_HEX,,}"
  offset="${DER_NEXT_OFFSET}"
  der_expect_eof "${seq_hex}" "${offset}"
  [[ ${#bit_hex} -ge 130 && ${bit_hex:0:2} == "04" ]] || die "Unsupported EC public key format"
  local pub_x="${bit_hex:2:64}"
  local pub_y="${bit_hex:66:64}"
  ECDSA_PUB_X_HEX="$(printf '%064s' "${pub_x}" | tr ' ' '0' | tr 'A-Z' 'a-z')"
  ECDSA_PUB_Y_HEX="$(printf '%064s' "${pub_y}" | tr ' ' '0' | tr 'A-Z' 'a-z')"
}

load_ecdsa_private_key() {
  local path="$1"
  local der_hex
  if ! der_hex="$(pem_block_to_hex "${path}" "EC PRIVATE KEY" 2>/dev/null)"; then
    die "Failed to load EC private key from ${path}"
  fi
  parse_ecdsa_private_der "${der_hex}"
}

load_ecdsa_public_key() {
  local path="$1"
  local der_hex
  if ! der_hex="$(pem_block_to_hex "${path}" "PUBLIC KEY" 2>/dev/null)"; then
    die "Failed to load EC public key from ${path}"
  fi
  parse_ecdsa_public_spki "${der_hex}"
}

parse_ecdsa_signature_der() {
  local hex="$1"
  der_read_sequence "${hex}" 0
  local seq_hex="${DER_SEQUENCE_HEX}"
  local offset=0
  der_read_integer "${seq_hex}" "${offset}"
  local r_hex="${DER_INTEGER_HEX,,}"
  offset="${DER_NEXT_OFFSET}"
  der_read_integer "${seq_hex}" "${offset}"
  local s_hex="${DER_INTEGER_HEX,,}"
  offset="${DER_NEXT_OFFSET}"
  der_expect_eof "${seq_hex}" "${offset}"
  ECDSA_SIG_R_HEX="$(printf '%064s' "${r_hex}" | tr ' ' '0' | tr 'A-Z' 'a-z')"
  ECDSA_SIG_S_HEX="$(printf '%064s' "${s_hex}" | tr ' ' '0' | tr 'A-Z' 'a-z')"
}

generate_secp_private_hex() {
  while true; do
    local candidate_hex
    candidate_hex="$(random_hex_bytes 32)"
    candidate_hex="${candidate_hex,,}"
    candidate_hex="$(printf '%064s' "${candidate_hex}" | tr ' ' '0')"
    local candidate_dec
    candidate_dec="$(hex_to_dec "${candidate_hex}")"
    if [[ "${candidate_dec}" == "0" ]]; then
      continue
    fi
    if [[ $(bc_simple "${candidate_dec} >= ${SECP256K1_N_DEC}") -eq 1 ]]; then
      continue
    fi
    printf '%s\n' "${candidate_hex}"
    return 0
  done
}

cmd_ecdsa_generate() {
  local private_out=""
  local public_out=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --private-out)
        [[ $# -lt 2 ]] && { usage_ecdsa_generate >&2; return 1; }
        private_out="$2"
        shift 2
        ;;
      --public-out)
        [[ $# -lt 2 ]] && { usage_ecdsa_generate >&2; return 1; }
        public_out="$2"
        shift 2
        ;;
      --help)
        usage_ecdsa_generate
        return 0
        ;;
      *)
        echo "Unknown option for ecdsa-generate: $1" >&2
        usage_ecdsa_generate >&2
        return 1
        ;;
    esac
  done

  if [[ -z "${private_out}" || -z "${public_out}" ]]; then
    usage_ecdsa_generate >&2
    return 1
  fi

  if [[ -e "${private_out}" || -e "${public_out}" ]]; then
    echo "Refusing to overwrite existing files" >&2
    return 1
  fi

  local priv_hex
  priv_hex="$(generate_secp_private_hex)"
  local pub_x pub_y
  read -r pub_x pub_y < <(secp_point_mul "${priv_hex}" "${SECP256K1_GX_HEX}" "${SECP256K1_GY_HEX}")
  [[ -n "${pub_x}" && "${pub_x}" != "INF" ]] || die "Failed to derive secp256k1 public key"
  pub_x="$(printf '%064s' "${pub_x}" | tr ' ' '0' | tr 'A-Z' 'a-z')"
  pub_y="$(printf '%064s' "${pub_y}" | tr ' ' '0' | tr 'A-Z' 'a-z')"

  local der_priv der_pub
  der_priv="$(ec_private_to_der_hex "${priv_hex}" "${pub_x}" "${pub_y}")"
  der_pub="$(ec_public_to_spki_hex "${pub_x}" "${pub_y}")"

  local priv_pem pub_pem
  priv_pem="$(pem_wrap_hex "EC PRIVATE KEY" "${der_priv}")"
  pub_pem="$(pem_wrap_hex "PUBLIC KEY" "${der_pub}")"

  ( umask 077; printf '%s\n' "${priv_pem}" > "${private_out}" )
  chmod 600 "${private_out}"
  ( umask 022; printf '%s\n' "${pub_pem}" > "${public_out}" )
  chmod 644 "${public_out}"
}

cmd_ecdsa_public() {
  local key_path=""
  local output_path=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --key)
        [[ $# -lt 2 ]] && { usage_ecdsa_public >&2; return 1; }
        key_path="$2"
        shift 2
        ;;
      --output)
        [[ $# -lt 2 ]] && { usage_ecdsa_public >&2; return 1; }
        output_path="$2"
        shift 2
        ;;
      --help)
        usage_ecdsa_public
        return 0
        ;;
      *)
        echo "Unknown option for ecdsa-public: $1" >&2
        usage_ecdsa_public >&2
        return 1
        ;;
    esac
  done

  if [[ -z "${key_path}" || -z "${output_path}" ]]; then
    usage_ecdsa_public >&2
    return 1
  fi

  load_ecdsa_private_key "${key_path}"
  local der_pub
  der_pub="$(ec_public_to_spki_hex "${ECDSA_PRIV_PUB_X_HEX}" "${ECDSA_PRIV_PUB_Y_HEX}")"
  local pem
  pem="$(pem_wrap_hex "PUBLIC KEY" "${der_pub}")"

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

cmd_ecdsa_sign() {
  local key_path=""
  local message_path=""
  local hash_name="sha256"
  local output_format="raw"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --key)
        [[ $# -lt 2 ]] && { usage_ecdsa_sign >&2; return 1; }
        key_path="$2"
        shift 2
        ;;
      --message)
        [[ $# -lt 2 ]] && { usage_ecdsa_sign >&2; return 1; }
        message_path="$2"
        shift 2
        ;;
      --hash)
        [[ $# -lt 2 ]] && { usage_ecdsa_sign >&2; return 1; }
        hash_name="$2"
        shift 2
        ;;
      --output)
        [[ $# -lt 2 ]] && { usage_ecdsa_sign >&2; return 1; }
        output_format="$2"
        shift 2
        ;;
      --help)
        usage_ecdsa_sign
        return 0
        ;;
      *)
        echo "Unknown option for ecdsa-sign: $1" >&2
        usage_ecdsa_sign >&2
        return 1
        ;;
    esac
  done

  if [[ -z "${key_path}" || -z "${message_path}" ]]; then
    usage_ecdsa_sign >&2
    return 1
  fi

  ensure_bc_common_session

  load_ecdsa_private_key "${key_path}"

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

  local k_hex
  k_hex="$(rfc6979_generate_k "${ECDSA_PRIV_SCALAR_HEX}" "${digest_hex}")"
  local r_point_x
  read -r r_point_x _ < <(secp_point_mul "${k_hex}" "${SECP256K1_GX_HEX}" "${SECP256K1_GY_HEX}")
  [[ "${r_point_x}" != "INF" && -n "${r_point_x}" ]] || die "Failed to compute ECDSA R"
  local r_point_dec
  r_point_dec="$(hex_to_dec "${r_point_x}")"
  local r_dec
  r_dec="$(bc_simple "(${r_point_dec}) % (${SECP256K1_N_DEC})")"
  if [[ "${r_dec}" == "0" ]]; then
    die "ECDSA r is zero"
  fi
  local k_dec
  k_dec="$(hex_to_dec "${k_hex}")"
  local k_inv_dec
  k_inv_dec="$(bc_eval_common "modinv(${k_dec}, ${SECP256K1_N_DEC})")"
  if [[ -z "${k_inv_dec}" || "${k_inv_dec}" == "0" ]]; then
    die "Failed to compute modular inverse for k"
  fi
  local z_hex
  z_hex="$(secp_bits2octets "${digest_hex}")"
  local z_dec
  z_dec="$(hex_to_dec "${z_hex}")"
  local priv_dec
  priv_dec="$(hex_to_dec "${ECDSA_PRIV_SCALAR_HEX}")"
  local r_mod_priv
  r_mod_priv="$(bc_simple "(${r_dec} * ${priv_dec}) % ${SECP256K1_N_DEC}")"
  local sum_dec
  sum_dec="$(bc_simple "(${z_dec} + ${r_mod_priv}) % ${SECP256K1_N_DEC}")"
  local s_dec
  s_dec="$(bc_simple "(${k_inv_dec} * ${sum_dec}) % ${SECP256K1_N_DEC}")"
  if [[ "${s_dec}" == "0" ]]; then
    die "ECDSA s is zero"
  fi
  if [[ $(bc_simple "${s_dec} > ${SECP256K1_HALF_N_DEC}") -eq 1 ]]; then
    s_dec="$(bc_simple "${SECP256K1_N_DEC} - ${s_dec}")"
  fi
  local r_hex
  r_hex="$(dec_to_hex "${r_dec}")"
  local s_hex
  s_hex="$(dec_to_hex "${s_dec}")"
  r_hex="$(printf '%064s' "${r_hex,,}" | tr ' ' '0')"
  s_hex="$(printf '%064s' "${s_hex,,}" | tr ' ' '0')"
  local sig_hex
  sig_hex="$(der_encode_sequence_hex "$(der_encode_integer_hex "${r_hex}")" "$(der_encode_integer_hex "${s_hex}")")"

  case "${output_format}" in
    raw)
      hex_to_raw "${sig_hex}"
      ;;
    hex)
      printf '%s\n' "${sig_hex}"
      ;;
    base64)
      hex_to_raw "${sig_hex}" | base64 | tr -d '\n'
      printf '\n'
      ;;
    *)
      echo "Invalid output format: ${output_format}" >&2
      return 1
      ;;
  esac
}

cmd_ecdsa_verify() {
  local key_path=""
  local message_path=""
  local signature_path=""
  local hash_name="sha256"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --key)
        [[ $# -lt 2 ]] && { usage_ecdsa_verify >&2; return 1; }
        key_path="$2"
        shift 2
        ;;
      --message)
        [[ $# -lt 2 ]] && { usage_ecdsa_verify >&2; return 1; }
        message_path="$2"
        shift 2
        ;;
      --signature)
        [[ $# -lt 2 ]] && { usage_ecdsa_verify >&2; return 1; }
        signature_path="$2"
        shift 2
        ;;
      --hash)
        [[ $# -lt 2 ]] && { usage_ecdsa_verify >&2; return 1; }
        hash_name="$2"
        shift 2
        ;;
      --help)
        usage_ecdsa_verify
        return 0
        ;;
      *)
        echo "Unknown option for ecdsa-verify: $1" >&2
        usage_ecdsa_verify >&2
        return 1
        ;;
    esac
  done

  if [[ -z "${key_path}" || -z "${message_path}" || -z "${signature_path}" ]]; then
    usage_ecdsa_verify >&2
    return 1
  fi

  load_ecdsa_public_key "${key_path}"

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

  local signature_hex
  signature_hex="$(read_hex "${signature_path}")"
  if [[ -z "${signature_hex}" ]]; then
    echo "verification failed" >&2
    return 1
  fi
  parse_ecdsa_signature_der "${signature_hex}"
  local r_dec
  r_dec="$(hex_to_dec "${ECDSA_SIG_R_HEX}")"
  local s_dec
  s_dec="$(hex_to_dec "${ECDSA_SIG_S_HEX}")"
  if [[ $(bc_simple "(${r_dec} <= 0) || (${r_dec} >= ${SECP256K1_N_DEC})") -eq 1 ]]; then
    echo "verification failed" >&2
    return 1
  fi
  if [[ $(bc_simple "(${s_dec} <= 0) || (${s_dec} >= ${SECP256K1_N_DEC})") -eq 1 ]]; then
    echo "verification failed" >&2
    return 1
  fi
  local z_hex
  z_hex="$(secp_bits2octets "${digest_hex}")"
  local z_dec
  z_dec="$(hex_to_dec "${z_hex}")"
  local s_inv_dec
  s_inv_dec="$(bc_eval_common "modinv(${s_dec}, ${SECP256K1_N_DEC})")"
  if [[ -z "${s_inv_dec}" || "${s_inv_dec}" == "0" ]]; then
    echo "verification failed" >&2
    return 1
  fi
  local u1_dec
  u1_dec="$(bc_simple "(${z_dec} * ${s_inv_dec}) % ${SECP256K1_N_DEC}")"
  local u2_dec
  u2_dec="$(bc_simple "(${r_dec} * ${s_inv_dec}) % ${SECP256K1_N_DEC}")"
  local u1_hex
  u1_hex="$(dec_to_hex "${u1_dec}")"
  local u2_hex
  u2_hex="$(dec_to_hex "${u2_dec}")"
  u1_hex="$(printf '%064s' "${u1_hex,,}" | tr ' ' '0')"
  u2_hex="$(printf '%064s' "${u2_hex,,}" | tr ' ' '0')"
  local X1_x X1_y
  read -r X1_x X1_y < <(secp_point_mul "${u1_hex}" "${SECP256K1_GX_HEX}" "${SECP256K1_GY_HEX}")
  local X2_x X2_y
  read -r X2_x X2_y < <(secp_point_mul "${u2_hex}" "${ECDSA_PUB_X_HEX}" "${ECDSA_PUB_Y_HEX}")
  if [[ "${X1_x}" == "INF" || "${X2_x}" == "INF" ]]; then
    echo "verification failed" >&2
    return 1
  fi
  read -r X3_x X3_y < <(secp_point_add "${X1_x}" "${X1_y}" "${X2_x}" "${X2_y}")
  if [[ "${X3_x}" == "0" && "${X3_y}" == "0" ]]; then
    echo "verification failed" >&2
    return 1
  fi
  local v_dec
  v_dec="$(bc_simple "$(hex_to_dec "${X3_x}") % ${SECP256K1_N_DEC}")"
  if [[ "${v_dec}" == "${r_dec}" ]]; then
    return 0
  fi
  echo "verification failed" >&2
  return 1
}
