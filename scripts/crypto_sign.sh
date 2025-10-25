#!/usr/bin/env bash
set -euo pipefail
set -o noclobber

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/lib"
# shellcheck source=scripts/lib/sha2.sh
source "${LIB_DIR}/sha2.sh"

declare -gA HEX_TO_DEC_CACHE=()
declare -gA DEC_TO_HEX_CACHE=()

declare -ga CRYPTO_SIGN_CLEANUP_FUNCS=()

CRYPTO_SIGN_MAIN_PID=$$

crypto_sign_register_cleanup() {
  local fn="$1"
  local existing
  for existing in "${CRYPTO_SIGN_CLEANUP_FUNCS[@]}"; do
    if [[ "${existing}" == "${fn}" ]]; then
      return 0
    fi
  done
  CRYPTO_SIGN_CLEANUP_FUNCS+=("${fn}")
}

die() {
  echo "crypto_sign.sh: $*" >&2
  exit 1
}

CRYPTO_SIGN_TRACE_ENABLED=0
CRYPTO_SIGN_TRACE_FILE=""
CRYPTO_SIGN_TRACE_FILE_OWNED=0
if [[ "${CRYPTO_SIGN_TRACE_CHURN:-0}" == "1" ]]; then
  CRYPTO_SIGN_TRACE_ENABLED=1
  if [[ -n "${CRYPTO_SIGN_TRACE_FILE_PATH:-}" ]]; then
    CRYPTO_SIGN_TRACE_FILE="${CRYPTO_SIGN_TRACE_FILE_PATH}"
    : >"${CRYPTO_SIGN_TRACE_FILE}"
    CRYPTO_SIGN_TRACE_FILE_OWNED=0
  else
    if ! CRYPTO_SIGN_TRACE_FILE="$(mktemp -t crypto_sign_trace.XXXXXX)"; then
      die "Failed to create trace scratch file"
    fi
    CRYPTO_SIGN_TRACE_FILE_OWNED=1
  fi
  crypto_sign_trace_increment() {
    local key="$1"
    printf '%s\n' "${key}" >>"${CRYPTO_SIGN_TRACE_FILE}"
  }
  crypto_sign_trace_dump() {
    local bc_simple_count=0
    local bc_eval_count=0
    local generate_count=0
    if [[ -f "${CRYPTO_SIGN_TRACE_FILE}" ]]; then
      bc_simple_count=$(grep -c '^bc_simple$' "${CRYPTO_SIGN_TRACE_FILE}" 2>/dev/null || true)
      bc_eval_count=$(grep -c '^bc_eval_common$' "${CRYPTO_SIGN_TRACE_FILE}" 2>/dev/null || true)
      generate_count=$(grep -c '^generate_prime_dec$' "${CRYPTO_SIGN_TRACE_FILE}" 2>/dev/null || true)
      if (( CRYPTO_SIGN_TRACE_FILE_OWNED )); then
        rm -f "${CRYPTO_SIGN_TRACE_FILE}"
      fi
    fi
    printf 'trace:bc_simple=%s\n' "${bc_simple_count}" >&2
    printf 'trace:bc_eval_common=%s\n' "${bc_eval_count}" >&2
    printf 'trace:generate_prime_dec=%s\n' "${generate_count}" >&2
  }
else
  crypto_sign_trace_increment() {
    return 0
  }
  crypto_sign_trace_dump() {
    return 0
  }
fi

cleanup_bc_common_session() {
  local pid="${BC_COMMON_PID:-}"
  if [[ -n "${pid}" ]]; then
    local bc_read_fd="${BC_COMMON[0]:-}"
    local bc_write_fd="${BC_COMMON[1]:-}"
    if [[ -n "${bc_write_fd}" ]]; then
      eval "exec ${bc_write_fd}>&-" 2>/dev/null || true
    fi
    if [[ -n "${bc_read_fd}" ]]; then
      eval "exec ${bc_read_fd}<&-" 2>/dev/null || true
    fi
    wait "${pid}" 2>/dev/null || true
    BC_COMMON_PID=""
  fi
}

crypto_sign_register_cleanup cleanup_bc_common_session

crypto_sign_global_cleanup() {
  if [[ $$ -ne ${CRYPTO_SIGN_MAIN_PID} ]]; then
    return 0
  fi
  local fn
  for fn in "${CRYPTO_SIGN_CLEANUP_FUNCS[@]}"; do
    if [[ -n "${fn}" ]]; then
      "${fn}" 2>/dev/null || true
    fi
  done
  if (( CRYPTO_SIGN_TRACE_ENABLED )); then
    crypto_sign_trace_dump
  fi
}

trap crypto_sign_global_cleanup EXIT

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
  ecdsa-sign     Sign message with secp256k1 ECDSA
  ecdsa-verify   Verify secp256k1 ECDSA signature
  ecdsa-generate Generate secp256k1 keypair (EC private + SPKI public)
  ecdsa-public   Derive secp256k1 public key from private key
  ed25519-public Derive Ed25519 public key from 32-byte seed
  ed25519-keypair Produce Ed25519 public key and 64-byte secret key

Run "crypto_sign.sh <command> --help" for command-specific flags.
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
  if [[ -n "${HEX_TO_DEC_CACHE[$hex]:-}" ]]; then
    printf '%s\n' "${HEX_TO_DEC_CACHE[$hex]}"
    return 0
  fi
  local result
  result="$(bc_simple "ibase=16; ${hex^^}")"
  HEX_TO_DEC_CACHE["${hex}"]="${result}"
  printf '%s\n' "${result}"
}

dec_to_hex() {
  local dec="$1"
  dec="$(bc_clean_output "${dec}")"
  if [[ -n "${DEC_TO_HEX_CACHE[$dec]:-}" ]]; then
    printf '%s\n' "${DEC_TO_HEX_CACHE[$dec]}"
    return 0
  fi
  local hex
  hex="$(bc_simple "obase=16; ${dec}")"
  if [[ -z "${hex}" ]]; then
    hex="0"
  fi
  hex="${hex,,}"
  DEC_TO_HEX_CACHE["${dec}"]="${hex}"
  printf '%s\n' "${hex}"
}

hex_mod_small_prime() {
  local hex="$1"
  local prime="$2"
  local mod=0
  local i digit value
  hex="${hex,,}"
  for (( i = 0; i < ${#hex}; i++ )); do
    digit="${hex:i:1}"
    case "${digit}" in
      [0-9]) value=$(( digit )) ;;
      a) value=10 ;;
      b) value=11 ;;
      c) value=12 ;;
      d) value=13 ;;
      e) value=14 ;;
      f) value=15 ;;
      *) value=0 ;;
    esac
    mod=$(( ((mod << 4) + value) % prime ))
  done
  printf '%d\n' "${mod}"
}

modexp_bc() {
  local base="$1"
  local exponent="$2"
  local modulus="$3"
  local result
  result="$(bc <<BC
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
)"
  result="$(bc_clean_output "${result}")"
  printf '%s\n' "${result}"
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

read -r -d '' BC_PRIME_FUNCS <<'BC_PRIME_FUNCS' || true
define prime_mr_trial(n, rand){
  if(n<=3){
    if(n==2||n==3) return 1;
    return 0;
  }
  if(n%2==0) return 0;
  if(rand<=1 || rand>=n-1) rand=(rand%(n-3))+2;
  return miller_rabin(n, rand);
}
BC_PRIME_FUNCS

BC_COMMON_SENTINEL="__BC_COMMON_DONE__"

start_bc_common_session() {
  if [[ -n "${BC_COMMON_PID:-}" ]] && kill -0 "${BC_COMMON_PID}" 2>/dev/null; then
    return 0
  fi
  coproc BC_COMMON { bc; }
  BC_COMMON_PID=$!
  local bc_write_fd="${BC_COMMON[1]}"
  printf 'scale=0\n' >&"${bc_write_fd}"
  printf 'ibase=10\n' >&"${bc_write_fd}"
  printf 'obase=10\n' >&"${bc_write_fd}"
  printf '%s\n' "${BC_COMMON_FUNCS}" >&"${bc_write_fd}"
  printf '%s\n' "${BC_PRIME_FUNCS}" >&"${bc_write_fd}"
}

bc_session_eval_raw() {
  local expr="$1"
  ensure_bc_common_session
  if [[ -z "${BC_COMMON_PID:-}" ]] || ! kill -0 "${BC_COMMON_PID}" 2>/dev/null; then
    bc <<BC
${BC_COMMON_FUNCS}
${BC_PRIME_FUNCS}
scale=0
${expr}
BC
    return 0
  fi
  local bc_write_fd="${BC_COMMON[1]}"
  printf '%s\n' "${expr}" >&"${bc_write_fd}"
  printf 'print "\n"\n' >&"${bc_write_fd}"
  printf 'print "%s"\n' "${BC_COMMON_SENTINEL}" >&"${bc_write_fd}"
  printf 'print "\n"\n' >&"${bc_write_fd}"
  local output=""
  local line
  local bc_read_fd="${BC_COMMON[0]}"
  while IFS= read -r line <&"${bc_read_fd}"; do
    if [[ "${line}" == "${BC_COMMON_SENTINEL}" ]]; then
      break
    fi
    if [[ -z "${line}" ]]; then
      continue
    fi
    if [[ -n "${output}" ]]; then
      output+=$'\n'
    fi
    output+="${line}"
  done
  printf '%s' "${output}"
}

bc_session_eval_isolated() {
  local expr="$1"
  local wrapped
  read -r -d '' wrapped <<EOF || true
g=ibase
h=obase
ibase=10
obase=10
${expr}
ibase=g
obase=h
EOF
  bc_session_eval_raw "${wrapped}"
}

ensure_bc_common_session() {
  if [[ -n "${BC_COMMON_PID:-}" ]] && kill -0 "${BC_COMMON_PID}" 2>/dev/null; then
    return 0
  fi
  if [[ $$ -eq ${CRYPTO_SIGN_MAIN_PID} ]]; then
    start_bc_common_session
  fi
}

bc_clean_output() {
  local raw="$1"
  local cleaned
  cleaned="$(printf '%s' "${raw}" | tr -d '\\[:space:]')"
  printf '%s' "${cleaned}"
}

bc_eval_common() {
  local expr="$1"
  crypto_sign_trace_increment bc_eval_common
  local bc_output
  bc_output="$(bc_session_eval_raw "${expr}")"
  bc_output="$(bc_clean_output "${bc_output}")"
  printf '%s\n' "${bc_output}"
}

bc_simple() {
  local expr="$1"
  crypto_sign_trace_increment bc_simple
  local output
  output="$(bc_session_eval_isolated "${expr}")"
  output="$(bc_clean_output "${output}")"
  printf '%s\n' "${output}"
}

prime_session_mr_trial() {
  local candidate="$1"
  local random_dec="$2"
  local expr
  read -r -d '' expr <<EOF || true
n=${candidate}
rand=${random_dec}
print prime_mr_trial(n, rand)
EOF
  local result
  result="$(bc_eval_common "${expr}")"
  result="$(bc_clean_output "${result}")"
  printf '%s\n' "${result}"
}

source "${LIB_DIR}/asn1.sh"
source "${LIB_DIR}/hmac.sh"
source "${LIB_DIR}/rsa.sh"
source "${LIB_DIR}/ecdsa.sh"
# shellcheck source=scripts/lib/ed25519.sh
source "${LIB_DIR}/ed25519.sh"

cmd_ed25519_public() {
  local seed_hex="" output_format="hex"
  while (($#)); do
    case "$1" in
      --seed-hex)
        shift
        seed_hex="${1-}"
        if [[ -z "${seed_hex}" ]]; then
          echo "--seed-hex requires a value" >&2
          return 1
        fi
        shift
        ;;
      --output)
        shift
        output_format="${1-}"
        if [[ -z "${output_format}" ]]; then
          echo "--output requires a value" >&2
          return 1
        fi
        shift
        ;;
      --help|-h)
        cat <<'USAGE'
Usage: crypto_sign.sh ed25519-public --seed-hex HEX [--output hex|raw]

  --seed-hex   32-byte Ed25519 seed in hex form
  --output     Output format: hex (default) or raw
USAGE
        return 0
        ;;
      *)
        echo "Unknown option '$1'" >&2
        return 1
        ;;
    esac
  done

  if [[ -z "${seed_hex}" ]]; then
    echo "ed25519-public requires --seed-hex" >&2
    return 1
  fi
  if [[ ! ${seed_hex} =~ ^[0-9A-Fa-f]{64}$ ]]; then
    echo "seed must be 32-byte hex" >&2
    return 1
  fi

  local pub_hex
  pub_hex="$(ed25519_public_key_from_seed_hex "${seed_hex}")" || return 1

  case "${output_format}" in
    hex)
      printf '%s\n' "${pub_hex}"
      ;;
    raw)
      hex_to_raw "${pub_hex}"
      ;;
    *)
      echo "Unsupported output format '${output_format}'" >&2
      return 1
      ;;
  esac
}

cmd_ed25519_keypair() {
  local seed_hex=""
  while (($#)); do
    case "$1" in
      --seed-hex)
        shift
        seed_hex="${1-}"
        if [[ -z "${seed_hex}" ]]; then
          echo "--seed-hex requires a value" >&2
          return 1
        fi
        shift
        ;;
      --help|-h)
        cat <<'USAGE'
Usage: crypto_sign.sh ed25519-keypair --seed-hex HEX

  --seed-hex   32-byte Ed25519 seed in hex form
USAGE
        return 0
        ;;
      *)
        echo "Unknown option '$1'" >&2
        return 1
        ;;
    esac
  done

  if [[ -z "${seed_hex}" ]]; then
    echo "ed25519-keypair requires --seed-hex" >&2
    return 1
  fi
  if [[ ! ${seed_hex} =~ ^[0-9A-Fa-f]{64}$ ]]; then
    echo "seed must be 32-byte hex" >&2
    return 1
  fi

  local pub_hex secret_hex64
  pub_hex="$(ed25519_public_key_from_seed_hex "${seed_hex}")" || return 1
  secret_hex64="$(ed25519_secret_key64_from_seed "${seed_hex}")" || return 1
  printf '%s %s %s\n' "${seed_hex,,}" "${pub_hex}" "${secret_hex64}"
}

main() {
  local cmd="${1:-}"
  if [[ -z "${cmd}" ]]; then
    usage
    return 1
  fi
  shift
  case "${cmd}" in
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
    ecdsa-generate)
      cmd_ecdsa_generate "$@"
      ;;
    ecdsa-public)
      cmd_ecdsa_public "$@"
      ;;
    ecdsa-sign)
      cmd_ecdsa_sign "$@"
      ;;
    ecdsa-verify)
      cmd_ecdsa_verify "$@"
      ;;
    ed25519-public)
      cmd_ed25519_public "$@"
      ;;
    ed25519-keypair)
      cmd_ed25519_keypair "$@"
      ;;
    --help|-h|help)
      usage
      ;;
    *)
      usage >&2
      return 1
      ;;
  esac
}

main "$@"
