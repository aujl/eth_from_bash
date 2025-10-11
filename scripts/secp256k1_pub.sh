#!/usr/bin/env bash
set -euo pipefail

CURVE_ORDER="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
FIELD_PRIME="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
GEN_X="79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
GEN_Y="483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"

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

require_tools() {
  for tool in bc; do
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
  printf '%s\n' "${upper,,}"
}

decimal_to_hex() {
  local decimal="$1"
  bc <<<"obase=16;${decimal}" | tr -d ' \n'
}

scalar_to_point() {
  local scalar_hex="${1^^}"
  local bc_output
  if ! bc_output="$(bc <<BC
scale=0
ibase=16
p=${FIELD_PRIME}
g[0]=${GEN_X}
g[1]=${GEN_Y}
k=${scalar_hex}
ibase=10

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

r[0] = 0;
r[1] = 0;
r[2] = 1;
q[0] = g[0];
q[1] = g[1];
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
  print "INF\n";
} else {
  r[0];
  r[1];
}
BC
)"; then
    err "Scalar multiplication failed"
    return 1
  fi

  bc_output="${bc_output//\\$'\n'/}"
  mapfile -t coords <<<"${bc_output}"
  if (( ${#coords[@]} != 2 )); then
    err "Scalar multiplication produced invalid output"
    return 1
  fi

  local x_dec="${coords[0]}"
  local y_dec="${coords[1]}"
  local x_hex="$(decimal_to_hex "${x_dec}")"
  local y_hex="$(decimal_to_hex "${y_dec}")"

  printf '%s %s\n' "${x_hex}" "${y_hex}"
}

derive_pubkeys() {
  local priv_input="$1"
  require_tools
  local priv_hex=""
  if ! priv_hex="$(validate_scalar "${priv_input}")"; then
    return 1
  fi

  local point_output=""
  if ! point_output="$(scalar_to_point "${priv_hex}")"; then
    err "Failed to derive public key"
    return 1
  fi

  local x_hex y_hex
  read -r x_hex y_hex <<<"${point_output}"
  x_hex="${x_hex^^}"
  y_hex="${y_hex^^}"

  x_hex="$(printf '%064s' "${x_hex}" | tr ' ' '0')"
  y_hex="$(printf '%064s' "${y_hex}" | tr ' ' '0')"

  local last_char="${y_hex: -1}"
  local parity=$((16#${last_char}))
  local prefix
  if (( parity % 2 == 0 )); then
    prefix="02"
  else
    prefix="03"
  fi

  local comp="${prefix}${x_hex,,}"
  local uncomp="04${x_hex,,}${y_hex,,}"
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
