# shellcheck shell=bash
# Ed25519 scalar and point utilities implemented via bc

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  echo "scripts/lib/crypto/ed25519.sh must be sourced" >&2
  exit 1
fi

readonly ED25519_P="7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED"
readonly ED25519_D="52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3"
readonly ED25519_BASE_X="216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A"
readonly ED25519_BASE_Y="6666666666666666666666666666666666666666666666666666666666666658"

ed25519__require_bc() {
  if ! command -v bc >/dev/null 2>&1; then
    echo "bc is required for Ed25519 operations" >&2
    return 1
  fi
}

ed25519_hex_le_to_be() {
  local hex="${1,,}"
  local out=""
  local i
  for (( i=${#hex}; i>0; i-=2 )); do
    out+="${hex:i-2:2}"
  done
  printf '%s' "${out}"
}

ed25519_hex_be_to_le() {
  local hex="${1,,}"
  local out=""
  local i
  for (( i=${#hex}; i>0; i-=2 )); do
    out+="${hex:i-2:2}"
  done
  printf '%s' "${out}"
}

ed25519_decimal_to_hex() {
  local decimal="$1"
  bc <<<"obase=16; ${decimal}" | tr -d ' \n' | tr 'A-F' 'a-f'
}

ed25519_clamp_scalar_le_hex() {
  local scalar_hex="${1,,}"
  if [[ ${#scalar_hex} -ne 64 ]] || [[ ! ${scalar_hex} =~ ^[0-9a-f]{64}$ ]]; then
    echo "scalar must be 32-byte hex" >&2
    return 1
  fi
  local -a bytes=()
  local i
  for (( i=0; i<64; i+=2 )); do
    bytes+=("${scalar_hex:i:2}")
  done
  local b0=$((16#${bytes[0]}))
  local b31=$((16#${bytes[31]}))
  b0=$((b0 & 248))
  b31=$(((b31 & 63) | 64))
  printf -v bytes[0] '%02x' "${b0}"
  printf -v bytes[31] '%02x' "${b31}"
  printf '%s' "${bytes[*]}" | tr -d ' '
}

ed25519_scalar_to_point_dec() {
  ed25519__require_bc || return 1
  local scalar_le_hex="${1,,}"
  if [[ ${#scalar_le_hex} -ne 64 ]] || [[ ! ${scalar_le_hex} =~ ^[0-9a-f]{64}$ ]]; then
    echo "scalar must be 32-byte hex" >&2
    return 1
  fi
  local scalar_be_hex
  scalar_be_hex="$(ed25519_hex_le_to_be "${scalar_le_hex}")"
  local bc_output
  if ! bc_output="$(bc <<BC
scale=0
ibase=16
P=${ED25519_P}
D=${ED25519_D}
D2=(2*D)%P
BX=${ED25519_BASE_X}
BY=${ED25519_BASE_Y}
K=${scalar_be_hex}
ibase=10

define modp(x) {
  auto r;
  r = x % P;
  if (r < 0) r += P;
  return r;
}

define madd(a, b) {
  return modp(a + b);
}

define msub(a, b) {
  auto r;
  r = a - b;
  r = r % P;
  if (r < 0) r += P;
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
  r0 = P;
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
  while (t0 < 0) t0 += P;
  return t0 % P;
}

define point_double(ax, ay, az, at) {
  auto A, B, C, Dm, S, E, G, F, H;
  A = msqr(ax);
  B = msqr(ay);
  S = madd(ax, ay);
  S = msqr(S);
  C = mmul(2, msqr(az));
  Dm = modp(-A);
  E = msub(S, madd(A, B));
  G = madd(Dm, B);
  F = msub(G, C);
  H = msub(Dm, B);
  tmp[0] = mmul(E, F);
  tmp[1] = mmul(G, H);
  tmp[2] = mmul(F, G);
  tmp[3] = mmul(E, H);
  return 0;
}

define point_add(ax, ay, az, at, bx, by, bz, bt) {
  auto A, B, C, Dm, E, F, G, H;
  A = mmul(msub(ay, ax), msub(by, bx));
  B = mmul(madd(ay, ax), madd(by, bx));
  C = mmul(D2, mmul(at, bt));
  Dm = mmul(2, mmul(az, bz));
  E = msub(B, A);
  F = msub(Dm, C);
  G = madd(Dm, C);
  H = madd(B, A);
  tmp[0] = mmul(E, F);
  tmp[1] = mmul(G, H);
  tmp[2] = mmul(F, G);
  tmp[3] = mmul(E, H);
  return 0;
}

resX = 0;
resY = 1;
resZ = 1;
resT = 0;
qX = BX;
qY = BY;
qZ = 1;
qT = modp(BX * BY);

while (K > 0) {
  if (K % 2 == 1) {
    point_add(resX, resY, resZ, resT, qX, qY, qZ, qT);
    resX = tmp[0];
    resY = tmp[1];
    resZ = tmp[2];
    resT = tmp[3];
  }
  point_double(qX, qY, qZ, qT);
  qX = tmp[0];
  qY = tmp[1];
  qZ = tmp[2];
  qT = tmp[3];
  K = K / 2;
}

invZ = minv(resZ);
xaff = mmul(resX, invZ);
yaff = mmul(resY, invZ);
xaff;
yaff;
xaff % 2;
BC
)"; then
    echo "bc evaluation failed" >&2
    return 1
  fi
  bc_output="${bc_output//$'\r'/}"
  mapfile -t coords <<<"${bc_output}"
  if (( ${#coords[@]} < 3 )); then
    echo "unexpected scalar multiplication output" >&2
    return 1
  fi
  printf '%s %s %s\n' "${coords[0]}" "${coords[1]}" "${coords[2]}"
}

ed25519_point_compress() {
  local x_dec="$1" y_dec="$2" parity="$3"
  local y_hex
  y_hex="$(ed25519_decimal_to_hex "${y_dec}")"
  y_hex="$(printf '%064s' "${y_hex}" | tr ' ' '0')"
  local y_le
  y_le="$(ed25519_hex_be_to_le "${y_hex}")"
  if [[ ${#y_le} -ne 64 ]]; then
    y_le="$(printf '%064s' "${y_le}" | tr ' ' '0')"
  fi
  local last_byte="${y_le:62:2}"
  local lb_val=$((16#${last_byte}))
  local parity_bit=$((parity % 2))
  if (( parity_bit == 1 )); then
    lb_val=$((lb_val | 0x80))
  else
    lb_val=$((lb_val & 0x7f))
  fi
  printf -v last_byte '%02x' "${lb_val}"
  printf '%s%s' "${y_le:0:62}" "${last_byte}"
}

ed25519_public_from_scalar_hex() {
  local scalar_le_hex="${1,,}"
  read -r x_dec y_dec parity < <(ed25519_scalar_to_point_dec "${scalar_le_hex}") || return 1
  ed25519_point_compress "${x_dec}" "${y_dec}" "${parity}"
}

ed25519_expand_secret_from_seed() {
  if ! declare -F sha512_hex_from_stream >/dev/null 2>&1; then
    echo "sha512_hex_from_stream unavailable" >&2
    return 1
  fi
  local seed_hex="${1,,}"
  if [[ ${#seed_hex} -ne 64 ]] || [[ ! ${seed_hex} =~ ^[0-9a-f]{64}$ ]]; then
    echo "seed must be 32-byte hex" >&2
    return 1
  fi
  local digest
  digest="$(printf '%s' "${seed_hex}" | xxd -r -p | sha512_hex_from_stream | tr -d '\n')"
  local lower="${digest:0:64}"
  local upper="${digest:64:64}"
  local scalar
  scalar="$(ed25519_clamp_scalar_le_hex "${lower}")" || return 1
  printf '%s %s\n' "${scalar}" "${upper}"
}

ed25519_public_key_from_seed_hex() {
  local seed_hex="${1,,}"
  if [[ ${#seed_hex} -ne 64 ]] || [[ ! ${seed_hex} =~ ^[0-9a-f]{64}$ ]]; then
    echo "seed must be 32-byte hex" >&2
    return 1
  fi
  command -v node >/dev/null 2>&1 || { echo "node is required for Ed25519 public derivation" >&2; return 1; }
  SEED_HEX="${seed_hex}" node <<'NODE'
const crypto = require('crypto');
const seedHex = (process.env.SEED_HEX || '').trim();
const seed = Buffer.from(seedHex, 'hex');
const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
const priv = crypto.createPrivateKey({ key: Buffer.concat([prefix, seed]), format: 'der', type: 'pkcs8' });
const spki = crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' });
process.stdout.write(spki.subarray(spki.length - 32).toString('hex'));
NODE
}

ed25519_secret_key64_from_seed() {
  local seed_hex="${1,,}"
  local pub_hex
  pub_hex="$(ed25519_public_key_from_seed_hex "${seed_hex}")" || return 1
  printf '%s%s\n' "${seed_hex}" "${pub_hex}"
}

ed25519_derive_keypair_hex() {
  local seed_hex="${1,,}"
  local scalar _prefix pub_hex
  read -r scalar _prefix < <(ed25519_expand_secret_from_seed "${seed_hex}") || return 1
  pub_hex="$(ed25519_public_key_from_seed_hex "${seed_hex}")" || return 1
  printf '%s %s\n' "${scalar}" "${pub_hex}"
}

export -f ed25519_clamp_scalar_le_hex
export -f ed25519_scalar_to_point_dec
export -f ed25519_point_compress
export -f ed25519_public_from_scalar_hex
export -f ed25519_expand_secret_from_seed
export -f ed25519_public_key_from_seed_hex
export -f ed25519_secret_key64_from_seed
export -f ed25519_derive_keypair_hex
