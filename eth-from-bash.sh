#!/usr/bin/env bash
# eth-from-bash-perl-keccak.sh
# Like before, but uses libdigest-sha3-perl for the final Keccak / SHA3 step
# deps: bash, xxd, bc, awk, sha256sum, openssl, Perl with Digest::SHA3

set -euo pipefail

# options: -q|--quiet to print only JSON
#          --mnemonic "w1 ... w12" to use provided phrase
#          --include-seed to include seed hex in JSON
QUIET=0
INCLUDE_SEED=0
USER_MNEMONIC=""
NO_ADDRESS=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -q|--quiet)
      QUIET=1; shift ;;
    --include-seed)
      INCLUDE_SEED=1; shift ;;
    --mnemonic)
      shift
      USER_MNEMONIC="${1-}"
      if [[ -z "$USER_MNEMONIC" ]]; then echo "--mnemonic requires a value" >&2; exit 2; fi
      shift ;;
    --no-address)
      NO_ADDRESS=1; shift ;;
    --)
      shift; break ;;
    -*)
      echo "Unknown option: $1" >&2; exit 2 ;;
    *)
      break ;;
  esac
done

debug(){ if [[ "$QUIET" -eq 0 ]]; then echo "$@" >&2; fi }

WLIST="${1:?path to english.txt}"
shift || true
# Use remaining args as passphrase (may contain spaces)
PASSPHRASE="${*:-}"

# validate wordlist
[[ -r "$WLIST" ]] || { echo "wordlist missing" >&2; exit 1; }
[[ "$(wc -l < "$WLIST")" -eq 2048 ]] || { echo "wordlist must have 2048 lines" >&2; exit 1; }

# check dependencies
for cmd in xxd bc awk sha256sum openssl perl; do
  command -v "$cmd" >/dev/null || { echo "need $cmd" >&2; exit 1; }
done


# Use provided mnemonic if any; else generate new 128-bit entropy phrase
if [[ -z "$USER_MNEMONIC" ]]; then
  ENT_HEX="$(head -c 16 /dev/random | xxd -p -c 16 | tr -d '\n')"
else
  ENT_HEX=""
fi


if [[ -n "$ENT_HEX" ]]; then
  CS_NIB_HEX="$(printf "%s" "$ENT_HEX" | xxd -r -p | sha256sum | cut -c1)"
  # sanitize CS_NIB_HEX
  CS_NIB_HEX_clean="$(echo "$CS_NIB_HEX" | tr -cd '0-9A-Fa-f')"
  CS_BITS="$(echo "obase=2; ibase=16; ${CS_NIB_HEX_clean^^}" | bc | awk '{printf "%04d\n", $0}')"
fi

if [[ -n "$ENT_HEX" ]]; then
  BIN_ENT="$(
    printf "%s" "$ENT_HEX" | xxd -r -p | \
    xxd -b -g 0 -c 16 | \
    awk '{ for(i=2; i < NF; i++) printf "%s", $i }'
  )"
fi

if [[ -n "$ENT_HEX" ]]; then
  BIN_ALL="${BIN_ENT}${CS_BITS}"
fi

if [[ -n "$ENT_HEX" ]]; then
  debug "checksum bits: $CS_BITS"
  debug "checksum nib_hex: $CS_NIB_HEX"
  debug "binary entropy: $BIN_ENT"
  debug "$BIN_ALL"
fi

mapfile -t WORDS < "$WLIST"
if [[ -z "$USER_MNEMONIC" ]]; then
  mnemonic=()
  for i in {0..11}; do
    idx_bits="${BIN_ALL:$((i*11)):11}"
    if [[ ! "$idx_bits" =~ ^[01]{11}$ ]]; then
      echo "Bad bit chunk: '$idx_bits'" >&2
      exit 1
    fi
    idx=$((2#$idx_bits))
    mnemonic+=( "${WORDS[$idx]}" )
    debug "idx: $idx, word: ${mnemonic[-1]}"
  done
  MNEMONIC="${mnemonic[*]}"
else
  MNEMONIC="$USER_MNEMONIC"
fi

# Derive seed with OpenSSL 3.0's kdf command
# OpenSSL 3 kdf PBKDF2 prints colon-separated hex; strip colons/newlines
SEED_HEX="$(
  openssl kdf -keylen 64 \
    -kdfopt digest:SHA512 \
    -kdfopt pass:"$MNEMONIC" \
    -kdfopt salt:"mnemonic${PASSPHRASE}" \
    -kdfopt iter:2048 PBKDF2 \
  | tr -d ':\n' | tr 'A-F' 'a-f'
)"

debug "Hex Seed: $SEED_HEX"
# master I, IL, IR
I_MASTER="$(printf "%s" "$SEED_HEX" | xxd -r -p | openssl dgst -sha512 -mac HMAC -macopt key:"Bitcoin seed" -binary | xxd -p -c 1000)"
IL="${I_MASTER:0:64}"; IR="${I_MASTER:64:64}"

debug "I_MASTER: $I_MASTER"
debug "IL: $IL"
debug "IR: $IR"
# define bn_add_mod_n, derive_hardened, derive_normal, pub derivation, etc
N_HEX="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"

bn_add_mod_n(){
  local a="$1" b="$2"
  # bc treats lowercase a-f as variables; force uppercase for hex digits
  a="${a^^}"
  b="${b^^}"
  # Important: set obase before ibase in bc. Otherwise obase=16 would be
  # interpreted in the new base (0x16 = 22), yielding spaced, non-hex output.
  local sum="$(bc <<<"obase=16; ibase=16; ( $a + $b ) % $N_HEX")"
  sum="${sum^^}"
  printf "%064s" "$sum" | tr ' ' 0
}

# Return 1 if a >= b (hex), else 0
bn_ge(){
  local a="${1^^}" b="${2^^}"
  bc <<<"obase=10; ibase=16; $a >= $b"
}

bn_is_zero(){
  local a="${1^^}"
  # quick check for 64 zeros
  [[ "$a" =~ ^0+$ ]] && { echo 1; return; }
  echo 0
}

derive_hardened(){
  local kpar="$1" cpar="$2" index="$3"
  local idx="$index"
  while :; do
    local i_hex; printf -v i_hex "%08X" $((idx | 0x80000000))
    local data="00${kpar}${i_hex}"
    local I="$(printf "%s" "$data" | xxd -r -p | openssl dgst -sha512 -mac HMAC -macopt "hexkey:${cpar}" -binary | xxd -p -c 1000)"
    local ILc="${I:0:64}" IRc="${I:64:64}"
    local child_k="$(bn_add_mod_n "$ILc" "$kpar")"
    # Guards: if IL >= n or child_k == 0, increment index and retry
    if [[ "$(bn_ge "$ILc" "$N_HEX")" -eq 1 ]] || [[ "$(bn_is_zero "$child_k")" -eq 1 ]]; then
      debug "hardened idx $idx invalid (IL>=n or child=0), trying $((idx+1))"
      idx=$((idx+1))
      continue
    fi
    printf "%s %s\n" "$child_k" "$IRc"
    break
  done
}

pkcs8_from_priv_hex(){
  local khex="$1"
  local derhex="302E0201010420${khex}A00706052B8104000A"
  printf "%s" "$derhex" | xxd -r -p
}

pub_compressed_from_priv_hex(){
  local khex="$1"
  pkcs8_from_priv_hex "$khex" | \
    openssl ec -inform DER -pubout -conv_form compressed -outform DER 2>/dev/null | \
    tail -c 33 | xxd -p -c 33
}

derive_normal(){
  local kpar="$1" cpar="$2" index="$3"
  local idx="$index"
  while :; do
    local i_hex; printf -v i_hex "%08X" "$idx"
    local Kpar_comp="$(pub_compressed_from_priv_hex "$kpar")"
    local data="${Kpar_comp}${i_hex}"
    local I="$(printf "%s" "$data" | xxd -r -p | openssl dgst -sha512 -mac HMAC -macopt "hexkey:${cpar}" -binary | xxd -p -c 1000)"
    local ILc="${I:0:64}" IRc="${I:64:64}"
    local child_k="$(bn_add_mod_n "$ILc" "$kpar")"
    if [[ "$(bn_ge "$ILc" "$N_HEX")" -eq 1 ]] || [[ "$(bn_is_zero "$child_k")" -eq 1 ]]; then
      debug "normal idx $idx invalid (IL>=n or child=0), trying $((idx+1))"
      idx=$((idx+1))
      continue
    fi
    printf "%s %s\n" "$child_k" "$IRc"
    break
  done
}

# path m/44'/60'/0'/0/0
k="$IL"; c="$IR"

debug "before derivation"
read k c < <(derive_hardened "$k" "$c" 44)
read k c < <(derive_hardened "$k" "$c" 60)
read k c < <(derive_hardened "$k" "$c" 0)

debug "after derive hardened"

read k c < <(derive_normal   "$k" "$c" 0)
read k c < <(derive_normal   "$k" "$c" 0)
debug "after derive normal"

PRIV_HEX="$k"

debug "PK_HEX k : $k "

ADDR_EIP55="0x"
if [[ "$NO_ADDRESS" -eq 0 ]]; then
  PUB_UNCOMP_HEX="$(
    pkcs8_from_priv_hex "$PRIV_HEX" | \
    openssl ec -inform DER -pubout -conv_form uncompressed -outform DER 2>/dev/null | \
    tail -c 65 | xxd -p -c 65
  )"
  PUB_XY_HEX="${PUB_UNCOMP_HEX:2}"
  debug "PUB_XY_HEX: $PUB_XY_HEX"
fi

eth_keccak256_hex(){
  # Primary: Python (pycryptodome) Keccak-256; read from stdin
  if command -v python3 >/dev/null; then
    python3 -c '
import sys
try:
    from Crypto.Hash import keccak
except Exception:
    sys.exit(1)
data = sys.stdin.buffer.read()
k = keccak.new(digest_bits=256)
k.update(data)
sys.stdout.write(k.hexdigest())
' || true
    if [[ $? -eq 0 ]]; then return; fi
  fi
  # Secondary: Perl Digest::Keccak if available
  if perl -MDigest::Keccak=keccak_256_hex -e '1' 2>/dev/null; then
    perl -MDigest::Keccak=keccak_256_hex -0777 -ne 'print keccak_256_hex($_)'
    return
  fi
  echo "ERROR: Keccak-256 provider not found. Install python3-pycryptodome (apt) or pycryptodome (pip), or libdigest-keccak-perl." >&2
  exit 1
}

if [[ "$NO_ADDRESS" -eq 0 ]]; then
  # Compute hash from pubkey XY using Keccak-256
  HASH="$(printf "%s" "$PUB_XY_HEX" | xxd -r -p | eth_keccak256_hex)"
  ADDR_HEX="${HASH:24}"
  ADDR_LC="${ADDR_HEX,,}"
# EIP-55 checksum: keccak256 of ASCII lowercase hex string
H2="$(printf "%s" "$ADDR_LC" | eth_keccak256_hex)"
debug "EIP55 base: $ADDR_LC"
debug "EIP55 h:    $H2"
  CHK=""
  for i in $(seq 0 39); do
    ch="${ADDR_LC:$i:1}"
    hd="${H2:$i:1}"
    if [[ "$ch" =~ [a-f] ]] && (( 0x$hd >= 8 )); then
      CHK+="${ch^^}"
    else
      CHK+="$ch"
    fi
  done
  ADDR_EIP55="0x$CHK"
fi

if [[ "$INCLUDE_SEED" -eq 1 ]]; then
  printf '{"mnemonic":"%s","path":"m/44'\''/60'\''/0'\''/0/0","privateKey":"0x%s","address":"%s","seed":"%s"}\n' \
    "$MNEMONIC" "$PRIV_HEX" "$ADDR_EIP55" "$SEED_HEX"
else
  printf '{"mnemonic":"%s","path":"m/44'\''/60'\''/0'\''/0/0","privateKey":"0x%s","address":"%s"}\n' \
    "$MNEMONIC" "$PRIV_HEX" "$ADDR_EIP55"
fi
