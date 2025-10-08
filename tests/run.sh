#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT_DIR/eth-from-bash.sh"
WLIST="$ROOT_DIR/english_bip-39.txt"

pass(){ echo "PASS: $1"; }
fail(){ echo "FAIL: $1"; exit 1; }

# Test 1: BIP39 seed vector for known mnemonic + passphrase TREZOR
test_seed_vector(){
  local mn="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  local expected="c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
  local out
  out=$(bash "$SCRIPT" -q --include-seed --no-address --mnemonic "$mn" "$WLIST" TREZOR)
  local seed
  seed=$(jq -r .seed <<<"$out")
  if [[ "$seed" == "$expected" ]]; then pass "BIP39 PBKDF2 seed vector"; else
    echo "Got:     $seed"
    echo "Expected: $expected"
    fail "BIP39 PBKDF2 seed vector"
  fi
}

# Test 2: Generated mnemonic checksum validity
test_mnemonic_checksum(){
  local out mn
  out=$(bash "$SCRIPT" -q --include-seed "$WLIST")
  mn=$(jq -r .mnemonic <<<"$out")
  # Build bitstring from words
  local bits=""; local idx
  for w in $mn; do
    # Find word index (0-based) via awk, no ripgrep dependency
    idx=$(awk -v w="$w" 'BEGIN{found=0} $0==w {print NR; found=1; exit} END{if(!found) exit 1}' "$WLIST" || true)
    if [[ -z "$idx" ]]; then fail "word $w not found"; fi
    idx=$((idx-1))
    # to 11-bit binary as string
    local b=$(echo "obase=2; $idx" | bc)
    b=$(printf "%011s" "$b" | tr ' ' 0)
    bits+="$b"
  done
  local ent_bits=${bits:0:128}
  local cs_bits=${bits:128:4}
  # Convert ENT bits to hex
  local ent_hex=""; local i=0
  while (( i < 128 )); do
    local byte=${ent_bits:$i:8}
    local val=$(echo "ibase=2; $byte" | bc)
    ent_hex+=$(printf "%02x" "$val")
    i=$((i+8))
  done
  # Compute checksum
  local cs_nib=$(printf "%s" "$ent_hex" | xxd -r -p | sha256sum | cut -c1)
  local cs_bin=$(echo "obase=2; ibase=16; ${cs_nib^^}" | bc | awk '{printf "%04d\n", $0}')
  if [[ "$cs_bin" == "$cs_bits" ]]; then pass "BIP39 mnemonic checksum"; else
    echo "mnemonic: $mn"
    echo "ent_hex:  $ent_hex"
    echo "cs_bits:  $cs_bits"
    echo "calc_cs:  $cs_bin"
    fail "BIP39 mnemonic checksum"
  fi
}

# Test 3: Keccak provider presence (informational)
test_keccak_provider(){
  if perl scripts/has_perl_keccak.pl >/dev/null 2>&1; then
    pass "Perl Keccak provider available"
  elif python3 scripts/has_keccak.py >/dev/null 2>&1; then
    pass "Python Keccak (pycryptodome) available"
  else
    echo "SKIP: No Keccak provider; addresses will not be correct. Install python3-pycryptodome (apt) or pycryptodome (pip), or libdigest-keccak-perl." >&2
  fi
}

# Test 4: EIP-55 checksum (if keccak available) using Python re-computation
test_eip55(){
  local out addr
  out=$(bash "$SCRIPT" -q --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" "$WLIST")
  addr=$(jq -r .address <<<"$out")

  # Prefer Python keccak via script
  if python3 scripts/has_keccak.py >/dev/null 2>&1; then
    recomputed=$(python3 scripts/eip55_recompute.py "${addr}")
  if [[ "$recomputed" == "$addr" ]]; then
    pass "EIP-55 checksum matches (Python)"
  else
    echo "Expected: $addr"
    echo "Recomp.:  $recomputed"
    fail "EIP-55 checksum (Python)"
  fi
    return
  fi

  # Fallback to Perl keccak via script
  if perl scripts/has_perl_keccak.pl >/dev/null 2>&1; then
    recomputed=$(perl scripts/eip55_recompute.pl "$addr")
    if [[ "$recomputed" == "$addr" ]]; then
      pass "EIP-55 checksum matches (Perl)"
    else
      fail "EIP-55 checksum (Perl)"
    fi
    return
  fi

  echo "SKIP: EIP-55 test (no Python or Perl Keccak)" >&2
}

test_seed_vector
test_mnemonic_checksum
test_keccak_provider
test_eip55

echo "All done."
