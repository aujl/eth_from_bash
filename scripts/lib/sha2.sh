# shellcheck shell=bash
# SHA-2 (SHA-256 and SHA-512) helpers implemented with Bash arithmetic.

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  echo "scripts/lib/sha2.sh must be sourced, not executed" >&2
  exit 1
fi

readonly SHA2_MASK32=$((0xFFFFFFFF))

readonly -a SHA2_K256=(
  0x428a2f98 0x71374491 0xb5c0fbcf 0xe9b5dba5 0x3956c25b 0x59f111f1 0x923f82a4 0xab1c5ed5
  0xd807aa98 0x12835b01 0x243185be 0x550c7dc3 0x72be5d74 0x80deb1fe 0x9bdc06a7 0xc19bf174
  0xe49b69c1 0xefbe4786 0x0fc19dc6 0x240ca1cc 0x2de92c6f 0x4a7484aa 0x5cb0a9dc 0x76f988da
  0x983e5152 0xa831c66d 0xb00327c8 0xbf597fc7 0xc6e00bf3 0xd5a79147 0x06ca6351 0x14292967
  0x27b70a85 0x2e1b2138 0x4d2c6dfc 0x53380d13 0x650a7354 0x766a0abb 0x81c2c92e 0x92722c85
  0xa2bfe8a1 0xa81a664b 0xc24b8b70 0xc76c51a3 0xd192e819 0xd6990624 0xf40e3585 0x106aa070
  0x19a4c116 0x1e376c08 0x2748774c 0x34b0bcb5 0x391c0cb3 0x4ed8aa4a 0x5b9cca4f 0x682e6ff3
  0x748f82ee 0x78a5636f 0x84c87814 0x8cc70208 0x90befffa 0xa4506ceb 0xbef9a3f7 0xc67178f2
)

readonly -a SHA2_K512_HI=(
  0x428a2f98 0x71374491 0xb5c0fbcf 0xe9b5dba5 0x3956c25b 0x59f111f1 0x923f82a4 0xab1c5ed5
  0xd807aa98 0x12835b01 0x243185be 0x550c7dc3 0x72be5d74 0x80deb1fe 0x9bdc06a7 0xc19bf174
  0xe49b69c1 0xefbe4786 0x0fc19dc6 0x240ca1cc 0x2de92c6f 0x4a7484aa 0x5cb0a9dc 0x76f988da
  0x983e5152 0xa831c66d 0xb00327c8 0xbf597fc7 0xc6e00bf3 0xd5a79147 0x06ca6351 0x14292967
  0x27b70a85 0x2e1b2138 0x4d2c6dfc 0x53380d13 0x650a7354 0x766a0abb 0x81c2c92e 0x92722c85
  0xa2bfe8a1 0xa81a664b 0xc24b8b70 0xc76c51a3 0xd192e819 0xd6990624 0xf40e3585 0x106aa070
  0x19a4c116 0x1e376c08 0x2748774c 0x34b0bcb5 0x391c0cb3 0x4ed8aa4a 0x5b9cca4f 0x682e6ff3
  0x748f82ee 0x78a5636f 0x84c87814 0x8cc70208 0x90befffa 0xa4506ceb 0xbef9a3f7 0xc67178f2
  0xca273ece 0xd186b8c7 0xeada7dd6 0xf57d4f7f 0x06f067aa 0x0a637dc5 0x113f9804 0x1b710b35
  0x28db77f5 0x32caab7b 0x3c9ebe0a 0x431d67c4 0x4cc5d4be 0x597f299c 0x5fcb6fab 0x6c44198c
)

readonly -a SHA2_K512_LO=(
  0xd728ae22 0x23ef65cd 0xec4d3b2f 0x8189dbbc 0xf348b538 0xb605d019 0xaf194f9b 0xda6d8118
  0xa3030242 0x45706fbe 0x4ee4b28c 0xd5ffb4e2 0xf27b896f 0x3b1696b1 0x25c71235 0xcf692694
  0x9ef14ad2 0x384f25e3 0x8b8cd5b5 0x77ac9c65 0x592b0275 0x6ea6e483 0xbd41fbd4 0x831153b5
  0xee66dfab 0x2db43210 0x98fb213f 0xbeef0ee4 0x3da88fc2 0x930aa725 0xe003826f 0x0a0e6e70
  0x46d22ffc 0x5c26c926 0x5ac42aed 0x9d95b3df 0x8baf63de 0x3c77b2a8 0x47edaee6 0x1482353b
  0x4cf10364 0xbc423001 0xd0f89791 0x0654be30 0xd6ef5218 0x5565a910 0x5771202a 0x32bbd1b8
  0xb8d2d0c8 0x5141ab53 0xdf8eeb99 0xe19b48a8 0xc5c95a63 0xe3418acb 0x7763e373 0xd6b2b8a3
  0x5defb2fc 0x43172f60 0xa1f0ab72 0x1a6439ec 0x23631e28 0xde82bde9 0xb2c67915 0xe372532b
  0xea26619c 0x21c0c207 0xcde0eb1e 0xee6ed178 0x72176fba 0xa2c898a6 0xbef90dae 0x131c471b
  0x23047d84 0x40c72493 0x15c9bebc 0x9c100d4c 0xcb3e42b6 0xfc657e2a 0x3ad6faec 0x4a475817
)

sha2__rotr32() {
  local value=$1
  local shift=$2
  shift=$((shift % 32))
  if ((shift == 0)); then
    printf '%u' "$((value & SHA2_MASK32))"
    return
  fi
  local right left
  right=$(((value >> shift) & SHA2_MASK32))
  left=$(((value << (32 - shift)) & SHA2_MASK32))
  printf '%u' "$(((right | left) & SHA2_MASK32))"
}

sha2__shr32() {
  local value=$1
  local shift=$2
  if ((shift >= 32)); then
    printf '0'
    return
  fi
  printf '%u' "$(((value >> shift) & SHA2_MASK32))"
}

sha2__add32() {
  local sum=0
  local value
  for value in "$@"; do
    sum=$(((sum + value) & SHA2_MASK32))
  done
  printf '%u' "$sum"
}

sha2__sigma0_256() {
  local x=$1
  local r2 r13 r22
  r2=$(sha2__rotr32 "$x" 2)
  r13=$(sha2__rotr32 "$x" 13)
  r22=$(sha2__rotr32 "$x" 22)
  printf '%u' "$(((r2 ^ r13 ^ r22) & SHA2_MASK32))"
}

sha2__sigma1_256() {
  local x=$1
  local r6 r11 r25
  r6=$(sha2__rotr32 "$x" 6)
  r11=$(sha2__rotr32 "$x" 11)
  r25=$(sha2__rotr32 "$x" 25)
  printf '%u' "$(((r6 ^ r11 ^ r25) & SHA2_MASK32))"
}

sha2__gamma0_256() {
  local x=$1
  local r7 r18 s3
  r7=$(sha2__rotr32 "$x" 7)
  r18=$(sha2__rotr32 "$x" 18)
  s3=$(sha2__shr32 "$x" 3)
  printf '%u' "$(((r7 ^ r18 ^ s3) & SHA2_MASK32))"
}

sha2__gamma1_256() {
  local x=$1
  local r17 r19 s10
  r17=$(sha2__rotr32 "$x" 17)
  r19=$(sha2__rotr32 "$x" 19)
  s10=$(sha2__shr32 "$x" 10)
  printf '%u' "$(((r17 ^ r19 ^ s10) & SHA2_MASK32))"
}

sha2__rotr64() {
  local hi=$1
  local lo=$2
  local shift=$3
  shift=$((shift % 64))
  if ((shift == 0)); then
    SHA2_TMP_HI=$((hi & SHA2_MASK32))
    SHA2_TMP_LO=$((lo & SHA2_MASK32))
    return
  fi
  local tmp_hi tmp_lo left_hi left_lo right_hi right_lo
  if ((shift >= 32)); then
    tmp_hi=$lo
    tmp_lo=$hi
    shift=$((shift - 32))
  else
    tmp_hi=$hi
    tmp_lo=$lo
  fi
  if ((shift == 0)); then
    SHA2_TMP_HI=$tmp_hi
    SHA2_TMP_LO=$tmp_lo
    return
  fi
  right_hi=$(((tmp_hi >> shift) & SHA2_MASK32))
  right_lo=$(((tmp_lo >> shift) & SHA2_MASK32))
  left_hi=$(((tmp_lo << (32 - shift)) & SHA2_MASK32))
  left_lo=$(((tmp_hi << (32 - shift)) & SHA2_MASK32))
  SHA2_TMP_HI=$(((right_hi | left_hi) & SHA2_MASK32))
  SHA2_TMP_LO=$(((right_lo | left_lo) & SHA2_MASK32))
}

sha2__shr64() {
  local hi=$1
  local lo=$2
  local shift=$3
  if ((shift >= 64)); then
    SHA2_TMP_HI=0
    SHA2_TMP_LO=0
    return
  fi
  if ((shift == 0)); then
    SHA2_TMP_HI=$((hi & SHA2_MASK32))
    SHA2_TMP_LO=$((lo & SHA2_MASK32))
    return
  fi
  local new_hi new_lo
  if ((shift >= 32)); then
    local shift2=$((shift - 32))
    new_lo=$(((hi >> shift2) & SHA2_MASK32))
    new_hi=0
  else
    new_lo=$(((lo >> shift) & SHA2_MASK32))
    new_hi=$(((hi >> shift) & SHA2_MASK32))
    new_lo=$(((new_lo | ((hi << (32 - shift)) & SHA2_MASK32)) & SHA2_MASK32))
  fi
  SHA2_TMP_HI=$new_hi
  SHA2_TMP_LO=$new_lo
}

sha2__xor64() {
  local a_hi=$1
  local a_lo=$2
  local b_hi=$3
  local b_lo=$4
  SHA2_TMP_HI=$(((a_hi ^ b_hi) & SHA2_MASK32))
  SHA2_TMP_LO=$(((a_lo ^ b_lo) & SHA2_MASK32))
}

sha2__and64() {
  local a_hi=$1
  local a_lo=$2
  local b_hi=$3
  local b_lo=$4
  SHA2_TMP_HI=$(((a_hi & b_hi) & SHA2_MASK32))
  SHA2_TMP_LO=$(((a_lo & b_lo) & SHA2_MASK32))
}

sha2__not64() {
  local hi=$1
  local lo=$2
  SHA2_TMP_HI=$(((~hi) & SHA2_MASK32))
  SHA2_TMP_LO=$(((~lo) & SHA2_MASK32))
}

sha2__add64() {
  local sum_hi=0
  local sum_lo=0
  local hi lo carry
  while (( $# > 0 )); do
    hi=$1
    lo=$2
    sum_lo=$((sum_lo + lo))
    carry=$((sum_lo >> 32))
    sum_lo=$((sum_lo & SHA2_MASK32))
    sum_hi=$(((sum_hi + hi + carry) & SHA2_MASK32))
    shift 2
  done
  SHA2_TMP_HI=$sum_hi
  SHA2_TMP_LO=$sum_lo
}

sha2__sigma0_512() {
  local hi=$1
  local lo=$2
  local r28_hi r28_lo r34_hi r34_lo r39_hi r39_lo
  sha2__rotr64 "$hi" "$lo" 28
  r28_hi=$SHA2_TMP_HI; r28_lo=$SHA2_TMP_LO
  sha2__rotr64 "$hi" "$lo" 34
  r34_hi=$SHA2_TMP_HI; r34_lo=$SHA2_TMP_LO
  sha2__rotr64 "$hi" "$lo" 39
  r39_hi=$SHA2_TMP_HI; r39_lo=$SHA2_TMP_LO
  SHA2_TMP_HI=$(((r28_hi ^ r34_hi ^ r39_hi) & SHA2_MASK32))
  SHA2_TMP_LO=$(((r28_lo ^ r34_lo ^ r39_lo) & SHA2_MASK32))
}

sha2__sigma1_512() {
  local hi=$1
  local lo=$2
  local r14_hi r14_lo r18_hi r18_lo r41_hi r41_lo
  sha2__rotr64 "$hi" "$lo" 14
  r14_hi=$SHA2_TMP_HI; r14_lo=$SHA2_TMP_LO
  sha2__rotr64 "$hi" "$lo" 18
  r18_hi=$SHA2_TMP_HI; r18_lo=$SHA2_TMP_LO
  sha2__rotr64 "$hi" "$lo" 41
  r41_hi=$SHA2_TMP_HI; r41_lo=$SHA2_TMP_LO
  SHA2_TMP_HI=$(((r14_hi ^ r18_hi ^ r41_hi) & SHA2_MASK32))
  SHA2_TMP_LO=$(((r14_lo ^ r18_lo ^ r41_lo) & SHA2_MASK32))
}

sha2__gamma0_512() {
  local hi=$1
  local lo=$2
  local r1_hi r1_lo r8_hi r8_lo s7_hi s7_lo
  sha2__rotr64 "$hi" "$lo" 1
  r1_hi=$SHA2_TMP_HI; r1_lo=$SHA2_TMP_LO
  sha2__rotr64 "$hi" "$lo" 8
  r8_hi=$SHA2_TMP_HI; r8_lo=$SHA2_TMP_LO
  sha2__shr64 "$hi" "$lo" 7
  s7_hi=$SHA2_TMP_HI; s7_lo=$SHA2_TMP_LO
  SHA2_TMP_HI=$(((r1_hi ^ r8_hi ^ s7_hi) & SHA2_MASK32))
  SHA2_TMP_LO=$(((r1_lo ^ r8_lo ^ s7_lo) & SHA2_MASK32))
}

sha2__gamma1_512() {
  local hi=$1
  local lo=$2
  local r19_hi r19_lo r61_hi r61_lo s6_hi s6_lo
  sha2__rotr64 "$hi" "$lo" 19
  r19_hi=$SHA2_TMP_HI; r19_lo=$SHA2_TMP_LO
  sha2__rotr64 "$hi" "$lo" 61
  r61_hi=$SHA2_TMP_HI; r61_lo=$SHA2_TMP_LO
  sha2__shr64 "$hi" "$lo" 6
  s6_hi=$SHA2_TMP_HI; s6_lo=$SHA2_TMP_LO
  SHA2_TMP_HI=$(((r19_hi ^ r61_hi ^ s6_hi) & SHA2_MASK32))
  SHA2_TMP_LO=$(((r19_lo ^ r61_lo ^ s6_lo) & SHA2_MASK32))
}

sha2__add_bits64() {
  local -n hi_ref=$1
  local -n lo_ref=$2
  local bits=$3
  lo_ref=$((lo_ref + bits))
  local carry=$((lo_ref >> 32))
  lo_ref=$((lo_ref & SHA2_MASK32))
  hi_ref=$(((hi_ref + carry) & SHA2_MASK32))
}

sha2__add_bits128() {
  local -n hi_hi_ref=$1
  local -n hi_lo_ref=$2
  local -n lo_hi_ref=$3
  local -n lo_lo_ref=$4
  local bits=$5
  lo_lo_ref=$((lo_lo_ref + bits))
  local carry=$((lo_lo_ref >> 32))
  lo_lo_ref=$((lo_lo_ref & SHA2_MASK32))
  lo_hi_ref=$((lo_hi_ref + carry))
  carry=$((lo_hi_ref >> 32))
  lo_hi_ref=$((lo_hi_ref & SHA2_MASK32))
  hi_lo_ref=$((hi_lo_ref + carry))
  carry=$((hi_lo_ref >> 32))
  hi_lo_ref=$((hi_lo_ref & SHA2_MASK32))
  hi_hi_ref=$(((hi_hi_ref + carry) & SHA2_MASK32))
}

sha2__compress256() {
  local -n state_arr=$1
  local block_hex=$2
  local mask=$((0xFFFFFFFF))
  local -a W=()
  local i
  for ((i = 0; i < 16; i++)); do
    W[i]=$((16#${block_hex:i*8:8}))
  done
  for ((i = 16; i < 64; i++)); do
    local s0 s1
    s0=$(sha2__gamma0_256 "${W[i-15]}")
    s1=$(sha2__gamma1_256 "${W[i-2]}")
    W[i]=$(((W[i-16] + s0 + W[i-7] + s1) & mask))
  done

  local a=${state_arr[0]}
  local b=${state_arr[1]}
  local c=${state_arr[2]}
  local d=${state_arr[3]}
  local e=${state_arr[4]}
  local f=${state_arr[5]}
  local g=${state_arr[6]}
  local h=${state_arr[7]}

  for ((i = 0; i < 64; i++)); do
    local S1 ch temp1 S0 maj temp2
    S1=$(sha2__sigma1_256 "$e")
    ch=$((((e & f) ^ ((~e & mask) & g)) & mask))
    temp1=$(((h + S1 + ch + SHA2_K256[i] + W[i]) & mask))
    S0=$(sha2__sigma0_256 "$a")
    maj=$((((a & b) ^ (a & c) ^ (b & c)) & mask))
    temp2=$(((S0 + maj) & mask))

    h=$g
    g=$f
    f=$e
    e=$(((d + temp1) & mask))
    d=$c
    c=$b
    b=$a
    a=$(((temp1 + temp2) & mask))
  done

  state_arr[0]=$(((state_arr[0] + a) & mask))
  state_arr[1]=$(((state_arr[1] + b) & mask))
  state_arr[2]=$(((state_arr[2] + c) & mask))
  state_arr[3]=$(((state_arr[3] + d) & mask))
  state_arr[4]=$(((state_arr[4] + e) & mask))
  state_arr[5]=$(((state_arr[5] + f) & mask))
  state_arr[6]=$(((state_arr[6] + g) & mask))
  state_arr[7]=$(((state_arr[7] + h) & mask))
}

sha2__compress512() {
  local -n state_hi_arr=$1
  local -n state_lo_arr=$2
  local block_hex=$3

  local -a W_HI=()
  local -a W_LO=()
  local i word_hex
  for ((i = 0; i < 16; i++)); do
    word_hex=${block_hex:i*16:16}
    W_HI[i]=$((16#${word_hex:0:8}))
    W_LO[i]=$((16#${word_hex:8:8}))
  done

  for ((i = 16; i < 80; i++)); do
    local s0_hi s0_lo s1_hi s1_lo tmp_hi tmp_lo
    sha2__gamma0_512 "${W_HI[i-15]}" "${W_LO[i-15]}"
    s0_hi=$SHA2_TMP_HI; s0_lo=$SHA2_TMP_LO
    sha2__gamma1_512 "${W_HI[i-2]}" "${W_LO[i-2]}"
    s1_hi=$SHA2_TMP_HI; s1_lo=$SHA2_TMP_LO
    sha2__add64 "${W_HI[i-16]}" "${W_LO[i-16]}" "${s0_hi}" "${s0_lo}" "${W_HI[i-7]}" "${W_LO[i-7]}" "${s1_hi}" "${s1_lo}"
    tmp_hi=$SHA2_TMP_HI
    tmp_lo=$SHA2_TMP_LO
    W_HI[i]=$tmp_hi
    W_LO[i]=$tmp_lo
  done

  local a_hi=${state_hi_arr[0]} a_lo=${state_lo_arr[0]}
  local b_hi=${state_hi_arr[1]} b_lo=${state_lo_arr[1]}
  local c_hi=${state_hi_arr[2]} c_lo=${state_lo_arr[2]}
  local d_hi=${state_hi_arr[3]} d_lo=${state_lo_arr[3]}
  local e_hi=${state_hi_arr[4]} e_lo=${state_lo_arr[4]}
  local f_hi=${state_hi_arr[5]} f_lo=${state_lo_arr[5]}
  local g_hi=${state_hi_arr[6]} g_lo=${state_lo_arr[6]}
  local h_hi=${state_hi_arr[7]} h_lo=${state_lo_arr[7]}

  for ((i = 0; i < 80; i++)); do
    local S1_hi S1_lo ch_hi ch_lo temp1_hi temp1_lo S0_hi S0_lo maj_hi maj_lo temp2_hi temp2_lo

    sha2__sigma1_512 "$e_hi" "$e_lo"
    S1_hi=$SHA2_TMP_HI; S1_lo=$SHA2_TMP_LO

    sha2__and64 "$e_hi" "$e_lo" "$f_hi" "$f_lo"
    local ef_hi=$SHA2_TMP_HI ef_lo=$SHA2_TMP_LO
    sha2__not64 "$e_hi" "$e_lo"
    local ne_hi=$SHA2_TMP_HI ne_lo=$SHA2_TMP_LO
    sha2__and64 "$ne_hi" "$ne_lo" "$g_hi" "$g_lo"
    local neg_hi=$SHA2_TMP_HI neg_lo=$SHA2_TMP_LO
    ch_hi=$(((ef_hi ^ neg_hi) & SHA2_MASK32))
    ch_lo=$(((ef_lo ^ neg_lo) & SHA2_MASK32))

    sha2__add64 "$h_hi" "$h_lo" "$S1_hi" "$S1_lo" "$ch_hi" "$ch_lo" "${SHA2_K512_HI[i]}" "${SHA2_K512_LO[i]}" "${W_HI[i]}" "${W_LO[i]}"
    temp1_hi=$SHA2_TMP_HI; temp1_lo=$SHA2_TMP_LO

    sha2__sigma0_512 "$a_hi" "$a_lo"
    S0_hi=$SHA2_TMP_HI; S0_lo=$SHA2_TMP_LO

    local ab_hi ac_hi bc_hi ab_lo ac_lo bc_lo
    sha2__and64 "$a_hi" "$a_lo" "$b_hi" "$b_lo"
    ab_hi=$SHA2_TMP_HI; ab_lo=$SHA2_TMP_LO
    sha2__and64 "$a_hi" "$a_lo" "$c_hi" "$c_lo"
    ac_hi=$SHA2_TMP_HI; ac_lo=$SHA2_TMP_LO
    sha2__and64 "$b_hi" "$b_lo" "$c_hi" "$c_lo"
    bc_hi=$SHA2_TMP_HI; bc_lo=$SHA2_TMP_LO
    maj_hi=$(((ab_hi ^ ac_hi ^ bc_hi) & SHA2_MASK32))
    maj_lo=$(((ab_lo ^ ac_lo ^ bc_lo) & SHA2_MASK32))

    sha2__add64 "$S0_hi" "$S0_lo" "$maj_hi" "$maj_lo"
    temp2_hi=$SHA2_TMP_HI; temp2_lo=$SHA2_TMP_LO

    h_hi=$g_hi; h_lo=$g_lo
    g_hi=$f_hi; g_lo=$f_lo
    f_hi=$e_hi; f_lo=$e_lo

    sha2__add64 "$d_hi" "$d_lo" "$temp1_hi" "$temp1_lo"
    e_hi=$SHA2_TMP_HI; e_lo=$SHA2_TMP_LO

    d_hi=$c_hi; d_lo=$c_lo
    c_hi=$b_hi; c_lo=$b_lo
    b_hi=$a_hi; b_lo=$a_lo

    sha2__add64 "$temp1_hi" "$temp1_lo" "$temp2_hi" "$temp2_lo"
    a_hi=$SHA2_TMP_HI; a_lo=$SHA2_TMP_LO
  done

  sha2__add64 "${state_hi_arr[0]}" "${state_lo_arr[0]}" "$a_hi" "$a_lo"
  state_hi_arr[0]=$SHA2_TMP_HI; state_lo_arr[0]=$SHA2_TMP_LO

  sha2__add64 "${state_hi_arr[1]}" "${state_lo_arr[1]}" "$b_hi" "$b_lo"
  state_hi_arr[1]=$SHA2_TMP_HI; state_lo_arr[1]=$SHA2_TMP_LO

  sha2__add64 "${state_hi_arr[2]}" "${state_lo_arr[2]}" "$c_hi" "$c_lo"
  state_hi_arr[2]=$SHA2_TMP_HI; state_lo_arr[2]=$SHA2_TMP_LO

  sha2__add64 "${state_hi_arr[3]}" "${state_lo_arr[3]}" "$d_hi" "$d_lo"
  state_hi_arr[3]=$SHA2_TMP_HI; state_lo_arr[3]=$SHA2_TMP_LO

  sha2__add64 "${state_hi_arr[4]}" "${state_lo_arr[4]}" "$e_hi" "$e_lo"
  state_hi_arr[4]=$SHA2_TMP_HI; state_lo_arr[4]=$SHA2_TMP_LO

  sha2__add64 "${state_hi_arr[5]}" "${state_lo_arr[5]}" "$f_hi" "$f_lo"
  state_hi_arr[5]=$SHA2_TMP_HI; state_lo_arr[5]=$SHA2_TMP_LO

  sha2__add64 "${state_hi_arr[6]}" "${state_lo_arr[6]}" "$g_hi" "$g_lo"
  state_hi_arr[6]=$SHA2_TMP_HI; state_lo_arr[6]=$SHA2_TMP_LO

  sha2__add64 "${state_hi_arr[7]}" "${state_lo_arr[7]}" "$h_hi" "$h_lo"
  state_hi_arr[7]=$SHA2_TMP_HI; state_lo_arr[7]=$SHA2_TMP_LO
}

sha2__finalize256() {
  local state_name=$1
  local remainder_hex=$2
  local total_hi=$3
  local total_lo=$4
  remainder_hex+="80"
  local remainder_len_bytes=$(( ${#remainder_hex} / 2 ))
  while (( (remainder_len_bytes % 64) != 56 )); do
    remainder_hex+="00"
    remainder_len_bytes=$((remainder_len_bytes + 1))
  done
  printf -v length_hex '%08x%08x' "$total_hi" "$total_lo"
  remainder_hex+="${length_hex}"
  local offset=0
  local block_hex
  while (( offset < ${#remainder_hex} )); do
    block_hex=${remainder_hex:offset:128}
    sha2__compress256 "$state_name" "${block_hex}"
    offset=$((offset + 128))
  done
}

sha2__finalize512() {
  local state_hi_name=$1
  local state_lo_name=$2
  local remainder_hex=$3
  local len_hi_hi=$4
  local len_hi_lo=$5
  local len_lo_hi=$6
  local len_lo_lo=$7
  remainder_hex+="80"
  local remainder_len_bytes=$(( ${#remainder_hex} / 2 ))
  while (( (remainder_len_bytes % 128) != 112 )); do
    remainder_hex+="00"
    remainder_len_bytes=$((remainder_len_bytes + 1))
  done
  printf -v length_hex '%08x%08x%08x%08x' "$len_hi_hi" "$len_hi_lo" "$len_lo_hi" "$len_lo_lo"
  remainder_hex+="${length_hex}"
  local offset=0
  local block_hex
  while (( offset < ${#remainder_hex} )); do
    block_hex=${remainder_hex:offset:256}
    sha2__compress512 "$state_hi_name" "$state_lo_name" "${block_hex}"
    offset=$((offset + 256))
  done
}

sha256_hex_from_stream() {
  local -a state=(
    0x6a09e667 0xbb67ae85 0x3c6ef372 0xa54ff53a
    0x510e527f 0x9b05688c 0x1f83d9ab 0x5be0cd19
  )
  local bits_hi=0
  local bits_lo=0
  local remainder_hex=""
  local chunk_hex=""
  while IFS= read -r chunk_hex; do
    chunk_hex=${chunk_hex//[[:space:]]/}
    if [[ -z ${chunk_hex} ]]; then
      continue
    fi
    local chunk_bytes=$(( ${#chunk_hex} / 2 ))
    sha2__add_bits64 bits_hi bits_lo $((chunk_bytes * 8))
    if (( chunk_bytes == 64 )); then
      sha2__compress256 state "${chunk_hex}"
      remainder_hex=""
    else
      remainder_hex+="${chunk_hex}"
    fi
  done < <(od -An -tx1 -v -w64)

  sha2__finalize256 state "${remainder_hex}" "${bits_hi}" "${bits_lo}"
  printf '%08x%08x%08x%08x%08x%08x%08x%08x\n' \
    "${state[0]}" "${state[1]}" "${state[2]}" "${state[3]}" \
    "${state[4]}" "${state[5]}" "${state[6]}" "${state[7]}"
}

sha512_hex_from_stream() {
  local -a state_hi=(
    0x6a09e667 0xbb67ae85 0x3c6ef372 0xa54ff53a
    0x510e527f 0x9b05688c 0x1f83d9ab 0x5be0cd19
  )
  local -a state_lo=(
    0xf3bcc908 0x84caa73b 0xfe94f82b 0x5f1d36f1
    0xade682d1 0x2b3e6c1f 0xfb41bd6b 0x137e2179
  )

  local len_hi_hi=0
  local len_hi_lo=0
  local len_lo_hi=0
  local len_lo_lo=0

  local remainder_hex=""
  local chunk_hex=""
  while IFS= read -r chunk_hex; do
    chunk_hex=${chunk_hex//[[:space:]]/}
    if [[ -z ${chunk_hex} ]]; then
      continue
    fi
    local chunk_bytes=$(( ${#chunk_hex} / 2 ))
    sha2__add_bits128 len_hi_hi len_hi_lo len_lo_hi len_lo_lo $((chunk_bytes * 8))
    if (( chunk_bytes == 128 )); then
      sha2__compress512 state_hi state_lo "${chunk_hex}"
      remainder_hex=""
    else
      remainder_hex+="${chunk_hex}"
    fi
  done < <(od -An -tx1 -v -w128)

  sha2__finalize512 state_hi state_lo "${remainder_hex}" \
    "${len_hi_hi}" "${len_hi_lo}" "${len_lo_hi}" "${len_lo_lo}"

  printf '%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x\n' \
    "${state_hi[0]}" "${state_lo[0]}" "${state_hi[1]}" "${state_lo[1]}" \
    "${state_hi[2]}" "${state_lo[2]}" "${state_hi[3]}" "${state_lo[3]}" \
    "${state_hi[4]}" "${state_lo[4]}" "${state_hi[5]}" "${state_lo[5]}" \
    "${state_hi[6]}" "${state_lo[6]}" "${state_hi[7]}" "${state_lo[7]}"
}
