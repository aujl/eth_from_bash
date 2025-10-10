#!/usr/bin/env bash
# Portable Keccak-256 helpers implemented in Bash arithmetic.
set -euo pipefail

MASK32=$((0xFFFFFFFF))
ROT_HI=0
ROT_LO=0
STATE_BYTES=()
NIST_A3_200_HEX="$(printf 'a3%.0s' {1..200})"
readonly NIST_A3_200_HEX

ROUND_CONSTANTS_HEX=(
  0000000000000001
  0000000000008082
  800000000000808A
  8000000080008000
  000000000000808B
  0000000080000001
  8000000080008081
  8000000000008009
  000000000000008A
  0000000000000088
  0000000080008009
  000000008000000A
  000000008000808B
  800000000000008B
  8000000000008089
  8000000000008003
  8000000000008002
  8000000000000080
  000000000000800A
  800000008000000A
  8000000080008081
  8000000000008080
  0000000080000001
  8000000080008008
)

ROTATION_OFFSETS=(
  0 36 3 41 18
  1 44 10 45 2
  62 6 43 15 61
  28 55 25 21 56
  27 20 39 8 14
)

CANONICAL_VECTOR_NAMES=(empty abc quickfox nist_a3_200)
CANONICAL_VECTOR_INPUT_HEX=(
  ""
  "616263"
  "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67"
  "${NIST_A3_200_HEX}"
)
CANONICAL_VECTOR_DIGEST_HEX=(
  "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
  "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
  "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"
  "3a57666b048777f2c953dc4456f45a2588e1cb6f2da760122d530ac2ce607d4a"
)
printf -v CANONICAL_VECTORS_JSON '[{"digest_hex":"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470","input_hex":"","name":"empty"},{"digest_hex":"4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45","input_hex":"616263","name":"abc"},{"digest_hex":"4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15","input_hex":"54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67","name":"quickfox"},{"digest_hex":"3a57666b048777f2c953dc4456f45a2588e1cb6f2da760122d530ac2ce607d4a","input_hex":"%s","name":"nist_a3_200"}]' "${NIST_A3_200_HEX}"

ROUND_CONST_HI=()
ROUND_CONST_LO=()
for rc in "${ROUND_CONSTANTS_HEX[@]}"; do
  ROUND_CONST_HI+=( $((16#${rc:0:8})) )
  ROUND_CONST_LO+=( $((16#${rc:8:8})) )
done

rotl64() {
  local hi=$1
  local lo=$2
  local offset=$3
  offset=$((offset % 64))
  if ((offset == 0)); then
    ROT_HI=$((hi & MASK32))
    ROT_LO=$((lo & MASK32))
    return
  fi
  local tmp_hi tmp_lo
  if ((offset >= 32)); then
    offset=$((offset - 32))
    tmp_hi=$lo
    tmp_lo=$hi
  else
    tmp_hi=$hi
    tmp_lo=$lo
  fi
  if ((offset == 0)); then
    ROT_HI=$((tmp_hi & MASK32))
    ROT_LO=$((tmp_lo & MASK32))
    return
  fi
  local left_hi left_lo right_hi right_lo
  left_hi=$(((tmp_hi << offset) & MASK32))
  left_lo=$(((tmp_lo << offset) & MASK32))
  right_hi=$(((tmp_lo >> (32 - offset)) & MASK32))
  right_lo=$(((tmp_hi >> (32 - offset)) & MASK32))
  ROT_HI=$(((left_hi | right_hi) & MASK32))
  ROT_LO=$(((left_lo | right_lo) & MASK32))
}

keccak_f() {
  local -n state_hi_ref="$1"
  local -n state_lo_ref="$2"
  local round x y idx b_idx
  local -a c_hi=(0 0 0 0 0)
  local -a c_lo=(0 0 0 0 0)
  local -a d_hi=(0 0 0 0 0)
  local -a d_lo=(0 0 0 0 0)
  local -a b_hi=(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0)
  local -a b_lo=(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0)

  for ((round = 0; round < ${#ROUND_CONST_HI[@]}; round++)); do
    for ((x = 0; x < 5; x++)); do
      local sum_hi=0
      local sum_lo=0
      for ((y = 0; y < 5; y++)); do
        idx=$((x + 5 * y))
        sum_hi=$((sum_hi ^ state_hi_ref[idx]))
        sum_lo=$((sum_lo ^ state_lo_ref[idx]))
      done
      c_hi[x]=$((sum_hi & MASK32))
      c_lo[x]=$((sum_lo & MASK32))
    done

    for ((x = 0; x < 5; x++)); do
      local idx_prev=$(((x + 4) % 5))
      local idx_next=$(((x + 1) % 5))
      rotl64 "${c_hi[idx_next]}" "${c_lo[idx_next]}" 1
      d_hi[x]=$(((c_hi[idx_prev] ^ ROT_HI) & MASK32))
      d_lo[x]=$(((c_lo[idx_prev] ^ ROT_LO) & MASK32))
    done

    for ((x = 0; x < 5; x++)); do
      for ((y = 0; y < 5; y++)); do
        idx=$((x + 5 * y))
        state_hi_ref[idx]=$(((state_hi_ref[idx] ^ d_hi[x]) & MASK32))
        state_lo_ref[idx]=$(((state_lo_ref[idx] ^ d_lo[x]) & MASK32))
      done
    done

    for ((x = 0; x < 5; x++)); do
      for ((y = 0; y < 5; y++)); do
        idx=$((x + 5 * y))
        b_idx=$((y + 5 * ((2 * x + 3 * y) % 5)))
        rotl64 "${state_hi_ref[idx]}" "${state_lo_ref[idx]}" "${ROTATION_OFFSETS[$((x * 5 + y))]}"
        b_hi[b_idx]=$ROT_HI
        b_lo[b_idx]=$ROT_LO
      done
    done

    for ((x = 0; x < 5; x++)); do
      for ((y = 0; y < 5; y++)); do
        idx=$((x + 5 * y))
        local idx1=$((((x + 1) % 5) + 5 * y))
        local idx2=$((((x + 2) % 5) + 5 * y))
        local not_hi=$(((~b_hi[idx1]) & MASK32))
        local not_lo=$(((~b_lo[idx1]) & MASK32))
        local and_hi=$(((not_hi & b_hi[idx2]) & MASK32))
        local and_lo=$(((not_lo & b_lo[idx2]) & MASK32))
        state_hi_ref[idx]=$(((b_hi[idx] ^ and_hi) & MASK32))
        state_lo_ref[idx]=$(((b_lo[idx] ^ and_lo) & MASK32))
      done
    done

    state_hi_ref[0]=$(((state_hi_ref[0] ^ ROUND_CONST_HI[round]) & MASK32))
    state_lo_ref[0]=$(((state_lo_ref[0] ^ ROUND_CONST_LO[round]) & MASK32))
  done
}

xor_block_from_data() {
  local -n state_hi_ref="$1"
  local -n state_lo_ref="$2"
  local -n bytes_ref="$3"
  local start=$4
  local len=$5
  local i lane shift byte
  for ((i = 0; i < len; i++)); do
    byte=${bytes_ref[start + i]}
    lane=$((i / 8))
    shift=$(((i % 8) * 8))
    if ((shift < 32)); then
      state_lo_ref[lane]=$(((state_lo_ref[lane] ^ (byte << shift)) & MASK32))
    else
      state_hi_ref[lane]=$(((state_hi_ref[lane] ^ (byte << (shift - 32))) & MASK32))
    fi
  done
}

xor_block_array() {
  local -n state_hi_ref="$1"
  local -n state_lo_ref="$2"
  local -n block_ref="$3"
  local len=${#block_ref[@]}
  local i lane shift byte
  for ((i = 0; i < len; i++)); do
    byte=${block_ref[i]}
    lane=$((i / 8))
    shift=$(((i % 8) * 8))
    if ((shift < 32)); then
      state_lo_ref[lane]=$(((state_lo_ref[lane] ^ (byte << shift)) & MASK32))
    else
      state_hi_ref[lane]=$(((state_hi_ref[lane] ^ (byte << (shift - 32))) & MASK32))
    fi
  done
}

state_to_bytes() {
  local -n state_hi_ref="$1"
  local -n state_lo_ref="$2"
  local rate=$3
  STATE_BYTES=()
  local lane offset byte_index byte
  for ((lane = 0; lane < 25; lane++)); do
    for ((offset = 0; offset < 8; offset++)); do
      byte_index=$((lane * 8 + offset))
      if ((byte_index >= rate)); then
        break 2
      fi
      if ((offset < 4)); then
        byte=$(((state_lo_ref[lane] >> (8 * offset)) & 0xFF))
      else
        byte=$(((state_hi_ref[lane] >> (8 * (offset - 4))) & 0xFF))
      fi
      STATE_BYTES+=("${byte}")
    done
  done
}

hex_to_bytes() {
  local -n dest="$1"
  local hex=${2:-}
  dest=()
  local len=${#hex}
  if ((len % 2 != 0)); then
    echo "hex input must have even length" >&2
    return 1
  fi
  local i
  for ((i = 0; i < len; i += 2)); do
    dest+=($((16#${hex:i:2})))
  done
}

keccak_digest() {
  local -n data_ref=$1
  local rate=$2
  local suffix=$3
  local digest_size=$4
  local i

# shellcheck disable=SC2034  # tracked through nameref helpers
  local -a state_hi=()
# shellcheck disable=SC2034  # tracked through nameref helpers
  local -a state_lo=()
  for ((i = 0; i < 25; i++)); do
    state_hi[i]=0
    state_lo[i]=0
  done

  local position=0
  local data_len=${#data_ref[@]}
  while ((position + rate <= data_len)); do
    xor_block_from_data state_hi state_lo data_ref "${position}" "${rate}"
    keccak_f state_hi state_lo
    position=$((position + rate))
  done

  local remaining=$((data_len - position))
  local -a block=()
  for ((i = 0; i < rate; i++)); do
    block[i]=0
  done
  for ((i = 0; i < remaining; i++)); do
    block[i]=${data_ref[position + i]}
  done
  block[remaining]=$(((block[remaining] ^ (suffix & 0xFF)) & 0xFF))
  block[rate - 1]=$(((block[rate - 1] ^ 0x80) & 0xFF))
  xor_block_array state_hi state_lo block
  keccak_f state_hi state_lo

  local -a output_bytes=()
  while ((${#output_bytes[@]} < digest_size)); do
    state_to_bytes state_hi state_lo "${rate}"
    output_bytes+=("${STATE_BYTES[@]}")
    if ((${#output_bytes[@]} >= digest_size)); then
      break
    fi
    keccak_f state_hi state_lo
  done

  local result=""
  for ((i = 0; i < digest_size; i++)); do
    printf -v byte_hex '%02x' "${output_bytes[i]}"
    result+="${byte_hex}"
  done
  printf '%s' "${result}"
}

keccak256_bytes() {
  keccak_digest "$1" 136 1 32
}

keccak256_stream() {
  local hex
  if command -v xxd >/dev/null 2>&1; then
    hex=$(xxd -p -c 0 | tr -d '\n')
  else
    hex=$(od -An -t x1 | tr -d ' \n')
  fi
# shellcheck disable=SC2034  # populated via hex_to_bytes
  local -a data=()
  hex_to_bytes data "${hex}"
  keccak256_bytes data
}

run_self_test() {
  local idx digest
# shellcheck disable=SC2034  # populated via hex_to_bytes
  local -a msg=()
  for idx in "${!CANONICAL_VECTOR_NAMES[@]}"; do
    hex_to_bytes msg "${CANONICAL_VECTOR_INPUT_HEX[idx]}"
    digest=$(keccak256_bytes msg)
    if [[ "${digest}" != "${CANONICAL_VECTOR_DIGEST_HEX[idx]}" ]]; then
      echo "Keccak-256 self-test failed for ${CANONICAL_VECTOR_NAMES[idx]}: ${digest} != ${CANONICAL_VECTOR_DIGEST_HEX[idx]}" >&2
      return 1
    fi
  done
}

usage() {
  cat <<'USAGE' >&2
usage: keccak256.sh <command>

Commands:
  keccak256-hex  Read STDIN and output Keccak-256 hex digest
  self-test      Run built-in test vectors
  vectors        Emit canonical Keccak vector JSON
USAGE
}

main() {
  local command=${1-}
  if [[ -z "${command}" ]]; then
    usage
    return 1
  fi

  case "${command}" in
    keccak256-hex)
      shift
      keccak256_stream
      ;;
    self-test)
      shift
      if run_self_test; then
        printf 'ok\n'
      else
        return 1
      fi
      ;;
    vectors)
      shift
      printf '%s' "${CANONICAL_VECTORS_JSON}"
      ;;
    -h|--help)
      usage
      ;;
    *)
      usage
      return 1
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
