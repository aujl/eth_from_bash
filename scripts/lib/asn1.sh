# shellcheck shell=bash

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

der_read_explicit() {
  der_read_tlv "$1" "$2" "${3,,}"
  DER_EXPLICIT_HEX="${DER_VALUE}"
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
  local hex="${1,,}"
  local offset="$2"
  (( offset * 2 == ${#hex} )) || die "DER: unexpected trailing data"
}

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
  value="$(normalize_hex "$1")"
  if [[ -z "${value}" ]]; then
    value="00"
  fi
  while (( ${#value} > 2 )); do
    if [[ ${value:0:2} != "00" ]]; then
      break
    fi
    if (( 16#${value:2:2} >= 0x80 )); then
      break
    fi
    value="${value:2}"
  done
  if (( 16#${value:0:2} >= 0x80 )); then
    value="00${value}"
  fi
  der_encode_tlv_hex "02" "${value}"
}

der_encode_octet_string_hex() {
  local content
  content="$(normalize_hex "$1")"
  der_encode_tlv_hex "04" "${content}"
}

der_encode_bit_string_hex() {
  local content
  content="$(normalize_hex "$1")"
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
    local i
    for (( i=${#stack[@]}-1; i>=0; i-- )); do
      local byte=$((16#${stack[i]}))
      if (( i != 0 )); then
        byte=$((byte | 0x80))
      fi
      encoded+=$(printf '%02x' "${byte}")
    done
  done
  der_encode_tlv_hex "06" "${encoded}"
}

der_encode_null_hex() {
  der_encode_tlv_hex "05" ""
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
