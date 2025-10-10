#!/usr/bin/env bash
# Compute an EIP-55 checksummed address using the Bash Keccak helper.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KECCAK_HELPER="${SCRIPT_DIR}/keccak256.sh"

usage() {
  cat <<'USAGE' >&2
usage: eip55_checksum.sh 0x<hex-address>
USAGE
}

if [[ $# -ne 1 ]]; then
  usage
  exit 1
fi

if [[ ! -x "${KECCAK_HELPER}" ]]; then
  echo "Keccak helper '${KECCAK_HELPER}' not executable" >&2
  exit 1
fi

addr="${1//[[:space:]]/}"
addr="${addr#0x}"
addr="${addr#0X}"

if [[ ! "${addr}" =~ ^[0-9A-Fa-f]{40}$ ]]; then
  echo "invalid address: must be 40 hex characters" >&2
  exit 1
fi

lower="${addr,,}"
digest="$(printf '%s' "${lower}" | "${KECCAK_HELPER}" keccak256-hex)"

if [[ ${#digest} -ne 64 ]]; then
  echo "Keccak helper returned unexpected digest length" >&2
  exit 1
fi

checksum=""
for ((i = 0; i < 40; i++)); do
  ch="${lower:i:1}"
  if [[ "${ch}" =~ [a-f] ]]; then
    nibble="${digest:i:1}"
    if (( 16#${nibble} >= 8 )); then
      ch="${ch^^}"
    fi
  fi
  checksum+="${ch}"
done

printf '0x%s\n' "${checksum}"
