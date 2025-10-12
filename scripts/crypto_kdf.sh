#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

usage() {
  cat <<'USAGE'
Usage: crypto_kdf.sh <command> [options]

Commands:
  pbkdf2         Derive PBKDF2-HMAC-SHA512 seed (BIP-39 semantics)
  hmac-sha512    Compute HMAC-SHA512 over hex-encoded inputs
  hmac-sha256    Compute HMAC-SHA256 over hex-encoded inputs
USAGE
}

error() {
  local message=$1
  echo "${message}" >&2
}

validate_hex() {
  local label=$1
  local value=$2
  local trimmed
  trimmed=${value//$'\t\r\n '/}
  if [[ -z ${trimmed} ]]; then
    error "${label} must be non-empty hex"
    exit 2
  fi
  if (( ${#trimmed} % 2 != 0 )); then
    error "${label} must have an even number of characters"
    exit 2
  fi
  if [[ ! ${trimmed} =~ ^[0-9A-Fa-f]+$ ]]; then
    error "${label} must be hexadecimal"
    exit 2
  fi
  printf '%s' "${trimmed,,}"
}

ascii_to_hex() {
  local input=$1
  if [[ -z ${input} ]]; then
    printf ''
    return
  fi
  printf '%s' "${input}" | xxd -p -c 256 | tr -d '\n'
}

hmac_hex() {
  local algo=$1
  local key_hex=$2
  local data_hex=$3
  perl - "${algo}" "${key_hex}" "${data_hex}" <<'PERL'
use strict;
use warnings;
use Digest::SHA qw(hmac_sha256_hex hmac_sha512_hex);
my ($algo, $key_hex, $data_hex) = @ARGV;
my $key = pack('H*', $key_hex);
my $data = pack('H*', $data_hex);
if ($algo eq 'sha512') {
  print hmac_sha512_hex($data, $key);
} elsif ($algo eq 'sha256') {
  print hmac_sha256_hex($data, $key);
} else {
  die "unsupported hmac algo: $algo";
}
PERL
}

pbkdf2_hmac_sha512() {
  local password_hex=$1
  local salt_hex=$2
  local iterations=$3
  local dk_len_bytes=64
  perl - "${password_hex}" "${salt_hex}" "${iterations}" "${dk_len_bytes}" <<'PERL'
use strict;
use warnings;
use Digest::SHA qw(hmac_sha512);
my ($password_hex, $salt_hex, $iterations, $dk_len_bytes) = @ARGV;
my $password = pack('H*', $password_hex);
my $salt = pack('H*', $salt_hex);
my $iters = int($iterations);
die "iterations must be positive" if $iters <= 0;
my $dk_len = int($dk_len_bytes);
my $hlen = 64;
my $block_count = int(($dk_len + $hlen - 1) / $hlen);
my $derived = '';
for my $block (1 .. $block_count) {
  my $u = hmac_sha512($salt . pack('N', $block), $password);
  my $t = $u;
  for (my $i = 2; $i <= $iters; $i++) {
    $u = hmac_sha512($u, $password);
    $t ^= $u;
  }
  $derived .= $t;
}
print unpack('H*', substr($derived, 0, $dk_len));
PERL
}

command_hmac_sha512() {
  local key_hex=""
  local data_hex=""
  while [[ $# -gt 0 ]]; do
    case $1 in
      --key-hex)
        shift
        if [[ $# -eq 0 ]]; then
          error "--key-hex requires a value"
          exit 2
        fi
        key_hex=$(validate_hex "key" "$1")
        shift
        ;;
      --data-hex)
        shift
        if [[ $# -eq 0 ]]; then
          error "--data-hex requires a value"
          exit 2
        fi
        data_hex=$(validate_hex "data" "$1")
        shift
        ;;
      *)
        error "Unknown argument: $1"
        exit 2
        ;;
    esac
  done
  printf '%s\n' "$(hmac_hex sha512 "${key_hex}" "${data_hex}")"
}

command_hmac_sha256() {
  local key_hex=""
  local data_hex=""
  while [[ $# -gt 0 ]]; do
    case $1 in
      --key-hex)
        shift
        if [[ $# -eq 0 ]]; then
          error "--key-hex requires a value"
          exit 2
        fi
        key_hex=$(validate_hex "key" "$1")
        shift
        ;;
      --data-hex)
        shift
        if [[ $# -eq 0 ]]; then
          error "--data-hex requires a value"
          exit 2
        fi
        data_hex=$(validate_hex "data" "$1")
        shift
        ;;
      *)
        error "Unknown argument: $1"
        exit 2
        ;;
    esac
  done
  printf '%s\n' "$(hmac_hex sha256 "${key_hex}" "${data_hex}")"
}

command_pbkdf2() {
  local mnemonic=""
  local passphrase=""
  local iterations=2048
  while [[ $# -gt 0 ]]; do
    case $1 in
      --mnemonic)
        shift
        if [[ $# -eq 0 ]]; then
          error "--mnemonic requires a value"
          exit 2
        fi
        mnemonic=$1
        shift
        ;;
      --passphrase)
        shift
        if [[ $# -eq 0 ]]; then
          error "--passphrase requires a value"
          exit 2
        fi
        passphrase=$1
        shift
        ;;
      --iterations)
        shift
        if [[ $# -eq 0 ]]; then
          error "--iterations requires a value"
          exit 2
        fi
        iterations=$1
        shift
        ;;
      *)
        error "Unknown argument: $1"
        exit 2
        ;;
    esac
  done
  if [[ -z ${mnemonic} ]]; then
    error "Mnemonic is required"
    exit 2
  fi
  if [[ ! ${iterations} =~ ^[0-9]+$ ]]; then
    error "Iterations must be a positive integer"
    exit 2
  fi
  if (( iterations <= 0 )); then
    error "Iterations must be greater than zero"
    exit 2
  fi
  local salt="mnemonic${passphrase}"
  local mnemonic_hex
  mnemonic_hex=$(ascii_to_hex "${mnemonic}")
  local salt_hex
  salt_hex=$(ascii_to_hex "${salt}")
  local derived
  derived=$(pbkdf2_hmac_sha512 "${mnemonic_hex}" "${salt_hex}" "${iterations}")
  printf '%s\n' "${derived}"
}

main() {
  if [[ $# -eq 0 ]]; then
    usage >&2
    exit 2
  fi
  local command=$1
  shift || true
  case ${command} in
    pbkdf2)
      command_pbkdf2 "$@"
      ;;
    hmac-sha512)
      command_hmac_sha512 "$@"
      ;;
    hmac-sha256)
      command_hmac_sha256 "$@"
      ;;
    -h|--help)
      usage
      ;;
    *)
      error "Unknown command: ${command}"
      usage >&2
      exit 2
      ;;
  esac
}

main "$@"
