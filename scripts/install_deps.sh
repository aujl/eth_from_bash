#!/usr/bin/env bash
set -euo pipefail

# Mapping of required commands to their corresponding apt packages
declare -A pkg_map=(
  [jq]=jq
  [bc]=bc
  [xxd]=xxd
  [openssl]=openssl
  [perl]=perl
  [python3]=python3
)

missing_pkgs=()

for cmd in "${!pkg_map[@]}"; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    missing_pkgs+=("${pkg_map[${cmd}]}")
  fi
done

if ((${#missing_pkgs[@]} == 0)); then
  exit 0
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "Missing dependencies: ${missing_pkgs[*]}" >&2
  echo "apt-get not available to install packages automatically." >&2
  exit 1
fi

echo "Installing missing packages via apt-get: ${missing_pkgs[*]}"

sudo_cmd=()
if [[ ${EUID} -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    sudo_cmd=(sudo)
  else
    echo "Cannot escalate privileges to install packages: ${missing_pkgs[*]}" >&2
    exit 1
  fi
fi

"${sudo_cmd[@]}" apt-get update
"${sudo_cmd[@]}" apt-get install -y "${missing_pkgs[@]}"
