#!/usr/bin/env bash
set -euo pipefail

missing=0
deps=(jq bc xxd awk sha256sum sha512sum perl)
for cmd in "${deps[@]}"; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Missing dependency: ${cmd}" >&2
    missing=1
  fi
done

if [[ ${missing} -eq 1 ]]; then
  echo "Install missing dependencies and retry." >&2
  exit 1
fi

echo "All required CLI deps present: ${deps[*]} (bc/xxd + sha256sum/sha512sum provide hashing + math primitives)"
