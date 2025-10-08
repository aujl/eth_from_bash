#!/usr/bin/env bash
set -euo pipefail

if ! command -v shellcheck >/dev/null 2>&1; then
  echo "shellcheck not found; skipping lint. Install with: sudo apt-get install shellcheck" >&2
  exit 0
fi

targets=(
  eth-from-bash.sh
  tests/run.sh
  scripts/*.sh
)

# Expand globs safely
shopt -s nullglob
files=()
for pat in "${targets[@]}"; do
  for f in $pat; do files+=("$f"); done
done

if ((${#files[@]}==0)); then
  echo "No shell scripts to lint." >&2
  exit 0
fi

echo "Running shellcheck on: ${files[*]}"
shellcheck -S style -o all "${files[@]}"
echo "Shellcheck passed."

