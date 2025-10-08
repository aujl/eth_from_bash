#!/usr/bin/env bash
set -euo pipefail

if ! command -v shellcheck >/dev/null 2>&1; then
  echo "shellcheck not found; skipping lint. Install with: sudo apt-get install shellcheck" >&2
  exit 0
fi

targets=(
  tests/run.sh
  scripts/*.sh
)

# Expand globs safely
files=()
for pat in "${targets[@]}"; do
  while IFS= read -r f; do
    files+=("$f")
  done < <(compgen -G "$pat" || true)
done

if ((${#files[@]}==0)); then
  echo "No shell scripts to lint." >&2
  exit 0
fi

echo "Running shellcheck on: ${files[*]}"
# Use warning severity for broader compatibility; fail CI on findings
shellcheck -S warning -o all "${files[@]}"
echo "Shellcheck passed."
