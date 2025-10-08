#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

if [[ ! -d .venv ]]; then
  python3 -m venv .venv || python3 -m venv --without-pip .venv
fi

# Activate and ensure pip exists
# shellcheck source=/dev/null disable=SC1091
source .venv/bin/activate
python - <<'PY' >/dev/null 2>&1 || true
import ensurepip, sys
ensurepip.bootstrap()
PY

pip install --upgrade pip >/dev/null

echo "Virtualenv ready at .venv"
