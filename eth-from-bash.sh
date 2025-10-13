#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_ENTRYPOINT="${SCRIPT_DIR}/bin/eth-from-bash"

if [[ ! -x "${CLI_ENTRYPOINT}" ]]; then
  echo "CLI entrypoint '${CLI_ENTRYPOINT}' not executable" >&2
  exit 1
fi

exec "${CLI_ENTRYPOINT}" "$@"
