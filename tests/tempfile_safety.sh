#!/usr/bin/env bash
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/common.sh
source "${TESTS_DIR}/common.sh"

if grep -RIn "mktemp -u" "${TESTS_DIR}" --exclude="tempfile_safety.sh" >/dev/null 2>&1; then
  grep -RIn "mktemp -u" "${TESTS_DIR}" --exclude="tempfile_safety.sh" >&2 || true
  fail "disallowed mktemp -u detected in tests/; use mktemp without -u"
fi

pass "tests do not use insecure mktemp -u"
