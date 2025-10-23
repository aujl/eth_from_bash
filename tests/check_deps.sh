#!/usr/bin/env bash
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/common.sh
source "${TEST_DIR}/common.sh"

CHECK_DEPS_BIN="${ROOT_DIR}/bin/check-deps"
if [[ ! -x "${CHECK_DEPS_BIN}" ]]; then
  fail "dependency checker missing at ${CHECK_DEPS_BIN}"
fi

output="$(${CHECK_DEPS_BIN})" || fail "expected dependency checker to succeed"

expected_phrase="deterministic self-tests"
if [[ "${output}" != *"${expected_phrase}"* ]]; then
  fail "checker output missing phrase '${expected_phrase}'"
fi

shim_dir="$(mktemp -d)"
trap 'rm -rf "${shim_dir}"' EXIT

cat <<'SHIM' > "${shim_dir}/sha256sum"
#!/usr/bin/env bash
echo "deadbeef"
SHIM
chmod +x "${shim_dir}/sha256sum"

set +e
tampered_output="$(PATH="${shim_dir}:${PATH}" "${CHECK_DEPS_BIN}" 2>&1)"
tampered_status=$?
set -e

if [[ ${tampered_status} -eq 0 ]]; then
  fail "tampered sha256sum should cause failure"
fi

if [[ "${tampered_output}" != *"Dependency self-test failed for sha256sum"* ]]; then
  fail "tampered output did not mention sha256sum failure"
fi

pass "dependency checker self-tests"
