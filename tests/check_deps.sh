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

expected_phrase="All required CLI deps passed deterministic self-tests: jq JSON query, bc division, xxd hex encode, awk arithmetic, sha256sum/sha512sum known digests, crypto-sign HMAC."
if [[ "${output}" != *"${expected_phrase}"* ]]; then
  fail "checker output missing phrase '${expected_phrase}'"
fi

crypto_shim_dir=""
sha_shim_dir="$(mktemp -d)"
trap 'rm -rf "${sha_shim_dir}" "${crypto_shim_dir}"' EXIT

cat <<'SHIM' > "${sha_shim_dir}/sha256sum"
#!/usr/bin/env bash
echo "deadbeef"
SHIM
chmod +x "${sha_shim_dir}/sha256sum"

set +e
tampered_output="$(PATH="${sha_shim_dir}:${PATH}" "${CHECK_DEPS_BIN}" 2>&1)"
tampered_status=$?
set -e

if [[ ${tampered_status} -eq 0 ]]; then
  fail "tampered sha256sum should cause failure"
fi

if [[ "${tampered_output}" != *"Dependency self-test failed for sha256sum"* ]]; then
  fail "tampered output did not mention sha256sum failure"
fi

crypto_shim_dir="$(mktemp -d)"

cat <<'SHIM' > "${crypto_shim_dir}/crypto-sign"
#!/usr/bin/env bash
if [[ "$1" == "hmac-sha256" ]]; then
  printf 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n'
  exit 0
fi
echo "unexpected invocation" >&2
exit 1
SHIM
chmod +x "${crypto_shim_dir}/crypto-sign"

set +e
crypto_tampered_output="$(PATH="${crypto_shim_dir}:${PATH}" "${CHECK_DEPS_BIN}" 2>&1)"
crypto_tampered_status=$?
set -e

if [[ ${crypto_tampered_status} -eq 0 ]]; then
  fail "tampered crypto-sign should cause failure"
fi

if [[ "${crypto_tampered_output}" != *"Dependency self-test failed for crypto-sign hmac-sha256"* ]]; then
  fail "tampered output did not mention crypto-sign failure"
fi

pass "dependency checker self-tests"
