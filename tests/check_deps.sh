#!/usr/bin/env bash
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/common.sh
source "${TEST_DIR}/common.sh"

CHECK_DEPS_BIN="${ROOT_DIR}/bin/check-deps"
if [[ ! -x "${CHECK_DEPS_BIN}" ]]; then
  fail "dependency checker missing at ${CHECK_DEPS_BIN}"
fi

sha2_lib="${ROOT_DIR}/scripts/lib/crypto/sha2.sh"
if [[ ! -r "${sha2_lib}" ]]; then
  fail "sha2 helper missing at ${sha2_lib}"
fi

# shellcheck source=scripts/lib/crypto/sha2.sh
source "${sha2_lib}"

if [[ "$(printf 'abc' | sha256_hex_from_stream)" != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ]]; then
  fail "sha256 helper failed known vector"
fi

if [[ "$(printf 'abc' | sha512_hex_from_stream)" != "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" ]]; then
  fail "sha512 helper failed known vector"
fi

output="$(${CHECK_DEPS_BIN})" || fail "expected dependency checker to succeed"

expected_phrase="All required CLI deps passed deterministic self-tests: jq JSON query, bc division, xxd hex encode, awk arithmetic, built-in SHA-256/SHA-512 helper digests, crypto-sign HMAC."
if [[ "${output}" != *"${expected_phrase}"* ]]; then
  fail "checker output missing phrase '${expected_phrase}'"
fi

sha_override_file="$(mktemp)"
crypto_shim_dir=""
trap 'rm -f "${sha_override_file}"; rm -rf "${crypto_shim_dir}"' EXIT

cat <<'OVERRIDE' > "${sha_override_file}"
sha256_hex_from_stream() {
  printf 'deadbeef\n'
}

sha512_hex_from_stream() {
  printf 'deadbeef\n'
}
OVERRIDE

set +e
tampered_output="$(BASH_ENV="${sha_override_file}" "${CHECK_DEPS_BIN}" 2>&1)"
tampered_status=$?
set -e

if [[ ${tampered_status} -eq 0 ]]; then
  fail "tampered sha2 helper should cause failure"
fi

if [[ "${tampered_output}" != *"Dependency self-test failed for sha256 helper"* ]]; then
  fail "tampered output did not mention sha256 helper failure"
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
crypto_tampered_output="$(BASH_ENV="${sha_override_file}" PATH="${crypto_shim_dir}:${PATH}" "${CHECK_DEPS_BIN}" 2>&1)"
crypto_tampered_status=$?
set -e

if [[ ${crypto_tampered_status} -eq 0 ]]; then
  fail "tampered crypto-sign should cause failure"
fi

if [[ "${crypto_tampered_output}" != *"Dependency self-test failed for crypto-sign hmac-sha256"* ]]; then
  fail "tampered output did not mention crypto-sign failure"
fi

pass "dependency checker self-tests"
