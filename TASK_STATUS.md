# Task Status Assessment

The previously requested migration from OpenSSL/Python helpers to Bash-only implementations has **not** been completed. The current repository still relies on the original tooling for the listed tasks:

1. **New signing helper module** – There is no `scripts/crypto_sign.py` (or Bash replacement) implementing HMAC-SHA256, RSA PKCS#1 v1.5, or secp256k1 ECDSA logic; the `scripts/` directory contains only the original helpers. 【5aa8bc†L1-L3】
2. **Core flow HMAC verification** – `tests/core_flow.sh` continues to call `openssl dgst` for HMAC verification instead of a Bash helper. 【F:tests/core_flow.sh†L52-L69】
3. **Detached signature generation** – `tests/recreate_signed_artifacts.sh` still shells out to `openssl` for random key material, HMAC generation, and RSA/ECDSA signatures; it does not invoke a Bash replacement. 【F:tests/recreate_signed_artifacts.sh†L44-L78】
4. **Maintainer key generation** – `tests/generate_maintainer_keys.sh` relies on `openssl genpkey`/`pkey` for RSA and secp256k1 key creation. 【F:tests/generate_maintainer_keys.sh†L61-L66】
5. **Regression coverage** – The test suite retains the OpenSSL verification path in `tests/keccak_primitive.sh` and `tests/secp256k1_primitive.sh`; no new Bash-based regression checks exist. 【F:tests/keccak_primitive.sh†L80-L80】【F:tests/secp256k1_primitive.sh†L27-L27】

Additional work is therefore required to provide Bash-based implementations for the cryptographic operations and to update the tests accordingly.
