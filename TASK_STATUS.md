# Task Status Assessment

All previously tracked migrations away from OpenSSL and Perl have been completed with on-repo Bash helpers:

1. **Signing helper module** – `bin/crypto-sign` delegates to `scripts/crypto_sign.sh`, which dispatches to Bash implementations for HMAC, random bytes, RSA PKCS#1 v1.5, and secp256k1 ECDSA flows. 【F:bin/crypto-sign†L1-L15】【F:scripts/crypto_sign.sh†L473-L521】【F:scripts/lib/hmac.sh†L3-L155】【F:scripts/lib/rsa.sh†L4-L200】【F:scripts/lib/ecdsa.sh†L4-L200】
2. **Core flow HMAC verification** – `tests/core_flow.sh` verifies fixture integrity with the Bash `crypto-sign hmac-sha256` command instead of OpenSSL. 【F:tests/core_flow.sh†L53-L125】
3. **Detached signature generation** – `tests/recreate_signed_artifacts.sh` derives fixture HMACs through `scripts/crypto_kdf.sh` and signs vectors via `bin/crypto-sign`. 【F:tests/recreate_signed_artifacts.sh†L1-L63】【F:tests/recreate_signed_artifacts.sh†L72-L104】
4. **Maintainer key generation** – `tests/generate_maintainer_keys.sh` produces and refreshes maintainer key material exclusively with `bin/crypto-sign` RSA/ECDSA commands. 【F:tests/generate_maintainer_keys.sh†L21-L88】
5. **Regression coverage** – `tests/crypto_sign_regression.sh` exercises RSA and secp256k1 signing, verification, public derivation, and key generation using the Bash helpers. 【F:tests/crypto_sign_regression.sh†L8-L160】

No further work is required for the Bash migration items documented in the earlier status report.
