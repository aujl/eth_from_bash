# RSA prime churn baseline

This baseline captures bc invocation churn for the RSA helper on Ubuntu 24.04 inside the Codestral-provided container (`uname -a`: `Linux e26c854414ee 6.12.13 #1 SMP Thu Mar 13 11:34:50 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux`). Each run was executed via `scripts/rsa_prime_churn.sh` with the default exponent (65537) after installing `bc`.

| bits | exponent | duration_ms | bc_simple | bc_eval_common | generate_prime_dec |
| ---- | -------- | ----------- | --------- | -------------- | ------------------ |
| 512  | 65537    | 45624       | 149       | 39             | 2                  |
| 1024 | 65537    | 52445       | 151       | 34             | 2                  |
| 2048 | 65537    | 113770      | 232       | 41             | 2                  |

> **Note:** Attempts to gather a 4096-bit datapoint exceeded the time budget for this session (progress surpassed 800 `bc_simple` invocations without completing). Maintainers running on less resource-constrained hosts should be able to extend this table with the 4096-bit result for a fuller baseline.
