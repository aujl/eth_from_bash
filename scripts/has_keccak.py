#!/usr/bin/env python3
try:
    from Crypto.Hash import keccak  # type: ignore
    print("ok")
    raise SystemExit(0)
except Exception:
    raise SystemExit(1)

