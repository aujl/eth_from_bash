#!/usr/bin/env python3
import sys

from keccak_primitives import run_self_test

try:
    run_self_test()
except Exception as exc:  # pragma: no cover - diagnostic path
    print(f"self-test failed: {exc}", file=sys.stderr)
    raise SystemExit(1)
else:
    print("ok")
    raise SystemExit(0)
