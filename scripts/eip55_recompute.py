#!/usr/bin/env python3
import sys

from keccak_primitives import keccak256_hex


def checksum(addr: str) -> str:
    if addr.startswith("0x") or addr.startswith("0X"):
        addr = addr[2:]
    lc = addr.lower()
    h = keccak256_hex(lc.encode("ascii"))
    out = []
    for i, c in enumerate(lc):
        if c in "abcdef" and int(h[i], 16) >= 8:
            out.append(c.upper())
        else:
            out.append(c)
    return "0x" + "".join(out)


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: eip55_recompute.py 0x<hexaddr>", file=sys.stderr)
        sys.exit(2)
    try:
        print(checksum(sys.argv[1]))
    except Exception as exc:
        print("error:", exc, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
