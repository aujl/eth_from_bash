#!/usr/bin/env python3
import sys

from keccak_primitives import keccak256_hex


def main() -> None:
    data = sys.stdin.buffer.read()
    sys.stdout.write(keccak256_hex(data))


if __name__ == "__main__":
    main()
