#!/usr/bin/env python3
import sys

def main():
    data = sys.stdin.buffer.read()
    try:
        from Crypto.Hash import keccak
    except Exception as e:
        sys.stderr.write("missing pycryptodome keccak: {}\n".format(e))
        sys.exit(2)
    k = keccak.new(digest_bits=256)
    k.update(data)
    sys.stdout.write(k.hexdigest())

if __name__ == "__main__":
    main()

