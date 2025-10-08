#!/usr/bin/env python3
"""Helper for deriving BIP-39 seed material and secp256k1 public keys."""

import argparse
import binascii
import sys
from hashlib import pbkdf2_hmac
from typing import Optional, Tuple

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


Point = Tuple[int, int]


def _point_add(p1: Optional[Point], p2: Optional[Point]) -> Optional[Point]:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p1 == p2:
        m = (3 * x1 * x1) * pow(2 * y1, _P - 2, _P)
    else:
        m = (y2 - y1) * pow(x2 - x1, _P - 2, _P)
    m %= _P
    x3 = (m * m - x1 - x2) % _P
    y3 = (m * (x1 - x3) - y1) % _P
    return x3, y3


def _scalar_mult(k: int, point: Point) -> Point:
    """Multiply *point* by scalar *k* using double-and-add.

    The routine performs a left-to-right double-and-add using Python integers.
    This implementation is not constant time because it branches on the bits of
    *k*. Callers must ensure that *k* is a fully sanitised secret (uniformly
    random and never attacker-controlled) before invoking this helper. The CLI
    validates scalars tightly before they reach this function.
    """

    if k <= 0 or k >= _N:
        raise SystemExit("Scalar out of range for multiplication")

    result: Optional[Point] = None
    addend = point
    mask = k
    while mask:
        if mask & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        mask >>= 1
    if result is None:
        raise SystemExit("Scalar multiplication resulted in point at infinity")
    return result


def derive_seed(mnemonic: str, passphrase: str) -> str:
    """Derive the BIP-39 seed using PBKDF2-HMAC-SHA512."""
    salt = "mnemonic" + passphrase
    seed = pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), salt.encode("utf-8"), 2048, dklen=64)
    return seed.hex()


def derive_pubkeys(priv_hex: str) -> tuple[str, str]:
    """Derive compressed and uncompressed secp256k1 public keys."""
    try:
        priv_bytes = binascii.unhexlify(priv_hex)
    except (binascii.Error, ValueError) as exc:
        raise SystemExit("Private key must be valid hex") from exc
    if len(priv_bytes) != 32:
        raise SystemExit("Private key must be 32 bytes (64 hex characters)")
    priv_int = int.from_bytes(priv_bytes, "big")
    if priv_int <= 0 or priv_int >= _N:
        raise SystemExit("Private key scalar out of range")
    x, y = _scalar_mult(priv_int, (_GX, _GY))
    x_bytes = x.to_bytes(32, "big")
    y_bytes = y.to_bytes(32, "big")
    uncompressed = b"\x04" + x_bytes + y_bytes
    prefix = 0x02 | (y & 1)
    compressed = bytes([prefix]) + x_bytes
    return compressed.hex(), uncompressed.hex()


def _run_selftest() -> None:
    """Execute internal correctness checks for the secp256k1 helper."""

    # 1. Generator multiplication should yield the canonical generator.
    gen_x, gen_y = _scalar_mult(1, (_GX, _GY))
    if (gen_x, gen_y) != (_GX, _GY):
        raise SystemExit("Generator self-test failed")

    # 2. Doubling the generator must match the known SEC1 test vector.
    two_x, two_y = _scalar_mult(2, (_GX, _GY))
    if (
        two_x
        != 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
        or two_y
        != 0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A
    ):
        raise SystemExit("Generator doubling self-test failed")

    # 3. Derive the canonical public key for scalar 1 and compare both encodings.
    comp, uncomp = derive_pubkeys(
        "0000000000000000000000000000000000000000000000000000000000000001"
    )
    if comp != "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798":
        raise SystemExit("Compressed derivation self-test failed")
    if (
        uncomp
        != "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    ):
        raise SystemExit("Uncompressed derivation self-test failed")

    # 4. Ensure edge scalars are rejected.
    for invalid in ("00" * 32, f"{_N:064x}"):
        try:
            derive_pubkeys(invalid)
        except SystemExit:
            continue
        raise SystemExit("Scalar validation self-test failed")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    seed_parser = subparsers.add_parser("seed", help="Derive BIP-39 seed")
    seed_parser.add_argument("--mnemonic", required=True, help="Mnemonic phrase")
    seed_parser.add_argument("--passphrase", default="", help="Optional passphrase")

    pub_parser = subparsers.add_parser("pub", help="Derive secp256k1 pubkeys from private key hex")
    pub_parser.add_argument("--priv-hex", required=True, help="Private key hex (64 chars)")

    subparsers.add_parser(
        "selftest", help="Run internal secp256k1 primitive validation"
    )

    args = parser.parse_args(argv)

    if args.command == "seed":
        seed_hex = derive_seed(args.mnemonic, args.passphrase)
        print(seed_hex)
        return 0

    if args.command == "pub":
        compressed, uncompressed = derive_pubkeys(args.priv_hex)
        print(f"{compressed} {uncompressed}")
        return 0

    if args.command == "selftest":
        _run_selftest()
        print("secp256k1 self-test passed")
        return 0

    parser.error("unknown command")
    return 1


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    sys.exit(main(sys.argv[1:]))
