#!/usr/bin/env python3
"""Helper for deriving BIP-39 seed material and secp256k1 public keys."""

import argparse
import binascii
import sys
from hashlib import pbkdf2_hmac
from typing import Optional, Tuple

USE_ECDSA = True
try:
    from ecdsa import SECP256k1, SigningKey
except ImportError:  # pragma: no cover - handled by caller environment
    USE_ECDSA = False

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
    result: Optional[Point] = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
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
    if USE_ECDSA:
        sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
        point = sk.verifying_key.pubkey.point
        x = point.x()
        y = point.y()
    else:
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


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    seed_parser = subparsers.add_parser("seed", help="Derive BIP-39 seed")
    seed_parser.add_argument("--mnemonic", required=True, help="Mnemonic phrase")
    seed_parser.add_argument("--passphrase", default="", help="Optional passphrase")

    pub_parser = subparsers.add_parser("pub", help="Derive secp256k1 pubkeys from private key hex")
    pub_parser.add_argument("--priv-hex", required=True, help="Private key hex (64 chars)")

    args = parser.parse_args(argv)

    if args.command == "seed":
        seed_hex = derive_seed(args.mnemonic, args.passphrase)
        print(seed_hex)
        return 0

    if args.command == "pub":
        compressed, uncompressed = derive_pubkeys(args.priv_hex)
        print(f"{compressed} {uncompressed}")
        return 0

    parser.error("unknown command")
    return 1


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    sys.exit(main(sys.argv[1:]))
