#!/usr/bin/env python3
"""Cryptographic key derivation helpers."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import sys
from typing import Callable


class HexDecodingError(ValueError):
    """Raised when hex decoding fails."""


def _decode_hex(label: str, value: str) -> bytes:
    stripped = value.strip()
    if len(stripped) == 0:
        raise HexDecodingError(f"{label} must be non-empty hex")
    if len(stripped) % 2 != 0:
        raise HexDecodingError(f"{label} must have an even number of characters")
    try:
        return bytes.fromhex(stripped)
    except ValueError as exc:
        raise HexDecodingError(f"{label} must be hexadecimal") from exc


def pbkdf2_command(args: argparse.Namespace) -> int:
    mnemonic = args.mnemonic
    passphrase = args.passphrase
    iterations = args.iterations
    salt = "mnemonic" + passphrase
    derived = hashlib.pbkdf2_hmac(
        "sha512",
        mnemonic.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
        dklen=64,
    )
    print(derived.hex())
    return 0


def hmac_sha512_command(args: argparse.Namespace) -> int:
    key_bytes = _decode_hex("key", args.key_hex)
    data_bytes = _decode_hex("data", args.data_hex)
    digest = hmac.new(key_bytes, data_bytes, hashlib.sha512).digest()
    print(digest.hex())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Internal cryptographic helpers for eth-from-bash",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    pbkdf2_parser = subparsers.add_parser(
        "pbkdf2", help="Derive BIP-39 seed using PBKDF2-HMAC-SHA512"
    )
    pbkdf2_parser.add_argument("--mnemonic", required=True, help="Mnemonic phrase")
    pbkdf2_parser.add_argument(
        "--passphrase",
        required=False,
        default="",
        help="Optional mnemonic passphrase",
    )
    pbkdf2_parser.add_argument(
        "--iterations",
        type=int,
        default=2048,
        help="Number of PBKDF2 iterations (default: 2048)",
    )
    pbkdf2_parser.set_defaults(func=pbkdf2_command)

    hmac_parser = subparsers.add_parser(
        "hmac-sha512", help="Compute HMAC-SHA512 over hex inputs"
    )
    hmac_parser.add_argument("--key-hex", required=True, help="Hex-encoded key")
    hmac_parser.add_argument("--data-hex", required=True, help="Hex-encoded data")
    hmac_parser.set_defaults(func=hmac_sha512_command)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        func: Callable[[argparse.Namespace], int] = getattr(args, "func")
        return func(args)
    except HexDecodingError as exc:
        parser.error(str(exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
