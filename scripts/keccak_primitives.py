#!/usr/bin/env python3
"""Constant-time Keccak-256 primitives and CLI helpers."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Iterable, List, Sequence

_MASK_64 = (1 << 64) - 1
_ROUND_CONSTANTS: Sequence[int] = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)
_ROTATION_OFFSETS: Sequence[Sequence[int]] = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
_CANONICAL_VECTORS = (
    {
        "name": "empty",
        "input_hex": "",
        "digest_hex": "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    },
    {
        "name": "abc",
        "input_hex": "616263",
        "digest_hex": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
    },
    {
        "name": "quickfox",
        "input_hex": "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
        "digest_hex": "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
    },
    {
        "name": "nist_a3_200",
        "input_hex": "a3"
        * 200,
        "digest_hex": "3a57666b048777f2c953dc4456f45a2588e1cb6f2da760122d530ac2ce607d4a",
    },
)


def _rotl(value: int, offset: int) -> int:
    offset &= 63
    return ((value << offset) & _MASK_64) | ((value & _MASK_64) >> (64 - offset))


def _keccak_f(state: List[int]) -> None:
    for rc in _ROUND_CONSTANTS:
        c = [0] * 5
        for x in range(5):
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
        d = [0] * 5
        for x in range(5):
            d[x] = c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1)
        for x in range(5):
            for y in range(5):
                idx = x + 5 * y
                state[idx] = (state[idx] ^ d[x]) & _MASK_64
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                idx = x + 5 * y
                b_idx = y + 5 * ((2 * x + 3 * y) % 5)
                b[b_idx] = _rotl(state[idx], _ROTATION_OFFSETS[x][y])
        for x in range(5):
            for y in range(5):
                idx = x + 5 * y
                state[idx] = (
                    b[idx]
                    ^ ((~b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y])
                ) & _MASK_64
        state[0] ^= rc
        state[0] &= _MASK_64


def _xor_into_state(state: List[int], block: bytes) -> None:
    for i, byte in enumerate(block):
        lane = i // 8
        shift = (i % 8) * 8
        state[lane] ^= (byte & 0xFF) << shift
        state[lane] &= _MASK_64


def _state_to_bytes(state: Sequence[int], rate_bytes: int) -> bytes:
    lanes = rate_bytes // 8
    out = bytearray(rate_bytes)
    for lane_index in range(lanes):
        lane_value = state[lane_index]
        for offset in range(8):
            byte_index = lane_index * 8 + offset
            if byte_index >= rate_bytes:
                break
            out[byte_index] = (lane_value >> (8 * offset)) & 0xFF
    return bytes(out)


def _sponge(rate_bytes: int, data: bytes, suffix: int, digest_size: int) -> bytes:
    state = [0] * 25
    rate = rate_bytes
    position = 0
    while position + rate <= len(data):
        block = data[position : position + rate]
        _xor_into_state(state, block)
        _keccak_f(state)
        position += rate
    tail = data[position:]
    block = bytearray(rate)
    block[: len(tail)] = tail
    block[len(tail)] ^= suffix & 0xFF
    block[rate - 1] ^= 0x80
    _xor_into_state(state, bytes(block))
    _keccak_f(state)
    output = bytearray()
    while len(output) < digest_size:
        output.extend(_state_to_bytes(state, rate))
        if len(output) >= digest_size:
            break
        _keccak_f(state)
    return bytes(output[:digest_size])


def keccak256(data: bytes) -> bytes:
    """Compute Keccak-256 digest for *data*."""
    return _sponge(136, data, 0x01, 32)


def keccak256_hex(data: bytes) -> str:
    return keccak256(data).hex()


def run_self_test() -> None:
    for vector in _CANONICAL_VECTORS:
        msg = bytes.fromhex(vector["input_hex"])
        expected = vector["digest_hex"]
        digest = keccak256_hex(msg)
        if digest != expected:
            raise RuntimeError(
                f"Keccak-256 self-test failed for {vector['name']}: {digest} != {expected}"
            )


def _dump_vectors() -> str:
    return json.dumps(_CANONICAL_VECTORS, separators=(",", ":"), sort_keys=True)


def _build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Keccak-256 helper utilities")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("keccak256-hex", help="Read stdin and emit Keccak-256 hex digest")
    sub.add_parser("self-test", help="Run internal test vectors")
    sub.add_parser("vectors", help="Emit canonical Keccak vector JSON")
    return parser


def _cmd_keccak256_hex() -> int:
    data = sys.stdin.buffer.read()
    sys.stdout.write(keccak256_hex(data))
    return 0


def _cmd_self_test() -> int:
    run_self_test()
    sys.stdout.write("ok\n")
    return 0


def _cmd_vectors() -> int:
    sys.stdout.write(_dump_vectors())
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    parser = _build_cli()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.command == "keccak256-hex":
        return _cmd_keccak256_hex()
    if args.command == "self-test":
        return _cmd_self_test()
    if args.command == "vectors":
        return _cmd_vectors()
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
