#!/usr/bin/env python3
"""Lightweight secp256k1 helpers for shell scripts."""
import sys
from typing import Optional, Tuple

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

Point = Optional[Tuple[int, int]]


def _normalize_hex(value: str) -> str:
    cleaned = ''.join(ch for ch in value if ch.lower() in '0123456789abcdef')
    if not cleaned:
        return '0'
    return cleaned.lstrip('0') or '0'


def _point_from_hex(x_hex: str, y_hex: str) -> Point:
    x_hex = _normalize_hex(x_hex)
    y_hex = _normalize_hex(y_hex)
    if x_hex == '0' and y_hex == '0':
        return None
    return (int(x_hex, 16), int(y_hex, 16))


def _point_to_hex(point: Point) -> str:
    if point is None:
        return 'INF'
    x, y = point
    return f"{x:x} {y:x}"


def _modinv(value: int) -> int:
    return pow(value, P - 2, P)


def point_add(p: Point, q: Point) -> Point:
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p == q:
        if y1 == 0:
            return None
        slope = (3 * x1 * x1) * _modinv(2 * y1 % P) % P
    else:
        numerator = (y1 - y2) % P
        denominator = (x1 - x2) % P
        slope = numerator * _modinv(denominator) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(k_hex: str, base: Point) -> Point:
    k_hex = _normalize_hex(k_hex)
    scalar = int(k_hex, 16) if k_hex else 0
    scalar %= N
    if scalar == 0 or base is None:
        return None
    result: Point = None
    addend = base
    while scalar > 0:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print('Usage: secp256k1.py <command> [...]', file=sys.stderr)
        return 1
    cmd = argv[1]
    if cmd == 'point-mul':
        if len(argv) != 5:
            print('Usage: secp256k1.py point-mul <scalar_hex> <x_hex> <y_hex>', file=sys.stderr)
            return 1
        base = _point_from_hex(argv[3], argv[4])
        point = point_mul(argv[2], base)
        if point is None:
            print('INF')
        else:
            x, y = point
            print(f"{x:x} {y:x}")
        return 0
    if cmd == 'point-add':
        if len(argv) != 6:
            print('Usage: secp256k1.py point-add <ax_hex> <ay_hex> <bx_hex> <by_hex>', file=sys.stderr)
            return 1
        p = _point_from_hex(argv[2], argv[3])
        q = _point_from_hex(argv[4], argv[5])
        point = point_add(p, q)
        if point is None:
            print('0 0')
        else:
            x, y = point
            print(f"{x:x} {y:x}")
        return 0
    if cmd == 'server':
        for line in sys.stdin:
            parts = line.strip().split()
            if not parts:
                continue
            try:
                if parts[0] == 'point-mul' and len(parts) == 4:
                    base = _point_from_hex(parts[2], parts[3])
                    point = point_mul(parts[1], base)
                    if point is None:
                        sys.stdout.write('INF\n')
                    else:
                        x, y = point
                        sys.stdout.write(f"{x:x} {y:x}\n")
                    sys.stdout.flush()
                elif parts[0] == 'point-add' and len(parts) == 5:
                    p = _point_from_hex(parts[1], parts[2])
                    q = _point_from_hex(parts[3], parts[4])
                    point = point_add(p, q)
                    if point is None:
                        sys.stdout.write('0 0\n')
                    else:
                        x, y = point
                        sys.stdout.write(f"{x:x} {y:x}\n")
                    sys.stdout.flush()
                else:
                    sys.stdout.write('ERR\n')
                    sys.stdout.flush()
            except Exception:
                sys.stdout.write('ERR\n')
                sys.stdout.flush()
        return 0
    print(f'Unknown command: {cmd}', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
