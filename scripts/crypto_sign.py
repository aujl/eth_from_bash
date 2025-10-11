#!/usr/bin/env python3
"""Cryptographic signing and key management helpers using only the Python stdlib."""
from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import hmac
import secrets
import sys
from typing import Iterable, List, Tuple


# === Utility helpers ===


def _read_file(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    with open(path, "rb") as handle:
        return handle.read()


def _write_file(path: str, data: bytes) -> None:
    with open(path, "wb") as handle:
        handle.write(data)


# === ASN.1 / DER helpers ===


class ASN1Error(ValueError):
    """Raised when DER parsing fails."""


class _DERReader:
    """Minimal DER reader supporting the structures we use."""

    def __init__(self, data: bytes):
        self._data = data
        self._offset = 0

    def _read_length(self) -> int:
        if self._offset >= len(self._data):
            raise ASN1Error("Unexpected end of data while reading length")
        first = self._data[self._offset]
        self._offset += 1
        if first < 0x80:
            return first
        nbytes = first & 0x7F
        if nbytes == 0 or nbytes > 4:
            raise ASN1Error("Invalid DER length encoding")
        if self._offset + nbytes > len(self._data):
            raise ASN1Error("Length bytes exceed buffer")
        value = int.from_bytes(self._data[self._offset : self._offset + nbytes], "big")
        self._offset += nbytes
        return value

    def _read_tlv(self, expected_tag: int) -> bytes:
        if self._offset >= len(self._data):
            raise ASN1Error("Unexpected end of data")
        tag = self._data[self._offset]
        if tag != expected_tag:
            raise ASN1Error(f"Expected tag {expected_tag:#x} but found {tag:#x}")
        self._offset += 1
        length = self._read_length()
        end = self._offset + length
        if end > len(self._data):
            raise ASN1Error("Field length exceeds buffer")
        chunk = self._data[self._offset : end]
        self._offset = end
        return chunk

    def read_sequence(self) -> "_DERReader":
        content = self._read_tlv(0x30)
        return _DERReader(content)

    def read_integer(self) -> int:
        raw = self._read_tlv(0x02)
        if not raw:
            raise ASN1Error("Zero-length integer")
        # Remove possible leading zero padding.
        value = int.from_bytes(raw, "big", signed=False)
        return value

    def read_octet_string(self) -> bytes:
        return self._read_tlv(0x04)

    def read_bit_string(self) -> bytes:
        raw = self._read_tlv(0x03)
        if not raw:
            raise ASN1Error("Invalid BIT STRING")
        unused_bits = raw[0]
        if unused_bits != 0:
            raise ASN1Error("Unsupported BIT STRING with unused bits")
        return raw[1:]

    def read_object_identifier(self) -> Tuple[int, ...]:
        raw = self._read_tlv(0x06)
        if not raw:
            raise ASN1Error("Invalid OID encoding")
        first = raw[0]
        components = [first // 40, first % 40]
        value = 0
        for byte in raw[1:]:
            value = (value << 7) | (byte & 0x7F)
            if not (byte & 0x80):
                components.append(value)
                value = 0
        if value:
            raise ASN1Error("OID truncated")
        return tuple(components)

    def read_explicit(self, tag: int) -> "_DERReader":
        content = self._read_tlv(tag)
        return _DERReader(content)

    def eof(self) -> bool:
        return self._offset == len(self._data)


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _encode_tagged(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(content)) + content


def _encode_integer(value: int) -> bytes:
    if value == 0:
        content = b"\x00"
    else:
        content = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if content[0] & 0x80:
            content = b"\x00" + content
    return _encode_tagged(0x02, content)


def _encode_octet_string(content: bytes) -> bytes:
    return _encode_tagged(0x04, content)


def _encode_bit_string(content: bytes) -> bytes:
    return _encode_tagged(0x03, b"\x00" + content)


def _encode_sequence(elements: Iterable[bytes]) -> bytes:
    body = b"".join(elements)
    return _encode_tagged(0x30, body)


def _encode_object_identifier(oid: Tuple[int, ...]) -> bytes:
    if len(oid) < 2:
        raise ValueError("OID must have at least two components")
    first = 40 * oid[0] + oid[1]
    encoded = [first]
    for component in oid[2:]:
        if component == 0:
            encoded.append(0)
            continue
        stack: List[int] = []
        value = component
        while value:
            stack.append(0x80 | (value & 0x7F))
            value >>= 7
        stack[0] &= 0x7F
        encoded.extend(reversed(stack))
    return _encode_tagged(0x06, bytes(encoded))


# === RSA helpers ===


@dataclasses.dataclass
class RSAPublicKey:
    n: int
    e: int


@dataclasses.dataclass
class RSAPrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int
    dp: int
    dq: int
    qi: int


_RSA_OID = (1, 2, 840, 113549, 1, 1, 1)
_SHA256_OID = (2, 16, 840, 1, 101, 3, 4, 2, 1)


def _parse_pem(data: bytes, label: str) -> bytes:
    header = f"-----BEGIN {label}-----".encode()
    footer = f"-----END {label}-----".encode()
    start = data.find(header)
    end = data.find(footer)
    if start == -1 or end == -1:
        raise ASN1Error(f"PEM block {label} not found")
    start += len(header)
    body = data[start:end]
    body = b"".join(body.strip().splitlines())
    return base64.b64decode(body)


def _load_pem_block(path: str, label: str) -> bytes:
    return _parse_pem(_read_file(path), label)


def _parse_rsa_private_der(data: bytes) -> RSAPrivateKey:
    reader = _DERReader(data)
    seq = reader.read_sequence()
    version = seq.read_integer()
    if version not in (0, 1):
        raise ASN1Error("Unsupported RSA private key version")
    n = seq.read_integer()
    e = seq.read_integer()
    d = seq.read_integer()
    p = seq.read_integer()
    q = seq.read_integer()
    dp = seq.read_integer()
    dq = seq.read_integer()
    qi = seq.read_integer()
    if not seq.eof():
        raise ASN1Error("Unexpected data in RSA private key")
    return RSAPrivateKey(n=n, e=e, d=d, p=p, q=q, dp=dp, dq=dq, qi=qi)


def _parse_rsa_pkcs8(data: bytes) -> RSAPrivateKey:
    reader = _DERReader(data)
    top = reader.read_sequence()
    if top.read_integer() != 0:
        raise ASN1Error("Unsupported PKCS#8 version")
    alg = top.read_sequence()
    oid = alg.read_object_identifier()
    if oid != _RSA_OID:
        raise ASN1Error("PKCS#8 is not RSA")
    if not alg.eof():
        # consume optional NULL
        _ = alg._read_tlv(0x05)
    private_octets = top.read_octet_string()
    if not top.eof():
        raise ASN1Error("Trailing data in PKCS#8 key")
    return _parse_rsa_private_der(private_octets)


def load_rsa_private_key(path: str) -> RSAPrivateKey:
    raw = _read_file(path)
    try:
        der = _parse_pem(raw, "PRIVATE KEY")
        return _parse_rsa_pkcs8(der)
    except ASN1Error:
        # Fallback to PKCS#1 structure
        der = _parse_pem(raw, "RSA PRIVATE KEY")
        return _parse_rsa_private_der(der)


def load_rsa_public_key(path: str) -> RSAPublicKey:
    der = _parse_pem(_read_file(path), "PUBLIC KEY")
    reader = _DERReader(der)
    top = reader.read_sequence()
    alg = top.read_sequence()
    oid = alg.read_object_identifier()
    if oid != _RSA_OID:
        raise ASN1Error("Public key is not RSA")
    if not alg.eof():
        _ = alg._read_tlv(0x05)
    bitstring = top.read_bit_string()
    inner = _DERReader(bitstring)
    seq = inner.read_sequence()
    n = seq.read_integer()
    e = seq.read_integer()
    if not seq.eof() or not top.eof():
        raise ASN1Error("Unexpected data in RSA public key")
    return RSAPublicKey(n=n, e=e)


def _digest_info(hash_name: str, digest: bytes) -> bytes:
    if hash_name != "sha256":
        raise ValueError("Only SHA-256 is supported")
    alg_id = _encode_sequence((_encode_object_identifier(_SHA256_OID), _encode_tagged(0x05, b"")))
    return _encode_sequence((alg_id, _encode_octet_string(digest)))


def rsa_pkcs1_v1_5_sign(priv: RSAPrivateKey, message: bytes, hash_name: str = "sha256") -> bytes:
    digest = hashlib.new(hash_name, message).digest()
    digest_info = _digest_info(hash_name, digest)
    k = (priv.n.bit_length() + 7) // 8
    padding_len = k - len(digest_info) - 3
    if padding_len < 8:
        raise ValueError("RSA modulus too short for digest")
    em = b"\x00\x01" + b"\xff" * padding_len + b"\x00" + digest_info
    signature_int = pow(int.from_bytes(em, "big"), priv.d, priv.n)
    return signature_int.to_bytes(k, "big")


def rsa_pkcs1_v1_5_verify(pub: RSAPublicKey, message: bytes, signature: bytes, hash_name: str = "sha256") -> bool:
    k = (pub.n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    sig_int = int.from_bytes(signature, "big")
    em = pow(sig_int, pub.e, pub.n).to_bytes(k, "big")
    digest = hashlib.new(hash_name, message).digest()
    expected = _digest_info(hash_name, digest)
    if not em.startswith(b"\x00\x01"):
        return False
    try:
        sep_index = em.index(b"\x00", 2)
    except ValueError:
        return False
    padding = em[2:sep_index]
    if len(padding) < 8 or any(x != 0xFF for x in padding):
        return False
    return em[sep_index + 1 :] == expected


# === secp256k1 helpers ===


@dataclasses.dataclass
class ECPoint:
    x: int
    y: int

    def is_at_infinity(self) -> bool:
        return self.x == 0 and self.y == 0


@dataclasses.dataclass
class ECPublicKey:
    point: ECPoint


@dataclasses.dataclass
class ECPrivateKey:
    scalar: int
    public_key: ECPublicKey


_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_A = 0
_B = 7
_G = ECPoint(
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424,
)
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

_EC_PUBLIC_OID = (1, 2, 840, 10045, 2, 1)
_SECP256K1_OID = (1, 3, 132, 0, 10)


def _mod_inv(value: int, modulus: int) -> int:
    if value == 0:
        raise ZeroDivisionError("Inverse of zero does not exist")
    return pow(value % modulus, -1, modulus)


def _point_add(p1: ECPoint, p2: ECPoint) -> ECPoint:
    if p1.is_at_infinity():
        return p2
    if p2.is_at_infinity():
        return p1
    if p1.x == p2.x:
        if (p1.y + p2.y) % _P == 0:
            return ECPoint(0, 0)
        numerator = (3 * p1.x * p1.x + _A) % _P
        denominator = (2 * p1.y) % _P
    else:
        numerator = (p2.y - p1.y) % _P
        denominator = (p2.x - p1.x) % _P
    lam = numerator * _mod_inv(denominator, _P) % _P
    x3 = (lam * lam - p1.x - p2.x) % _P
    y3 = (lam * (p1.x - x3) - p1.y) % _P
    return ECPoint(x3 % _P, y3 % _P)


def _point_mul(k: int, point: ECPoint) -> ECPoint:
    result = ECPoint(0, 0)
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _rfc6979_generate_k(priv_scalar: int, msg_hash: bytes) -> int:
    qlen = (_N.bit_length() + 7) // 8
    x = priv_scalar.to_bytes(qlen, "big")
    h1 = int.from_bytes(msg_hash, "big") % _N
    h1_bytes = h1.to_bytes(qlen, "big")
    V = b"\x01" * 32
    K = b"\x00" * 32
    K = hmac.new(K, V + b"\x00" + x + h1_bytes, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + b"\x01" + x + h1_bytes, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    while True:
        T = b""
        while len(T) < qlen:
            V = hmac.new(K, V, hashlib.sha256).digest()
            T += V
        k = int.from_bytes(T[:qlen], "big") % _N
        if 1 <= k < _N:
            return k
        K = hmac.new(K, V + b"\x00", hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()


def ecdsa_sign(priv: ECPrivateKey, message: bytes, hash_name: str = "sha256") -> bytes:
    digest = hashlib.new(hash_name, message).digest()
    z = int.from_bytes(digest, "big") % _N
    qlen = (_N.bit_length() + 7) // 8
    while True:
        k = _rfc6979_generate_k(priv.scalar, digest)
        R = _point_mul(k, _G)
        r = R.x % _N
        if r == 0:
            continue
        k_inv = _mod_inv(k, _N)
        s = (k_inv * (z + r * priv.scalar)) % _N
        if s == 0:
            continue
        # enforce low-S form
        if s > _N // 2:
            s = _N - s
        return _encode_sequence((_encode_integer(r), _encode_integer(s)))


def ecdsa_verify(pub: ECPublicKey, message: bytes, signature: bytes, hash_name: str = "sha256") -> bool:
    try:
        reader = _DERReader(signature)
        seq = reader.read_sequence()
        r = seq.read_integer()
        s = seq.read_integer()
        if not seq.eof() or not reader.eof():
            return False
    except ASN1Error:
        return False
    if not (1 <= r < _N and 1 <= s < _N):
        return False
    digest = hashlib.new(hash_name, message).digest()
    z = int.from_bytes(digest, "big") % _N
    w = _mod_inv(s, _N)
    u1 = (z * w) % _N
    u2 = (r * w) % _N
    point = _point_add(_point_mul(u1, _G), _point_mul(u2, pub.point))
    if point.is_at_infinity():
        return False
    v = point.x % _N
    return v == r


def _parse_ecdsa_private(path: str) -> ECPrivateKey:
    raw = _read_file(path)
    try:
        der = _parse_pem(raw, "EC PRIVATE KEY")
    except ASN1Error as exc:
        raise ASN1Error("Unsupported EC private key format") from exc
    reader = _DERReader(der)
    seq = reader.read_sequence()
    version = seq.read_integer()
    if version != 1:
        raise ASN1Error("Unsupported EC private key version")
    priv_bytes = seq.read_octet_string()
    priv_scalar = int.from_bytes(priv_bytes, "big")
    pub_point: ECPoint | None = None
    while not seq.eof():
        tag_peek = seq._data[seq._offset]
        if tag_peek == 0xA0:
            params_reader = seq.read_explicit(0xA0)
            oid = params_reader.read_object_identifier()
            if oid != _SECP256K1_OID:
                raise ASN1Error("EC key is not secp256k1")
        elif tag_peek == 0xA1:
            pub_reader = seq.read_explicit(0xA1)
            pub_bytes = pub_reader.read_bit_string()
            if not pub_bytes or pub_bytes[0] != 0x04:
                raise ASN1Error("Unsupported EC public key format")
            x = int.from_bytes(pub_bytes[1:33], "big")
            y = int.from_bytes(pub_bytes[33:], "big")
            pub_point = ECPoint(x, y)
        else:
            raise ASN1Error("Unexpected field in EC private key")
    if pub_point is None:
        pub_point = _point_mul(priv_scalar, _G)
    return ECPrivateKey(priv_scalar, ECPublicKey(pub_point))


def _parse_ecdsa_public(path: str) -> ECPublicKey:
    der = _parse_pem(_read_file(path), "PUBLIC KEY")
    reader = _DERReader(der)
    seq = reader.read_sequence()
    alg = seq.read_sequence()
    if alg.read_object_identifier() != _EC_PUBLIC_OID:
        raise ASN1Error("Public key is not EC")
    params_oid = alg.read_object_identifier()
    if params_oid != _SECP256K1_OID:
        raise ASN1Error("EC key is not secp256k1")
    pub_bytes = seq.read_bit_string()
    if not seq.eof():
        raise ASN1Error("Trailing data in EC public key")
    if not pub_bytes or pub_bytes[0] != 0x04:
        raise ASN1Error("Unsupported EC public key format")
    x = int.from_bytes(pub_bytes[1:33], "big")
    y = int.from_bytes(pub_bytes[33:], "big")
    return ECPublicKey(ECPoint(x, y))


# === Key generation ===


def _is_probable_prime(candidate: int, rounds: int = 32) -> bool:
    if candidate < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for prime in small_primes:
        if candidate % prime == 0:
            return candidate == prime
    d = candidate - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(candidate - 3) + 2
        x = pow(a, d, candidate)
        if x in (1, candidate - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, candidate)
            if x == candidate - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits)
        candidate |= 1
        candidate |= 1 << (bits - 1)
        if _is_probable_prime(candidate):
            return candidate


def generate_rsa_keypair(bits: int = 2048) -> RSAPrivateKey:
    e = 65537
    half = bits // 2
    while True:
        p = _generate_prime(half)
        q = _generate_prime(bits - half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        d = _mod_inv(e, phi)
        dp = d % (p - 1)
        dq = d % (q - 1)
        qi = _mod_inv(q, p)
        return RSAPrivateKey(n=n, e=e, d=d, p=p, q=q, dp=dp, dq=dq, qi=qi)


def rsa_private_to_pkcs8(priv: RSAPrivateKey) -> bytes:
    inner = _encode_sequence(
        (
            _encode_integer(0),
            _encode_integer(priv.n),
            _encode_integer(priv.e),
            _encode_integer(priv.d),
            _encode_integer(priv.p),
            _encode_integer(priv.q),
            _encode_integer(priv.dp),
            _encode_integer(priv.dq),
            _encode_integer(priv.qi),
        )
    )
    alg_id = _encode_sequence((_encode_object_identifier(_RSA_OID), _encode_tagged(0x05, b"")))
    pkcs8 = _encode_sequence((
        _encode_integer(0),
        alg_id,
        _encode_octet_string(inner),
    ))
    return pkcs8


def rsa_public_to_spki(pub: RSAPublicKey) -> bytes:
    alg_id = _encode_sequence((_encode_object_identifier(_RSA_OID), _encode_tagged(0x05, b"")))
    public_seq = _encode_sequence((_encode_integer(pub.n), _encode_integer(pub.e)))
    return _encode_sequence((alg_id, _encode_bit_string(public_seq)))


def generate_secp256k1_keypair() -> ECPrivateKey:
    while True:
        scalar = secrets.randbelow(_N - 1) + 1
        point = _point_mul(scalar, _G)
        if not point.is_at_infinity():
            return ECPrivateKey(scalar, ECPublicKey(point))


def ec_private_to_pem(priv: ECPrivateKey) -> bytes:
    priv_bytes = priv.scalar.to_bytes(32, "big")
    params = _encode_tagged(0xA0, _encode_object_identifier(_SECP256K1_OID))
    pub_point = b"\x04" + priv.public_key.point.x.to_bytes(32, "big") + priv.public_key.point.y.to_bytes(32, "big")
    pub = _encode_tagged(0xA1, _encode_bit_string(pub_point))
    seq = _encode_sequence((
        _encode_integer(1),
        _encode_octet_string(priv_bytes),
        params,
        pub,
    ))
    return seq


def ec_public_to_spki(pub: ECPublicKey) -> bytes:
    alg = _encode_sequence((
        _encode_object_identifier(_EC_PUBLIC_OID),
        _encode_object_identifier(_SECP256K1_OID),
    ))
    point_bytes = b"\x04" + pub.point.x.to_bytes(32, "big") + pub.point.y.to_bytes(32, "big")
    return _encode_sequence((alg, _encode_bit_string(point_bytes)))


# === PEM encoding ===


def _pem_wrap(label: str, der: bytes) -> bytes:
    b64 = base64.encodebytes(der).replace(b"\n", b"")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    body = b"\n".join(line for line in lines if line)
    return (
        f"-----BEGIN {label}-----\n".encode()
        + body
        + b"\n"
        + f"-----END {label}-----\n".encode()
    )


# === Command handlers ===


def cmd_hmac_sha256(args: argparse.Namespace) -> int:
    key = _read_file(args.key)
    data = _read_file(args.message)
    digest = hmac.new(key, data, hashlib.sha256).digest()
    if args.output == "hex":
        print(digest.hex())
    elif args.output == "base64":
        print(base64.b64encode(digest).decode())
    else:
        sys.stdout.buffer.write(digest)
    return 0


def cmd_random_bytes(args: argparse.Namespace) -> int:
    data = secrets.token_bytes(args.count)
    if args.output == "hex":
        print(data.hex())
    elif args.output == "base64":
        print(base64.b64encode(data).decode())
    else:
        sys.stdout.buffer.write(data)
    return 0


def cmd_rsa_sign(args: argparse.Namespace) -> int:
    priv = load_rsa_private_key(args.key)
    message = _read_file(args.message)
    signature = rsa_pkcs1_v1_5_sign(priv, message, args.hash)
    if args.output == "hex":
        print(signature.hex())
    elif args.output == "base64":
        print(base64.b64encode(signature).decode())
    else:
        sys.stdout.buffer.write(signature)
    return 0


def cmd_rsa_verify(args: argparse.Namespace) -> int:
    pub = load_rsa_public_key(args.key)
    message = _read_file(args.message)
    signature = _read_file(args.signature)
    if rsa_pkcs1_v1_5_verify(pub, message, signature, args.hash):
        return 0
    print("verification failed", file=sys.stderr)
    return 1


def cmd_rsa_generate(args: argparse.Namespace) -> int:
    priv = generate_rsa_keypair(args.bits)
    priv_pem = _pem_wrap("PRIVATE KEY", rsa_private_to_pkcs8(priv))
    pub_pem = _pem_wrap("PUBLIC KEY", rsa_public_to_spki(RSAPublicKey(n=priv.n, e=priv.e)))
    _write_file(args.private_out, priv_pem)
    _write_file(args.public_out, pub_pem)
    return 0


def cmd_rsa_public(args: argparse.Namespace) -> int:
    priv = load_rsa_private_key(args.key)
    pub = RSAPublicKey(n=priv.n, e=priv.e)
    pem = _pem_wrap("PUBLIC KEY", rsa_public_to_spki(pub))
    _write_file(args.output, pem)
    return 0


def cmd_ecdsa_sign(args: argparse.Namespace) -> int:
    priv = _parse_ecdsa_private(args.key)
    message = _read_file(args.message)
    signature = ecdsa_sign(priv, message, args.hash)
    if args.output == "hex":
        print(signature.hex())
    elif args.output == "base64":
        print(base64.b64encode(signature).decode())
    else:
        sys.stdout.buffer.write(signature)
    return 0


def cmd_ecdsa_verify(args: argparse.Namespace) -> int:
    pub = _parse_ecdsa_public(args.key)
    message = _read_file(args.message)
    signature = _read_file(args.signature)
    if ecdsa_verify(pub, message, signature, args.hash):
        return 0
    print("verification failed", file=sys.stderr)
    return 1


def cmd_ecdsa_generate(args: argparse.Namespace) -> int:
    priv = generate_secp256k1_keypair()
    priv_pem = _pem_wrap("EC PRIVATE KEY", ec_private_to_pem(priv))
    pub_pem = _pem_wrap("PUBLIC KEY", ec_public_to_spki(priv.public_key))
    _write_file(args.private_out, priv_pem)
    _write_file(args.public_out, pub_pem)
    return 0


def cmd_ecdsa_public(args: argparse.Namespace) -> int:
    priv = _parse_ecdsa_private(args.key)
    pem = _pem_wrap("PUBLIC KEY", ec_public_to_spki(priv.public_key))
    _write_file(args.output, pem)
    return 0


# === Argument parser ===


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Internal signing helpers")
    sub = parser.add_subparsers(dest="command", required=True)

    hmac_parser = sub.add_parser("hmac-sha256", help="Compute HMAC-SHA256")
    hmac_parser.add_argument("--key", required=True, help="Key file (use - for stdin)")
    hmac_parser.add_argument("--message", required=True, help="Message file (use - for stdin)")
    hmac_parser.add_argument("--output", choices=["hex", "base64", "raw"], default="hex")
    hmac_parser.set_defaults(func=cmd_hmac_sha256)

    rand_parser = sub.add_parser("random-bytes", help="Generate secure random bytes")
    rand_parser.add_argument("--count", type=int, required=True)
    rand_parser.add_argument("--output", choices=["hex", "base64", "raw"], default="hex")
    rand_parser.set_defaults(func=cmd_random_bytes)

    rsa_sign = sub.add_parser("rsa-sign", help="Sign message with RSA PKCS#1 v1.5")
    rsa_sign.add_argument("--key", required=True)
    rsa_sign.add_argument("--message", required=True)
    rsa_sign.add_argument("--hash", default="sha256")
    rsa_sign.add_argument("--output", choices=["hex", "base64", "raw"], default="raw")
    rsa_sign.set_defaults(func=cmd_rsa_sign)

    rsa_verify = sub.add_parser("rsa-verify", help="Verify RSA PKCS#1 v1.5 signature")
    rsa_verify.add_argument("--key", required=True)
    rsa_verify.add_argument("--message", required=True)
    rsa_verify.add_argument("--signature", required=True)
    rsa_verify.add_argument("--hash", default="sha256")
    rsa_verify.set_defaults(func=cmd_rsa_verify)

    rsa_gen = sub.add_parser("rsa-generate", help="Generate RSA keypair")
    rsa_gen.add_argument("--bits", type=int, default=2048)
    rsa_gen.add_argument("--private-out", required=True)
    rsa_gen.add_argument("--public-out", required=True)
    rsa_gen.set_defaults(func=cmd_rsa_generate)

    rsa_pub = sub.add_parser("rsa-public", help="Derive RSA public key from private key")
    rsa_pub.add_argument("--key", required=True)
    rsa_pub.add_argument("--output", required=True)
    rsa_pub.set_defaults(func=cmd_rsa_public)

    ecdsa_sign_parser = sub.add_parser("ecdsa-sign", help="Sign message with secp256k1 ECDSA")
    ecdsa_sign_parser.add_argument("--key", required=True)
    ecdsa_sign_parser.add_argument("--message", required=True)
    ecdsa_sign_parser.add_argument("--hash", default="sha256")
    ecdsa_sign_parser.add_argument("--output", choices=["hex", "base64", "raw"], default="raw")
    ecdsa_sign_parser.set_defaults(func=cmd_ecdsa_sign)

    ecdsa_verify_parser = sub.add_parser("ecdsa-verify", help="Verify secp256k1 ECDSA signature")
    ecdsa_verify_parser.add_argument("--key", required=True)
    ecdsa_verify_parser.add_argument("--message", required=True)
    ecdsa_verify_parser.add_argument("--signature", required=True)
    ecdsa_verify_parser.add_argument("--hash", default="sha256")
    ecdsa_verify_parser.set_defaults(func=cmd_ecdsa_verify)

    ecdsa_gen = sub.add_parser("ecdsa-generate", help="Generate secp256k1 keypair")
    ecdsa_gen.add_argument("--private-out", required=True)
    ecdsa_gen.add_argument("--public-out", required=True)
    ecdsa_gen.set_defaults(func=cmd_ecdsa_generate)

    ecdsa_pub = sub.add_parser("ecdsa-public", help="Derive secp256k1 public key from private key")
    ecdsa_pub.add_argument("--key", required=True)
    ecdsa_pub.add_argument("--output", required=True)
    ecdsa_pub.set_defaults(func=cmd_ecdsa_public)

    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func")
    return func(args)


if __name__ == "__main__":
    sys.exit(main())
