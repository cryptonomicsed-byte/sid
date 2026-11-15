"""Signature suites for sid/0.2 — dependency-free reference implementations.

Two suites, both with 32-byte public keys and 64-byte signatures (hex on the wire):

    ed25519   RFC 8032 Ed25519 over the message bytes
    bip340    BIP-340 Schnorr (secp256k1, x-only keys) over sha256(message bytes)

Verification only handles public data, so plain big-integer arithmetic is fine
there. The signing functions exist to mint fixtures and for tooling; they are
NOT constant-time and must not be used to sign with production keys — issuers
sign inside the kernel.

The arithmetic follows the reference code published in RFC 8032 §6 and in
BIP-340.
"""
from __future__ import annotations

import hashlib

ALGS = ("ed25519", "bip340")

# ── Ed25519 (RFC 8032) ───────────────────────────────────────────────────────
_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _ed_add(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % _P
    B = (a[1] + a[0]) * (b[1] + b[0]) % _P
    C = 2 * a[3] * b[3] * _D % _P
    D = 2 * a[2] * b[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _ed_mul(s: int, point):
    out = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            out = _ed_add(out, point)
        point = _ed_add(point, point)
        s >>= 1
    return out


def _ed_equal(a, b) -> bool:
    return ((a[0] * b[2] - b[0] * a[2]) % _P == 0
            and (a[1] * b[2] - b[1] * a[2]) % _P == 0)


def _ed_recover_x(y: int, sign: int):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _inv(5) % _P
_GX = _ed_recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _ed_compress(point) -> bytes:
    zinv = _inv(point[2])
    x, y = point[0] * zinv % _P, point[1] * zinv % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _ed_decompress(data: bytes):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _ed_recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _ed_expand(secret: bytes):
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def _sha512_modq(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % _Q


def ed25519_public(secret: bytes) -> bytes:
    a, _ = _ed_expand(secret)
    return _ed_compress(_ed_mul(a, _G))


def ed25519_sign(secret: bytes, message: bytes) -> bytes:
    a, prefix = _ed_expand(secret)
    public = _ed_compress(_ed_mul(a, _G))
    r = _sha512_modq(prefix + message)
    r_bytes = _ed_compress(_ed_mul(r, _G))
    h = _sha512_modq(r_bytes + public + message)
    return r_bytes + ((r + h * a) % _Q).to_bytes(32, "little")


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    a_point = _ed_decompress(public)
    r_point = _ed_decompress(signature[:32])
    if a_point is None or r_point is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _Q:
        return False
    h = _sha512_modq(signature[:32] + public + message)
    return _ed_equal(_ed_mul(s, _G), _ed_add(r_point, _ed_mul(h, a_point)))


# ── BIP-340 Schnorr (secp256k1) ──────────────────────────────────────────────
_SP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SN = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SG = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
       0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _tagged(tag: str, data: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


def _s_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and a[1] != b[1]:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], _SP - 2, _SP) % _SP
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], _SP - 2, _SP) % _SP
    x = (lam * lam - a[0] - b[0]) % _SP
    return (x, (lam * (a[0] - x) - a[1]) % _SP)


def _s_mul(point, k: int):
    out = None
    for i in range(256):
        if (k >> i) & 1:
            out = _s_add(out, point)
        point = _s_add(point, point)
    return out


def _lift_x(x: int):
    if x >= _SP:
        return None
    y2 = (pow(x, 3, _SP) + 7) % _SP
    y = pow(y2, (_SP + 1) // 4, _SP)
    if pow(y, 2, _SP) != y2:
        return None
    return (x, y if y & 1 == 0 else _SP - y)


def bip340_public(secret: bytes) -> bytes:
    d = int.from_bytes(secret, "big")
    if not 1 <= d < _SN:
        raise ValueError("secret key out of range")
    return _s_mul(_SG, d)[0].to_bytes(32, "big")


def bip340_sign(secret: bytes, message: bytes, aux: bytes = b"\x00" * 32) -> bytes:
    """Sign sha256(message). `aux` fixed at zero gives a deterministic signature."""
    digest = hashlib.sha256(message).digest()
    d0 = int.from_bytes(secret, "big")
    if not 1 <= d0 < _SN:
        raise ValueError("secret key out of range")
    point = _s_mul(_SG, d0)
    d = d0 if point[1] % 2 == 0 else _SN - d0
    px = point[0].to_bytes(32, "big")
    t = (d ^ int.from_bytes(_tagged("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(_tagged("BIP0340/nonce", t + px + digest), "big") % _SN
    if k0 == 0:
        raise ValueError("nonce is zero")
    r_point = _s_mul(_SG, k0)
    k = k0 if r_point[1] % 2 == 0 else _SN - k0
    rx = r_point[0].to_bytes(32, "big")
    e = int.from_bytes(_tagged("BIP0340/challenge", rx + px + digest), "big") % _SN
    return rx + ((k + e * d) % _SN).to_bytes(32, "big")


def bip340_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    digest = hashlib.sha256(message).digest()
    point = _lift_x(int.from_bytes(public, "big"))
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if point is None or r >= _SP or s >= _SN:
        return False
    e = int.from_bytes(_tagged("BIP0340/challenge", signature[:32] + public + digest), "big") % _SN
    r_point = _s_add(_s_mul(_SG, s), _s_mul(point, _SN - e))
    return r_point is not None and r_point[1] % 2 == 0 and r_point[0] == r


# ── suite dispatch (hex in, hex out) ─────────────────────────────────────────
def public_key(alg: str, secret_hex: str) -> str:
    secret = bytes.fromhex(secret_hex)
    if alg == "ed25519":
        return ed25519_public(secret).hex()
    if alg == "bip340":
        return bip340_public(secret).hex()
    raise ValueError(f"unsupported alg {alg}")


def sign(alg: str, secret_hex: str, message: str) -> str:
    secret, data = bytes.fromhex(secret_hex), message.encode("utf-8")
    if alg == "ed25519":
        return ed25519_sign(secret, data).hex()
    if alg == "bip340":
        return bip340_sign(secret, data).hex()
    raise ValueError(f"unsupported alg {alg}")


def verify(alg: str, public_hex: str, message: str, signature_hex: str) -> bool:
    """False for anything malformed or unsupported — never raises."""
    try:
        public, signature = bytes.fromhex(public_hex), bytes.fromhex(signature_hex)
    except (ValueError, TypeError):
        return False
    data = message.encode("utf-8")
    if alg == "ed25519":
        return ed25519_verify(public, data, signature)
    if alg == "bip340":
        return bip340_verify(public, data, signature)
    return False
