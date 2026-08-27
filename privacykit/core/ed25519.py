"""
Ed25519 signature verification, pure Python (RFC 8032).

Why this is here rather than a dependency: license verification must never fail
*open*. If the check were skipped whenever an optional package was missing, the
licensing system would be defeated by uninstalling a library. Embedding the
verifier means the check always runs.

Verification only — there is no signing code in the shipped application, because
the application never needs to sign anything. The private key lives with the
vendor, in ``tools/keygen.py``.

This is the well-known reference implementation. It is not constant-time, which
does not matter here: it verifies a public signature over public data, so there
is no secret to leak through timing. When the ``cryptography`` package is
available :func:`verify` uses it instead, purely for speed.
"""

from __future__ import annotations

import hashlib

# Curve constants
_b = 256
_q = 2 ** 255 - 19
_l = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, _q - 2, _q)


_d = -121665 * _inv(121666) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = 4 * _inv(5)
_Bx = _xrecover(_By)
_B = (_Bx % _q, _By % _q)


def _edwards_add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    denom = _inv(1 + _d * x1 * x2 * y1 * y2)
    x3 = (x1 * y2 + x2 * y1) * denom
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return (x3 % _q, y3 % _q)


def _scalarmult(P, e: int):
    """Iterative double-and-add — recursion would hit Python's stack limit."""
    result = (0, 1)
    addend = P
    while e > 0:
        if e & 1:
            result = _edwards_add(result, addend)
        addend = _edwards_add(addend, addend)
        e >>= 1
    return result


def _is_on_curve(P) -> bool:
    x, y = P
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _q == 0


def _decode_point(s: bytes):
    if len(s) != 32:
        raise ValueError("point must be 32 bytes")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != ((s[31] >> 7) & 1):
        x = _q - x
    P = (x, y)
    if not _is_on_curve(P):
        raise ValueError("decoded point is not on the curve")
    return P


def _encode_point(P) -> bytes:
    x, y = P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _verify_pure(signature: bytes, message: bytes, public_key: bytes) -> bool:
    if len(signature) != 64 or len(public_key) != 32:
        return False
    try:
        R = _decode_point(signature[:32])
        A = _decode_point(public_key)
        S = int.from_bytes(signature[32:], "little")
        if S >= _l:
            return False
        h = int.from_bytes(_H(signature[:32] + public_key + message), "little")
        left = _scalarmult(_B, S)
        right = _edwards_add(R, _scalarmult(A, h))
        return left == right
    except Exception:
        return False


def verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
    """
    Verify an Ed25519 signature. Returns False on any malformed input.

    Never raises: a licence check that throws would be an easy way to crash the
    application into an unhandled state.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey)
        from cryptography.exceptions import InvalidSignature
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False
    except Exception:
        pass
    return _verify_pure(signature, message, public_key)


def self_test() -> tuple:
    """
    Check the verifier against RFC 8032 test vector 1.

    Also confirms a tampered message and a tampered signature are both
    rejected — a verifier that accepts everything would pass a naive
    "valid signature verifies" test.
    """
    import binascii
    pk = binascii.unhexlify(
        "d75a980182b10ab7d54bfed3c964073a"
        "0ee172f3daa62325af021a68f707511a")
    sig = binascii.unhexlify(
        "e5564300c360ac729086e2cc806e828a"
        "84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b")
    msg = b""

    if not _verify_pure(sig, msg, pk):
        return False, "RFC 8032 vector 1 failed to verify"
    if _verify_pure(sig, b"x", pk):
        return False, "verifier accepted a signature over the wrong message"
    bad = bytearray(sig)
    bad[0] ^= 0x01
    if _verify_pure(bytes(bad), msg, pk):
        return False, "verifier accepted a tampered signature"
    if _verify_pure(sig, msg, b"\x00" * 32):
        return False, "verifier accepted an invalid public key"
    return True, "Ed25519 verifier matches RFC 8032 vector 1 and rejects tampering"
