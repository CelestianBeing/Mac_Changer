"""
Pure-Python AES (FIPS-197) with CBC mode.

This exists so the vault works on a bare Python install with no pip packages.
When the ``cryptography`` package is present, :mod:`privacykit.core.crypto`
uses it instead — it is faster and hardware-accelerated. This module is the
fallback, not the preferred path.

The S-box and its inverse are *computed* from the field inverse and affine
transform rather than pasted in as 256 hex literals. Transcribing tables by
hand is a classic source of silent, catastrophic bugs; deriving them means the
implementation is either right or obviously broken. The self-test suite checks
the result against the FIPS-197 known-answer vectors.

Scope note: this is a straightforward reference implementation. It is not
constant-time and makes no attempt to resist side-channel analysis. For
encrypting files at rest with a strong passphrase that is fine; it is not
suitable for high-rate network cryptography.
"""

from __future__ import annotations

import os
from typing import List

BLOCK_SIZE = 16


# ──────────────────────────────────────────────────────────────────────────────
# GF(2^8) arithmetic and table construction
# ──────────────────────────────────────────────────────────────────────────────

def _xtime(a: int) -> int:
    """Multiply by x (i.e. 0x02) in GF(2^8) modulo the AES polynomial."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _mul(a: int, b: int) -> int:
    """Multiply two field elements."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result & 0xFF


def _build_sbox() -> tuple:
    """
    Derive the AES S-box: multiplicative inverse in GF(2^8), then the affine
    transform s' = s ^ rotl(s,1) ^ rotl(s,2) ^ rotl(s,3) ^ rotl(s,4) ^ 0x63.
    """
    # Multiplicative inverses via exponentiation over the generator 0x03.
    inverse = [0] * 256
    p = 1
    log = [0] * 256
    alog = [0] * 256
    for i in range(255):
        alog[i] = p
        log[p] = i
        p = _mul(p, 0x03)
    for i in range(1, 256):
        inverse[i] = alog[(255 - log[i]) % 255]

    sbox = [0] * 256
    for i in range(256):
        s = inverse[i]
        x = s
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            s ^= x
        sbox[i] = s ^ 0x63

    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    return tuple(sbox), tuple(inv_sbox)


SBOX, INV_SBOX = _build_sbox()

RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A)


# ──────────────────────────────────────────────────────────────────────────────
# Core cipher
# ──────────────────────────────────────────────────────────────────────────────

class AES:
    """Raw AES block cipher. Key must be 16, 24, or 32 bytes."""

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError(f"AES key must be 16, 24 or 32 bytes, got {len(key)}")
        self.nk = len(key) // 4
        self.nr = self.nk + 6                # 10, 12, or 14 rounds
        self.round_keys = self._expand_key(key)

    def _expand_key(self, key: bytes) -> List[List[int]]:
        nk, nr = self.nk, self.nr
        w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        for i in range(nk, 4 * (nr + 1)):
            temp = list(w[i - 1])
            if i % nk == 0:
                temp = temp[1:] + temp[:1]                 # RotWord
                temp = [SBOX[b] for b in temp]             # SubWord
                temp[0] ^= RCON[i // nk]
            elif nk > 6 and i % nk == 4:
                temp = [SBOX[b] for b in temp]
            w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
        return w

    # ── state helpers (state is a flat list of 16 bytes, column-major) ──
    def _add_round_key(self, state: List[int], rnd: int) -> None:
        for c in range(4):
            word = self.round_keys[rnd * 4 + c]
            for r in range(4):
                state[c * 4 + r] ^= word[r]

    @staticmethod
    def _sub_bytes(state: List[int], box) -> None:
        for i in range(16):
            state[i] = box[state[i]]

    @staticmethod
    def _shift_rows(state: List[int]) -> None:
        for r in range(1, 4):
            row = [state[c * 4 + r] for c in range(4)]
            row = row[r:] + row[:r]
            for c in range(4):
                state[c * 4 + r] = row[c]

    @staticmethod
    def _inv_shift_rows(state: List[int]) -> None:
        for r in range(1, 4):
            row = [state[c * 4 + r] for c in range(4)]
            row = row[-r:] + row[:-r]
            for c in range(4):
                state[c * 4 + r] = row[c]

    @staticmethod
    def _mix_columns(state: List[int]) -> None:
        for c in range(4):
            a = state[c * 4:c * 4 + 4]
            state[c * 4 + 0] = _mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3]
            state[c * 4 + 1] = a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3]
            state[c * 4 + 2] = a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3)
            state[c * 4 + 3] = _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)

    @staticmethod
    def _inv_mix_columns(state: List[int]) -> None:
        for c in range(4):
            a = state[c * 4:c * 4 + 4]
            state[c * 4 + 0] = (_mul(a[0], 14) ^ _mul(a[1], 11)
                                ^ _mul(a[2], 13) ^ _mul(a[3], 9))
            state[c * 4 + 1] = (_mul(a[0], 9) ^ _mul(a[1], 14)
                                ^ _mul(a[2], 11) ^ _mul(a[3], 13))
            state[c * 4 + 2] = (_mul(a[0], 13) ^ _mul(a[1], 9)
                                ^ _mul(a[2], 14) ^ _mul(a[3], 11))
            state[c * 4 + 3] = (_mul(a[0], 11) ^ _mul(a[1], 13)
                                ^ _mul(a[2], 9) ^ _mul(a[3], 14))

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError("block must be exactly 16 bytes")
        state = list(block)
        self._add_round_key(state, 0)
        for rnd in range(1, self.nr):
            self._sub_bytes(state, SBOX)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, rnd)
        self._sub_bytes(state, SBOX)
        self._shift_rows(state)
        self._add_round_key(state, self.nr)
        return bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError("block must be exactly 16 bytes")
        state = list(block)
        self._add_round_key(state, self.nr)
        for rnd in range(self.nr - 1, 0, -1):
            self._inv_shift_rows(state)
            self._sub_bytes(state, INV_SBOX)
            self._add_round_key(state, rnd)
            self._inv_mix_columns(state)
        self._inv_shift_rows(state)
        self._sub_bytes(state, INV_SBOX)
        self._add_round_key(state, 0)
        return bytes(state)


# ──────────────────────────────────────────────────────────────────────────────
# CBC mode with PKCS#7 padding
# ──────────────────────────────────────────────────────────────────────────────

def pad(data: bytes) -> bytes:
    n = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([n]) * n


def unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("ciphertext length is not a multiple of the block size")
    n = data[-1]
    if n < 1 or n > BLOCK_SIZE or data[-n:] != bytes([n]) * n:
        raise ValueError("invalid padding — wrong key or corrupted data")
    return data[:-n]


def encrypt_cbc(key: bytes, plaintext: bytes, iv: bytes | None = None) -> tuple:
    """Encrypt with AES-CBC. Returns ``(iv, ciphertext)``."""
    iv = iv or os.urandom(BLOCK_SIZE)
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes")
    cipher = AES(key)
    data = pad(plaintext)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), BLOCK_SIZE):
        block = bytes(a ^ b for a, b in zip(data[i:i + BLOCK_SIZE], prev))
        enc = cipher.encrypt_block(block)
        out += enc
        prev = enc
    return iv, bytes(out)


def decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt AES-CBC and strip padding."""
    if len(ciphertext) % BLOCK_SIZE:
        raise ValueError("ciphertext length is not a multiple of the block size")
    cipher = AES(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        dec = cipher.decrypt_block(block)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = block
    return unpad(bytes(out))


#: FIPS-197 Appendix C known-answer vectors, used by the self-test suite.
TEST_VECTORS = [
    # (key, plaintext, expected ciphertext) — all hex
    ("000102030405060708090a0b0c0d0e0f",
     "00112233445566778899aabbccddeeff",
     "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("000102030405060708090a0b0c0d0e0f1011121314151617",
     "00112233445566778899aabbccddeeff",
     "dda97ca4864cdfe06eaf70a0ec0d7191"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "00112233445566778899aabbccddeeff",
     "8ea2b7ca516745bfeafc49904b496089"),
]


def self_test() -> tuple:
    """Verify the implementation against the FIPS-197 vectors."""
    import binascii
    for key_hex, pt_hex, ct_hex in TEST_VECTORS:
        key = binascii.unhexlify(key_hex)
        pt = binascii.unhexlify(pt_hex)
        expected = binascii.unhexlify(ct_hex)
        cipher = AES(key)
        got = cipher.encrypt_block(pt)
        if got != expected:
            return False, (f"AES-{len(key) * 8} encrypt mismatch: "
                           f"got {got.hex()}, expected {ct_hex}")
        if cipher.decrypt_block(expected) != pt:
            return False, f"AES-{len(key) * 8} decrypt mismatch"
    return True, "AES matches all FIPS-197 known-answer vectors"
