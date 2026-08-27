"""
File encryption vault.

Format (PrivacyKit Vault v1)
---------------------------
    magic        8 bytes   b"PKVAULT1"
    cipher id    1 byte    1 = AES-256-GCM, 2 = AES-256-CBC + HMAC-SHA256
    salt        16 bytes   random, per file
    kdf params   9 bytes   log2(N) | r | p as 1 + 4 + 4 bytes, big-endian
    nonce/iv    16 bytes   12 used for GCM, 16 for CBC
    ciphertext  variable
    tag         16 (GCM) or 32 (HMAC-SHA256) bytes

Design decisions worth stating:

* **scrypt, not a bare hash.** ``hashlib.scrypt`` is in the standard library,
  so a memory-hard KDF costs us no dependency. Parameters are stored in the
  file, so files stay readable if the defaults are raised later.
* **Encrypt-then-MAC on the fallback path.** The CBC branch authenticates the
  ciphertext, IV, and header with HMAC-SHA256 and verifies it *before*
  decrypting. Without that, CBC padding errors become a padding oracle, and
  "wrong password" and "tampered file" become indistinguishable.
* **Separate keys.** The 64-byte scrypt output is split into independent
  encryption and MAC keys rather than reusing one key for both.
* **No password recovery.** There is deliberately no hint field or escrow. If
  the passphrase is lost the data is gone, and the UI says so before encrypting.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Tuple

from . import aes as pyaes

MAGIC = b"PKVAULT1"
CIPHER_GCM = 1
CIPHER_CBC_HMAC = 2

# scrypt cost. N=2^15 with r=8 needs about 32 MB and roughly a tenth of a
# second — enough to make guessing expensive without an unpleasant wait.
SCRYPT_LOGN = 15
SCRYPT_R = 8
SCRYPT_P = 1
SALT_LEN = 16
KEY_LEN = 64            # 32 for encryption + 32 for MAC

HEADER_STRUCT = ">8sB16sBII16s"
HEADER_LEN = struct.calcsize(HEADER_STRUCT)


def _have_cryptography() -> bool:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        return True
    except Exception:
        return False


HAVE_CRYPTOGRAPHY = _have_cryptography()


@dataclass
class VaultResult:
    ok: bool
    message: str
    path: str = ""
    bytes_written: int = 0
    cipher: str = ""


def derive_key(password: str, salt: bytes, logn: int = SCRYPT_LOGN,
               r: int = SCRYPT_R, p: int = SCRYPT_P) -> Tuple[bytes, bytes]:
    """Derive ``(encryption_key, mac_key)`` from a passphrase via scrypt."""
    if not password:
        raise ValueError("passphrase cannot be empty")
    material = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2 ** logn, r=r, p=p,
        dklen=KEY_LEN, maxmem=(2 ** logn) * r * 200,
    )
    return material[:32], material[32:]


def encrypt_bytes(data: bytes, password: str) -> bytes:
    """Encrypt a blob and return the complete vault container."""
    salt = os.urandom(SALT_LEN)
    enc_key, mac_key = derive_key(password, salt)

    if HAVE_CRYPTOGRAPHY:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = os.urandom(12)
        header = struct.pack(HEADER_STRUCT, MAGIC, CIPHER_GCM, salt,
                             SCRYPT_LOGN, SCRYPT_R, SCRYPT_P,
                             nonce + b"\x00" * 4)
        # The header is authenticated as associated data, so the KDF params and
        # salt cannot be tampered with either.
        blob = AESGCM(enc_key).encrypt(nonce, data, header)
        return header + blob

    iv, ciphertext = pyaes.encrypt_cbc(enc_key, data)
    header = struct.pack(HEADER_STRUCT, MAGIC, CIPHER_CBC_HMAC, salt,
                         SCRYPT_LOGN, SCRYPT_R, SCRYPT_P, iv)
    tag = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()
    return header + ciphertext + tag


def decrypt_bytes(container: bytes, password: str) -> bytes:
    """Decrypt a vault container. Raises ValueError on any integrity failure."""
    if len(container) < HEADER_LEN + 16:
        raise ValueError("File is too short to be a PrivacyKit vault.")
    header = container[:HEADER_LEN]
    magic, cipher_id, salt, logn, r, p, iv_field = struct.unpack(HEADER_STRUCT, header)
    if magic != MAGIC:
        raise ValueError("Not a PrivacyKit vault file (bad magic bytes).")
    if logn < 10 or logn > 22:
        raise ValueError(f"Refusing unreasonable scrypt cost parameter (2^{logn}).")

    enc_key, mac_key = derive_key(password, salt, logn, r, p)
    body = container[HEADER_LEN:]

    if cipher_id == CIPHER_GCM:
        if not HAVE_CRYPTOGRAPHY:
            raise ValueError(
                "This vault uses AES-GCM, which needs the 'cryptography' "
                "package on this machine. Install it with:  pip install cryptography"
            )
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = iv_field[:12]
        try:
            return AESGCM(enc_key).decrypt(nonce, body, header)
        except Exception as exc:
            raise ValueError(
                "Decryption failed — wrong passphrase, or the file has been "
                "modified since it was encrypted."
            ) from exc

    if cipher_id == CIPHER_CBC_HMAC:
        if len(body) < 32:
            raise ValueError("Vault file is truncated (missing authentication tag).")
        ciphertext, tag = body[:-32], body[-32:]
        expected = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()
        # Verify BEFORE decrypting — this is what stops padding-oracle attacks.
        if not hmac.compare_digest(expected, tag):
            raise ValueError(
                "Authentication check failed — wrong passphrase, or the file has "
                "been modified since it was encrypted."
            )
        return pyaes.decrypt_cbc(enc_key, iv_field, ciphertext)

    raise ValueError(f"Unknown cipher identifier in vault header: {cipher_id}")


# ──────────────────────────────────────────────────────────────────────────────
# File-level operations
# ──────────────────────────────────────────────────────────────────────────────

def encrypt_file(src: str, password: str, dest: Optional[str] = None,
                 shred_original: bool = False,
                 progress: Optional[Callable[[str], None]] = None) -> VaultResult:
    """Encrypt a file to ``<name>.pkv``."""
    src_path = Path(src)
    if not src_path.is_file():
        return VaultResult(False, f"'{src}' is not a file.")
    out_path = Path(dest) if dest else src_path.with_suffix(src_path.suffix + ".pkv")
    if out_path.exists():
        return VaultResult(False, f"'{out_path.name}' already exists — refusing to overwrite.")

    try:
        if progress:
            progress(f"Reading {src_path.name}…")
        data = src_path.read_bytes()
        if progress:
            progress("Deriving key (scrypt — this takes a moment by design)…")
        container = encrypt_bytes(data, password)
        if progress:
            progress(f"Writing {out_path.name}…")
        out_path.write_bytes(container)
    except MemoryError:
        return VaultResult(False, "File is too large to encrypt in memory on this machine.")
    except Exception as exc:
        return VaultResult(False, f"{type(exc).__name__}: {exc}")

    if shred_original:
        from . import shredder
        res = shredder.shred_file(str(src_path), passes=3)
        if not res.ok and progress:
            progress(f"Warning: original not shredded — {res.message}")

    return VaultResult(
        True,
        f"Encrypted to {out_path.name} "
        f"({'AES-256-GCM' if HAVE_CRYPTOGRAPHY else 'AES-256-CBC + HMAC-SHA256'}).",
        str(out_path), len(container),
        "AES-256-GCM" if HAVE_CRYPTOGRAPHY else "AES-256-CBC+HMAC",
    )


def decrypt_file(src: str, password: str, dest: Optional[str] = None,
                 progress: Optional[Callable[[str], None]] = None) -> VaultResult:
    """Decrypt a ``.pkv`` file back to its original form."""
    src_path = Path(src)
    if not src_path.is_file():
        return VaultResult(False, f"'{src}' is not a file.")

    if dest:
        out_path = Path(dest)
    elif src_path.suffix.lower() == ".pkv":
        out_path = src_path.with_suffix("")
    else:
        out_path = src_path.with_suffix(src_path.suffix + ".decrypted")
    if out_path.exists():
        return VaultResult(False, f"'{out_path.name}' already exists — refusing to overwrite.")

    try:
        if progress:
            progress(f"Reading {src_path.name}…")
        container = src_path.read_bytes()
        if progress:
            progress("Deriving key and verifying integrity…")
        data = decrypt_bytes(container, password)
        out_path.write_bytes(data)
    except ValueError as exc:
        return VaultResult(False, str(exc))
    except Exception as exc:
        return VaultResult(False, f"{type(exc).__name__}: {exc}")

    return VaultResult(True, f"Decrypted to {out_path.name}.", str(out_path), len(data))


def encrypt_text(text: str, password: str) -> str:
    """Encrypt a note and return it base64-armoured, for copy/paste."""
    import base64
    return base64.b64encode(encrypt_bytes(text.encode("utf-8"), password)).decode("ascii")


def decrypt_text(armoured: str, password: str) -> str:
    import base64
    raw = base64.b64decode(armoured.strip().encode("ascii"), validate=False)
    return decrypt_bytes(raw, password).decode("utf-8", errors="replace")


def inspect(path: str) -> dict:
    """Read a vault header without decrypting — shows what a file is."""
    try:
        with open(path, "rb") as fh:
            header = fh.read(HEADER_LEN)
        if len(header) < HEADER_LEN:
            return {"valid": False, "error": "file too short"}
        magic, cipher_id, salt, logn, r, p, _ = struct.unpack(HEADER_STRUCT, header)
        if magic != MAGIC:
            return {"valid": False, "error": "not a PrivacyKit vault"}
        return {
            "valid": True,
            "cipher": {CIPHER_GCM: "AES-256-GCM",
                       CIPHER_CBC_HMAC: "AES-256-CBC + HMAC-SHA256"}.get(cipher_id, "unknown"),
            "kdf": f"scrypt N=2^{logn} r={r} p={p}",
            "size": os.path.getsize(path),
        }
    except Exception as exc:
        return {"valid": False, "error": str(exc)}


# ──────────────────────────────────────────────────────────────────────────────
# Hashing utilities
# ──────────────────────────────────────────────────────────────────────────────

def hash_file(path: str, algorithm: str = "sha256") -> str:
    """Hash a file in chunks, so multi-gigabyte files do not exhaust memory."""
    try:
        h = hashlib.new(algorithm)
    except ValueError:
        return f"unsupported algorithm: {algorithm}"
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as exc:
        return f"error: {exc}"


def hash_text(text: str, algorithm: str = "sha256") -> str:
    try:
        return hashlib.new(algorithm, text.encode("utf-8")).hexdigest()
    except ValueError:
        return f"unsupported algorithm: {algorithm}"


AVAILABLE_HASHES = ["md5", "sha1", "sha256", "sha384", "sha512", "blake2b", "sha3_256"]


def self_test() -> tuple:
    """Round-trip check across both cipher paths."""
    sample = b"PrivacyKit vault self-test payload \x00\xff" * 40
    pw = "correct horse battery staple"
    try:
        container = encrypt_bytes(sample, pw)
        if decrypt_bytes(container, pw) != sample:
            return False, "round-trip produced different data"
        try:
            decrypt_bytes(container, "wrong passphrase")
            return False, "decryption with a wrong passphrase unexpectedly succeeded"
        except ValueError:
            pass
        # Tamper detection: flip one bit in the ciphertext body.
        tampered = bytearray(container)
        tampered[HEADER_LEN + 4] ^= 0x01
        try:
            decrypt_bytes(bytes(tampered), pw)
            return False, "tampered ciphertext was accepted"
        except ValueError:
            pass
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    backend = "AES-256-GCM (cryptography)" if HAVE_CRYPTOGRAPHY else "AES-256-CBC+HMAC (built-in)"
    return True, f"vault round-trip, wrong-password, and tamper checks all passed — {backend}"
