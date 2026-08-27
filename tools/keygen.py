#!/usr/bin/env python3
"""
PrivacyKit licence generator — VENDOR TOOL. Do not ship this to customers.

Generates the Ed25519 keypair and mints signed licence blocks. The private key
must never leave your machine; anyone holding it can issue licences.

    python tools/keygen.py --new                     # create a keypair
    python tools/keygen.py --issue "Jane Smith" --edition pro
    python tools/keygen.py --issue "ACME Ltd" --edition business --seats 25 --days 365
    python tools/keygen.py --issue "Jane" --edition pro --bind 26465879-8AFB4C47-...

Requires the `cryptography` package for signing (verification in the app does
not).
"""

from __future__ import annotations

import argparse
import base64
import json
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from privacykit.core.licensing import (LICENSE_FOOTER, LICENSE_HEADER,
                                       _PAYLOAD_STRUCT, Edition)

KEY_FILE = Path(__file__).parent / "vendor_private_key.pem"


def _require_cryptography():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey)
        return Ed25519PrivateKey
    except ImportError:
        sys.exit("Signing needs the 'cryptography' package:\n"
                 "    pip install cryptography")


def create_keypair(force: bool = False) -> None:
    Ed25519PrivateKey = _require_cryptography()
    from cryptography.hazmat.primitives import serialization

    if KEY_FILE.exists() and not force:
        sys.exit(f"{KEY_FILE} already exists. Use --force to overwrite "
                 "(this invalidates every licence you have already issued).")

    private = Ed25519PrivateKey.generate()
    pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    KEY_FILE.write_bytes(pem)
    try:
        KEY_FILE.chmod(0o600)
    except Exception:
        pass

    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)

    print(f"Private key written to {KEY_FILE}")
    print("  Keep this file secret and backed up. Losing it means you cannot")
    print("  issue new licences; leaking it means anyone can.\n")
    print("Paste this into privacykit/core/licensing.py as VENDOR_PUBLIC_KEY:\n")
    print('VENDOR_PUBLIC_KEY = bytes.fromhex(')
    print(f'    "{public.hex()}")')


def _load_private():
    Ed25519PrivateKey = _require_cryptography()
    from cryptography.hazmat.primitives import serialization
    if not KEY_FILE.exists():
        sys.exit(f"No private key at {KEY_FILE}. Run --new first.")
    return serialization.load_pem_private_key(KEY_FILE.read_bytes(), password=None)


def issue(licensee: str, edition: str, days: int, seats: int,
          bind: str = "") -> str:
    private = _load_private()
    edition_map = {"free": Edition.FREE, "pro": Edition.PRO,
                   "business": Edition.BUSINESS}
    ed = edition_map.get(edition.lower())
    if ed is None:
        sys.exit(f"Unknown edition '{edition}'. Use free, pro, or business.")

    today = int(time.time() // 86400)
    expires = 0 if days <= 0 else today + days

    machine = b"\x00" * 16
    if bind:
        hexed = bind.replace("-", "").strip()
        if len(hexed) != 32:
            sys.exit("A machine fingerprint is 32 hex characters "
                     "(as shown on the customer's Licence screen).")
        machine = bytes.fromhex(hexed)

    payload = struct.pack(_PAYLOAD_STRUCT, int(ed), today, expires,
                          max(1, seats), machine)
    signature = private.sign(payload + licensee.encode("utf-8"))

    blob = base64.b32encode(payload + signature).decode("ascii").rstrip("=")
    lines = [blob[i:i + 44] for i in range(0, len(blob), 44)]

    return (f"{LICENSE_HEADER}\n"
            f"Licensed to: {licensee}\n\n"
            + "\n".join(lines) + "\n"
            + LICENSE_FOOTER)


def main() -> int:
    ap = argparse.ArgumentParser(description="PrivacyKit licence generator")
    ap.add_argument("--new", action="store_true", help="generate a keypair")
    ap.add_argument("--force", action="store_true", help="overwrite existing key")
    ap.add_argument("--issue", metavar="NAME", help="licensee name")
    ap.add_argument("--edition", default="pro",
                    choices=["free", "pro", "business"])
    ap.add_argument("--days", type=int, default=0,
                    help="validity in days (0 = perpetual)")
    ap.add_argument("--seats", type=int, default=1)
    ap.add_argument("--bind", default="",
                    help="lock to a machine fingerprint")
    ap.add_argument("--out", help="write the licence to a file")
    args = ap.parse_args()

    if args.new:
        create_keypair(args.force)
        return 0

    if not args.issue:
        ap.print_help()
        return 1

    text = issue(args.issue, args.edition, args.days, args.seats, args.bind)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"Licence written to {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
