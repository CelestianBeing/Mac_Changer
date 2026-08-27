"""
Embedded OUI (vendor prefix) table.

Why this exists
---------------
A purely random MAC has the "locally administered" bit set (``x2:``, ``x6:``,
``xA:``, ``xE:`` as the second hex digit). Any network that bothers to look can
spot that instantly — it is a flashing sign that says "this address is
spoofed". Some captive portals and enterprise NACs reject such addresses
outright.

Generating an address inside a *real* vendor's assigned range instead makes the
adapter look like an ordinary Intel/Apple/Samsung NIC. These are genuine,
publicly registered IEEE OUI assignments.
"""

from __future__ import annotations

import random
from typing import Dict, List, Tuple

#: vendor -> list of real 3-byte OUI prefixes assigned to them by the IEEE.
VENDORS: Dict[str, List[str]] = {
    "Intel": [
        "00:1B:21", "00:1E:67", "3C:FD:FE", "A4:C3:F0", "8C:8C:AA",
        "00:15:17", "5C:51:4F", "00:24:D7", "34:13:E8", "94:65:9C",
        "48:51:B7", "7C:B2:7D", "E4:B3:18", "00:1F:3B",
    ],
    "Apple": [
        "00:1B:63", "3C:22:FB", "88:66:5A", "A4:83:E7", "F0:18:98",
        "00:26:BB", "AC:BC:32", "68:AB:BC", "04:0C:CE", "D0:81:7A",
        "9C:F3:87", "F4:0F:24", "20:C9:D0", "BC:52:B7",
    ],
    "Samsung": [
        "00:12:FB", "78:1F:DB", "5C:0A:5B", "34:BE:00", "08:37:3D",
        "E8:50:8B", "1C:5A:3E", "50:CC:F8", "C8:19:F7", "AC:5F:3E",
    ],
    "Dell": [
        "00:14:22", "B8:2A:72", "F8:BC:12", "18:66:DA", "D4:BE:D9",
        "00:1E:C9", "84:2B:2B", "F8:DB:88", "54:BF:64", "00:24:E8",
    ],
    "HP": [
        "00:1B:78", "3C:D9:2B", "9C:8E:99", "00:25:B3", "70:5A:0F",
        "98:E7:F4", "80:C1:6E", "00:21:5A", "10:60:4B", "94:57:A5",
    ],
    "Lenovo": [
        "00:59:07", "6C:5F:1C", "8C:16:45", "E8:6A:64", "50:7B:9D",
        "A4:8C:DB", "68:F7:28",
    ],
    "ASUS": [
        "00:1B:FC", "2C:56:DC", "04:D9:F5", "50:46:5D", "AC:22:0B",
        "1C:87:2C", "38:D5:47", "F0:2F:74",
    ],
    "TP-Link": [
        "00:27:19", "50:C7:BF", "EC:08:6B", "B0:48:7A", "14:CC:20",
        "A4:2B:B0", "60:32:B1",
    ],
    "Microsoft": [
        "00:12:5A", "28:18:78", "7C:1E:52", "00:50:F2", "58:82:A8",
        "00:15:5D",  # Hyper-V virtual NICs
    ],
    "Cisco": [
        "00:1A:A1", "00:26:0B", "58:97:BD", "00:1B:D4", "00:23:04",
        "F4:0F:1B", "70:E4:22",
    ],
    "Realtek": [
        # 52:54:00 is deliberately absent: it is QEMU/KVM's prefix and has the
        # locally-administered bit set, which is exactly the "obviously
        # spoofed" pattern this table exists to avoid.
        "00:E0:4C", "00:1A:4D", "00:14:D1",
    ],
    "Broadcom": [
        "00:10:18", "00:05:B5", "D4:01:29", "00:1B:E9",
    ],
    "Qualcomm": [
        "00:03:7F", "00:13:74", "40:E2:30", "9C:B6:D0", "00:A0:C6",
    ],
    "Google": [
        "3C:5A:B4", "F4:F5:E8", "94:EB:2C", "A4:77:33", "F8:8F:CA",
    ],
    "Xiaomi": [
        "64:09:80", "8C:BE:BE", "F0:B4:29", "34:CE:00", "78:11:DC",
    ],
    "Huawei": [
        "00:E0:FC", "48:DB:50", "78:D7:52", "20:F3:A3", "80:B6:86",
    ],
    "Sony": [
        "00:13:A9", "30:F9:ED", "FC:0F:E6", "00:24:BE", "54:42:49",
    ],
    "Nintendo": [
        "00:09:BF", "40:F4:07", "98:B6:E9", "18:2A:7B", "E8:4E:CE",
    ],
    "VMware": [
        "00:05:69", "00:0C:29", "00:1C:14", "00:50:56",
    ],
    "Raspberry Pi": [
        "B8:27:EB", "DC:A6:32", "E4:5F:01", "28:CD:C1",
    ],
    "Netgear": [
        "00:09:5B", "20:4E:7F", "A0:40:A0", "9C:3D:CF", "CC:40:D0",
    ],
}

#: Order used to populate the vendor dropdown in the UI.
VENDOR_NAMES: List[str] = sorted(VENDORS)


def random_from_vendor(vendor: str, rng: random.Random | None = None) -> str:
    """
    Build a plausible MAC inside ``vendor``'s registered range.

    The first three bytes are a real assigned OUI; the last three (the NIC-
    specific portion, which the manufacturer allocates however it likes) are
    random. The result has the locally-administered bit clear, so it reads as a
    genuine factory address.
    """
    rng = rng or random.SystemRandom()
    if vendor not in VENDORS:
        raise KeyError(f"unknown vendor: {vendor}")
    prefix = rng.choice(VENDORS[vendor])
    tail = [rng.randint(0x00, 0xFF) for _ in range(3)]
    return f"{prefix}:{tail[0]:02X}:{tail[1]:02X}:{tail[2]:02X}".lower()


def random_any_vendor(rng: random.Random | None = None) -> Tuple[str, str]:
    """Pick a random vendor and return ``(vendor_name, mac)``."""
    rng = rng or random.SystemRandom()
    vendor = rng.choice(VENDOR_NAMES)
    return vendor, random_from_vendor(vendor, rng)


def random_local_admin(rng: random.Random | None = None) -> str:
    """
    Classic fully-random MAC with the locally-administered bit set.

    Kept because it is the correct choice when you specifically do *not* want to
    impersonate a vendor — it is honest about being an assigned address, and it
    can never collide with a real factory MAC.
    """
    rng = rng or random.SystemRandom()
    b = [rng.randint(0, 255) for _ in range(6)]
    b[0] = (b[0] & 0xFE) | 0x02  # unicast + locally administered
    return ":".join(f"{x:02x}" for x in b)


def lookup(mac: str) -> str | None:
    """Reverse-lookup: which embedded vendor does this MAC belong to?"""
    if not mac or len(mac) < 8:
        return None
    prefix = mac.replace("-", ":").upper()[:8]
    for vendor, prefixes in VENDORS.items():
        if prefix in prefixes:
            return vendor
    return None


def describe(mac: str) -> str:
    """One-line human description of a MAC address, used in the UI."""
    if not mac or ":" not in mac:
        return "unknown"
    try:
        first = int(mac.split(":")[0], 16)
    except ValueError:
        return "unrecognised format"
    bits = []
    bits.append("multicast" if first & 0x01 else "unicast")
    bits.append("locally administered" if first & 0x02 else "globally unique (factory)")
    vendor = lookup(mac)
    if vendor:
        bits.append(f"vendor: {vendor}")
    return ", ".join(bits)


def validate() -> list:
    """
    Check every embedded prefix is a plausible factory OUI.

    A real IEEE assignment is unicast (bit 0 clear) and globally unique (bit 1
    clear). A prefix failing either test would defeat the whole purpose of
    vendor mode — the resulting address would be visibly spoofed. Called by the
    self-test so a bad prefix cannot be pasted in unnoticed.
    """
    problems = []
    for vendor, prefixes in VENDORS.items():
        for prefix in prefixes:
            parts = prefix.split(":")
            if len(parts) != 3:
                problems.append(f"{vendor}: '{prefix}' is not three octets")
                continue
            try:
                first = int(parts[0], 16)
            except ValueError:
                problems.append(f"{vendor}: '{prefix}' is not hexadecimal")
                continue
            if first & 0x01:
                problems.append(f"{vendor}: {prefix} has the multicast bit set")
            if first & 0x02:
                problems.append(
                    f"{vendor}: {prefix} has the locally-administered bit set, "
                    "so addresses built from it would look spoofed")
    return problems


def total_prefixes() -> int:
    return sum(len(v) for v in VENDORS.values())
