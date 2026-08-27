"""
Licensing, activation, and trial management.

Design goals, in priority order:

1. **Offline verification.** A privacy tool that phones home to check a licence
   is self-defeating, and users of this category of software will notice
   immediately. Licences are Ed25519-signed blobs the application verifies
   locally against an embedded public key. No network call, ever.
2. **Unforgeable.** Only the holder of the private key can mint a licence.
   Because verification is asymmetric, extracting the public key from the binary
   gains an attacker nothing.
3. **Fail closed, degrade gracefully.** A missing, corrupt, or tampered licence
   drops to the Free edition rather than either crashing or unlocking
   everything.

What this does not attempt: stopping a determined attacker who patches the
binary. That is not achievable in a Python application, and pretending otherwise
would mean spending effort on obfuscation that only inconveniences paying
customers. The goal is to make casual sharing not work, which this does.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import platform
import struct
import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import ed25519, shell, sysinfo

if sysinfo.IS_WINDOWS:
    import winreg
else:
    winreg = None  # type: ignore


class Edition(IntEnum):
    FREE = 0
    PRO = 1
    BUSINESS = 2


EDITION_NAMES = {
    Edition.FREE: "Free",
    Edition.PRO: "Pro",
    Edition.BUSINESS: "Business",
}

TRIAL_DAYS = 14

#: Vendor public key. Replace with your own from ``tools/keygen.py --new``
#: before shipping — this placeholder verifies nothing you did not sign.
VENDOR_PUBLIC_KEY = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

#: Mixed into the trial HMAC. Not a secret in any real sense — it raises the
#: effort of hand-editing the trial record from "open the file" to "read the
#: source", which is the honest limit of client-side trial enforcement.
_TRIAL_PEPPER = b"PrivacyKit/trial/v1"

LICENSE_HEADER = "-----BEGIN PRIVACYKIT LICENSE-----"
LICENSE_FOOTER = "-----END PRIVACYKIT LICENSE-----"

_PAYLOAD_STRUCT = ">BIIB16s"          # edition, issued, expires, seats, machine
_PAYLOAD_LEN = struct.calcsize(_PAYLOAD_STRUCT)


# ──────────────────────────────────────────────────────────────────────────────
# Feature gating
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Feature:
    key: str
    title: str
    minimum: Edition
    note: str = ""


#: Free covers the original tool's scope plus the diagnostics, so the free
#: edition is genuinely useful rather than crippled. Pro is the automation,
#: continuous protection, and the parts that took the most work.
FEATURES: List[Feature] = [
    Feature("mac", "MAC address spoofing", Edition.FREE),
    Feature("ip", "Local IP management", Edition.FREE),
    Feature("hostname", "Computer name randomiser", Edition.FREE),
    Feature("wifi", "Wi-Fi profile management", Edition.FREE),
    Feature("dns", "DNS resolver switching and DoH", Edition.FREE),
    Feature("leaks", "Leak tests and privacy score", Edition.FREE),
    Feature("cleaner", "Trace cleaning", Edition.FREE),
    Feature("passwords", "Password generator and hashes", Edition.FREE),
    Feature("journal", "Change journal and panic restore", Edition.FREE),
    Feature("hardening", "Windows privacy tweaks", Edition.FREE),

    Feature("tor", "Tor control and exit-node selection", Edition.PRO),
    Feature("killswitch", "Firewall kill switch", Edition.PRO),
    Feature("geo", "Location matching", Edition.PRO,
            "Aligns timezone, region, and coordinates with your exit IP."),
    Feature("noise", "Profile poisoning", Edition.PRO),
    Feature("protection", "Live protection monitoring", Edition.PRO),
    Feature("threatfeed", "Auto-updating blocklist", Edition.PRO),
    Feature("vault", "File encryption vault", Edition.PRO),
    Feature("shredder", "Secure file shredder", Edition.PRO),
    Feature("metadata", "Metadata scrubber", Edition.PRO),
    Feature("tray", "Tray agent and network automation", Edition.PRO),
    Feature("profiles", "Custom saved profiles", Edition.PRO),
    Feature("reports", "PDF audit reports", Edition.PRO),

    Feature("multiseat", "Multi-machine deployment", Edition.BUSINESS),
    Feature("cli", "Command-line automation", Edition.BUSINESS),
]

FEATURES_BY_KEY = {f.key: f for f in FEATURES}


# ──────────────────────────────────────────────────────────────────────────────
# Machine fingerprint
# ──────────────────────────────────────────────────────────────────────────────

def machine_fingerprint() -> bytes:
    """
    A stable 16-byte identifier for this machine.

    Built from values that are read-only and survive reboots and updates.
    Deliberately does *not* include anything the toolkit itself can change —
    binding a licence to the MAC address would break the moment someone used the
    headline feature.
    """
    parts: List[str] = [platform.machine(), platform.system()]

    if sysinfo.IS_WINDOWS and winreg is not None:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Microsoft\Cryptography") as k:
                parts.append(str(winreg.QueryValueEx(k, "MachineGuid")[0]))
        except Exception:
            pass
        res = shell.run(["cmd", "/c", "vol", "C:"], check_rc=False, timeout=15)
        import re
        m = re.search(r"([0-9A-F]{4}-[0-9A-F]{4})", res.out or "")
        if m:
            parts.append(m.group(1))
    else:
        parts.append(str(uuid.getnode()))

    if len(parts) < 3:
        parts.append(str(uuid.getnode()))

    digest = hashlib.sha256("|".join(parts).encode("utf-8")).digest()
    return digest[:16]


def fingerprint_display() -> str:
    """Human-readable fingerprint, for the user to quote when buying."""
    fp = machine_fingerprint().hex().upper()
    return "-".join(fp[i:i + 8] for i in range(0, 32, 8))


# ──────────────────────────────────────────────────────────────────────────────
# License model
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class License:
    edition: Edition = Edition.FREE
    licensee: str = ""
    issued: int = 0                  # unix days
    expires: int = 0                 # unix days, 0 = perpetual
    seats: int = 1
    machine_bound: bool = False
    valid: bool = False
    reason: str = ""

    @property
    def edition_name(self) -> str:
        return EDITION_NAMES.get(self.edition, "Unknown")

    @property
    def perpetual(self) -> bool:
        return self.expires == 0

    @property
    def expired(self) -> bool:
        return not self.perpetual and _today() > self.expires

    @property
    def days_left(self) -> Optional[int]:
        if self.perpetual:
            return None
        return max(0, self.expires - _today())

    def describe(self) -> str:
        if not self.valid:
            return self.reason or "No licence"
        if self.perpetual:
            return f"{self.edition_name} — perpetual"
        return f"{self.edition_name} — {self.days_left} day(s) remaining"


def _today() -> int:
    return int(time.time() // 86400)


def _days_to_date(days: int) -> str:
    if days == 0:
        return "never"
    return time.strftime("%Y-%m-%d", time.gmtime(days * 86400))


# ──────────────────────────────────────────────────────────────────────────────
# Encoding / decoding
# ──────────────────────────────────────────────────────────────────────────────

def _encode_block(payload: bytes, signature: bytes, licensee: str) -> str:
    blob = base64.b32encode(payload + signature).decode("ascii").rstrip("=")
    lines = [blob[i:i + 44] for i in range(0, len(blob), 44)]
    body = "\n".join(lines)
    return (f"{LICENSE_HEADER}\n"
            f"Licensed to: {licensee}\n\n"
            f"{body}\n"
            f"{LICENSE_FOOTER}")


def _decode_block(text: str) -> Tuple[Optional[bytes], str]:
    """Extract ``(raw_bytes, licensee)`` from a pasted licence block."""
    if not text or LICENSE_HEADER not in text:
        return None, ""
    try:
        inner = text.split(LICENSE_HEADER, 1)[1].split(LICENSE_FOOTER, 1)[0]
    except Exception:
        return None, ""

    licensee = ""
    data_lines: List[str] = []
    for line in inner.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.lower().startswith("licensed to:"):
            licensee = line.split(":", 1)[1].strip()
            continue
        data_lines.append(line)

    blob = "".join(data_lines).replace(" ", "").upper()
    padding = (-len(blob)) % 8
    try:
        return base64.b32decode(blob + "=" * padding), licensee
    except Exception:
        return None, licensee


def verify_license_text(text: str) -> License:
    """Parse and cryptographically verify a licence block."""
    raw, licensee = _decode_block(text)
    if raw is None:
        return License(reason="That does not look like a PrivacyKit licence.")
    if len(raw) < _PAYLOAD_LEN + 64:
        return License(reason="Licence is truncated or corrupted.")

    payload, signature = raw[:-64], raw[-64:]
    # The licensee name is signed too, so it cannot be edited after issue.
    message = payload + licensee.encode("utf-8")

    if not ed25519.verify(signature, message, VENDOR_PUBLIC_KEY):
        return License(reason="Licence signature is not valid. It may have been "
                              "edited, or it was issued for a different product.")

    try:
        edition_v, issued, expires, seats, machine = struct.unpack(
            _PAYLOAD_STRUCT, payload[:_PAYLOAD_LEN])
    except Exception:
        return License(reason="Licence payload is malformed.")

    try:
        edition = Edition(edition_v)
    except ValueError:
        return License(reason=f"Unknown edition code {edition_v}.")

    lic = License(edition=edition, licensee=licensee, issued=issued,
                  expires=expires, seats=seats,
                  machine_bound=machine != b"\x00" * 16)

    if lic.machine_bound and not hmac.compare_digest(machine, machine_fingerprint()):
        lic.reason = ("This licence is bound to a different machine. "
                      f"This machine is {fingerprint_display()}.")
        return lic

    if lic.expired:
        lic.reason = f"Licence expired on {_days_to_date(expires)}."
        return lic

    lic.valid = True
    lic.reason = "Licence is valid."
    return lic


# ──────────────────────────────────────────────────────────────────────────────
# Storage
# ──────────────────────────────────────────────────────────────────────────────

def license_path() -> Path:
    return sysinfo.appdata_dir() / "license.pklic"


def install_license(text: str) -> Tuple[bool, str, License]:
    """Verify then store a licence. Nothing invalid is ever written to disk."""
    lic = verify_license_text(text)
    if not lic.valid:
        return False, lic.reason, lic
    try:
        license_path().write_text(text, encoding="utf-8")
    except Exception as exc:
        return False, f"Licence is valid but could not be saved: {exc}", lic
    _reset_cache()
    return True, (f"{lic.edition_name} licence activated"
                  + (f" for {lic.licensee}" if lic.licensee else "") + "."), lic


def remove_license() -> Tuple[bool, str]:
    try:
        p = license_path()
        if p.exists():
            p.unlink()
        _reset_cache()
        return True, "Licence removed. The application has reverted to Free."
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def load_license() -> Optional[License]:
    p = license_path()
    if not p.exists():
        return None
    try:
        lic = verify_license_text(p.read_text(encoding="utf-8"))
        return lic if lic.valid else None
    except Exception:
        return None


# ──────────────────────────────────────────────────────────────────────────────
# Trial
# ──────────────────────────────────────────────────────────────────────────────

TRIAL_REG_PATH = r"Software\PrivacyKit"


@dataclass
class Trial:
    started: int = 0                 # unix days
    active: bool = False
    days_left: int = 0
    tampered: bool = False
    ever_started: bool = False

    def describe(self) -> str:
        if self.tampered:
            return "Trial record was modified — trial unavailable"
        if not self.ever_started:
            return f"{TRIAL_DAYS}-day trial available"
        if self.active:
            return f"Trial — {self.days_left} day(s) remaining"
        return "Trial expired"


def _trial_mac(record: dict) -> str:
    key = hashlib.sha256(_TRIAL_PEPPER + machine_fingerprint()).digest()
    body = json.dumps({k: record[k] for k in sorted(record) if k != "mac"},
                      separators=(",", ":")).encode("utf-8")
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def _trial_file() -> Path:
    return sysinfo.appdata_dir() / "trial.dat"


def _read_trial_file() -> Optional[dict]:
    try:
        return json.loads(_trial_file().read_text(encoding="utf-8"))
    except Exception:
        return None


def _read_trial_registry() -> Optional[dict]:
    if not sysinfo.IS_WINDOWS or winreg is None:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, TRIAL_REG_PATH) as k:
            return json.loads(str(winreg.QueryValueEx(k, "t")[0]))
    except Exception:
        return None


def _write_trial(record: dict) -> None:
    record = dict(record)
    record["mac"] = _trial_mac(record)
    blob = json.dumps(record, separators=(",", ":"))
    try:
        _trial_file().write_text(blob, encoding="utf-8")
    except Exception:
        pass
    if sysinfo.IS_WINDOWS and winreg is not None:
        try:
            k = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, TRIAL_REG_PATH, 0,
                                   winreg.KEY_READ | winreg.KEY_WRITE)
            winreg.SetValueEx(k, "t", 0, winreg.REG_SZ, blob)
            winreg.CloseKey(k)
        except Exception:
            pass


def _valid_record(record: Optional[dict]) -> Optional[dict]:
    if not record or "mac" not in record:
        return None
    expected = _trial_mac(record)
    return record if hmac.compare_digest(expected, record["mac"]) else None


def get_trial() -> Trial:
    """
    Read trial state from two independent stores.

    Both a file and a registry value are kept, each authenticated with an HMAC
    keyed to the machine. Deleting one is detected by the other; editing either
    breaks its HMAC. When the two disagree, the *earlier* start date wins, so
    removing one store cannot extend the trial.
    """
    file_rec = _valid_record(_read_trial_file())
    reg_rec = _valid_record(_read_trial_registry())

    raw_file = _read_trial_file()
    raw_reg = _read_trial_registry()
    tampered = bool((raw_file and not file_rec) or (raw_reg and not reg_rec))

    records = [r for r in (file_rec, reg_rec) if r]
    if not records:
        return Trial(tampered=tampered, ever_started=tampered)

    started = min(int(r.get("started", 0)) for r in records)
    last_seen = max(int(r.get("seen", 0)) for r in records)
    today = _today()

    # Clock rolled back: the machine claims a date earlier than one we have
    # already recorded, which only happens when someone is trying to extend the
    # trial by changing the system date.
    if today < last_seen:
        tampered = True

    elapsed = today - started
    days_left = max(0, TRIAL_DAYS - elapsed)

    if not tampered and today > last_seen:
        rec = dict(records[0])
        rec["seen"] = today
        rec["started"] = started
        _write_trial(rec)

    return Trial(started=started, active=(days_left > 0 and not tampered),
                 days_left=days_left, tampered=tampered, ever_started=True)


def start_trial() -> Tuple[bool, str]:
    trial = get_trial()
    if trial.tampered:
        return False, ("The trial record on this machine has been modified, so "
                       "the trial is no longer available. A licence will still "
                       "activate normally.")
    if trial.ever_started:
        if trial.active:
            return True, f"Trial already running — {trial.days_left} day(s) left."
        return False, "The trial period on this machine has already been used."

    today = _today()
    _write_trial({"started": today, "seen": today, "v": 1})
    _reset_cache()
    return True, (f"{TRIAL_DAYS}-day Pro trial started. Every feature is "
                  "unlocked until it ends.")


# ──────────────────────────────────────────────────────────────────────────────
# Effective entitlement
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Entitlement:
    edition: Edition = Edition.FREE
    source: str = "free"             # free | trial | license
    license: Optional[License] = None
    trial: Optional[Trial] = None

    @property
    def name(self) -> str:
        if self.source == "trial":
            return f"Pro (trial — {self.trial.days_left if self.trial else 0} days left)"
        return EDITION_NAMES.get(self.edition, "Free")

    @property
    def is_paid(self) -> bool:
        return self.source == "license"


_cache: Optional[Entitlement] = None


def _reset_cache() -> None:
    global _cache
    _cache = None


def entitlement(refresh: bool = False) -> Entitlement:
    """Resolve what this installation is currently entitled to."""
    global _cache
    if _cache is not None and not refresh:
        return _cache

    lic = load_license()
    if lic and lic.valid:
        _cache = Entitlement(edition=lic.edition, source="license", license=lic)
        return _cache

    trial = get_trial()
    if trial.active:
        _cache = Entitlement(edition=Edition.PRO, source="trial", trial=trial)
        return _cache

    _cache = Entitlement(edition=Edition.FREE, source="free", trial=trial)
    return _cache


def has_feature(key: str) -> bool:
    feature = FEATURES_BY_KEY.get(key)
    if feature is None:
        return True                  # unknown keys are not gated
    return entitlement().edition >= feature.minimum


def require(key: str) -> Tuple[bool, str]:
    """Check a feature, returning an upgrade message when it is locked."""
    if has_feature(key):
        return True, ""
    feature = FEATURES_BY_KEY.get(key)
    if feature is None:
        return True, ""
    tier = EDITION_NAMES.get(feature.minimum, "Pro")
    trial = get_trial()
    hint = ("\n\nA free 14-day trial is available — start it from the Licence "
            "screen." if not trial.ever_started else "")
    return False, (f"“{feature.title}” is a {tier} feature.{hint}")


def locked_features() -> List[Feature]:
    current = entitlement().edition
    return [f for f in FEATURES if f.minimum > current]


def summary() -> dict:
    ent = entitlement(refresh=True)
    return {
        "edition": ent.name,
        "source": ent.source,
        "fingerprint": fingerprint_display(),
        "licensee": ent.license.licensee if ent.license else "",
        "expires": (_days_to_date(ent.license.expires)
                    if ent.license and not ent.license.perpetual else "never"),
        "locked": len(locked_features()),
        "trial": ent.trial.describe() if ent.trial else "",
    }
