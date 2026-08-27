"""
Computer name (hostname) randomisation.

Why it matters: your hostname is broadcast constantly — in DHCP requests, in
NetBIOS/LLMNR/mDNS chatter, and in the client list of every router you join.
"NILOTPAL-LAPTOP" following you between coffee shops is as identifying as a MAC
address, and spoofing the MAC while leaving the hostname untouched defeats the
purpose.

The change requires a reboot to fully take effect, which the UI states plainly.
"""

from __future__ import annotations

import random
import re
import socket
import string
from typing import List

from . import journal, shell, sysinfo

if sysinfo.IS_WINDOWS:
    import winreg
else:
    winreg = None  # type: ignore

# Windows NetBIOS names are limited to 15 characters and a restricted charset.
MAX_LEN = 15
_INVALID = set('\\/:*?"<>|,~;[]+=@ ')

#: Patterns that blend in with default names Windows and OEMs actually assign.
_PATTERNS = [
    ("DESKTOP-", 7),
    ("LAPTOP-", 7),
    ("WIN-", 11),
    ("PC-", 8),
    ("WORKSTATION", 0),
]


def current() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return ""


def is_valid(name: str) -> tuple:
    """Validate a proposed computer name. Returns ``(ok, reason)``."""
    if not name:
        return False, "Name cannot be empty."
    if len(name) > MAX_LEN:
        return False, f"Windows limits computer names to {MAX_LEN} characters."
    if any(c in _INVALID for c in name):
        return False, 'Name cannot contain spaces or \\ / : * ? " < > | , ~ ; [ ] + = @'
    if name.isdigit():
        return False, "A computer name cannot be entirely numeric."
    if not re.match(r"^[A-Za-z0-9\-]+$", name):
        return False, "Use only letters, digits, and hyphens."
    if name.startswith("-") or name.endswith("-"):
        return False, "Name cannot start or end with a hyphen."
    return True, "Valid."


def generate(style: str = "windows") -> str:
    """
    Produce a believable random computer name.

    ``"windows"`` mimics the DESKTOP-XXXXXXX form Windows generates itself, so
    the name is unremarkable on any network. ``"random"`` is pure noise, which
    is more unique but also more memorable to anyone watching.
    """
    rng = random.SystemRandom()
    alphabet = string.ascii_uppercase + string.digits
    if style == "random":
        length = rng.randint(8, MAX_LEN)
        return "".join(rng.choice(alphabet) for _ in range(length))

    prefix, tail_len = rng.choice(_PATTERNS)
    if tail_len == 0:
        return prefix
    tail = "".join(rng.choice(alphabet) for _ in range(tail_len))
    return (prefix + tail)[:MAX_LEN]


def set_hostname(new_name: str) -> tuple:
    """
    Rename the computer. Returns ``(ok, message)``.

    Uses ``WMIC``/``Rename-Computer`` semantics via the registry-backed
    ``netdom``-free path: PowerShell's Rename-Computer is the supported API and
    handles domain-joined machines correctly (it will refuse without
    credentials rather than half-applying).
    """
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    if not sysinfo.is_admin():
        return False, "Administrator rights are required to rename the computer."

    ok, reason = is_valid(new_name)
    if not ok:
        return False, reason

    old = current()
    if old.lower() == new_name.lower():
        return False, "That is already the computer's name."

    entry = journal.record(
        module="hostname",
        action=f"Renamed computer '{old}' → '{new_name}'",
        undo={"kind": "hostname.restore", "previous": old},
        before={"hostname": old},
    )

    res = shell.run_powershell(
        f"Rename-Computer -NewName '{new_name.replace(chr(39), '')}' "
        "-Force -ErrorAction Stop; 'RENAMED'",
        timeout=60,
    )
    if "RENAMED" in res.out:
        return True, (f"Computer renamed to '{new_name}'. "
                      "A restart is required before the change is fully visible "
                      "to the network.")

    journal.drop(entry.id)
    err = res.text.strip().splitlines()
    detail = err[0][:200] if err else "unknown error"
    if "domain" in res.text.lower():
        detail = ("This machine appears to be domain-joined; renaming needs "
                  "domain credentials and should go through your administrator.")
    return False, f"Rename failed: {detail}"


@journal.register_undo("hostname.restore")
def _undo_hostname(payload: dict) -> tuple:
    prev = payload.get("previous")
    if not prev:
        return False, "no previous hostname recorded"
    if current().lower() == prev.lower():
        return True, "already the original name"
    res = shell.run_powershell(
        f"Rename-Computer -NewName '{prev.replace(chr(39), '')}' -Force "
        "-ErrorAction Stop; 'RENAMED'",
        timeout=60,
    )
    if "RENAMED" in res.out:
        return True, f"restored '{prev}' (restart required)"
    return False, res.text.strip()[:160] or "rename failed"


def netbios_names() -> List[str]:
    """Other names the machine announces, useful context in the UI."""
    names = []
    try:
        names.append(socket.gethostname())
        fqdn = socket.getfqdn()
        if fqdn and fqdn not in names:
            names.append(fqdn)
    except Exception:
        pass
    if sysinfo.IS_WINDOWS and winreg is not None:
        for key, val in (
            (r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName", "ComputerName"),
            (r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "Hostname"),
            (r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "NV Hostname"),
        ):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
                    v, _ = winreg.QueryValueEx(k, val)
                    if v and str(v) not in names:
                        names.append(str(v))
            except Exception:
                continue
    return names


def snapshot() -> dict:
    return {"hostname": current(), "all_names": netbios_names()}
