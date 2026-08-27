"""
MAC address spoofing — the module the original tool grew out of.

Mechanism (unchanged from v1, because it is the correct one on Windows):
Windows lets a NIC's MAC be overridden by the ``NetworkAddress`` value under
the adapter's class key in ``HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\
{4D36E972-E325-11CE-BFC1-08002BE10318}\\<nnnn>``. Writing that value and then
cycling the adapter makes Windows present the new address. Deleting the value
reverts to the burned-in hardware address.

What v2 adds:
  * adapter enumeration via ``Get-NetAdapter`` (structured JSON, including the
    interface GUID) instead of scraping ``getmac`` CSV, with the old paths kept
    as fallbacks;
  * vendor-realistic addresses from :mod:`privacykit.core.oui`;
  * every change written to the reversible journal, so Panic Restore can undo a
    spoof made hours ago in a different session;
  * the pre-change address stored in the journal entry itself, so "original
    MAC" survives restarting the app — v1 lost it when the process exited.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import List, Optional

from . import journal, oui, shell, sysinfo

if sysinfo.IS_WINDOWS:
    import winreg
else:  # keeps the module importable for self-tests on other platforms
    winreg = None  # type: ignore

NET_CLASS_GUID = "{4D36E972-E325-11CE-BFC1-08002BE10318}"
CLASS_KEY = rf"SYSTEM\CurrentControlSet\Control\Class\{NET_CLASS_GUID}"
NETWORK_KEY = rf"SYSTEM\CurrentControlSet\Control\Network\{NET_CLASS_GUID}"

MAC_RE = re.compile(r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$")


@dataclass
class Adapter:
    name: str                      # friendly name, e.g. "Wi-Fi"
    description: str = ""          # driver description, e.g. "Intel(R) Wi-Fi 6 AX201"
    mac: str = ""                  # current MAC, lowercase colon-separated
    guid: str = ""                 # interface GUID, e.g. "{0A1B...}"
    status: str = ""               # Up / Disconnected / Disabled
    link_speed: str = ""
    is_virtual: bool = False
    permanent_mac: str = ""        # burned-in hardware address, when known

    @property
    def spoofed(self) -> bool:
        """True when the current MAC differs from the hardware address."""
        if not self.permanent_mac or not self.mac:
            return False
        return normalise(self.permanent_mac) != normalise(self.mac)

    @property
    def vendor(self) -> str:
        return oui.lookup(self.mac) or "unknown"

    def label(self) -> str:
        bits = [self.name]
        if self.status:
            bits.append(f"[{self.status}]")
        return " ".join(bits)


# ──────────────────────────────────────────────────────────────────────────────
# Validation / generation
# ──────────────────────────────────────────────────────────────────────────────

def normalise(mac: str) -> str:
    """Lowercase, colon-separated form. Accepts dashes, dots, or bare hex."""
    if not mac:
        return ""
    clean = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(clean) != 12:
        return mac.strip().lower().replace("-", ":")
    return ":".join(clean[i:i + 2] for i in range(0, 12, 2)).lower()


def is_valid(mac: str) -> tuple:
    """
    Validate a MAC for use as a NIC address. Returns ``(ok, reason)``.

    Rejects, with an explanation the UI can show rather than a bare "invalid":
      * wrong format;
      * multicast addresses (bit 0 of octet 1 set) — a NIC cannot own one;
      * all-zero and broadcast, which are reserved.
    """
    if not mac or not MAC_RE.match(mac.strip()):
        return False, "Format must be AA:BB:CC:DD:EE:FF (6 hex pairs)."
    norm = normalise(mac)
    first = int(norm.split(":")[0], 16)
    if first & 0x01:
        return False, ("The first octet has the multicast bit set. A network card "
                       "address must be unicast — make the first octet even "
                       f"(try {first & 0xFE:02x} instead of {first:02x}).")
    if norm == "00:00:00:00:00:00":
        return False, "All-zero address is reserved and will be rejected by Windows."
    if norm == "ff:ff:ff:ff:ff:ff":
        return False, "Broadcast address is reserved and cannot be assigned to a NIC."
    return True, "Valid."


def generate(mode: str = "vendor", vendor: Optional[str] = None) -> tuple:
    """
    Produce a new MAC. Returns ``(mac, description)``.

    ``mode`` is one of:
      * ``"vendor"``  — inside a chosen (or random) real vendor's OUI range;
      * ``"local"``   — random with the locally-administered bit set;
      * ``"keep-oui"``— keep an existing prefix, randomise the last 3 bytes.
    """
    if mode == "local":
        mac = oui.random_local_admin()
        return mac, "Random locally-administered address"
    if mode == "vendor":
        if vendor and vendor in oui.VENDORS:
            return oui.random_from_vendor(vendor), f"Looks like a {vendor} adapter"
        v, mac = oui.random_any_vendor()
        return mac, f"Looks like a {v} adapter"
    raise ValueError(f"unknown generation mode: {mode}")


def keep_oui_randomise(existing: str) -> str:
    """Keep the first 3 bytes of ``existing``, randomise the rest."""
    import random
    rng = random.SystemRandom()
    norm = normalise(existing)
    parts = norm.split(":")
    if len(parts) != 6:
        return oui.random_local_admin()
    tail = [f"{rng.randint(0, 255):02x}" for _ in range(3)]
    return ":".join(parts[:3] + tail)


# ──────────────────────────────────────────────────────────────────────────────
# Adapter enumeration
# ──────────────────────────────────────────────────────────────────────────────

def list_adapters(include_virtual: bool = True) -> List[Adapter]:
    """
    Enumerate network adapters, best source first.

    Get-NetAdapter is preferred because it returns the interface GUID directly
    (saving a registry walk) and reports the *permanent* hardware address, which
    is how we know whether an adapter is currently spoofed.
    """
    adapters = _list_via_powershell()
    if not adapters:
        adapters = _list_via_getmac()
    if not adapters:
        adapters = _list_via_ipconfig()
    if not include_virtual:
        adapters = [a for a in adapters if not a.is_virtual]
    return adapters


_VIRTUAL_HINTS = ("virtual", "vmware", "hyper-v", "vethernet", "loopback",
                  "tap-", "tunnel", "wan miniport", "bluetooth", "vbox",
                  "wireguard", "openvpn", "teredo", "pseudo")


def _looks_virtual(name: str, desc: str) -> bool:
    blob = f"{name} {desc}".lower()
    return any(h in blob for h in _VIRTUAL_HINTS)


def _list_via_powershell() -> List[Adapter]:
    if not sysinfo.IS_WINDOWS:
        return []
    script = (
        "Get-NetAdapter -IncludeHidden | "
        "Select-Object Name,InterfaceDescription,MacAddress,PermanentAddress,"
        "Status,InterfaceGuid,LinkSpeed,Virtual | ConvertTo-Json -Compress"
    )
    res = shell.run_powershell(script, timeout=35)
    if not res.out.strip():
        return []
    try:
        data = json.loads(res.out)
    except Exception:
        return []
    if isinstance(data, dict):   # a single adapter is not wrapped in a list
        data = [data]

    out: List[Adapter] = []
    for item in data:
        name = (item.get("Name") or "").strip()
        if not name:
            continue
        desc = (item.get("InterfaceDescription") or "").strip()
        out.append(Adapter(
            name=name,
            description=desc,
            mac=normalise(item.get("MacAddress") or ""),
            permanent_mac=normalise(item.get("PermanentAddress") or ""),
            guid=(item.get("InterfaceGuid") or "").strip(),
            status=(item.get("Status") or "").strip(),
            link_speed=str(item.get("LinkSpeed") or ""),
            is_virtual=bool(item.get("Virtual")) or _looks_virtual(name, desc),
        ))
    return out


def _list_via_getmac() -> List[Adapter]:
    """
    Fallback: parse ``getmac /v /fo csv /nh``.

    v1 split on the literal ``","`` sequence, which broke on any adapter whose
    name contained a comma. Using csv.reader handles quoting properly.
    """
    if not sysinfo.IS_WINDOWS:
        return []
    res = shell.run(["getmac", "/v", "/fo", "csv", "/nh"], check_rc=False)
    if not res.out.strip():
        return []
    import csv
    import io
    out: List[Adapter] = []
    for row in csv.reader(io.StringIO(res.out)):
        if len(row) < 3:
            continue
        name, desc, mac_raw = row[0].strip(), row[1].strip(), row[2].strip()
        if not mac_raw or "N/A" in mac_raw or "Disabled" in mac_raw:
            continue
        guid = ""
        if len(row) >= 4:
            m = re.search(r"\{[0-9A-Fa-f\-]{36}\}", row[3])
            if m:
                guid = m.group(0)
        out.append(Adapter(name=name, description=desc, mac=normalise(mac_raw),
                           guid=guid, is_virtual=_looks_virtual(name, desc)))
    return out


def _list_via_ipconfig() -> List[Adapter]:
    """Last resort: scrape ``ipconfig /all``."""
    if not sysinfo.IS_WINDOWS:
        return []
    res = shell.run(["ipconfig", "/all"], check_rc=False)
    out: List[Adapter] = []
    for block in re.split(r"\r?\n\r?\n", res.out):
        name_m = re.search(r"adapter\s+(.+?):\s*$", block, re.MULTILINE | re.IGNORECASE)
        mac_m = re.search(r"Physical Address[.\s]*:\s*([0-9A-Fa-f\-]{17})", block)
        desc_m = re.search(r"Description[.\s]*:\s*(.+)", block)
        if name_m and mac_m:
            name = name_m.group(1).strip()
            desc = desc_m.group(1).strip() if desc_m else name
            out.append(Adapter(name=name, description=desc,
                               mac=normalise(mac_m.group(1)),
                               is_virtual=_looks_virtual(name, desc)))
    return out


def get_adapter(name: str) -> Optional[Adapter]:
    for a in list_adapters():
        if a.name.lower() == name.lower():
            return a
    return None


def current_mac(name: str) -> str:
    a = get_adapter(name)
    return a.mac if a else ""


# ──────────────────────────────────────────────────────────────────────────────
# Registry plumbing
# ──────────────────────────────────────────────────────────────────────────────

def find_guid(friendly_name: str) -> Optional[str]:
    """Map a friendly adapter name to its interface GUID via the registry."""
    if not sysinfo.IS_WINDOWS:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, NETWORK_KEY) as net_key:
            i = 0
            while True:
                try:
                    guid = winreg.EnumKey(net_key, i)
                    i += 1
                except OSError:
                    break
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                        rf"{NETWORK_KEY}\{guid}\Connection") as conn:
                        nm, _ = winreg.QueryValueEx(conn, "Name")
                        if str(nm).lower() == friendly_name.lower():
                            return guid
                except OSError:
                    continue
    except Exception:
        pass
    return None


def find_class_subkey(guid: str) -> Optional[str]:
    """Find the ``...\\Class\\{4D36E972-...}\\nnnn`` key for an adapter GUID."""
    if not sysinfo.IS_WINDOWS or not guid:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, CLASS_KEY,
                            access=winreg.KEY_READ) as cls:
            idx = 0
            while True:
                try:
                    sub = winreg.EnumKey(cls, idx)
                    idx += 1
                except OSError:
                    break
                if not sub.isdigit():
                    continue
                path = rf"{CLASS_KEY}\{sub}"
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path,
                                        access=winreg.KEY_READ) as sk:
                        nid, _ = winreg.QueryValueEx(sk, "NetCfgInstanceId")
                        if str(nid).lower() == guid.lower():
                            return path
                except OSError:
                    continue
    except Exception:
        pass
    return None


def read_override(name: str) -> Optional[str]:
    """Return the currently-written NetworkAddress override, if any."""
    if not sysinfo.IS_WINDOWS:
        return None
    guid = _resolve_guid(name)
    path = find_class_subkey(guid) if guid else None
    if not path:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as sk:
            val, _ = winreg.QueryValueEx(sk, "NetworkAddress")
            return normalise(str(val))
    except FileNotFoundError:
        return None
    except Exception:
        return None


def _resolve_guid(name: str) -> Optional[str]:
    a = get_adapter(name)
    if a and a.guid:
        return a.guid
    return find_guid(name)


def _write_override(path: str, mac: str) -> bool:
    plain = normalise(mac).replace(":", "").upper()
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path,
                            access=winreg.KEY_READ | winreg.KEY_WRITE) as sk:
            winreg.SetValueEx(sk, "NetworkAddress", 0, winreg.REG_SZ, plain)
        return True
    except Exception:
        return False


def _delete_override(path: str) -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path,
                            access=winreg.KEY_READ | winreg.KEY_WRITE) as sk:
            winreg.DeleteValue(sk, "NetworkAddress")
        return True
    except FileNotFoundError:
        return True  # already absent — the desired end state
    except Exception:
        return False


def cycle_adapter(name: str, settle: float = 2.0) -> bool:
    """
    Disable then re-enable an adapter so the driver re-reads NetworkAddress.

    Returns False if the *enable* step failed, which is the dangerous case —
    leaving the user's network card switched off would be a nasty surprise, so
    the caller retries and reports loudly.
    """
    shell.run(["netsh", "interface", "set", "interface", name, "admin=disable"],
              check_rc=False, timeout=25)
    time.sleep(0.6)
    res = shell.run(["netsh", "interface", "set", "interface", name, "admin=enable"],
                    check_rc=False, timeout=25)
    time.sleep(settle)
    if res.code != 0:
        # One retry: transient failures here are common and the cost of leaving
        # the adapter disabled is high.
        time.sleep(1.0)
        res = shell.run(["netsh", "interface", "set", "interface", name, "admin=enable"],
                        check_rc=False, timeout=25)
        time.sleep(settle)
    return res.code == 0


# ──────────────────────────────────────────────────────────────────────────────
# Public operations
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ChangeResult:
    ok: bool
    message: str
    before: str = ""
    after: str = ""
    entry_id: str = ""
    hints: List[str] = field(default_factory=list)


def set_mac(name: str, new_mac: str, cycle: bool = True) -> ChangeResult:
    """
    Apply ``new_mac`` to adapter ``name``, recording an undo entry first.

    The undo entry stores the previous override (or the fact that there was
    none), so reverting restores exactly the prior state rather than assuming
    "no override" was the starting point — important if the user had already
    spoofed the adapter with another tool.
    """
    if not sysinfo.IS_WINDOWS:
        return ChangeResult(False, "MAC spoofing via registry is Windows-only.")
    if not sysinfo.is_admin():
        return ChangeResult(False, "Administrator rights are required to write to HKLM.")

    ok, reason = is_valid(new_mac)
    if not ok:
        return ChangeResult(False, reason)
    new_mac = normalise(new_mac)

    adapter = get_adapter(name)
    if adapter is None:
        return ChangeResult(False, f"Adapter '{name}' not found.")
    before = adapter.mac

    guid = adapter.guid or find_guid(name)
    if not guid:
        return ChangeResult(False, f"Could not resolve the interface GUID for '{name}'.")
    path = find_class_subkey(guid)
    if not path:
        return ChangeResult(
            False,
            "Could not locate this adapter's driver registry key. Some virtual "
            "adapters (Hyper-V, VPN tunnels) genuinely have no NetworkAddress "
            "key and cannot be spoofed this way.",
        )

    prior_override = read_override(name)

    entry = journal.record(
        module="mac",
        action=f"Set MAC on '{name}' to {new_mac}",
        undo={
            "kind": "mac.restore",
            "adapter": name,
            "reg_path": path,
            "prior_override": prior_override,   # None means "no override existed"
            "hardware_mac": adapter.permanent_mac,
        },
        before={"mac": before, "permanent": adapter.permanent_mac,
                "override": prior_override},
    )

    if not _write_override(path, new_mac):
        journal.drop(entry.id)
        return ChangeResult(False, "Failed to write NetworkAddress to the registry.")

    if cycle and not cycle_adapter(name):
        return ChangeResult(
            False,
            f"Wrote the new address, but re-enabling '{name}' failed. "
            "Re-enable it in Network Connections if it is still down.",
            before=before, entry_id=entry.id,
        )

    after = current_mac(name)
    if after and after == new_mac:
        return ChangeResult(True, f"MAC changed: {before} → {after}",
                            before=before, after=after, entry_id=entry.id)

    # Registry write succeeded but the driver ignored it — the classic symptom
    # of a NIC whose driver does not honour NetworkAddress.
    return ChangeResult(
        False,
        f"The registry was updated but the adapter still reports {after or 'the old address'}.",
        before=before, after=after, entry_id=entry.id,
        hints=[
            "Some Wi-Fi chipsets (notably several Intel and Broadcom models) "
            "ignore the NetworkAddress override entirely.",
            "Check Device Manager → the adapter → Properties → Advanced for a "
            "'Network Address' or 'Locally Administered Address' property. If it "
            "is missing, the driver does not support software MAC spoofing.",
            "Try an address in a real vendor range — a few drivers silently "
            "reject locally-administered addresses.",
        ],
    )


def restore_mac(name: str, cycle: bool = True) -> ChangeResult:
    """Delete the NetworkAddress override, reverting to the hardware address."""
    if not sysinfo.IS_WINDOWS:
        return ChangeResult(False, "Windows-only operation.")
    if not sysinfo.is_admin():
        return ChangeResult(False, "Administrator rights are required.")

    adapter = get_adapter(name)
    before = adapter.mac if adapter else ""
    guid = (adapter.guid if adapter else "") or find_guid(name)
    path = find_class_subkey(guid) if guid else None
    if not path:
        return ChangeResult(False, f"Could not locate the registry key for '{name}'.")

    if not _delete_override(path):
        return ChangeResult(False, "Failed to delete the NetworkAddress value.")
    if cycle:
        cycle_adapter(name)

    after = current_mac(name)
    # Mark every outstanding MAC entry for this adapter as reverted — the
    # hardware address is back, so they no longer describe live changes.
    for e in journal.pending():
        if e.module == "mac" and e.undo.get("adapter", "").lower() == name.lower():
            journal.mark_undone(e.id)

    return ChangeResult(True, f"Hardware MAC restored: {before} → {after}",
                        before=before, after=after)


@journal.register_undo("mac.restore")
def _undo_mac(payload: dict) -> tuple:
    """
    Undo handler: put the adapter back to its pre-change override state.

    If there was no override before, the value is deleted (hardware MAC). If
    there was one, it is rewritten — we restore the state we found, not a
    guess at what "clean" means.
    """
    name = payload.get("adapter", "")
    path = payload.get("reg_path") or (find_class_subkey(_resolve_guid(name) or "") or "")
    if not path:
        return False, f"registry key for '{name}' not found"

    prior = payload.get("prior_override")
    if prior:
        ok = _write_override(path, prior)
        msg = f"restored previous override {prior}"
    else:
        ok = _delete_override(path)
        msg = "removed override (hardware MAC)"
    if ok and name:
        cycle_adapter(name)
    return ok, msg if ok else "registry write failed"


def snapshot() -> dict:
    """Baseline snapshot of every adapter's hardware address."""
    return {
        a.name: {
            "mac": a.mac,
            "permanent": a.permanent_mac,
            "description": a.description,
            "guid": a.guid,
            "override": read_override(a.name),
        }
        for a in list_adapters()
    }
