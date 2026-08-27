"""
Wi-Fi profile management and nearby-network inspection.

Two privacy problems this addresses:

1. **Saved network leakage.** Windows keeps every network you have ever joined.
   Older clients actively probe for saved SSIDs, broadcasting a list of the
   places you have been ("HOTEL_MARRIOTT_LHR", "CorpNet-Guest") to anyone with
   a receiver. Forgetting networks you no longer need shrinks that list.

2. **Evil twins.** An attacker who clones the SSID and security type of a
   network you trust gets your device to join automatically. Listing nearby
   networks with their BSSIDs and signal strengths lets you spot two APs
   claiming the same name.

Passwords are only ever revealed on explicit request, and the UI makes that an
opt-in click rather than something shown by default.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from . import journal, shell, sysinfo


@dataclass
class WifiProfile:
    name: str
    auth: str = ""
    encryption: str = ""
    auto_connect: bool = True
    password: Optional[str] = None   # only populated on explicit request

    def describe(self) -> str:
        bits = [self.auth or "unknown security"]
        if self.auto_connect:
            bits.append("auto-connect")
        return ", ".join(bits)


@dataclass
class NearbyNetwork:
    ssid: str
    auth: str = ""
    encryption: str = ""
    signal: int = 0
    channel: str = ""
    bssids: List[str] = field(default_factory=list)

    @property
    def open_network(self) -> bool:
        return "open" in self.auth.lower()


def available() -> bool:
    """Is there a Wi-Fi interface at all? (Desktops often have none.)"""
    if not sysinfo.IS_WINDOWS:
        return False
    res = shell.run(["netsh", "wlan", "show", "interfaces"], check_rc=False)
    return "There is no wireless interface" not in res.text and bool(res.out.strip())


def list_profiles() -> List[WifiProfile]:
    """Every saved Wi-Fi network on this machine."""
    if not sysinfo.IS_WINDOWS:
        return []
    res = shell.run(["netsh", "wlan", "show", "profiles"], check_rc=False, timeout=30)
    names = re.findall(r":\s*(.+?)\s*$", res.out, re.MULTILINE)
    # The output also contains header lines; keep only entries that resolve to
    # a real profile when queried.
    profiles: List[WifiProfile] = []
    seen = set()
    for raw in names:
        name = raw.strip()
        if not name or name in seen or name.lower().startswith(("group policy", "user profile")):
            continue
        seen.add(name)
        detail = shell.run(["netsh", "wlan", "show", "profile", f"name={name}"],
                           check_rc=False, timeout=20)
        if "is not found" in detail.text.lower() or not detail.out.strip():
            continue
        auth = _grab(detail.out, r"Authentication\s*:\s*(.+)")
        enc = _grab(detail.out, r"Cipher\s*:\s*(.+)")
        mode = _grab(detail.out, r"Connection mode\s*:\s*(.+)")
        profiles.append(WifiProfile(
            name=name, auth=auth, encryption=enc,
            auto_connect="automatic" in mode.lower(),
        ))
    return profiles


def _grab(text: str, pattern: str) -> str:
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def reveal_password(profile_name: str) -> Optional[str]:
    """
    Return the stored key for a profile, or None if there is none.

    Deliberately a separate explicit call rather than part of list_profiles():
    dumping every saved password to the screen the moment the tab opens would
    be a hazard, not a feature.
    """
    if not sysinfo.IS_WINDOWS:
        return None
    if not sysinfo.is_admin():
        return None  # netsh only reveals keys to an elevated session
    res = shell.run(["netsh", "wlan", "show", "profile",
                     f"name={profile_name}", "key=clear"], check_rc=False, timeout=20)
    key = _grab(res.out, r"Key Content\s*:\s*(.+)")
    return key or None


def forget_profile(profile_name: str) -> tuple:
    """
    Delete a saved network.

    This is journalled with the profile's exported XML so it can be restored —
    without that, "forget" would be the one irreversible action in a toolkit
    that promises reversibility.
    """
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."

    xml_backup = _export_profile(profile_name)
    entry = journal.record(
        module="wifi",
        action=f"Forgot Wi-Fi network '{profile_name}'",
        undo={"kind": "wifi.restore", "profile": profile_name, "xml": xml_backup},
        before={"profile": profile_name, "backed_up": bool(xml_backup)},
    )

    res = shell.run(["netsh", "wlan", "delete", "profile", f"name={profile_name}"],
                    check_rc=False, timeout=20)
    if "deleted" in res.text.lower() or res.code == 0:
        return True, f"Removed saved network '{profile_name}'."
    journal.drop(entry.id)
    return False, res.text.strip()[:200] or "delete failed"


def _export_profile(profile_name: str) -> str:
    """Export a profile to XML (including the key) so it can be re-imported."""
    if not sysinfo.IS_WINDOWS:
        return ""
    import tempfile
    from pathlib import Path
    tmp = Path(tempfile.mkdtemp(prefix="pk_wifi_"))
    args = ["netsh", "wlan", "export", "profile", f"name={profile_name}",
            f"folder={tmp}"]
    if sysinfo.is_admin():
        args.append("key=clear")
    shell.run(args, check_rc=False, timeout=25)
    try:
        for f in tmp.glob("*.xml"):
            return f.read_text(encoding="utf-8", errors="replace")
    except Exception:
        pass
    finally:
        pass
    return ""


@journal.register_undo("wifi.restore")
def _undo_wifi(payload: dict) -> tuple:
    xml = payload.get("xml") or ""
    name = payload.get("profile", "network")
    if not xml.strip():
        return False, f"no backup XML was captured for '{name}'"
    if any(p.name == name for p in list_profiles()):
        return True, "profile already present"
    import tempfile
    from pathlib import Path
    tmp = Path(tempfile.mkdtemp(prefix="pk_wifi_restore_"))
    path = tmp / "profile.xml"
    try:
        path.write_text(xml, encoding="utf-8")
        res = shell.run(["netsh", "wlan", "add", "profile", f"filename={path}",
                         "user=all"], check_rc=False, timeout=25)
        ok = "added" in res.text.lower() or res.code == 0
        return ok, f"re-imported '{name}'" if ok else res.text[:160]
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def set_random_mac_policy(enabled: bool) -> tuple:
    """
    Toggle Windows' own per-network random hardware address feature.

    Windows 10/11 can randomise the Wi-Fi MAC natively. Where the driver
    supports it this is *better* than registry spoofing — it survives reboots
    cleanly and rotates per network. Surfaced here so users prefer it when it
    is available.
    """
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    state = "enabled" if enabled else "disabled"
    return True, (
        "Windows' built-in Wi-Fi MAC randomisation is a per-adapter setting "
        f"that must be {state} in Settings → Network & Internet → Wi-Fi → "
        "'Random hardware addresses'. PrivacyKit does not force this on because "
        "the switch is driver-dependent and Windows manages the rotation itself."
    )


def scan_nearby() -> List[NearbyNetwork]:
    """List visible access points, with BSSIDs, for evil-twin spotting."""
    if not sysinfo.IS_WINDOWS:
        return []
    res = shell.run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                    check_rc=False, timeout=40)
    nets: List[NearbyNetwork] = []
    current: Optional[NearbyNetwork] = None
    for line in res.out.splitlines():
        line = line.strip()
        m = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line)
        if m:
            if current:
                nets.append(current)
            current = NearbyNetwork(ssid=m.group(1).strip() or "<hidden>")
            continue
        if current is None:
            continue
        if line.lower().startswith("authentication"):
            current.auth = line.split(":", 1)[1].strip()
        elif line.lower().startswith("encryption"):
            current.encryption = line.split(":", 1)[1].strip()
        elif line.lower().startswith("bssid"):
            current.bssids.append(line.split(":", 1)[1].strip())
        elif line.lower().startswith("signal"):
            try:
                current.signal = int(re.sub(r"[^\d]", "", line.split(":", 1)[1]))
            except Exception:
                pass
        elif line.lower().startswith("channel"):
            current.channel = line.split(":", 1)[1].strip()
    if current:
        nets.append(current)
    return nets


def find_duplicate_ssids(networks: List[NearbyNetwork]) -> List[str]:
    """
    SSIDs advertised by BSSIDs with different vendor prefixes.

    A legitimate multi-AP network (a mesh, an office) uses APs from one vendor,
    so mixed prefixes on one SSID is a reasonable evil-twin heuristic — worth a
    warning, not an accusation.
    """
    suspicious = []
    for net in networks:
        if len(net.bssids) < 2:
            continue
        prefixes = {b.replace("-", ":").upper()[:8] for b in net.bssids}
        if len(prefixes) > 1:
            suspicious.append(net.ssid)
    return suspicious


def current_connection() -> dict:
    """Details of the Wi-Fi network currently joined."""
    if not sysinfo.IS_WINDOWS:
        return {}
    res = shell.run(["netsh", "wlan", "show", "interfaces"], check_rc=False)
    if not res.out.strip():
        return {}
    return {
        "ssid": _grab(res.out, r"^\s*SSID\s*:\s*(.+)"),
        "bssid": _grab(res.out, r"BSSID\s*:\s*(.+)"),
        "state": _grab(res.out, r"State\s*:\s*(.+)"),
        "auth": _grab(res.out, r"Authentication\s*:\s*(.+)"),
        "cipher": _grab(res.out, r"Cipher\s*:\s*(.+)"),
        "signal": _grab(res.out, r"Signal\s*:\s*(.+)"),
        "channel": _grab(res.out, r"Channel\s*:\s*(.+)"),
    }


def snapshot() -> dict:
    return {"profiles": [p.name for p in list_profiles()]}
