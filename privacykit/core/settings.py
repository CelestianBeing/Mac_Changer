"""
Persistent settings and user-defined profiles.

Two stores, kept separate because they have different lifetimes and different
failure modes:

* **Settings** — preferences that should survive updates and never block
  startup. A corrupt settings file falls back to defaults rather than refusing
  to launch.
* **Custom profiles** — user-authored combinations of actions, which are data
  the user created and would be annoyed to lose. These are written atomically
  and backed up on overwrite.
"""

from __future__ import annotations

import copy
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import sysinfo

DEFAULTS: Dict[str, Any] = {
    # Appearance
    "theme": "dark",                      # dark | light | system
    "accent": "blue",                     # blue | violet | teal | green | amber
    "compact_mode": False,
    "window_geometry": "",

    # Behaviour
    "confirm_destructive": True,
    "auto_capture_baseline": True,
    "restore_on_exit_prompt": True,
    "start_minimised": False,
    "run_at_startup": False,
    "minimise_to_tray": True,

    # Automation
    "tray_enabled": True,
    "auto_profile_on_network_change": False,
    "auto_profile_untrusted": "public_wifi",
    "trusted_networks": [],
    "panic_hotkey": "Ctrl+Alt+P",
    "panic_hotkey_enabled": False,
    "clean_on_shutdown": False,

    # Protection
    "live_protection": False,
    "protection_watchers": {},
    "notify_events": True,
    "notify_min_severity": "warning",

    # Threat feed
    "threatfeed_enabled": False,
    "threatfeed_sources": ["stevenblack", "adguard_tracking", "notracking"],
    "threatfeed_auto_update_days": 7,
    "threatfeed_last_update": 0,

    # Noise
    "noise_rate": 20,
    "noise_via_tor": True,
    "noise_endpoints": [],

    # Tor
    "tor_control_password": "",
    "tor_preferred_exit": "",

    # First run
    "onboarding_complete": False,
    "version_seen": "",
}


def settings_path() -> Path:
    return sysinfo.appdata_dir() / "settings.json"


def profiles_path() -> Path:
    return sysinfo.appdata_dir() / "profiles.json"


class Settings:
    """
    Dict-like settings store with change notification.

    Writes are debounced by the caller rather than here; every ``set`` persists
    immediately, because losing a preference because the app was killed is more
    annoying than an occasional small write.
    """

    def __init__(self):
        self._data: Dict[str, Any] = copy.deepcopy(DEFAULTS)
        self._listeners: List[Any] = []
        self.load()

    # ── persistence ──
    def load(self) -> None:
        p = settings_path()
        if not p.exists():
            return
        try:
            stored = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(stored, dict):
                # Merge rather than replace, so a key added in a later version
                # gets its default instead of being missing.
                for key, value in stored.items():
                    if key in DEFAULTS:
                        self._data[key] = value
        except Exception:
            # Keep the unreadable file for diagnosis, carry on with defaults.
            try:
                p.replace(p.with_suffix(f".corrupt-{int(time.time())}.json"))
            except Exception:
                pass

    def save(self) -> bool:
        p = settings_path()
        tmp = p.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
            os.replace(tmp, p)
            return True
        except Exception:
            return False

    # ── access ──
    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, DEFAULTS.get(key, default))

    def set(self, key: str, value: Any, save: bool = True) -> None:
        if self._data.get(key) == value:
            return
        self._data[key] = value
        if save:
            self.save()
        for cb in list(self._listeners):
            try:
                cb(key, value)
            except Exception:
                pass

    def update(self, values: Dict[str, Any]) -> None:
        for key, value in values.items():
            self.set(key, value, save=False)
        self.save()

    def reset(self) -> None:
        self._data = copy.deepcopy(DEFAULTS)
        self.save()

    def on_change(self, callback) -> None:
        self._listeners.append(callback)

    def as_dict(self) -> Dict[str, Any]:
        return copy.deepcopy(self._data)

    def __getitem__(self, key: str) -> Any:
        return self.get(key)

    def __setitem__(self, key: str, value: Any) -> None:
        self.set(key, value)


#: Process-wide settings instance.
settings = Settings()


# ──────────────────────────────────────────────────────────────────────────────
# Custom profiles
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class CustomProfile:
    key: str
    name: str
    icon: str = "★"
    description: str = ""
    accent: str = "#4c8dff"
    actions: List[Dict[str, Any]] = field(default_factory=list)
    created: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {"key": self.key, "name": self.name, "icon": self.icon,
                "description": self.description, "accent": self.accent,
                "actions": self.actions, "created": self.created}

    @classmethod
    def from_dict(cls, d: dict) -> "CustomProfile":
        return cls(key=d.get("key", ""), name=d.get("name", "Untitled"),
                   icon=d.get("icon", "★"), description=d.get("description", ""),
                   accent=d.get("accent", "#4c8dff"),
                   actions=d.get("actions", []),
                   created=d.get("created", time.time()))

    def summary(self) -> str:
        return f"{len(self.actions)} action(s)"


#: Every action a custom profile can perform, with the arguments it accepts.
#: Kept declarative so the profile editor can build its UI from this table
#: rather than hardcoding a form per action.
ACTION_CATALOGUE = [
    {"key": "mac.spoof", "title": "Spoof MAC address",
     "args": {"mode": ["vendor", "local"]}, "feature": "mac"},
    {"key": "mac.restore", "title": "Restore hardware MAC", "args": {}, "feature": "mac"},
    {"key": "dns.provider", "title": "Set DNS provider",
     "args": {"provider": "text", "doh": "bool"}, "feature": "dns"},
    {"key": "dns.automatic", "title": "DNS back to automatic", "args": {}, "feature": "dns"},
    {"key": "dns.flush", "title": "Flush DNS cache", "args": {}, "feature": "dns"},
    {"key": "hostname.randomise", "title": "Randomise computer name",
     "args": {"style": ["windows", "random"]}, "feature": "hostname"},
    {"key": "ip.renew", "title": "Release and renew DHCP", "args": {}, "feature": "ip"},
    {"key": "tor.route", "title": "Route traffic through Tor", "args": {}, "feature": "tor"},
    {"key": "tor.newnym", "title": "Request a new Tor identity", "args": {}, "feature": "tor"},
    {"key": "proxy.off", "title": "Turn the system proxy off", "args": {}, "feature": "dns"},
    {"key": "firewall.killswitch", "title": "Arm the kill switch",
     "args": {"allow_lan": "bool"}, "feature": "killswitch"},
    {"key": "firewall.disarm", "title": "Disarm the kill switch", "args": {}, "feature": "killswitch"},
    {"key": "firewall.lan", "title": "Block local network", "args": {}, "feature": "killswitch"},
    {"key": "firewall.smb", "title": "Block SMB and NetBIOS", "args": {}, "feature": "killswitch"},
    {"key": "firewall.llmnr", "title": "Disable LLMNR", "args": {}, "feature": "hardening"},
    {"key": "firewall.ipv6", "title": "Disable IPv6 on the adapter", "args": {}, "feature": "hardening"},
    {"key": "geo.match", "title": "Match location to exit IP", "args": {}, "feature": "geo"},
    {"key": "geo.country", "title": "Set location to a country",
     "args": {"country": "text"}, "feature": "geo"},
    {"key": "noise.rotate", "title": "Rotate tracking identifiers", "args": {}, "feature": "noise"},
    {"key": "noise.start", "title": "Start decoy traffic", "args": {}, "feature": "noise"},
    {"key": "hardening.tweaks", "title": "Apply privacy tweaks",
     "args": {"set": ["low_impact", "all"]}, "feature": "hardening"},
    {"key": "hardening.hosts", "title": "Apply telemetry blocklist", "args": {}, "feature": "hardening"},
    {"key": "clean.traces", "title": "Clean local traces",
     "args": {"set": ["recommended", "all"]}, "feature": "cleaner"},
    {"key": "restore.all", "title": "Restore everything (panic)", "args": {}, "feature": "journal"},
]

ACTIONS_BY_KEY = {a["key"]: a for a in ACTION_CATALOGUE}


class ProfileStore:
    def __init__(self):
        self.profiles: Dict[str, CustomProfile] = {}
        self.load()

    def load(self) -> None:
        p = profiles_path()
        if not p.exists():
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            for item in data.get("profiles", []):
                prof = CustomProfile.from_dict(item)
                if prof.key:
                    self.profiles[prof.key] = prof
        except Exception:
            pass

    def save(self) -> bool:
        p = profiles_path()
        # Back up before overwriting — these are user-authored and worth keeping.
        if p.exists():
            try:
                p.replace(sysinfo.backups_dir() / f"profiles.{int(time.time())}.json")
            except Exception:
                pass
        tmp = p.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(
                {"profiles": [pr.to_dict() for pr in self.profiles.values()]},
                indent=2), encoding="utf-8")
            os.replace(tmp, p)
            return True
        except Exception:
            return False

    def add(self, profile: CustomProfile) -> bool:
        self.profiles[profile.key] = profile
        return self.save()

    def remove(self, key: str) -> bool:
        self.profiles.pop(key, None)
        return self.save()

    def get(self, key: str) -> Optional[CustomProfile]:
        return self.profiles.get(key)

    def all(self) -> List[CustomProfile]:
        return sorted(self.profiles.values(), key=lambda p: p.name.lower())

    def next_key(self, name: str) -> str:
        import re
        base = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_") or "profile"
        key, n = base, 2
        while key in self.profiles:
            key, n = f"{base}_{n}", n + 1
        return key


profile_store = ProfileStore()
