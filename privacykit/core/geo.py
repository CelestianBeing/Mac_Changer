"""
Location matching — align what Windows says about where you are with where your
IP says you are.

The problem this solves is concrete and widely overlooked. You route traffic
through a Frankfurt exit node, and a site sees:

    IP address     185.220.101.x   →  Germany
    Timezone       UTC+05:30       →  India
    Region         IN              →  India
    Locale         en-IN           →  India

That mismatch is a stronger identifier than either signal alone, because almost
nobody has it by accident. Commercial VPNs do not fix it; browser fingerprinting
scripts read `Intl.DateTimeFormat().resolvedOptions().timeZone` in one line.

What this module aligns
-----------------------
* **Timezone** — the highest-value signal, readable from JavaScript with no
  permission prompt whatsoever.
* **Home region (GeoID)** — what Windows reports as your country to apps and the
  Store. Resolved at runtime from .NET's ``RegionInfo``, so the mapping comes
  from Windows itself rather than a hardcoded table that could drift.
* **Locale / culture** — drives ``Accept-Language``, date and number formats.
* **Windows default location** — the coordinates the Geolocation API hands to
  apps that ask.
* **Wi-Fi positioning** — Windows reports nearby access-point BSSIDs to
  Microsoft for location. That runs on real observed hardware, so it cannot be
  faked, only switched off.

What it deliberately does not claim
-----------------------------------
It cannot change what a *browser* reports through the JavaScript Geolocation
API if the browser has its own location permission granted, and it cannot alter
GPS hardware. The tab says so rather than implying full coverage.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import journal, shell, sysinfo

if sysinfo.IS_WINDOWS:
    import winreg
else:
    winreg = None  # type: ignore

# Windows stores the default location for the Geolocation API here. This is the
# one piece Microsoft does not document, so writes are best-effort and the UI
# says so instead of reporting a success it cannot verify.
LOCATION_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SensorDataService\Devices"
DEFAULT_LOC_KEY = r"SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
CONSENT_LOCATION = (r"SOFTWARE\Microsoft\Windows\CurrentVersion"
                    r"\CapabilityAccessManager\ConsentStore\location")


@dataclass
class Country:
    """Everything needed to make a machine look like it lives somewhere."""
    code: str                 # ISO 3166-1 alpha-2
    name: str
    timezone: str             # Windows timezone identifier
    locale: str               # BCP-47 culture tag
    lat: float
    lon: float
    city: str = ""

    @property
    def coords(self) -> str:
        return f"{self.lat:.4f}, {self.lon:.4f}"


#: Curated set covering the Tor exit-node countries plus the common VPN
#: locations. Coordinates are city centres, not precise addresses — the point is
#: to be plausibly *in* the country, not to claim a street.
COUNTRIES: Dict[str, Country] = {
    "de": Country("DE", "Germany", "W. Europe Standard Time", "de-DE", 50.1109, 8.6821, "Frankfurt"),
    "nl": Country("NL", "Netherlands", "W. Europe Standard Time", "nl-NL", 52.3676, 4.9041, "Amsterdam"),
    "se": Country("SE", "Sweden", "W. Europe Standard Time", "sv-SE", 59.3293, 18.0686, "Stockholm"),
    "ch": Country("CH", "Switzerland", "W. Europe Standard Time", "de-CH", 47.3769, 8.5417, "Zurich"),
    "fr": Country("FR", "France", "Romance Standard Time", "fr-FR", 48.8566, 2.3522, "Paris"),
    "gb": Country("GB", "United Kingdom", "GMT Standard Time", "en-GB", 51.5074, -0.1278, "London"),
    "us": Country("US", "United States", "Eastern Standard Time", "en-US", 40.7128, -74.0060, "New York"),
    "ca": Country("CA", "Canada", "Eastern Standard Time", "en-CA", 43.6532, -79.3832, "Toronto"),
    "no": Country("NO", "Norway", "W. Europe Standard Time", "nb-NO", 59.9139, 10.7522, "Oslo"),
    "fi": Country("FI", "Finland", "FLE Standard Time", "fi-FI", 60.1699, 24.9384, "Helsinki"),
    "at": Country("AT", "Austria", "W. Europe Standard Time", "de-AT", 48.2082, 16.3738, "Vienna"),
    "is": Country("IS", "Iceland", "Greenwich Standard Time", "is-IS", 64.1466, -21.9426, "Reykjavik"),
    "ro": Country("RO", "Romania", "GTB Standard Time", "ro-RO", 44.4268, 26.1025, "Bucharest"),
    "cz": Country("CZ", "Czechia", "Central Europe Standard Time", "cs-CZ", 50.0755, 14.4378, "Prague"),
    "es": Country("ES", "Spain", "Romance Standard Time", "es-ES", 40.4168, -3.7038, "Madrid"),
    "it": Country("IT", "Italy", "W. Europe Standard Time", "it-IT", 41.9028, 12.4964, "Rome"),
    "pl": Country("PL", "Poland", "Central European Standard Time", "pl-PL", 52.2297, 21.0122, "Warsaw"),
    "jp": Country("JP", "Japan", "Tokyo Standard Time", "ja-JP", 35.6762, 139.6503, "Tokyo"),
    "sg": Country("SG", "Singapore", "Singapore Standard Time", "en-SG", 1.3521, 103.8198, "Singapore"),
    "au": Country("AU", "Australia", "AUS Eastern Standard Time", "en-AU", -33.8688, 151.2093, "Sydney"),
    "lu": Country("LU", "Luxembourg", "W. Europe Standard Time", "fr-LU", 49.6116, 6.1319, "Luxembourg"),
    "dk": Country("DK", "Denmark", "Romance Standard Time", "da-DK", 55.6761, 12.5683, "Copenhagen"),
    "ie": Country("IE", "Ireland", "GMT Standard Time", "en-IE", 53.3498, -6.2603, "Dublin"),
    "be": Country("BE", "Belgium", "Romance Standard Time", "nl-BE", 50.8503, 4.3517, "Brussels"),
    "pt": Country("PT", "Portugal", "GMT Standard Time", "pt-PT", 38.7223, -9.1393, "Lisbon"),
    "in": Country("IN", "India", "India Standard Time", "en-IN", 28.6139, 77.2090, "New Delhi"),
    "br": Country("BR", "Brazil", "E. South America Standard Time", "pt-BR", -23.5505, -46.6333, "Sao Paulo"),
    "nz": Country("NZ", "New Zealand", "New Zealand Standard Time", "en-NZ", -36.8485, 174.7633, "Auckland"),
    "za": Country("ZA", "South Africa", "South Africa Standard Time", "en-ZA", -26.2041, 28.0473, "Johannesburg"),
    "ua": Country("UA", "Ukraine", "FLE Standard Time", "uk-UA", 50.4501, 30.5234, "Kyiv"),
    "hk": Country("HK", "Hong Kong", "China Standard Time", "zh-HK", 22.3193, 114.1694, "Hong Kong"),
    "ae": Country("AE", "United Arab Emirates", "Arabian Standard Time", "ar-AE", 25.2048, 55.2708, "Dubai"),
}

#: Fallback GeoIDs, used only if .NET RegionInfo cannot be queried. Windows is
#: the authoritative source; this table exists so the feature degrades rather
#: than failing outright.
_GEOID_FALLBACK = {
    "US": 244, "GB": 242, "DE": 94, "FR": 84, "NL": 176, "SE": 221,
    "CH": 223, "CA": 39, "AU": 12, "JP": 122, "IN": 113, "SG": 215,
    "NO": 177, "FI": 77, "DK": 61, "IE": 68, "ES": 217, "IT": 118,
    "PL": 191, "AT": 14, "CZ": 75, "RO": 200, "IS": 110, "LU": 137,
    "BR": 32, "NZ": 183, "BE": 21, "PT": 193, "ZA": 209, "UA": 241,
    "HK": 104, "AE": 224,
}

_geoid_cache: Dict[str, int] = {}


@dataclass
class LocationState:
    timezone: str = ""
    timezone_display: str = ""
    geoid: int = 0
    region: str = ""
    locale: str = ""
    lat: Optional[float] = None
    lon: Optional[float] = None
    location_service: bool = True

    def describe(self) -> str:
        bits = []
        if self.timezone_display:
            bits.append(self.timezone_display)
        if self.region:
            bits.append(f"region {self.region}")
        if self.locale:
            bits.append(self.locale)
        return " · ".join(bits) or "unknown"


# ──────────────────────────────────────────────────────────────────────────────
# Reading current state
# ──────────────────────────────────────────────────────────────────────────────

def current_timezone() -> Tuple[str, str]:
    """Return ``(timezone_id, display_name)``."""
    if not sysinfo.IS_WINDOWS:
        return "", ""
    res = shell.run(["tzutil", "/g"], check_rc=False, timeout=15)
    tz_id = res.out.strip()
    display = ""
    if tz_id:
        listing = shell.run(["tzutil", "/l"], check_rc=False, timeout=20)
        lines = listing.out.splitlines()
        for i, line in enumerate(lines):
            if line.strip() == tz_id and i > 0:
                display = lines[i - 1].strip()
                break
    return tz_id, display or tz_id


def current_geoid() -> int:
    """Read the Windows home-location GeoID."""
    if not sysinfo.IS_WINDOWS or winreg is None:
        return 0
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Control Panel\International\Geo") as k:
            val, _ = winreg.QueryValueEx(k, "Nation")
            return int(val)
    except Exception:
        return 0


def current_region() -> str:
    """Two-letter region code Windows reports."""
    if not sysinfo.IS_WINDOWS or winreg is None:
        return ""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Control Panel\International\Geo") as k:
            val, _ = winreg.QueryValueEx(k, "Name")
            return str(val)
    except Exception:
        return ""


def current_locale() -> str:
    if not sysinfo.IS_WINDOWS:
        return ""
    res = shell.run_powershell("(Get-Culture).Name", timeout=20)
    return res.out.strip()


def location_service_enabled() -> bool:
    """Is the Windows location service allowed to give apps your position?"""
    if not sysinfo.IS_WINDOWS or winreg is None:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, CONSENT_LOCATION) as k:
            val, _ = winreg.QueryValueEx(k, "Value")
            return str(val).lower() == "allow"
    except Exception:
        return True


def get_state() -> LocationState:
    tz_id, tz_display = current_timezone()
    lat, lon = read_default_coordinates()
    return LocationState(
        timezone=tz_id, timezone_display=tz_display,
        geoid=current_geoid(), region=current_region(),
        locale=current_locale(), lat=lat, lon=lon,
        location_service=location_service_enabled(),
    )


def read_default_coordinates() -> Tuple[Optional[float], Optional[float]]:
    if not sysinfo.IS_WINDOWS or winreg is None:
        return None, None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, DEFAULT_LOC_KEY) as k:
            lat, _ = winreg.QueryValueEx(k, "DefaultLatitude")
            lon, _ = winreg.QueryValueEx(k, "DefaultLongitude")
            return float(lat), float(lon)
    except Exception:
        return None, None


# ──────────────────────────────────────────────────────────────────────────────
# GeoID resolution
# ──────────────────────────────────────────────────────────────────────────────

def geoid_for(region_code: str) -> int:
    """
    Resolve an ISO country code to a Windows GeoID.

    Asks .NET's ``RegionInfo`` — the same source Windows itself uses — rather
    than trusting a table baked in months ago. Falls back to the embedded map
    only if that query fails.
    """
    code = (region_code or "").upper()
    if not code:
        return 0
    if code in _geoid_cache:
        return _geoid_cache[code]

    if sysinfo.IS_WINDOWS:
        res = shell.run_powershell(
            f"try {{ (New-Object System.Globalization.RegionInfo '{code}').GeoId }} "
            "catch {{ '' }}", timeout=20)
        digits = re.search(r"\d+", res.out or "")
        if digits:
            value = int(digits.group(0))
            _geoid_cache[code] = value
            return value

    value = _GEOID_FALLBACK.get(code, 0)
    _geoid_cache[code] = value
    return value


def timezone_exists(tz_id: str) -> bool:
    """Confirm a timezone identifier is present on this machine before using it."""
    if not sysinfo.IS_WINDOWS:
        return False
    res = shell.run(["tzutil", "/l"], check_rc=False, timeout=20)
    return tz_id in res.out


# ──────────────────────────────────────────────────────────────────────────────
# Applying a location
# ──────────────────────────────────────────────────────────────────────────────

def apply_country(code: str, set_timezone: bool = True, set_region: bool = True,
                  set_locale: bool = False, set_coordinates: bool = True,
                  progress=None) -> dict:
    """
    Make Windows look like it lives in ``code``.

    ``set_locale`` defaults to **off**. Changing the display culture alters date
    and number formats across every application, which users notice immediately
    and often find alarming. It is the smallest fingerprinting win of the four
    and by far the most disruptive, so it is opt-in.
    """
    country = COUNTRIES.get((code or "").lower())
    if country is None:
        return {"ok": False, "message": f"No profile for country '{code}'.",
                "steps": []}
    if not sysinfo.IS_WINDOWS:
        return {"ok": False, "message": "Windows-only.", "steps": []}

    steps: List[str] = []
    ok_count = 0

    def say(msg: str, ok: bool = True):
        steps.append(("OK   " if ok else "FAIL ") + msg)
        if progress:
            progress(msg, ok)

    if set_timezone:
        ok, msg = set_system_timezone(country.timezone)
        say(msg, ok)
        ok_count += ok

    if set_region:
        ok, msg = set_home_region(country.code)
        say(msg, ok)
        ok_count += ok

    if set_locale:
        ok, msg = set_system_locale(country.locale)
        say(msg, ok)
        ok_count += ok

    if set_coordinates:
        ok, msg = set_default_coordinates(country.lat, country.lon)
        say(msg, ok)
        ok_count += ok

    return {
        "ok": ok_count > 0,
        "message": f"Aligned {ok_count} location signal(s) to {country.name}.",
        "country": country,
        "steps": steps,
    }


def set_system_timezone(tz_id: str) -> Tuple[bool, str]:
    """Set the Windows timezone, journalling the previous one."""
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    if not sysinfo.is_admin():
        return False, "Administrator rights are required to change the timezone."
    if not timezone_exists(tz_id):
        return False, f"'{tz_id}' is not a timezone this machine knows about."

    prev_id, prev_display = current_timezone()
    if prev_id == tz_id:
        return True, f"Timezone already {tz_id}."

    journal.record(
        module="geo", action=f"Timezone → {tz_id}",
        undo={"kind": "geo.timezone_restore", "previous": prev_id},
        before={"timezone": prev_id, "display": prev_display},
    )
    res = shell.run(["tzutil", "/s", tz_id], check_rc=False, timeout=20)
    if res.code == 0:
        return True, f"Timezone set to {tz_id} (was {prev_id})."
    journal_cleanup("geo.timezone_restore", prev_id)
    return False, f"tzutil rejected the change: {res.text[:160]}"


@journal.register_undo("geo.timezone_restore")
def _undo_timezone(payload: dict) -> Tuple[bool, str]:
    prev = payload.get("previous")
    if not prev:
        return False, "no previous timezone recorded"
    res = shell.run(["tzutil", "/s", prev], check_rc=False, timeout=20)
    return res.code == 0, f"timezone restored to {prev}"


def set_home_region(region_code: str) -> Tuple[bool, str]:
    """Set the Windows home location (GeoID)."""
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    geoid = geoid_for(region_code)
    if not geoid:
        return False, f"Could not resolve a GeoID for '{region_code}'."

    prev_geoid = current_geoid()
    prev_region = current_region()
    if prev_geoid == geoid:
        return True, f"Home region already {region_code}."

    journal.record(
        module="geo", action=f"Home region → {region_code} (GeoID {geoid})",
        undo={"kind": "geo.region_restore", "previous_geoid": prev_geoid,
              "previous_region": prev_region},
        before={"geoid": prev_geoid, "region": prev_region},
    )
    res = shell.run_powershell(
        f"Set-WinHomeLocation -GeoId {geoid} -ErrorAction Stop; 'DONE'", timeout=25)
    if "DONE" in res.out:
        return True, f"Home region set to {region_code} (GeoID {geoid})."
    return False, f"Set-WinHomeLocation failed: {res.text[:160]}"


@journal.register_undo("geo.region_restore")
def _undo_region(payload: dict) -> Tuple[bool, str]:
    prev = payload.get("previous_geoid")
    if not prev:
        return False, "no previous GeoID recorded"
    res = shell.run_powershell(
        f"Set-WinHomeLocation -GeoId {int(prev)} -ErrorAction SilentlyContinue; 'DONE'",
        timeout=25)
    return "DONE" in res.out, f"home region restored (GeoID {prev})"


def set_system_locale(culture: str) -> Tuple[bool, str]:
    """
    Change the display culture.

    Disruptive by nature: every date, time, and number in every application
    changes format. Journalled, and the UI warns before offering it.
    """
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    prev = current_locale()
    if prev.lower() == culture.lower():
        return True, f"Locale already {culture}."

    journal.record(
        module="geo", action=f"Locale → {culture}",
        undo={"kind": "geo.locale_restore", "previous": prev},
        before={"locale": prev},
    )
    res = shell.run_powershell(
        f"Set-Culture -CultureInfo '{culture}' -ErrorAction Stop; 'DONE'", timeout=25)
    if "DONE" in res.out:
        return True, (f"Locale set to {culture} (was {prev}). "
                      "Sign out and back in for applications to pick it up.")
    return False, f"Set-Culture failed: {res.text[:160]}"


@journal.register_undo("geo.locale_restore")
def _undo_locale(payload: dict) -> Tuple[bool, str]:
    prev = payload.get("previous")
    if not prev:
        return False, "no previous locale recorded"
    res = shell.run_powershell(
        f"Set-Culture -CultureInfo '{prev}' -ErrorAction SilentlyContinue; 'DONE'",
        timeout=25)
    return "DONE" in res.out, f"locale restored to {prev}"


def set_default_coordinates(lat: float, lon: float) -> Tuple[bool, str]:
    """
    Write the coordinates Windows hands to apps that request location.

    This is the one piece Microsoft does not document, so the write is
    best-effort and reported as such rather than claimed as verified.
    """
    if not sysinfo.IS_WINDOWS or winreg is None:
        return False, "Windows-only."
    if not sysinfo.is_admin():
        return False, "Administrator rights are required."

    prev_lat, prev_lon = read_default_coordinates()
    journal.record(
        module="geo", action=f"Default location → {lat:.4f}, {lon:.4f}",
        undo={"kind": "geo.coords_restore", "lat": prev_lat, "lon": prev_lon},
        before={"lat": prev_lat, "lon": prev_lon},
    )
    try:
        k = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, DEFAULT_LOC_KEY, 0,
                               winreg.KEY_READ | winreg.KEY_WRITE)
        winreg.SetValueEx(k, "DefaultLatitude", 0, winreg.REG_SZ, f"{lat:.6f}")
        winreg.SetValueEx(k, "DefaultLongitude", 0, winreg.REG_SZ, f"{lon:.6f}")
        winreg.CloseKey(k)
        return True, (f"Default location set to {lat:.4f}, {lon:.4f}. "
                      "Applications that ask Windows for your position get this; "
                      "browsers with their own location permission may not.")
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


@journal.register_undo("geo.coords_restore")
def _undo_coords(payload: dict) -> Tuple[bool, str]:
    if not sysinfo.IS_WINDOWS or winreg is None:
        return False, "Windows-only."
    lat, lon = payload.get("lat"), payload.get("lon")
    try:
        k = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, DEFAULT_LOC_KEY, 0,
                               winreg.KEY_READ | winreg.KEY_WRITE)
        if lat is None or lon is None:
            for name in ("DefaultLatitude", "DefaultLongitude"):
                try:
                    winreg.DeleteValue(k, name)
                except FileNotFoundError:
                    pass
            msg = "default coordinates removed (none were set before)"
        else:
            winreg.SetValueEx(k, "DefaultLatitude", 0, winreg.REG_SZ, f"{float(lat):.6f}")
            winreg.SetValueEx(k, "DefaultLongitude", 0, winreg.REG_SZ, f"{float(lon):.6f}")
            msg = f"default coordinates restored to {lat}, {lon}"
        winreg.CloseKey(k)
        return True, msg
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def set_location_service(enabled: bool) -> Tuple[bool, str]:
    """
    Allow or deny apps access to the Windows location service.

    Turning it off also stops Windows reporting nearby Wi-Fi access points to
    Microsoft for positioning — which is the part that cannot be spoofed,
    because it runs on real observed hardware.
    """
    if not sysinfo.IS_WINDOWS or winreg is None:
        return False, "Windows-only."
    if not sysinfo.is_admin():
        return False, "Administrator rights are required."

    prev = location_service_enabled()
    if prev == enabled:
        return True, f"Location service already {'allowed' if enabled else 'denied'}."

    journal.record(
        module="geo",
        action=f"Location service {'allowed' if enabled else 'denied'}",
        undo={"kind": "geo.location_service_restore", "was": prev},
        before={"allowed": prev},
    )
    try:
        k = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, CONSENT_LOCATION, 0,
                               winreg.KEY_READ | winreg.KEY_WRITE)
        winreg.SetValueEx(k, "Value", 0, winreg.REG_SZ,
                          "Allow" if enabled else "Deny")
        winreg.CloseKey(k)
        return True, ("Apps may use the location service."
                      if enabled else
                      "Location service denied to apps. Windows also stops "
                      "reporting nearby Wi-Fi networks to Microsoft for "
                      "positioning — the one location signal that cannot be "
                      "faked, only switched off.")
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


@journal.register_undo("geo.location_service_restore")
def _undo_location_service(payload: dict) -> Tuple[bool, str]:
    if not sysinfo.IS_WINDOWS or winreg is None:
        return False, "Windows-only."
    try:
        k = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, CONSENT_LOCATION, 0,
                               winreg.KEY_READ | winreg.KEY_WRITE)
        winreg.SetValueEx(k, "Value", 0, winreg.REG_SZ,
                          "Allow" if payload.get("was", True) else "Deny")
        winreg.CloseKey(k)
        return True, "location service permission restored"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def journal_cleanup(kind: str, marker) -> None:
    """Drop the most recent entry of ``kind`` when the change it describes failed."""
    for e in reversed(journal.pending()):
        if e.undo.get("kind") == kind:
            journal.drop(e.id)
            return


# ──────────────────────────────────────────────────────────────────────────────
# Mismatch detection
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Mismatch:
    signal: str
    reported: str
    expected: str
    severity: str = "warning"


def detect_mismatch(ip_country: str) -> List[Mismatch]:
    """
    Compare what Windows says about your location against what your IP says.

    This is the diagnostic that makes the feature obvious: it shows the exact
    contradiction a fingerprinting script would see.
    """
    out: List[Mismatch] = []
    country = COUNTRIES.get((ip_country or "").lower())
    if country is None:
        return out

    state = get_state()

    if state.timezone and state.timezone != country.timezone:
        out.append(Mismatch(
            "Timezone", state.timezone_display or state.timezone,
            f"{country.timezone} ({country.name})",
            "critical"))

    if state.region and state.region.upper() != country.code:
        out.append(Mismatch(
            "Windows region", state.region.upper(), country.code, "warning"))

    if state.locale:
        loc_region = state.locale.split("-")[-1].upper()
        if len(loc_region) == 2 and loc_region != country.code:
            out.append(Mismatch(
                "Locale", state.locale, country.locale, "info"))

    if state.lat is not None and state.lon is not None:
        drift = abs(state.lat - country.lat) + abs(state.lon - country.lon)
        if drift > 12:
            out.append(Mismatch(
                "Default coordinates", f"{state.lat:.2f}, {state.lon:.2f}",
                country.coords, "warning"))

    return out


def country_list() -> List[Tuple[str, str]]:
    """``(code, label)`` pairs for the picker, alphabetical by name."""
    return sorted(((c.code.lower(), f"{c.name} — {c.city}")
                   for c in COUNTRIES.values()), key=lambda t: t[1])


def snapshot() -> dict:
    s = get_state()
    return {"timezone": s.timezone, "geoid": s.geoid, "region": s.region,
            "locale": s.locale, "lat": s.lat, "lon": s.lon,
            "location_service": s.location_service}
