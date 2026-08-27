"""
Profile poisoning — making the picture trackers build about you wrong.

Blocking a tracker leaves a shaped hole: no data is itself a signal, and a
profile with gaps can still be joined to other profiles. Poisoning takes the
opposite approach — let the data flow, but make it false, so the profile is
confidently wrong rather than merely incomplete. It is the strategy behind
published tools like TrackMeNot and AdNauseam.

Two mechanisms, in order of how well they actually work:

**1. Identifier rotation (recommended, no network traffic).**
Advertising and analytics systems key on stable identifiers. Rotating the ones
Windows lets you reset breaks the thread between yesterday's profile and
today's — the old profile still exists but can no longer be extended. This is
purely local, has no downside, and is genuinely effective.

**2. Decoy traffic (opt-in, rate-capped).**
Low-rate requests carrying randomised fake identifiers, diluting any profile
keyed to you. Honest caveats, stated in the UI rather than buried:

* It **contradicts blocking**. If the hosts blocklist is on, these requests go
  nowhere. Pick one strategy — you cannot both block and poison the same
  endpoint.
* **Effectiveness is unproven** against sophisticated correlation. Timing,
  IP, and TLS fingerprints can separate noise from real activity.
* It **generates traffic attributable to you**, which is the opposite of quiet.

Because of that last point, the generator is off by default, capped, and jittered
so it can never become a flood against someone else's infrastructure.
"""

from __future__ import annotations

import random
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from . import journal, netclient, shell, sysinfo

if sysinfo.IS_WINDOWS:
    import winreg
else:
    winreg = None  # type: ignore

#: Hard ceiling on decoy request rate, regardless of what the UI asks for.
#: Poisoning your own profile is legitimate; hammering a third party's servers
#: is not, and this is the line between the two.
MAX_REQUESTS_PER_HOUR = 120
DEFAULT_REQUESTS_PER_HOUR = 20

#: Minimum seconds between requests, enforced on top of the hourly cap.
MIN_INTERVAL = 20.0


# ──────────────────────────────────────────────────────────────────────────────
# Resettable identifiers
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Identifier:
    key: str
    title: str
    description: str
    hive: str
    path: str
    value_name: str
    kind: str = "guid"          # guid | dword-zero
    safe: bool = True
    caution: str = ""

    def _hive(self):
        return (winreg.HKEY_CURRENT_USER if self.hive == "HKCU"
                else winreg.HKEY_LOCAL_MACHINE)

    def read(self) -> Optional[str]:
        if not sysinfo.IS_WINDOWS or winreg is None:
            return None
        try:
            with winreg.OpenKey(self._hive(), self.path) as k:
                val, _ = winreg.QueryValueEx(k, self.value_name)
                return str(val)
        except Exception:
            return None


#: Identifiers Windows treats as resettable. Deliberately excludes MachineGUID
#: and the installation ID: those are load-bearing for software activation and
#: licensing, and changing them breaks unrelated applications in ways users
#: struggle to diagnose.
IDENTIFIERS: List[Identifier] = [
    Identifier(
        "advertising_id", "Advertising ID",
        "The per-user identifier apps use to join your behaviour across "
        "everything you install. Windows itself offers a reset button for this, "
        "so rotating it is entirely supported.",
        "HKCU",
        r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Id"),
    Identifier(
        "csp_client_id", "Cloud experience client ID",
        "Identifier attached to cloud-backed personalisation and suggestion "
        "features.",
        "HKCU",
        r"Software\Microsoft\Windows\CurrentVersion\CloudExperienceHost", "ClientId"),
    Identifier(
        "sqm_client_id", "SQM (telemetry) client ID",
        "The identifier attached to Windows quality-metrics reports, which ties "
        "separate telemetry submissions to one machine.",
        "HKLM", r"SOFTWARE\Microsoft\SQMClient", "MachineId",
        safe=False,
        caution="Machine-wide. Harmless to rotate, but some enterprise "
                "inventory tools key on it."),
]

IDENTIFIERS_BY_KEY = {i.key: i for i in IDENTIFIERS}


def new_guid(braced: bool = True) -> str:
    value = str(uuid.UUID(bytes=secrets.token_bytes(16), version=4))
    return "{" + value + "}" if braced else value


def rotate_identifier(key: str) -> Tuple[bool, str]:
    """Replace one tracking identifier with a fresh random value."""
    ident = IDENTIFIERS_BY_KEY.get(key)
    if ident is None:
        return False, f"Unknown identifier '{key}'."
    if not sysinfo.IS_WINDOWS or winreg is None:
        return False, "Windows-only."
    if ident.hive == "HKLM" and not sysinfo.is_admin():
        return False, "Administrator rights are required for this identifier."

    previous = ident.read()
    braced = not previous or previous.startswith("{")
    fresh = new_guid(braced)

    journal.record(
        module="noise", action=f"Rotated {ident.title}",
        undo={"kind": "noise.identifier_restore", "identifier": key,
              "previous": previous},
        before={ident.value_name: previous},
    )
    try:
        k = winreg.CreateKeyEx(ident._hive(), ident.path, 0,
                               winreg.KEY_READ | winreg.KEY_WRITE)
        winreg.SetValueEx(k, ident.value_name, 0, winreg.REG_SZ, fresh)
        winreg.CloseKey(k)
        return True, f"{ident.title} rotated to a new random value."
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


@journal.register_undo("noise.identifier_restore")
def _undo_identifier(payload: dict) -> Tuple[bool, str]:
    ident = IDENTIFIERS_BY_KEY.get(payload.get("identifier", ""))
    if ident is None or not sysinfo.IS_WINDOWS or winreg is None:
        return False, "identifier not available"
    previous = payload.get("previous")
    try:
        k = winreg.CreateKeyEx(ident._hive(), ident.path, 0,
                               winreg.KEY_READ | winreg.KEY_WRITE)
        if previous is None:
            try:
                winreg.DeleteValue(k, ident.value_name)
            except FileNotFoundError:
                pass
            msg = f"{ident.title} removed (was not previously set)"
        else:
            winreg.SetValueEx(k, ident.value_name, 0, winreg.REG_SZ, previous)
            msg = f"{ident.title} restored"
        winreg.CloseKey(k)
        return True, msg
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def rotate_all(safe_only: bool = True,
               progress: Optional[Callable[[str, bool], None]] = None) -> dict:
    rotated, failed = 0, []
    for ident in IDENTIFIERS:
        if safe_only and not ident.safe:
            continue
        ok, msg = rotate_identifier(ident.key)
        if progress:
            progress(f"{ident.title}: {msg}", ok)
        if ok:
            rotated += 1
        else:
            failed.append(f"{ident.title} — {msg}")
    return {"rotated": rotated, "failed": failed}


def identifier_report() -> List[dict]:
    return [{"key": i.key, "title": i.title, "description": i.description,
             "current": i.read(), "safe": i.safe, "caution": i.caution}
            for i in IDENTIFIERS]


# ──────────────────────────────────────────────────────────────────────────────
# Decoy traffic
# ──────────────────────────────────────────────────────────────────────────────

#: Analytics and advertising collectors that accept unauthenticated beacons.
#: These are endpoints that profile *you*; the decoys carry randomised
#: identifiers so what lands is attached to a person who does not exist.
DEFAULT_DECOY_ENDPOINTS = [
    "https://www.google-analytics.com/collect",
    "https://ssl.google-analytics.com/collect",
    "https://api.mixpanel.com/track",
    "https://api.segment.io/v1/track",
    "https://api.amplitude.com/2/httpapi",
    "https://in.hotjar.com/api/v2/client/sites",
    "https://sb.scorecardresearch.com/b",
]

#: Plausible interests a decoy profile might express. Deliberately mundane —
#: the goal is a believable but wrong profile, not an absurd one that is
#: obviously synthetic and therefore easy to filter out.
DECOY_TOPICS = [
    "gardening tools", "sourdough starter", "hiking boots review",
    "used caravan prices", "knitting patterns", "aquarium filter",
    "classical guitar lessons", "budget lawn mower", "bird watching binoculars",
    "vintage watch repair", "camping stove comparison", "orchid care",
    "model railway track", "sewing machine service", "chess opening theory",
    "beekeeping starter kit", "pottery wheel", "telescope for beginners",
    "kayak roof rack", "espresso grinder", "fountain pen ink",
    "mushroom foraging guide", "vinyl record cleaning", "home brewing kit",
]

DECOY_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
]


@dataclass
class NoiseStats:
    sent: int = 0
    failed: int = 0
    started_at: float = 0.0
    last_sent: float = 0.0
    last_target: str = ""
    running: bool = False
    recent: List[str] = field(default_factory=list)

    @property
    def uptime(self) -> str:
        if not self.started_at:
            return "—"
        secs = int(time.time() - self.started_at)
        h, rem = divmod(secs, 3600)
        m, s = divmod(rem, 60)
        return f"{h}h {m:02d}m" if h else f"{m}m {s:02d}s"

    @property
    def rate(self) -> str:
        if not self.started_at or not self.sent:
            return "—"
        hours = max((time.time() - self.started_at) / 3600.0, 1 / 60)
        return f"{self.sent / hours:.1f}/hour"


class NoiseGenerator:
    """
    Background decoy traffic generator.

    Rate limiting is enforced in two independent ways — a per-hour budget and a
    minimum gap between requests — so a misconfigured interval cannot turn this
    into a flood. Intervals are jittered because perfectly periodic traffic is
    trivially separable from human activity, which would defeat the purpose.
    """

    def __init__(self):
        self.stats = NoiseStats()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.endpoints: List[str] = list(DEFAULT_DECOY_ENDPOINTS)
        self.requests_per_hour = DEFAULT_REQUESTS_PER_HOUR
        self.via_tor = False
        self.tor_port = 9050
        self._sent_times: List[float] = []
        self.on_event: Optional[Callable[[str], None]] = None

    # ── configuration ──
    def configure(self, requests_per_hour: int = DEFAULT_REQUESTS_PER_HOUR,
                  endpoints: Optional[List[str]] = None,
                  via_tor: bool = False, tor_port: int = 9050) -> str:
        capped = max(1, min(int(requests_per_hour), MAX_REQUESTS_PER_HOUR))
        self.requests_per_hour = capped
        if endpoints is not None:
            self.endpoints = [e.strip() for e in endpoints if e.strip()]
        self.via_tor = via_tor
        self.tor_port = tor_port
        note = ""
        if capped != int(requests_per_hour):
            note = (f" Requested rate was reduced to the {MAX_REQUESTS_PER_HOUR}/hour "
                    "ceiling — beyond that this stops being noise and starts "
                    "being abusive traffic to someone else's servers.")
        return f"Decoy rate set to {capped} requests/hour.{note}"

    # ── lifecycle ──
    @property
    def running(self) -> bool:
        return self.stats.running

    def start(self) -> Tuple[bool, str]:
        if self.running:
            return True, "Decoy traffic is already running."
        if not self.endpoints:
            return False, "No decoy endpoints configured."

        self._stop = threading.Event()
        self.stats = NoiseStats(started_at=time.time(), running=True)
        self._sent_times = []
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()
        return True, (f"Decoy traffic started at {self.requests_per_hour} "
                      "requests/hour with randomised identifiers.")

    def stop(self) -> Tuple[bool, str]:
        if not self.running:
            return True, "Decoy traffic is not running."
        self._stop.set()
        self.stats.running = False
        return True, f"Decoy traffic stopped after {self.stats.sent} request(s)."

    # ── worker ──
    def _worker(self) -> None:
        while not self._stop.is_set():
            interval = self._next_interval()
            if self._stop.wait(timeout=interval):
                break
            if not self._budget_available():
                continue
            self._send_one()

    def _next_interval(self) -> float:
        """Jittered gap, never below the hard minimum."""
        base = 3600.0 / max(self.requests_per_hour, 1)
        jitter = random.SystemRandom().uniform(0.45, 1.75)
        return max(MIN_INTERVAL, base * jitter)

    def _budget_available(self) -> bool:
        """Second, independent check that we are inside the hourly budget."""
        now = time.time()
        with self._lock:
            self._sent_times = [t for t in self._sent_times if now - t < 3600]
            return len(self._sent_times) < self.requests_per_hour

    def _send_one(self) -> None:
        rng = random.SystemRandom()
        url = rng.choice(self.endpoints)
        topic = rng.choice(DECOY_TOPICS)
        params = {
            "cid": new_guid(braced=False),
            "uid": secrets.token_hex(8),
            "ev": "page_view",
            "q": topic.replace(" ", "+"),
            "t": str(int(time.time())),
        }
        query = "&".join(f"{k}={v}" for k, v in params.items())
        target = f"{url}{'&' if '?' in url else '?'}{query}"

        resp = netclient.get(
            target, timeout=10, via_tor=self.via_tor, proxy_port=self.tor_port,
            headers={"User-Agent": rng.choice(DECOY_USER_AGENTS),
                     "Accept-Language": rng.choice(
                         ["en-US,en;q=0.9", "en-GB,en;q=0.8", "de-DE,de;q=0.9"])})

        with self._lock:
            self._sent_times.append(time.time())
            self.stats.last_sent = time.time()
            self.stats.last_target = url
            if resp.ok or resp.status:
                self.stats.sent += 1
            else:
                self.stats.failed += 1
            line = (f"{time.strftime('%H:%M:%S')}  decoy \"{topic}\" → "
                    f"{url.split('/')[2]}")
            self.stats.recent.insert(0, line)
            del self.stats.recent[12:]

        if self.on_event:
            try:
                self.on_event(line)
            except Exception:
                pass


#: Process-wide generator, so the tray agent and the window share one instance
#: rather than each running their own and doubling the real rate.
generator = NoiseGenerator()


def blocklist_conflict() -> Optional[str]:
    """
    Warn when blocking and poisoning are both active.

    They are mutually exclusive strategies against the same endpoint: if the
    hosts file sends analytics domains to 0.0.0.0, decoy requests to those
    domains go nowhere and achieve nothing.
    """
    try:
        from . import hardening
        if hardening.hosts_blocked_count() > 0:
            return ("The telemetry blocklist is currently active, which sends "
                    "these same domains to 0.0.0.0. Decoy requests to them will "
                    "not leave your machine. Blocking and poisoning are "
                    "alternative strategies — choose one per endpoint, not both.")
    except Exception:
        pass
    return None


def effectiveness_note() -> str:
    """The honest assessment, shown next to the controls rather than hidden."""
    return (
        "Identifier rotation is the part that reliably works: it is local, "
        "supported by Windows, and genuinely severs yesterday's profile from "
        "today's.\n\n"
        "Decoy traffic is more speculative. Large analytics operators can often "
        "separate synthetic events from real ones using timing regularity, TLS "
        "fingerprints, and the absence of corroborating signals. It also means "
        "sending more traffic that is attributable to your connection, which "
        "cuts against everything else this toolkit does. Use it when diluting a "
        "profile matters more than staying quiet — and prefer routing it "
        "through Tor if you use it at all."
    )


def snapshot() -> dict:
    return {"identifiers": {i.key: i.read() for i in IDENTIFIERS},
            "decoy_running": generator.running}
