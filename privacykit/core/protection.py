"""
Live protection — continuous watchers instead of on-demand checks.

The gap this closes: a one-off audit tells you the machine was fine when you
looked. It does not tell you that a VPN client rewrote your DNS an hour later,
that you joined an untrusted network this morning, or that an unfamiliar device
appeared on your subnet.

Each watcher is a small polling class with its own interval, chosen against how
fast the thing it watches actually changes — there is no value in checking the
timezone every five seconds. Events flow to a single callback so the tray agent
and the window can both react without either polling anything itself.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from . import dnsconf, firewall, mac, proxy, sysinfo, tor, wifi

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2, "good": 3}


@dataclass
class Event:
    kind: str
    title: str
    detail: str
    severity: str = "info"
    ts: float = field(default_factory=time.time)
    action: str = ""            # suggested remedy, shown in the notification

    @property
    def when(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.ts))

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 9)


class Watcher:
    """Base polling watcher. Subclasses implement :meth:`check`."""

    name = "watcher"
    interval = 30.0
    description = ""

    def __init__(self):
        self.enabled = True
        self._last_run = 0.0

    def due(self, now: float) -> bool:
        return self.enabled and (now - self._last_run) >= self.interval

    def run(self, now: float) -> List[Event]:
        self._last_run = now
        try:
            return self.check() or []
        except Exception as exc:
            return [Event("watcher.error", f"{self.name} check failed",
                          f"{type(exc).__name__}: {exc}", "info")]

    def check(self) -> List[Event]:
        raise NotImplementedError


class DnsWatcher(Watcher):
    """
    Detect DNS being changed out from under you.

    VPN clients, network drivers, and captive portals all rewrite resolvers
    without asking. Silently losing your encrypted resolver is exactly the
    failure this toolkit exists to prevent.
    """

    name = "DNS integrity"
    interval = 45.0
    description = "Alerts when another program changes your DNS servers."

    def __init__(self):
        super().__init__()
        self._known: Dict[str, List[str]] = {}

    def check(self) -> List[Event]:
        events: List[Event] = []
        for adapter in mac.list_adapters(include_virtual=False):
            if adapter.status.lower() not in ("up", ""):
                continue
            state = dnsconf.get_state(adapter.name)
            current = list(state.servers)
            previous = self._known.get(adapter.name)
            self._known[adapter.name] = current

            if previous is None or previous == current:
                continue
            events.append(Event(
                "dns.changed",
                f"DNS changed on '{adapter.name}'",
                f"Was {', '.join(previous) or 'automatic'} — now "
                f"{', '.join(current) or 'automatic'}. Something other than you "
                "may have done this.",
                "critical" if not current else "warning",
                action="Re-apply your resolver on the DNS tab."))
        return events


class NetworkWatcher(Watcher):
    """
    Detect joining a different network.

    This is the trigger for the tray agent's headline feature: notice the new
    Wi-Fi network, decide whether it is trusted, apply the matching profile.
    """

    name = "Network changes"
    interval = 20.0
    description = "Notices when you join a different Wi-Fi network."

    def __init__(self):
        super().__init__()
        self._current_ssid: Optional[str] = None
        self._first_run = True

    def check(self) -> List[Event]:
        conn = wifi.current_connection()
        ssid = (conn.get("ssid") or "").strip()
        if ssid == self._current_ssid:
            return []
        previous, self._current_ssid = self._current_ssid, ssid

        if self._first_run:
            self._first_run = False
            return []
        if not ssid:
            return [Event("network.left", "Disconnected from Wi-Fi",
                          f"Left '{previous}'." if previous else "Wi-Fi is down.",
                          "info")]

        auth = conn.get("auth", "")
        open_network = "open" in auth.lower()
        return [Event(
            "network.joined", f"Joined Wi-Fi network '{ssid}'",
            (f"Security: {auth or 'unknown'}."
             + (" This network is unencrypted — everything not using HTTPS is "
                "readable by anyone nearby." if open_network else "")),
            "warning" if open_network else "info",
            action="Apply the Public Wi-Fi profile if you do not trust it.")]


class LeakWatcher(Watcher):
    """Watch for protections silently dropping."""

    name = "Protection state"
    interval = 60.0
    description = "Alerts if Tor stops, the proxy drops, or the kill switch is removed."

    def __init__(self):
        super().__init__()
        self._tor_was: Optional[bool] = None
        self._proxy_was: Optional[bool] = None
        self._ks_was: Optional[bool] = None

    def check(self) -> List[Event]:
        events: List[Event] = []

        tor_now = tor.is_running()
        if self._tor_was is True and not tor_now:
            events.append(Event(
                "tor.stopped", "Tor is no longer running",
                "Traffic configured to route through Tor now has nowhere to go. "
                "If the kill switch is armed you will lose connectivity; if it "
                "is not, traffic is going direct.",
                "critical", action="Restart Tor, or disarm the kill switch."))
        self._tor_was = tor_now

        proxy_now = proxy.get_state().enabled
        if self._proxy_was is True and not proxy_now:
            events.append(Event(
                "proxy.dropped", "System proxy was turned off",
                "Something disabled the Windows proxy setting. Traffic is now "
                "going direct.", "critical",
                action="Re-enable routing on the Tor tab."))
        self._proxy_was = proxy_now

        ks_now = firewall.killswitch_active()
        if self._ks_was is True and not ks_now:
            events.append(Event(
                "killswitch.removed", "Kill switch rule disappeared",
                "The outbound block rule is no longer present. Traffic can now "
                "leave outside the proxy.", "warning",
                action="Re-arm it on the Firewall tab."))
        self._ks_was = ks_now

        return events


class DeviceWatcher(Watcher):
    """
    Notice new devices on the local network.

    On a home network a new device is usually a guest's phone. On a café network
    it is background noise. The value is on a network you believe is private —
    an unfamiliar device on your own subnet is worth a look.
    """

    name = "Network neighbours"
    interval = 120.0
    description = "Notices devices appearing on your local network."

    def __init__(self):
        super().__init__()
        self._known: set = set()
        self._first_run = True

    def check(self) -> List[Event]:
        from . import shell
        if not sysinfo.IS_WINDOWS:
            return []
        res = shell.run(["arp", "-a"], check_rc=False, timeout=25)
        import re
        seen = set()
        for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})", res.out):
            ip, hw = m.group(1), m.group(2).replace("-", ":").lower()
            if hw.startswith(("ff:ff", "01:00:5e", "33:33")):
                continue
            seen.add((ip, hw))

        if self._first_run:
            self._known = seen
            self._first_run = False
            return []

        new = seen - self._known
        self._known |= seen
        events = []
        for ip, hw in sorted(new)[:5]:
            from . import oui
            vendor = oui.lookup(hw) or "unknown vendor"
            events.append(Event(
                "device.new", "New device on your network",
                f"{ip} · {hw.upper()} · {vendor}", "info"))
        return events


class ProtectionService:
    """
    Runs the watchers on one background thread.

    One thread rather than one per watcher: these are cheap, mostly-idle checks,
    and a dozen threads polling independently would be harder to stop cleanly
    and would produce interleaved event ordering that is confusing to read.
    """

    def __init__(self):
        self.watchers: List[Watcher] = [
            NetworkWatcher(), DnsWatcher(), LeakWatcher(), DeviceWatcher(),
        ]
        self.events: List[Event] = []
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.on_event: Optional[Callable[[Event], None]] = None
        self.started_at = 0.0
        self.checks_run = 0

    def watcher_by_name(self, name: str) -> Optional[Watcher]:
        return next((w for w in self.watchers if w.name == name), None)

    def start(self) -> tuple:
        if self.running:
            return True, "Live protection is already running."
        self._stop = threading.Event()
        self.running = True
        self.started_at = time.time()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        active = sum(1 for w in self.watchers if w.enabled)
        return True, f"Live protection started with {active} watcher(s)."

    def stop(self) -> tuple:
        if not self.running:
            return True, "Live protection is not running."
        self._stop.set()
        self.running = False
        return True, "Live protection stopped."

    def _loop(self) -> None:
        # Stagger the first run so four watchers do not all fire at once on
        # startup and produce a burst of notifications.
        time.sleep(3.0)
        while not self._stop.is_set():
            now = time.time()
            for watcher in self.watchers:
                if self._stop.is_set():
                    break
                if not watcher.due(now):
                    continue
                for event in watcher.run(now):
                    self._emit(event)
                self.checks_run += 1
            self._stop.wait(timeout=5.0)

    def _emit(self, event: Event) -> None:
        with self._lock:
            self.events.insert(0, event)
            del self.events[200:]
        if self.on_event:
            try:
                self.on_event(event)
            except Exception:
                pass

    def recent(self, limit: int = 50) -> List[Event]:
        with self._lock:
            return list(self.events[:limit])

    def clear(self) -> None:
        with self._lock:
            self.events.clear()

    @property
    def uptime(self) -> str:
        if not self.running or not self.started_at:
            return "—"
        secs = int(time.time() - self.started_at)
        h, rem = divmod(secs, 3600)
        m, s = divmod(rem, 60)
        return f"{h}h {m:02d}m" if h else f"{m}m {s:02d}s"


#: Shared instance, so the window and the tray agent observe the same stream.
service = ProtectionService()
