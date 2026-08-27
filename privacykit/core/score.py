"""
Privacy score — a weighted, explainable summary of the machine's posture.

A score is only useful if it can justify itself. Every check here contributes a
named, weighted result and carries its own "how to fix this" text, so the
dashboard can show *why* the number is what it is rather than presenting an
unexplained 62/100.

Weights reflect real-world impact, not how impressive a feature sounds:
encrypted DNS and a non-ISP resolver matter more day to day than a spoofed MAC,
because DNS leaks your entire browsing history to a third party continuously
while a MAC address only identifies you to the local network segment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional


@dataclass
class Check:
    key: str
    title: str
    weight: int
    passed: bool = False
    partial: bool = False
    detail: str = ""
    fix: str = ""
    tab: str = ""            # which tab addresses it

    @property
    def earned(self) -> float:
        if self.passed:
            return float(self.weight)
        if self.partial:
            return self.weight * 0.5
        return 0.0


@dataclass
class ScoreReport:
    checks: List[Check] = field(default_factory=list)
    error: str = ""

    @property
    def total_weight(self) -> int:
        return sum(c.weight for c in self.checks) or 1

    @property
    def earned(self) -> float:
        return sum(c.earned for c in self.checks)

    @property
    def score(self) -> int:
        return int(round(100 * self.earned / self.total_weight))

    @property
    def grade(self) -> str:
        s = self.score
        if s >= 90:
            return "A"
        if s >= 78:
            return "B"
        if s >= 62:
            return "C"
        if s >= 45:
            return "D"
        return "F"

    @property
    def colour(self) -> str:
        s = self.score
        if s >= 78:
            return "#3fb950"
        if s >= 62:
            return "#58a6ff"
        if s >= 45:
            return "#e3b341"
        return "#f85149"

    def failing(self) -> List[Check]:
        """Unmet checks, worst first — the dashboard's 'what to do next' list."""
        return sorted([c for c in self.checks if not c.passed],
                      key=lambda c: -c.weight)

    def passing(self) -> List[Check]:
        return [c for c in self.checks if c.passed]


def compute(progress: Optional[Callable[[str], None]] = None,
            quick: bool = True) -> ScoreReport:
    """
    Assess the machine.

    ``quick`` skips checks that need network round trips, so the dashboard can
    render immediately and refine itself afterwards.
    """
    from . import dnsconf, firewall, hardening, mac, proxy, sysinfo, tor, wifi

    rep = ScoreReport()

    def say(msg: str) -> None:
        if progress:
            progress(msg)

    # ── DNS ──
    say("Checking DNS configuration…")
    dns_private, dns_encrypted = False, False
    try:
        adapters = [a for a in mac.list_adapters(include_virtual=False)
                    if a.status.lower() in ("up", "")]
        for a in adapters:
            st = dnsconf.get_state(a.name)
            if st.servers and not st.automatic:
                if any(s in p.servers for p in dnsconf.PROVIDERS.values()
                       for s in st.servers):
                    dns_private = True
            if st.doh_enabled:
                dns_encrypted = True
    except Exception as exc:
        rep.error = f"DNS check failed: {exc}"

    rep.checks.append(Check(
        "dns_provider", "DNS uses a privacy-respecting resolver", 18,
        passed=dns_private,
        detail=("A privacy resolver is configured." if dns_private else
                "DNS is still handled by your ISP or router, which sees every "
                "domain you visit."),
        fix="Open the DNS tab and pick Cloudflare, Quad9, or Mullvad.",
        tab="DNS",
    ))
    rep.checks.append(Check(
        "dns_encrypted", "DNS queries are encrypted (DoH)", 15,
        passed=dns_encrypted,
        detail=("DNS-over-HTTPS is active." if dns_encrypted else
                "DNS queries travel in plaintext and are readable by anyone on "
                "the path, even when the resolver itself is trustworthy."),
        fix="Enable DNS-over-HTTPS alongside your resolver in the DNS tab.",
        tab="DNS",
    ))

    # ── Tor ──
    say("Checking Tor…")
    tor_running = False
    try:
        tor_running = tor.is_running()
    except Exception:
        pass
    proxy_on = False
    try:
        proxy_on = proxy.get_state().enabled
    except Exception:
        pass
    rep.checks.append(Check(
        "anonymity", "Traffic routed through Tor or a proxy", 16,
        passed=tor_running and proxy_on, partial=tor_running or proxy_on,
        detail=("Tor is running and the system proxy points at it."
                if (tor_running and proxy_on) else
                "Tor is running but the system proxy is not pointed at it."
                if tor_running else
                "A system proxy is set but Tor is not running." if proxy_on else
                "Your real IP address is visible to every site you visit."),
        fix="Start Tor, then use 'Route system traffic through Tor' in the Tor tab.",
        tab="Tor",
    ))

    # ── MAC ──
    say("Checking network identity…")
    spoofed = False
    try:
        spoofed = any(a.spoofed for a in mac.list_adapters(include_virtual=False))
    except Exception:
        pass
    rep.checks.append(Check(
        "mac_spoofed", "Hardware MAC address is masked", 8,
        passed=spoofed,
        detail=("At least one adapter is using a spoofed address."
                if spoofed else
                "Your adapters broadcast their factory MAC, which identifies "
                "this device to every network you join."),
        fix="Spoof the MAC of your active adapter in the Network Identity tab.",
        tab="Network Identity",
    ))

    # ── Firewall ──
    say("Checking firewall…")
    fw_on, killswitch = False, False
    try:
        fw_on = firewall.firewall_enabled()
        killswitch = firewall.killswitch_active()
    except Exception:
        pass
    rep.checks.append(Check(
        "firewall_on", "Windows Firewall is enabled", 10,
        passed=fw_on,
        detail="Firewall is on." if fw_on else
               "The firewall is off — every listening service is exposed.",
        fix="Turn the Windows Firewall back on in the Firewall tab.",
        tab="Firewall",
    ))
    rep.checks.append(Check(
        "killswitch", "Kill switch armed against proxy failure", 6,
        passed=killswitch,
        detail=("Outbound traffic is blocked unless it goes through the local "
                "proxy." if killswitch else
                "If your VPN or Tor drops, traffic silently falls back to your "
                "real connection."),
        fix="Arm the kill switch in the Firewall tab while using Tor or a VPN.",
        tab="Firewall",
    ))

    # ── LLMNR / name resolution ──
    llmnr_off = False
    try:
        llmnr_off = not firewall.llmnr_enabled()
    except Exception:
        pass
    rep.checks.append(Check(
        "llmnr", "LLMNR disabled (credential-theft vector)", 7,
        passed=llmnr_off,
        detail=("LLMNR is off." if llmnr_off else
                "LLMNR broadcasts name lookups to the whole local network, where "
                "an attacker can answer and harvest credentials."),
        fix="Disable LLMNR in the Firewall tab.",
        tab="Firewall",
    ))

    # ── Telemetry hardening ──
    say("Checking Windows privacy settings…")
    try:
        audit = hardening.audit()
        private_count = sum(1 for t in audit if t["private"])
        ratio = private_count / max(len(audit), 1)
    except Exception:
        private_count, ratio, audit = 0, 0.0, []
    rep.checks.append(Check(
        "telemetry", "Windows telemetry and tracking reduced", 12,
        passed=ratio >= 0.7, partial=ratio >= 0.35,
        detail=f"{private_count} of {len(audit)} privacy settings are hardened.",
        fix="Apply the recommended tweaks in the Windows Hardening tab.",
        tab="Windows Hardening",
    ))

    hosts_blocked = 0
    try:
        hosts_blocked = hardening.hosts_blocked_count()
    except Exception:
        pass
    rep.checks.append(Check(
        "hosts_block", "Telemetry domains blocked at the hosts file", 5,
        passed=hosts_blocked > 20,
        detail=(f"{hosts_blocked} domains blocked." if hosts_blocked else
                "Telemetry and ad domains resolve normally."),
        fix="Apply the telemetry blocklist in the Windows Hardening tab.",
        tab="Windows Hardening",
    ))

    # ── Wi-Fi hygiene ──
    say("Checking saved Wi-Fi networks…")
    try:
        profiles = wifi.list_profiles()
        n = len(profiles)
    except Exception:
        n = 0
    rep.checks.append(Check(
        "wifi_profiles", "Saved Wi-Fi network list kept small", 5,
        passed=0 < n <= 5, partial=5 < n <= 12,
        detail=(f"{n} saved networks." if n else "No saved networks found.")
        + (" Each one is a place your device can be shown to have been."
           if n > 5 else ""),
        fix="Forget networks you no longer use in the Network Identity tab.",
        tab="Network Identity",
    ))

    # ── Elevation ──
    rep.checks.append(Check(
        "admin", "Running with the rights needed to fix problems", 3,
        passed=sysinfo.is_admin(),
        detail=("Running as Administrator." if sysinfo.is_admin() else
                "Not elevated — many fixes are unavailable."),
        fix="Restart PrivacyKit as Administrator.",
        tab="Dashboard",
    ))

    say("Score complete.")
    return rep
