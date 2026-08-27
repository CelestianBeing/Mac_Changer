"""
Leak tests — the "prove it" layer.

Every other module in this toolkit *configures* something. This one checks
whether the configuration is actually doing what it claims. That distinction
matters: a proxy setting that a program ignores, a DoH template Windows
silently fell back from, or an IPv6 route that bypasses your IPv4 VPN all look
fine in the settings UI and leak anyway.

Tests implemented:
  * public IP and geolocation, direct
  * public IP through Tor's SOCKS port, compared against the direct answer
  * DNS resolver identity (who is actually answering your queries)
  * IPv6 reachability (the classic VPN bypass)
  * WebRTC exposure — reported, with the honest caveat that it lives inside the
    browser and cannot be fixed from outside it
  * local DNS cache contents (a browsing history sitting in plain sight)
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from . import dnsconf, netclient, socks5, tor

#: Endpoints used for IP lookup. Several, because any one of them can be down,
#: rate-limited, or blocked on a restrictive network.
IP_SERVICES = [
    ("https://ipinfo.io/json", "ip", "country", "org", "city"),
    ("https://api.ipify.org?format=json", "ip", None, None, None),
    ("https://ifconfig.co/json", "ip", "country_iso", "asn_org", "city"),
]

#: Resolvers that report which server answered — used for the DNS leak test.
DNS_ECHO_SERVICES = [
    "https://edns.ip-api.com/json",
]

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2, "good": 3}


@dataclass
class Finding:
    title: str
    severity: str          # critical | warning | info | good
    detail: str
    advice: str = ""

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 9)


@dataclass
class LeakReport:
    public_ip: str = ""
    public_country: str = ""
    public_org: str = ""
    public_city: str = ""
    tor_ip: str = ""
    tor_country: str = ""
    using_tor: bool = False
    ipv6_address: str = ""
    ipv6_exposed: bool = False
    dns_servers: List[str] = field(default_factory=list)
    dns_resolver_seen: str = ""
    dns_encrypted: bool = False
    cached_domains: int = 0
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: f.rank)

    def worst_severity(self) -> str:
        if not self.findings:
            return "info"
        return min(self.findings, key=lambda f: f.rank).severity


# ──────────────────────────────────────────────────────────────────────────────
# Individual tests
# ──────────────────────────────────────────────────────────────────────────────

def public_ip(via_tor: bool = False, socks_port: int = 9050) -> dict:
    """Ask an external service what address it sees. Returns a dict of facts."""
    for spec in IP_SERVICES:
        url, ip_key, cc_key, org_key, city_key = spec
        r = netclient.get(url, via_tor=via_tor, proxy_port=socks_port,
                          timeout=20 if via_tor else 10)
        data = r.json() if r.ok else None
        if data and data.get(ip_key):
            return {
                "ip": str(data.get(ip_key) or ""),
                "country": str(data.get(cc_key) or "") if cc_key else "",
                "org": str(data.get(org_key) or "") if org_key else "",
                "city": str(data.get(city_key) or "") if city_key else "",
                "source": url,
            }
    return {}


def ipv6_status() -> dict:
    """
    Is IPv6 working and externally reachable?

    This is the single most common way a "protected" connection leaks: a VPN or
    proxy that only handles IPv4 while the OS quietly prefers IPv6 for any site
    that has an AAAA record.
    """
    result = {"has_local": False, "local": "", "public": "", "exposed": False}
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.settimeout(2.0)
        s.connect(("2001:4860:4860::8888", 53))   # no packets sent for UDP connect
        result["local"] = s.getsockname()[0]
        result["has_local"] = True
        s.close()
    except Exception:
        pass

    if result["has_local"]:
        r = netclient.get("https://api64.ipify.org?format=json", timeout=8)
        data = r.json() if r.ok else None
        if data and ":" in str(data.get("ip", "")):
            result["public"] = str(data["ip"])
            result["exposed"] = True
    return result


def dns_leak_test() -> dict:
    """
    Determine which resolver is actually answering, as seen from outside.

    ip-api's EDNS endpoint reports the resolver that reached it, which is the
    only way to see past the local configuration to what really happened.
    """
    out = {"resolver_ip": "", "resolver_org": "", "resolver_country": "", "ok": False}
    for url in DNS_ECHO_SERVICES:
        r = netclient.get(url, timeout=12)
        data = r.json() if r.ok else None
        if not data:
            continue
        dns_info = data.get("dns") or {}
        ip = dns_info.get("ip") or data.get("query") or ""
        if ip:
            out.update({"resolver_ip": str(ip),
                        "resolver_org": str(dns_info.get("geo") or data.get("org") or ""),
                        "resolver_country": str(data.get("countryCode") or ""),
                        "ok": True})
            return out
    return out


def webrtc_note() -> Finding:
    """
    WebRTC exposure.

    Reported rather than tested, because WebRTC runs inside the browser: no
    external process can enumerate what a page would see. Claiming to have
    "fixed" it from here would be a lie, so this states the situation and gives
    the actual per-browser remedy.
    """
    return Finding(
        title="WebRTC can reveal your real IP inside the browser",
        severity="warning",
        detail=("WebRTC lets a web page ask your browser directly for its local "
                "and public IP addresses, bypassing the system proxy entirely. A "
                "page can see your real address even while everything else is "
                "routed through Tor or a VPN. This happens inside the browser, so "
                "no external tool — including this one — can test or fix it."),
        advice=("Firefox: set media.peerconnection.enabled to false in about:config. "
                "Chrome/Edge: install the uBlock Origin extension and enable "
                "'Prevent WebRTC from leaking local IP addresses' in its settings. "
                "Tor Browser blocks WebRTC by default — nothing to do there."),
    )


# ──────────────────────────────────────────────────────────────────────────────
# Full run
# ──────────────────────────────────────────────────────────────────────────────

def run_all(progress: Optional[Callable[[str], None]] = None,
            check_tor: bool = True) -> LeakReport:
    """
    Run every test and assemble a report with findings.

    ``progress`` receives a short status string before each test so the GUI can
    show what is happening — several of these involve network round trips and a
    frozen window with no explanation is worse than a slow one.
    """
    rep = LeakReport()

    def say(msg: str) -> None:
        if progress:
            progress(msg)

    # ── direct public IP ──
    say("Checking your public IP address…")
    info = public_ip(via_tor=False)
    if info:
        rep.public_ip = info["ip"]
        rep.public_country = info.get("country", "")
        rep.public_org = info.get("org", "")
        rep.public_city = info.get("city", "")
    else:
        rep.errors.append("Could not reach any public-IP service (are you online?).")

    # ── Tor comparison ──
    if check_tor:
        say("Checking whether Tor is running…")
        st = tor.detect()
        if st.running:
            say("Fetching your exit IP through Tor…")
            tinfo = public_ip(via_tor=True, socks_port=st.socks_port)
            if tinfo:
                rep.tor_ip = tinfo["ip"]
                rep.tor_country = tinfo.get("country", "")
                rep.using_tor = bool(rep.tor_ip and rep.tor_ip != rep.public_ip)

    # ── IPv6 ──
    say("Testing IPv6 exposure…")
    v6 = ipv6_status()
    rep.ipv6_address = v6.get("public") or v6.get("local") or ""
    rep.ipv6_exposed = bool(v6.get("exposed"))

    # ── DNS ──
    say("Identifying your DNS resolver…")
    from . import mac as macmod
    for a in macmod.list_adapters(include_virtual=False):
        st_dns = dnsconf.get_state(a.name)
        for s in st_dns.servers:
            if s not in rep.dns_servers:
                rep.dns_servers.append(s)
        if st_dns.doh_enabled:
            rep.dns_encrypted = True
    leak = dns_leak_test()
    rep.dns_resolver_seen = leak.get("resolver_org") or leak.get("resolver_ip") or ""

    say("Reading the local DNS cache…")
    rep.cached_domains = len(dnsconf.cache_entries())

    _build_findings(rep)
    say("Done.")
    return rep


def _build_findings(rep: LeakReport) -> None:
    """Turn raw measurements into ranked, actionable findings."""

    # Tor / public IP
    if rep.using_tor:
        rep.findings.append(Finding(
            "Traffic is reaching the internet through Tor", "good",
            f"Your real address is {rep.public_ip or 'unknown'}; sites reached "
            f"through Tor see {rep.tor_ip}"
            + (f" ({rep.tor_country})" if rep.tor_country else "") + ".",
        ))
    elif rep.tor_ip and rep.tor_ip == rep.public_ip:
        rep.findings.append(Finding(
            "Tor is running but its exit IP matches your real IP", "critical",
            "Traffic sent through the Tor SOCKS port came back with the same "
            "address as a direct request. That should be impossible in a working "
            "Tor setup and suggests the SOCKS port is not really Tor.",
            "Stop and investigate before relying on this connection.",
        ))
    elif rep.public_ip:
        rep.findings.append(Finding(
            "Your real IP address is visible to every site you visit", "info",
            f"{rep.public_ip}"
            + (f" — {rep.public_org}" if rep.public_org else "")
            + (f", {rep.public_city}" if rep.public_city else "")
            + (f" ({rep.public_country})" if rep.public_country else ""),
            "Expected without a VPN or Tor. Use the Tor tab to route through Tor.",
        ))

    # IPv6
    if rep.ipv6_exposed:
        rep.findings.append(Finding(
            "IPv6 is publicly reachable — a common VPN/proxy bypass", "warning",
            f"Your machine answers on IPv6 as {rep.ipv6_address}. If your VPN or "
            "proxy only carries IPv4, any site with an AAAA record will be "
            "reached over IPv6 directly, outside the tunnel.",
            "Disable IPv6 on the adapter in the Firewall tab while using a "
            "IPv4-only VPN, or confirm your VPN handles IPv6.",
        ))
    elif rep.ipv6_address:
        rep.findings.append(Finding(
            "IPv6 is configured locally but not publicly reachable", "good",
            f"Local IPv6 address {rep.ipv6_address}; no public IPv6 connectivity "
            "detected, so there is no IPv6 bypass path.",
        ))

    # DNS
    isp_resolver = not rep.dns_servers or all(
        _is_private(s) for s in rep.dns_servers)
    if isp_resolver:
        rep.findings.append(Finding(
            "DNS queries are going to your router or ISP", "warning",
            f"Configured resolvers: {', '.join(rep.dns_servers) or 'automatic (DHCP)'}. "
            "Whoever runs them sees a timestamped list of every domain you visit, "
            "regardless of HTTPS.",
            "Switch to a privacy resolver with DNS-over-HTTPS in the DNS tab.",
        ))
    else:
        known = dnsconf.PROVIDERS
        name = next((p.name for p in known.values()
                     if rep.dns_servers and rep.dns_servers[0] in p.servers), "a custom resolver")
        sev = "good" if rep.dns_encrypted else "info"
        rep.findings.append(Finding(
            f"DNS is pointed at {name}"
            + (" over encrypted DoH" if rep.dns_encrypted else " (unencrypted)"),
            sev,
            f"Resolvers in use: {', '.join(rep.dns_servers)}."
            + ("" if rep.dns_encrypted else
               " Queries still travel in plaintext, so your ISP can read them even "
               "though it is no longer answering them."),
            "" if rep.dns_encrypted else "Enable DNS-over-HTTPS in the DNS tab.",
        ))

    if rep.dns_resolver_seen:
        rep.findings.append(Finding(
            "Resolver seen by external services", "info",
            f"Queries appear to arrive from: {rep.dns_resolver_seen}. If that is "
            "your ISP while you expected a privacy resolver, something is "
            "overriding your setting.",
        ))

    # Local cache
    if rep.cached_domains > 40:
        rep.findings.append(Finding(
            f"{rep.cached_domains} domains sitting in the local DNS cache", "warning",
            "Anyone with access to this machine can run 'ipconfig /displaydns' "
            "and read a recent browsing history — no admin rights needed.",
            "Flush it from the DNS tab, or use the Anti-Forensics tab to clear it "
            "along with other traces.",
        ))
    elif rep.cached_domains:
        rep.findings.append(Finding(
            f"{rep.cached_domains} domains in the local DNS cache", "info",
            "A small cache is normal. It still reveals recent activity to anyone "
            "at this keyboard.",
        ))

    rep.findings.append(webrtc_note())


def _is_private(ip: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def quick_status() -> dict:
    """Cheap status for the dashboard tiles — no full test sweep."""
    st = tor.detect()
    return {
        "tor_running": st.running,
        "tor_port": st.socks_port,
        "socks_open": socks5.probe("127.0.0.1", st.socks_port) if st.socks_port else False,
    }
