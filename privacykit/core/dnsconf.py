"""
DNS resolver switching, DNS-over-HTTPS, and cache control.

Why DNS is the weak link: even with a VPN or Tor proxy configured, if your
resolver is still your ISP's, every domain you visit is handed to them in
plaintext. Switching to a privacy-respecting resolver *and* encrypting the
queries (DoH) closes that. The Leak Tests tab verifies it actually worked
rather than taking the setting's word for it.

Provider list note: the resolver addresses and DoH templates below were checked
against each operator's own documentation. dns0.eu is deliberately absent — the
service was discontinued, and shipping its addresses would silently break
name resolution for anyone who selected it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import journal, shell, sysinfo


@dataclass
class Provider:
    key: str
    name: str
    servers: List[str]
    doh: str = ""
    note: str = ""
    filters: str = ""          # what, if anything, it blocks
    logging: str = ""          # operator's stated logging policy

    @property
    def supports_doh(self) -> bool:
        return bool(self.doh)


PROVIDERS: Dict[str, Provider] = {
    "cloudflare": Provider(
        "cloudflare", "Cloudflare", ["1.1.1.1", "1.0.0.1"],
        "https://cloudflare-dns.com/dns-query",
        note="Fast and widely available.",
        filters="None", logging="Stated 24-hour retention, no PII sold.",
    ),
    "cloudflare-security": Provider(
        "cloudflare-security", "Cloudflare (malware blocking)",
        ["1.1.1.2", "1.0.0.2"],
        "https://security.cloudflare-dns.com/dns-query",
        note="Cloudflare with known-malware domains blocked.",
        filters="Malware", logging="As Cloudflare.",
    ),
    "quad9": Provider(
        "quad9", "Quad9", ["9.9.9.9", "149.112.112.112"],
        "https://dns.quad9.net/dns-query",
        note="Swiss non-profit; blocks known-malicious domains.",
        filters="Malware, phishing", logging="No IP logging claimed.",
    ),
    "mullvad": Provider(
        "mullvad", "Mullvad DNS", ["194.242.2.2"],
        "https://dns.mullvad.net/dns-query",
        note="Run by Mullvad; usable without an account.",
        filters="None", logging="No-logging policy.",
    ),
    "mullvad-adblock": Provider(
        "mullvad-adblock", "Mullvad (ad blocking)", ["194.242.2.3"],
        "https://adblock.dns.mullvad.net/dns-query",
        note="Mullvad resolver with ad and tracker blocking.",
        filters="Ads, trackers", logging="No-logging policy.",
    ),
    "adguard": Provider(
        "adguard", "AdGuard DNS", ["94.140.14.14", "94.140.15.15"],
        "https://dns.adguard-dns.com/dns-query",
        note="Blocks ads and trackers at the DNS layer.",
        filters="Ads, trackers, malware", logging="Anonymised statistics.",
    ),
    "adguard-unfiltered": Provider(
        "adguard-unfiltered", "AdGuard (unfiltered)",
        ["94.140.14.140", "94.140.14.141"],
        "https://unfiltered.adguard-dns.com/dns-query",
        note="AdGuard infrastructure with no blocking.",
        filters="None", logging="Anonymised statistics.",
    ),
    "google": Provider(
        "google", "Google Public DNS", ["8.8.8.8", "8.8.4.4"],
        "https://dns.google/dns-query",
        note="Reliable, but it is Google — included for completeness.",
        filters="None", logging="Retains some data; see their policy.",
    ),
}

PROVIDER_ORDER = ["cloudflare", "quad9", "mullvad", "mullvad-adblock",
                  "adguard", "adguard-unfiltered", "cloudflare-security", "google"]


@dataclass
class DNSState:
    adapter: str
    servers: List[str] = field(default_factory=list)
    automatic: bool = True
    doh_enabled: bool = False

    def provider_name(self) -> str:
        if self.automatic or not self.servers:
            return "Automatic (from DHCP — usually your ISP)"
        for p in PROVIDERS.values():
            if self.servers[0] in p.servers:
                return p.name
        return "Custom"


def get_state(adapter: str) -> DNSState:
    """Current DNS configuration for one adapter."""
    if not sysinfo.IS_WINDOWS:
        return DNSState(adapter)
    script = (
        f"$n='{adapter.replace(chr(39), chr(39) * 2)}';"
        "$s=Get-DnsClientServerAddress -InterfaceAlias $n -AddressFamily IPv4"
        " -ErrorAction SilentlyContinue;"
        "[pscustomobject]@{Servers=@($s.ServerAddresses)} | ConvertTo-Json -Compress"
    )
    res = shell.run_powershell(script, timeout=25)
    servers: List[str] = []
    try:
        d = json.loads(res.out.strip())
        raw = d.get("Servers") or []
        servers = [raw] if isinstance(raw, str) else [str(x) for x in raw]
    except Exception:
        pass

    # An adapter on DHCP-supplied DNS reports the DHCP values here too, so
    # distinguish by asking netsh whether the config is static.
    cfg = shell.run(["netsh", "interface", "ipv4", "show", "dnsservers",
                     f"name={adapter}"], check_rc=False)
    automatic = "DHCP" in cfg.out or "dhcp" in cfg.out.lower()
    return DNSState(adapter=adapter, servers=servers, automatic=automatic,
                    doh_enabled=is_doh_configured(servers[0]) if servers else False)


def set_provider(adapter: str, provider_key: str, enable_doh: bool = True) -> tuple:
    """Point an adapter at a named provider, optionally enabling DoH."""
    provider = PROVIDERS.get(provider_key)
    if provider is None:
        return False, f"Unknown DNS provider '{provider_key}'."
    return set_servers(adapter, provider.servers, enable_doh=enable_doh,
                       doh_template=provider.doh, label=provider.name)


def set_servers(adapter: str, servers: List[str], enable_doh: bool = False,
                doh_template: str = "", label: str = "") -> tuple:
    """Apply a list of DNS servers to an adapter, journalling the prior state."""
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    if not sysinfo.is_admin():
        return False, "Administrator rights are required to change DNS servers."
    if not servers:
        return False, "No DNS servers supplied."

    import ipaddress
    for s in servers:
        try:
            ipaddress.ip_address(s)
        except Exception:
            return False, f"'{s}' is not a valid IP address."

    prior = get_state(adapter)
    entry = journal.record(
        module="dns",
        action=f"DNS on '{adapter}' → {label or ', '.join(servers)}",
        undo={"kind": "dns.restore", "adapter": adapter,
              "prior_servers": prior.servers, "prior_automatic": prior.automatic,
              "doh_added": [s for s in servers if enable_doh and doh_template]},
        before={"servers": prior.servers, "automatic": prior.automatic},
    )

    # DoH must be registered *before* the server is assigned, otherwise Windows
    # briefly resolves in the clear before picking up the encryption template.
    if enable_doh and doh_template:
        for s in servers:
            add_doh_template(s, doh_template)

    res = shell.run(["netsh", "interface", "ipv4", "set", "dnsservers",
                     f"name={adapter}", "static", servers[0], "primary",
                     "validate=no"], check_rc=False, timeout=30)
    if res.code != 0 and "Ok" not in res.out:
        journal.drop(entry.id)
        return False, f"netsh rejected the change: {res.text[:200]}"

    for idx, srv in enumerate(servers[1:], start=2):
        shell.run(["netsh", "interface", "ipv4", "add", "dnsservers",
                   f"name={adapter}", srv, f"index={idx}", "validate=no"],
                  check_rc=False, timeout=30)

    flush_cache()
    doh_note = " with DNS-over-HTTPS" if (enable_doh and doh_template) else ""
    return True, f"DNS set to {label or ', '.join(servers)}{doh_note}."


def set_automatic(adapter: str) -> tuple:
    """Revert an adapter to DHCP-supplied DNS."""
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    if not sysinfo.is_admin():
        return False, "Administrator rights are required."

    prior = get_state(adapter)
    if not prior.automatic:
        journal.record(
            module="dns", action=f"DNS on '{adapter}' → automatic",
            undo={"kind": "dns.restore", "adapter": adapter,
                  "prior_servers": prior.servers, "prior_automatic": prior.automatic},
            before={"servers": prior.servers},
        )
    res = shell.run(["netsh", "interface", "ipv4", "set", "dnsservers",
                     f"name={adapter}", "source=dhcp"], check_rc=False, timeout=30)
    flush_cache()
    ok = res.code == 0 or "Ok" in res.out
    return ok, ("DNS returned to automatic (DHCP)." if ok else res.text[:200])


@journal.register_undo("dns.restore")
def _undo_dns(payload: dict) -> tuple:
    adapter = payload.get("adapter", "")
    if not adapter:
        return False, "no adapter recorded"
    for srv in payload.get("doh_added") or []:
        remove_doh_template(srv)

    if payload.get("prior_automatic", True) or not payload.get("prior_servers"):
        res = shell.run(["netsh", "interface", "ipv4", "set", "dnsservers",
                         f"name={adapter}", "source=dhcp"], check_rc=False, timeout=30)
        flush_cache()
        return (res.code == 0 or "Ok" in res.out), "DNS returned to automatic"

    servers = payload["prior_servers"]
    res = shell.run(["netsh", "interface", "ipv4", "set", "dnsservers",
                     f"name={adapter}", "static", servers[0], "primary",
                     "validate=no"], check_rc=False, timeout=30)
    for idx, srv in enumerate(servers[1:], start=2):
        shell.run(["netsh", "interface", "ipv4", "add", "dnsservers",
                   f"name={adapter}", srv, f"index={idx}", "validate=no"],
                  check_rc=False, timeout=30)
    flush_cache()
    return (res.code == 0 or "Ok" in res.out), f"restored {', '.join(servers)}"


# ──────────────────────────────────────────────────────────────────────────────
# DNS over HTTPS (Windows 11 native)
# ──────────────────────────────────────────────────────────────────────────────

def doh_supported() -> bool:
    """Does this Windows build have the ``netsh dns`` DoH context?"""
    if not sysinfo.IS_WINDOWS:
        return False
    res = shell.run(["netsh", "dns", "show", "encryption"], check_rc=False, timeout=15)
    return res.code == 0 or "server" in res.out.lower()


def list_doh_templates() -> List[dict]:
    """Registered DoH templates, as Windows knows them."""
    if not sysinfo.IS_WINDOWS:
        return []
    res = shell.run(["netsh", "dns", "show", "encryption"], check_rc=False, timeout=20)
    out, current = [], {}
    for line in res.out.splitlines():
        line = line.strip()
        if not line:
            if current:
                out.append(current)
                current = {}
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            current[k.strip().lower().replace(" ", "_")] = v.strip()
    if current:
        out.append(current)
    return [c for c in out if c.get("server")]


def is_doh_configured(server: str) -> bool:
    return any(t.get("server") == server for t in list_doh_templates())


def add_doh_template(server: str, template: str, udp_fallback: bool = False) -> tuple:
    """
    Register a DoH endpoint for a resolver IP.

    ``udp_fallback=False`` is the privacy-correct default: with fallback on,
    Windows silently drops to plaintext DNS whenever the encrypted endpoint is
    unreachable, which is precisely the moment you would want it to fail loudly.
    """
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    if not sysinfo.is_admin():
        return False, "Administrator rights are required."
    if is_doh_configured(server):
        return True, f"DoH already registered for {server}."

    journal.record(
        module="dns", action=f"Registered DoH template for {server}",
        undo={"kind": "dns.doh_remove", "server": server},
        before={"server": server, "template": template},
    )
    res = shell.run(["netsh", "dns", "add", "encryption", f"server={server}",
                     f"dohtemplate={template}", "autoupgrade=yes",
                     f"udpfallback={'yes' if udp_fallback else 'no'}"],
                    check_rc=False, timeout=25)
    ok = res.code == 0 or "Ok" in res.out
    return ok, (f"DoH enabled for {server}." if ok else res.text[:200])


def remove_doh_template(server: str) -> tuple:
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    res = shell.run(["netsh", "dns", "delete", "encryption", f"server={server}"],
                    check_rc=False, timeout=20)
    return (res.code == 0 or "Ok" in res.out), f"removed DoH template for {server}"


@journal.register_undo("dns.doh_remove")
def _undo_doh(payload: dict) -> tuple:
    return remove_doh_template(payload.get("server", ""))


# ──────────────────────────────────────────────────────────────────────────────
# Cache
# ──────────────────────────────────────────────────────────────────────────────

def flush_cache() -> tuple:
    """
    Clear the resolver cache.

    Both a privacy action (the cache is a browsable list of everywhere you have
    been — ``ipconfig /displaydns`` reveals it to anyone at the keyboard) and a
    practical one after changing resolvers.
    """
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    res = shell.run(["ipconfig", "/flushdns"], check_rc=False, timeout=20)
    ok = res.code == 0 or "success" in res.out.lower()
    return ok, ("DNS resolver cache flushed." if ok else res.text[:160])


def cache_entries() -> List[str]:
    """Domain names currently sitting in the resolver cache."""
    if not sysinfo.IS_WINDOWS:
        return []
    res = shell.run(["ipconfig", "/displaydns"], check_rc=False, timeout=30)
    names = []
    for line in res.out.splitlines():
        line = line.strip()
        if line.startswith("Record Name") and ":" in line:
            name = line.split(":", 1)[1].strip()
            if name and name not in names:
                names.append(name)
    return names


def snapshot() -> dict:
    from . import mac as macmod
    out = {}
    for a in macmod.list_adapters(include_virtual=False):
        st = get_state(a.name)
        out[a.name] = {"servers": st.servers, "automatic": st.automatic}
    out["_doh_templates"] = [t.get("server") for t in list_doh_templates()]
    return out
