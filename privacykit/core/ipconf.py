"""
Local IP address management.

An important clarification the UI repeats, because it is the single most
common misconception about "IP changers": this module changes your **local
(LAN) IP address** — the one your router hands out, e.g. 192.168.1.42. It does
**not** change the public IP the internet sees. Only a VPN, proxy, or Tor can
do that; see :mod:`privacykit.core.tor` and :mod:`privacykit.core.proxy`.

What you *can* usefully do locally:
  * release and renew the DHCP lease (often yields a different LAN IP, and on
    some ISPs with short lease times a different public IP too);
  * pin a static IP, which stops the router logging a new lease for you;
  * randomise the host portion of your LAN address to break simple
    "same device came back" correlation on a network you revisit.
"""

from __future__ import annotations

import ipaddress
import json
import random
import re
from dataclasses import dataclass
from typing import List, Optional

from . import journal, shell, sysinfo


@dataclass
class IPConfig:
    adapter: str
    dhcp: bool = True
    ip: str = ""
    prefix: int = 24
    gateway: str = ""
    dns: List[str] = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.dns is None:
            self.dns = []

    @property
    def netmask(self) -> str:
        try:
            return str(ipaddress.IPv4Network(f"0.0.0.0/{self.prefix}").netmask)
        except Exception:
            return "255.255.255.0"

    def describe(self) -> str:
        if self.dhcp:
            return f"DHCP — {self.ip or 'no lease'}"
        return f"Static — {self.ip}/{self.prefix} via {self.gateway or 'no gateway'}"


def get_config(adapter: str) -> Optional[IPConfig]:
    """Read the current IPv4 configuration for an adapter."""
    if not sysinfo.IS_WINDOWS:
        return None
    script = (
        f"$n='{_ps_escape(adapter)}';"
        "$a=Get-NetIPConfiguration -InterfaceAlias $n -ErrorAction SilentlyContinue;"
        "$i=Get-NetIPAddress -InterfaceAlias $n -AddressFamily IPv4 -ErrorAction SilentlyContinue |"
        " Select-Object -First 1;"
        "$d=Get-NetIPInterface -InterfaceAlias $n -AddressFamily IPv4 -ErrorAction SilentlyContinue;"
        "[pscustomobject]@{"
        " IP=$i.IPAddress; Prefix=$i.PrefixLength;"
        " Dhcp=($d.Dhcp -eq 'Enabled');"
        " Gateway=($a.IPv4DefaultGateway.NextHop);"
        " Dns=@($a.DNSServer | Where-Object {$_.AddressFamily -eq 2} |"
        " ForEach-Object {$_.ServerAddresses}) } | ConvertTo-Json -Compress"
    )
    res = shell.run_powershell(script, timeout=30)
    try:
        d = json.loads(res.out.strip())
    except Exception:
        return _get_config_netsh(adapter)
    dns = d.get("Dns") or []
    if isinstance(dns, str):
        dns = [dns]
    return IPConfig(
        adapter=adapter,
        dhcp=bool(d.get("Dhcp", True)),
        ip=str(d.get("IP") or ""),
        prefix=int(d.get("Prefix") or 24),
        gateway=str(d.get("Gateway") or ""),
        dns=[str(x) for x in dns if x],
    )


def _get_config_netsh(adapter: str) -> Optional[IPConfig]:
    """Fallback parser for ``netsh interface ipv4 show config``."""
    res = shell.run(["netsh", "interface", "ipv4", "show", "config",
                     f"name={adapter}"], check_rc=False)
    if not res.out:
        return None
    txt = res.out
    dhcp = "DHCP enabled" in txt and re.search(r"DHCP enabled:\s*Yes", txt) is not None
    ip_m = re.search(r"IP Address:\s*([\d.]+)", txt)
    gw_m = re.search(r"Default Gateway:\s*([\d.]+)", txt)
    mask_m = re.search(r"[Ss]ubnet [Pp]refix:\s*[\d.]+/(\d+)", txt)
    dns_list = re.findall(r"(?:DNS servers configured[^:]*:|^\s{4,})\s*([\d.]+)",
                          txt, re.MULTILINE)
    return IPConfig(
        adapter=adapter, dhcp=dhcp,
        ip=ip_m.group(1) if ip_m else "",
        prefix=int(mask_m.group(1)) if mask_m else 24,
        gateway=gw_m.group(1) if gw_m else "",
        dns=list(dict.fromkeys(dns_list)),
    )


def _ps_escape(value: str) -> str:
    """Escape a value for single-quoted PowerShell."""
    return value.replace("'", "''")


# ──────────────────────────────────────────────────────────────────────────────
# Operations
# ──────────────────────────────────────────────────────────────────────────────

def release_renew(adapter: Optional[str] = None) -> tuple:
    """
    Release and renew the DHCP lease.

    No journal entry: this is not a persistent configuration change, it just
    asks the router for a lease again. Nothing to undo.
    """
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    args_rel = ["ipconfig", "/release"] + ([adapter] if adapter else [])
    args_ren = ["ipconfig", "/renew"] + ([adapter] if adapter else [])
    shell.run(args_rel, check_rc=False, timeout=40)
    res = shell.run(args_ren, check_rc=False, timeout=90)
    cfg = get_config(adapter) if adapter else None
    got = f" New address: {cfg.ip}" if cfg and cfg.ip else ""
    if res.code == 0 or (cfg and cfg.ip):
        return True, f"DHCP lease released and renewed.{got}"
    return False, f"Renew failed: {res.text[:200] or 'unknown error'}"


def set_static(adapter: str, ip: str, prefix: int = 24, gateway: str = "",
               keep_dns: bool = True) -> tuple:
    """Pin a static IPv4 address, recording the prior config for undo."""
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    if not sysinfo.is_admin():
        return False, "Administrator rights are required."

    try:
        ipaddress.IPv4Address(ip)
    except Exception:
        return False, f"'{ip}' is not a valid IPv4 address."
    if not 1 <= int(prefix) <= 32:
        return False, "Prefix length must be between 1 and 32."
    if gateway:
        try:
            ipaddress.IPv4Address(gateway)
        except Exception:
            return False, f"'{gateway}' is not a valid gateway address."

    prior = get_config(adapter)
    if prior is None:
        return False, f"Could not read the current configuration for '{adapter}'."

    entry = journal.record(
        module="ip",
        action=f"Static IP {ip}/{prefix} on '{adapter}'",
        undo={"kind": "ip.restore", "adapter": adapter,
              "prior": {"dhcp": prior.dhcp, "ip": prior.ip, "prefix": prior.prefix,
                        "gateway": prior.gateway, "dns": prior.dns}},
        before={"config": prior.describe()},
    )

    mask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
    args = ["netsh", "interface", "ipv4", "set", "address",
            f"name={adapter}", "source=static", f"addr={ip}", f"mask={mask}"]
    if gateway:
        args += [f"gateway={gateway}", "gwmetric=1"]
    res = shell.run(args, check_rc=False, timeout=45)

    if res.code != 0 and "Ok" not in res.out:
        journal.drop(entry.id)
        return False, f"netsh rejected the change: {res.text[:250]}"

    if keep_dns and prior.dns:
        _apply_dns_list(adapter, prior.dns)

    return True, f"Static address set: {ip}/{prefix}" + (f" via {gateway}" if gateway else "")


def set_dhcp(adapter: str) -> tuple:
    """Return an adapter to automatic (DHCP) addressing."""
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    if not sysinfo.is_admin():
        return False, "Administrator rights are required."

    prior = get_config(adapter)
    if prior and not prior.dhcp:
        journal.record(
            module="ip",
            action=f"Switched '{adapter}' to DHCP",
            undo={"kind": "ip.restore", "adapter": adapter,
                  "prior": {"dhcp": prior.dhcp, "ip": prior.ip,
                            "prefix": prior.prefix, "gateway": prior.gateway,
                            "dns": prior.dns}},
            before={"config": prior.describe()},
        )

    res = shell.run(["netsh", "interface", "ipv4", "set", "address",
                     f"name={adapter}", "source=dhcp"], check_rc=False, timeout=45)
    shell.run(["netsh", "interface", "ipv4", "set", "dnsservers",
               f"name={adapter}", "source=dhcp"], check_rc=False, timeout=30)
    if res.code == 0 or "Ok" in res.out:
        return True, f"'{adapter}' set to automatic (DHCP) addressing."
    return False, f"netsh error: {res.text[:250]}"


def randomise_host_octet(adapter: str, low: int = 20, high: int = 240) -> tuple:
    """
    Keep the current subnet and gateway but pick a new host address.

    Useful on a network you rejoin often: the DHCP server will still see a new
    lease, but you land on a different address each time rather than being
    handed the same reserved one.
    """
    cfg = get_config(adapter)
    if not cfg or not cfg.ip:
        return False, "No current IPv4 address to work from."
    try:
        net = ipaddress.IPv4Network(f"{cfg.ip}/{cfg.prefix}", strict=False)
    except Exception:
        return False, "Could not determine the subnet."

    rng = random.SystemRandom()
    gw = cfg.gateway
    for _ in range(60):
        candidate = str(net.network_address + rng.randint(low, high))
        if candidate in (cfg.ip, gw, str(net.network_address), str(net.broadcast_address)):
            continue
        if ipaddress.IPv4Address(candidate) not in net:
            continue
        return set_static(adapter, candidate, cfg.prefix, gw)
    return False, "Could not find a free-looking address in this subnet."


def _apply_dns_list(adapter: str, servers: List[str]) -> None:
    if not servers:
        shell.run(["netsh", "interface", "ipv4", "set", "dnsservers",
                   f"name={adapter}", "source=dhcp"], check_rc=False)
        return
    shell.run(["netsh", "interface", "ipv4", "set", "dnsservers",
               f"name={adapter}", "static", servers[0], "primary", "validate=no"],
              check_rc=False, timeout=30)
    for idx, srv in enumerate(servers[1:], start=2):
        shell.run(["netsh", "interface", "ipv4", "add", "dnsservers",
                   f"name={adapter}", srv, f"index={idx}", "validate=no"],
                  check_rc=False, timeout=30)


@journal.register_undo("ip.restore")
def _undo_ip(payload: dict) -> tuple:
    adapter = payload.get("adapter", "")
    prior = payload.get("prior") or {}
    if not adapter:
        return False, "no adapter recorded"

    if prior.get("dhcp", True):
        shell.run(["netsh", "interface", "ipv4", "set", "address",
                   f"name={adapter}", "source=dhcp"], check_rc=False, timeout=45)
        shell.run(["netsh", "interface", "ipv4", "set", "dnsservers",
                   f"name={adapter}", "source=dhcp"], check_rc=False, timeout=30)
        return True, "returned to DHCP"

    ip, prefix = prior.get("ip"), int(prior.get("prefix") or 24)
    if not ip:
        return False, "prior static address missing from journal entry"
    mask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
    args = ["netsh", "interface", "ipv4", "set", "address",
            f"name={adapter}", "source=static", f"addr={ip}", f"mask={mask}"]
    if prior.get("gateway"):
        args += [f"gateway={prior['gateway']}", "gwmetric=1"]
    res = shell.run(args, check_rc=False, timeout=45)
    _apply_dns_list(adapter, prior.get("dns") or [])
    return (res.code == 0 or "Ok" in res.out), f"restored static {ip}/{prefix}"


def snapshot() -> dict:
    from . import mac as macmod
    out = {}
    for a in macmod.list_adapters(include_virtual=False):
        cfg = get_config(a.name)
        if cfg:
            out[a.name] = {"dhcp": cfg.dhcp, "ip": cfg.ip, "prefix": cfg.prefix,
                           "gateway": cfg.gateway, "dns": cfg.dns}
    return out
