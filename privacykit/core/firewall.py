"""
Windows Firewall rules: kill switch, LAN isolation, and protocol toggles.

The kill switch is the enforcing layer behind the proxy settings. A system
proxy is advisory — programs can ignore it. A firewall rule is not. When the
kill switch is armed, outbound traffic is blocked unless it is going to the
local Tor/VPN listener, so an application that tries to bypass the proxy simply
fails to connect instead of silently leaking.

Every rule this module creates is named with the ``PrivacyKit-`` prefix, which
gives a reliable cleanup handle: even if the journal were lost, every rule can
be found and removed by name.

Safety design: arming the kill switch is journalled *before* the blocking rule
is created, and the allow rules are created *before* the block rule. Getting
that order wrong would cut the machine off from the network with no way for the
tool to reach anything — including, potentially, itself.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from . import journal, shell, sysinfo

RULE_PREFIX = "PrivacyKit-"
KILLSWITCH_BLOCK = f"{RULE_PREFIX}KillSwitch-BlockAll"
KILLSWITCH_ALLOW_LOCAL = f"{RULE_PREFIX}KillSwitch-AllowLoopback"
KILLSWITCH_ALLOW_TOR = f"{RULE_PREFIX}KillSwitch-AllowTor"
KILLSWITCH_ALLOW_DHCP = f"{RULE_PREFIX}KillSwitch-AllowDHCP"
LAN_BLOCK = f"{RULE_PREFIX}Block-LAN"
SMB_BLOCK = f"{RULE_PREFIX}Block-SMB"


@dataclass
class FirewallProfile:
    name: str
    state: str = ""
    inbound: str = ""
    outbound: str = ""


def profiles() -> List[FirewallProfile]:
    """Read the state of the Domain/Private/Public firewall profiles."""
    if not sysinfo.IS_WINDOWS:
        return []
    res = shell.run(["netsh", "advfirewall", "show", "allprofiles"],
                    check_rc=False, timeout=25)
    out: List[FirewallProfile] = []
    current: Optional[FirewallProfile] = None
    for line in res.out.splitlines():
        line = line.strip()
        m = re.match(r"^(Domain|Private|Public)\s+Profile\s+Settings", line, re.I)
        if m:
            if current:
                out.append(current)
            current = FirewallProfile(name=m.group(1))
            continue
        if current is None:
            continue
        if line.lower().startswith("state"):
            current.state = line.split(None, 1)[1].strip() if len(line.split()) > 1 else ""
        elif "inboundusernotification" in line.lower().replace(" ", ""):
            continue
        elif line.lower().startswith("firewallpolicy"):
            policy = line.split(None, 1)[1] if len(line.split()) > 1 else ""
            parts = [p.strip() for p in policy.split(",")]
            if len(parts) == 2:
                current.inbound, current.outbound = parts
    if current:
        out.append(current)
    return out


def firewall_enabled() -> bool:
    return any("ON" in (p.state or "").upper() for p in profiles())


def list_our_rules() -> List[str]:
    """Every firewall rule PrivacyKit has created that still exists."""
    if not sysinfo.IS_WINDOWS:
        return []
    res = shell.run(["netsh", "advfirewall", "firewall", "show", "rule",
                     "name=all"], check_rc=False, timeout=45)
    names = re.findall(r"^Rule Name:\s+(" + re.escape(RULE_PREFIX) + r".+)$",
                       res.out, re.MULTILINE)
    return sorted(set(n.strip() for n in names))


def _rule_exists(name: str) -> bool:
    """
    True only when netsh actually reported a matching rule.

    Testing for the absence of "No rules match" is not enough: if netsh is
    missing, blocked by policy, or times out, that string is also absent and the
    rule would be reported as present. A kill switch wrongly shown as armed is
    exactly the failure that gets someone hurt, so this requires positive
    evidence — a "Rule Name:" line in successful output.
    """
    res = shell.run(["netsh", "advfirewall", "firewall", "show", "rule",
                     f"name={name}"], check_rc=False, timeout=20)
    if res.code in (127, 124):          # not found, or timed out
        return False
    return res.code == 0 and "Rule Name" in res.out


def _delete_rule(name: str) -> bool:
    res = shell.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                     f"name={name}"], check_rc=False, timeout=25)
    return res.code == 0 or "Deleted" in res.out or "No rules match" in res.text


# ──────────────────────────────────────────────────────────────────────────────
# Kill switch
# ──────────────────────────────────────────────────────────────────────────────

def killswitch_active() -> bool:
    return _rule_exists(KILLSWITCH_BLOCK)


def arm_killswitch(tor_socks_port: int = 9050, allow_lan: bool = False,
                   allow_dhcp: bool = True) -> tuple:
    """
    Block all outbound traffic except to the local proxy.

    ``allow_dhcp`` keeps DHCP working; without it, the machine loses its lease
    on renewal and drops off the network entirely, which looks like the tool
    broke the computer. It costs nothing privacy-wise (DHCP is link-local) so
    it defaults on.
    """
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    if not sysinfo.is_admin():
        return False, "Administrator rights are required to change firewall rules."
    if killswitch_active():
        return True, "Kill switch is already armed."

    journal.record(
        module="firewall",
        action="Armed the outbound kill switch",
        undo={"kind": "firewall.disarm_killswitch"},
        before={"active": False},
        note="Blocks outbound traffic that is not destined for the local proxy.",
    )

    # Allow rules FIRST — if we created the block rule first and then failed,
    # the machine would be left with no network at all.
    shell.run(["netsh", "advfirewall", "firewall", "add", "rule",
               f"name={KILLSWITCH_ALLOW_LOCAL}", "dir=out", "action=allow",
               "remoteip=127.0.0.1,::1", "profile=any",
               "description=PrivacyKit: allow loopback so local proxies work"],
              check_rc=False, timeout=25)

    shell.run(["netsh", "advfirewall", "firewall", "add", "rule",
               f"name={KILLSWITCH_ALLOW_TOR}", "dir=out", "action=allow",
               "protocol=TCP", f"remoteport={tor_socks_port}",
               "remoteip=127.0.0.1", "profile=any",
               "description=PrivacyKit: allow the local Tor SOCKS listener"],
              check_rc=False, timeout=25)

    if allow_dhcp:
        shell.run(["netsh", "advfirewall", "firewall", "add", "rule",
                   f"name={KILLSWITCH_ALLOW_DHCP}", "dir=out", "action=allow",
                   "protocol=UDP", "remoteport=67,68", "profile=any",
                   "description=PrivacyKit: keep DHCP working"],
                  check_rc=False, timeout=25)

    if allow_lan:
        shell.run(["netsh", "advfirewall", "firewall", "add", "rule",
                   f"name={RULE_PREFIX}KillSwitch-AllowLAN", "dir=out",
                   "action=allow", "remoteip=LocalSubnet", "profile=any",
                   "description=PrivacyKit: allow local network access"],
                  check_rc=False, timeout=25)

    res = shell.run(["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={KILLSWITCH_BLOCK}", "dir=out", "action=block",
                     "remoteip=any", "profile=any",
                     "description=PrivacyKit kill switch: block all other outbound"],
                    check_rc=False, timeout=25)

    if res.code != 0 and "Ok" not in res.out:
        disarm_killswitch()
        return False, f"Could not create the block rule: {res.text[:200]}"

    return True, (
        "Kill switch armed. Outbound traffic is now blocked unless it goes to "
        f"127.0.0.1:{tor_socks_port}. If your browser stops loading pages, that "
        "is the kill switch doing its job — disarm it to restore normal access."
    )


def disarm_killswitch() -> tuple:
    """Remove every kill-switch rule."""
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    removed = 0
    for name in (KILLSWITCH_BLOCK, KILLSWITCH_ALLOW_TOR, KILLSWITCH_ALLOW_LOCAL,
                 KILLSWITCH_ALLOW_DHCP, f"{RULE_PREFIX}KillSwitch-AllowLAN"):
        if _rule_exists(name) and _delete_rule(name):
            removed += 1
    for e in journal.pending():
        if e.module == "firewall" and e.undo.get("kind") == "firewall.disarm_killswitch":
            journal.mark_undone(e.id)
    return True, f"Kill switch disarmed ({removed} rule(s) removed)."


@journal.register_undo("firewall.disarm_killswitch")
def _undo_killswitch(payload: dict) -> tuple:
    ok, msg = disarm_killswitch()
    return ok, msg


# ──────────────────────────────────────────────────────────────────────────────
# LAN isolation and SMB
# ──────────────────────────────────────────────────────────────────────────────

def block_lan(enabled: bool = True) -> tuple:
    """
    Cut off local-subnet traffic.

    The right setting on a public network: it stops other guests on the same
    café or hotel Wi-Fi from reaching your machine or being reached by it,
    without touching internet access.
    """
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    if not sysinfo.is_admin():
        return False, "Administrator rights are required."

    if not enabled:
        _delete_rule(LAN_BLOCK)
        _delete_rule(LAN_BLOCK + "-In")
        for e in journal.pending():
            if e.undo.get("kind") == "firewall.unblock_lan":
                journal.mark_undone(e.id)
        return True, "Local network traffic allowed again."

    if _rule_exists(LAN_BLOCK):
        return True, "LAN traffic is already blocked."

    journal.record(module="firewall", action="Blocked local network (LAN) traffic",
                   undo={"kind": "firewall.unblock_lan"}, before={"blocked": False})

    shell.run(["netsh", "advfirewall", "firewall", "add", "rule",
               f"name={LAN_BLOCK}", "dir=out", "action=block",
               "remoteip=LocalSubnet", "profile=any",
               "description=PrivacyKit: isolate from the local network"],
              check_rc=False, timeout=25)
    shell.run(["netsh", "advfirewall", "firewall", "add", "rule",
               f"name={LAN_BLOCK}-In", "dir=in", "action=block",
               "remoteip=LocalSubnet", "profile=any",
               "description=PrivacyKit: isolate from the local network (inbound)"],
              check_rc=False, timeout=25)
    return True, ("Local network isolated. Printers, network shares, and casting "
                  "will stop working until this is turned off.")


@journal.register_undo("firewall.unblock_lan")
def _undo_lan(payload: dict) -> tuple:
    _delete_rule(LAN_BLOCK)
    _delete_rule(LAN_BLOCK + "-In")
    return True, "LAN traffic restored"


def block_smb(enabled: bool = True) -> tuple:
    """Block SMB/NetBIOS ports — file-sharing exposure on hostile networks."""
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    if not sysinfo.is_admin():
        return False, "Administrator rights are required."

    if not enabled:
        _delete_rule(SMB_BLOCK)
        for e in journal.pending():
            if e.undo.get("kind") == "firewall.unblock_smb":
                journal.mark_undone(e.id)
        return True, "SMB/NetBIOS ports unblocked."

    if _rule_exists(SMB_BLOCK):
        return True, "SMB is already blocked."
    journal.record(module="firewall", action="Blocked SMB/NetBIOS ports",
                   undo={"kind": "firewall.unblock_smb"}, before={"blocked": False})
    shell.run(["netsh", "advfirewall", "firewall", "add", "rule",
               f"name={SMB_BLOCK}", "dir=in", "action=block", "protocol=TCP",
               "localport=135,139,445", "profile=any",
               "description=PrivacyKit: block file-sharing ports"],
              check_rc=False, timeout=25)
    return True, "SMB and NetBIOS ports (135, 139, 445) blocked inbound."


@journal.register_undo("firewall.unblock_smb")
def _undo_smb(payload: dict) -> tuple:
    _delete_rule(SMB_BLOCK)
    return True, "SMB ports unblocked"


# ──────────────────────────────────────────────────────────────────────────────
# Protocol toggles
# ──────────────────────────────────────────────────────────────────────────────

def ipv6_enabled(adapter: str) -> bool:
    if not sysinfo.IS_WINDOWS:
        return False
    res = shell.run_powershell(
        f"(Get-NetAdapterBinding -Name '{adapter}' -ComponentID ms_tcpip6"
        " -ErrorAction SilentlyContinue).Enabled", timeout=25)
    return "true" in res.out.lower()


def set_ipv6(adapter: str, enabled: bool) -> tuple:
    """
    Enable or disable the IPv6 binding on an adapter.

    Disabling IPv6 is the standard remedy for the IPv6-bypasses-your-IPv4-VPN
    leak. It is reversible and per-adapter, so it does not touch the global
    ``DisabledComponents`` registry value that Microsoft warns against.
    """
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    if not sysinfo.is_admin():
        return False, "Administrator rights are required."

    was = ipv6_enabled(adapter)
    if was == enabled:
        return True, f"IPv6 is already {'enabled' if enabled else 'disabled'} on '{adapter}'."

    journal.record(
        module="firewall",
        action=f"{'Enabled' if enabled else 'Disabled'} IPv6 on '{adapter}'",
        undo={"kind": "firewall.ipv6_restore", "adapter": adapter, "was": was},
        before={"ipv6_enabled": was},
    )
    verb = "Enable" if enabled else "Disable"
    res = shell.run_powershell(
        f"{verb}-NetAdapterBinding -Name '{adapter}' -ComponentID ms_tcpip6"
        " -ErrorAction Stop; 'DONE'", timeout=40)
    ok = "DONE" in res.out
    return ok, (f"IPv6 {'enabled' if enabled else 'disabled'} on '{adapter}'."
                if ok else res.text[:200])


@journal.register_undo("firewall.ipv6_restore")
def _undo_ipv6(payload: dict) -> tuple:
    adapter, was = payload.get("adapter", ""), payload.get("was", True)
    verb = "Enable" if was else "Disable"
    res = shell.run_powershell(
        f"{verb}-NetAdapterBinding -Name '{adapter}' -ComponentID ms_tcpip6"
        " -ErrorAction SilentlyContinue; 'DONE'", timeout=40)
    return "DONE" in res.out, f"IPv6 {'enabled' if was else 'disabled'} on '{adapter}'"


def set_netbios(adapter_guid: str, enabled: bool) -> tuple:
    """
    Toggle NetBIOS over TCP/IP for an interface.

    NetBIOS broadcasts your hostname and workgroup constantly and is the vector
    for classic name-poisoning attacks. Almost nothing modern needs it.
    Registry value: 1 = enabled, 2 = disabled, 0 = use DHCP setting.
    """
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    if not sysinfo.is_admin():
        return False, "Administrator rights are required."
    import winreg
    path = (r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
            rf"\Tcpip_{adapter_guid}")
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                            winreg.KEY_READ | winreg.KEY_WRITE) as k:
            try:
                prior, _ = winreg.QueryValueEx(k, "NetbiosOptions")
            except FileNotFoundError:
                prior = 0
            journal.record(
                module="firewall",
                action=f"NetBIOS over TCP/IP {'enabled' if enabled else 'disabled'}",
                undo={"kind": "firewall.netbios_restore",
                      "guid": adapter_guid, "prior": int(prior)},
                before={"NetbiosOptions": int(prior)},
            )
            winreg.SetValueEx(k, "NetbiosOptions", 0, winreg.REG_DWORD,
                              1 if enabled else 2)
        return True, f"NetBIOS over TCP/IP {'enabled' if enabled else 'disabled'}."
    except FileNotFoundError:
        return False, "No NetBT interface key for that adapter."
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


@journal.register_undo("firewall.netbios_restore")
def _undo_netbios(payload: dict) -> tuple:
    import winreg
    path = (r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
            rf"\Tcpip_{payload.get('guid', '')}")
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                            winreg.KEY_READ | winreg.KEY_WRITE) as k:
            winreg.SetValueEx(k, "NetbiosOptions", 0, winreg.REG_DWORD,
                              int(payload.get("prior", 0)))
        return True, "NetBIOS setting restored"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def llmnr_enabled() -> bool:
    if not sysinfo.IS_WINDOWS:
        return False
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient") as k:
            val, _ = winreg.QueryValueEx(k, "EnableMulticast")
            return bool(val)
    except Exception:
        return True   # absent policy means LLMNR is on


def set_llmnr(enabled: bool) -> tuple:
    """
    Toggle LLMNR (Link-Local Multicast Name Resolution).

    LLMNR asks the entire local network "who is <name>?" whenever DNS fails —
    and on a hostile network, an attacker answers "me", harvesting credentials.
    Disabling it is a standard hardening step with essentially no downside on a
    home or public network.
    """
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    if not sysinfo.is_admin():
        return False, "Administrator rights are required."
    import winreg
    path = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    was = llmnr_enabled()
    if was == enabled:
        return True, f"LLMNR is already {'enabled' if enabled else 'disabled'}."
    journal.record(
        module="firewall",
        action=f"LLMNR {'enabled' if enabled else 'disabled'}",
        undo={"kind": "firewall.llmnr_restore", "was": was},
        before={"llmnr": was},
    )
    try:
        k = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0,
                               winreg.KEY_READ | winreg.KEY_WRITE)
        winreg.SetValueEx(k, "EnableMulticast", 0, winreg.REG_DWORD,
                          1 if enabled else 0)
        winreg.CloseKey(k)
        return True, (f"LLMNR {'enabled' if enabled else 'disabled'}. "
                      "This blocks a common credential-harvesting trick on "
                      "untrusted networks.")
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


@journal.register_undo("firewall.llmnr_restore")
def _undo_llmnr(payload: dict) -> tuple:
    import winreg
    path = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    try:
        k = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0,
                               winreg.KEY_READ | winreg.KEY_WRITE)
        winreg.SetValueEx(k, "EnableMulticast", 0, winreg.REG_DWORD,
                          1 if payload.get("was", True) else 0)
        winreg.CloseKey(k)
        return True, "LLMNR setting restored"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def cleanup_all_rules() -> tuple:
    """Remove every PrivacyKit firewall rule — the belt-and-braces cleanup."""
    names = list_our_rules()
    removed = sum(1 for n in names if _delete_rule(n))
    return True, f"Removed {removed} PrivacyKit firewall rule(s)."


def snapshot() -> dict:
    return {
        "profiles": [{"name": p.name, "state": p.state, "outbound": p.outbound}
                     for p in profiles()],
        "killswitch": killswitch_active(),
        "our_rules": list_our_rules(),
        "llmnr": llmnr_enabled(),
    }
