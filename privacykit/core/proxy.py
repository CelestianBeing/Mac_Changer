"""
Windows system proxy control (WinINET), including "route everything via Tor".

Scope, stated honestly because it is easy to get wrong: these settings are the
ones under Settings → Network & Internet → Proxy. They are respected by Edge,
Chrome, Internet Explorer, and most applications that use WinINET/WinHTTP.
They are **not** respected by Firefox (which has its own proxy settings), and
not by software that opens raw sockets. So "system proxy on" is a strong
default, not a guarantee — which is exactly why the firewall kill switch in
:mod:`privacykit.core.firewall` exists as the enforcing layer.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import List, Optional

from . import journal, shell, sysinfo

if sysinfo.IS_WINDOWS:
    import winreg
else:
    winreg = None  # type: ignore

INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

# WinINET refresh flags — without these, changes only apply to new processes.
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37

#: Hosts that should never go through the proxy, or the machine loses LAN access.
DEFAULT_BYPASS = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;" \
                 "172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;" \
                 "172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;" \
                 "192.168.*;<local>"


@dataclass
class ProxyState:
    enabled: bool = False
    server: str = ""
    bypass: str = ""
    auto_config_url: str = ""

    def describe(self) -> str:
        if not self.enabled:
            return "Direct connection (no proxy)"
        return f"Proxy: {self.server}" + (f"  (bypass: {self.bypass.split(';')[0]}…)"
                                          if self.bypass else "")


def get_state() -> ProxyState:
    """Read the current per-user WinINET proxy settings."""
    if not sysinfo.IS_WINDOWS or winreg is None:
        return ProxyState()
    st = ProxyState()
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS) as k:
            for name, attr in (("ProxyEnable", "enabled"), ("ProxyServer", "server"),
                               ("ProxyOverride", "bypass"), ("AutoConfigURL", "auto_config_url")):
                try:
                    val, _ = winreg.QueryValueEx(k, name)
                    setattr(st, attr, bool(val) if attr == "enabled" else str(val))
                except FileNotFoundError:
                    continue
    except Exception:
        pass
    return st


def _refresh_wininet() -> None:
    """Tell running applications that proxy settings changed."""
    if not sysinfo.IS_WINDOWS:
        return
    try:
        wininet = ctypes.windll.wininet  # type: ignore[attr-defined]
        wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
    except Exception:
        pass


def _write(values: dict) -> bool:
    if not sysinfo.IS_WINDOWS or winreg is None:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0,
                            winreg.KEY_READ | winreg.KEY_WRITE) as k:
            for name, val in values.items():
                if val is None:
                    try:
                        winreg.DeleteValue(k, name)
                    except FileNotFoundError:
                        pass
                elif isinstance(val, int):
                    winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, val)
                else:
                    winreg.SetValueEx(k, name, 0, winreg.REG_SZ, str(val))
        _refresh_wininet()
        return True
    except Exception:
        return False


def set_proxy(server: str, bypass: str = DEFAULT_BYPASS,
              label: str = "") -> tuple:
    """
    Enable the system proxy, journalling the previous state.

    ``server`` is ``host:port``, optionally prefixed per-protocol
    (``socks=127.0.0.1:9050``).
    """
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    prior = get_state()

    journal.record(
        module="proxy",
        action=f"System proxy → {label or server}",
        undo={"kind": "proxy.restore",
              "prior": {"enabled": prior.enabled, "server": prior.server,
                        "bypass": prior.bypass, "pac": prior.auto_config_url}},
        before={"state": prior.describe()},
    )

    ok = _write({"ProxyEnable": 1, "ProxyServer": server, "ProxyOverride": bypass})
    if ok:
        return True, f"System proxy enabled: {server}"
    return False, "Could not write proxy settings to the registry."


def disable_proxy() -> tuple:
    """Turn the system proxy off."""
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    prior = get_state()
    if prior.enabled:
        journal.record(
            module="proxy",
            action="Disabled system proxy",
            undo={"kind": "proxy.restore",
                  "prior": {"enabled": prior.enabled, "server": prior.server,
                            "bypass": prior.bypass, "pac": prior.auto_config_url}},
            before={"state": prior.describe()},
        )
    ok = _write({"ProxyEnable": 0})
    return (ok, "System proxy disabled." if ok else "Could not update proxy settings.")


def route_through_tor(socks_port: int = 9050) -> tuple:
    """
    Point the system proxy at Tor's SOCKS listener.

    Note the WinINET quirk: the plain ``ProxyServer`` value is an HTTP proxy
    field. Windows accepts ``socks=host:port`` here and honours it for
    applications that ask for SOCKS, but a few HTTP-only clients will ignore it
    and go direct. The Leak Tests tab is the way to confirm what is actually
    happening rather than assuming.
    """
    from . import socks5
    if not socks5.probe("127.0.0.1", socks_port, timeout=2.0):
        return False, (f"Nothing is listening on 127.0.0.1:{socks_port}. "
                       "Start Tor Browser (SOCKS 9150) or the Tor service (9050) first.")
    return set_proxy(f"socks={socks_port and f'127.0.0.1:{socks_port}'}",
                     DEFAULT_BYPASS, label=f"Tor SOCKS5 127.0.0.1:{socks_port}")


@journal.register_undo("proxy.restore")
def _undo_proxy(payload: dict) -> tuple:
    prior = payload.get("prior") or {}
    values = {
        "ProxyEnable": 1 if prior.get("enabled") else 0,
        "ProxyServer": prior.get("server") or "",
        "ProxyOverride": prior.get("bypass") or "",
    }
    if prior.get("pac"):
        values["AutoConfigURL"] = prior["pac"]
    ok = _write(values)
    return ok, ("restored previous proxy settings" if ok else "registry write failed")


def winhttp_state() -> str:
    """
    Read the machine-wide WinHTTP proxy (separate from the per-user WinINET one).

    Services and some background updaters use this, so a proxy set only in the
    user settings can still leave svchost traffic going direct.
    """
    res = shell.run(["netsh", "winhttp", "show", "proxy"], check_rc=False)
    return res.out.strip() or "unavailable"


def set_winhttp_from_ie() -> tuple:
    """Copy the user's proxy settings into the machine-wide WinHTTP store."""
    if not sysinfo.is_admin():
        return False, "Administrator rights are required for WinHTTP settings."
    journal.record(
        module="proxy", action="Imported user proxy into WinHTTP (machine-wide)",
        undo={"kind": "proxy.winhttp_reset"}, before={"winhttp": winhttp_state()},
    )
    res = shell.run(["netsh", "winhttp", "import", "proxy", "source=ie"], check_rc=False)
    ok = res.code == 0
    return ok, ("WinHTTP proxy imported from user settings."
                if ok else res.text[:200])


@journal.register_undo("proxy.winhttp_reset")
def _undo_winhttp(payload: dict) -> tuple:
    res = shell.run(["netsh", "winhttp", "reset", "proxy"], check_rc=False)
    return res.code == 0, "WinHTTP proxy reset to direct"


def snapshot() -> dict:
    st = get_state()
    return {"enabled": st.enabled, "server": st.server, "bypass": st.bypass,
            "pac": st.auto_config_url, "winhttp": winhttp_state()}
