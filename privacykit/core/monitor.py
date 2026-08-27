"""
Live network connection monitor — "what is my machine talking to?"

Answers a question the rest of the toolkit cannot: you may have locked down
DNS, MAC, and proxy, but if some background process holds an open connection to
a telemetry endpoint, none of that helped. This lists established connections
with the owning process, resolves the remote address, and flags known
telemetry/advertising destinations.

Implementation: ``netstat -ano`` for the connection table (fast, always present,
no dependencies), then PID→name resolution via ``tasklist``. If psutil happens
to be installed it is used instead, because it is quicker and gives the full
executable path.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import shell, sysinfo

#: Domain fragments that indicate telemetry, advertising, or tracking.
SUSPICIOUS_HOSTS = [
    "telemetry", "analytics", "metrics", "tracking", "doubleclick",
    "googlesyndication", "googleadservices", "scorecardresearch",
    "vortex.data.microsoft", "watson.telemetry", "settings-win.data.microsoft",
    "browser.events.data.msn", "self.events.data.microsoft",
    "adservice", "adnxs", "criteo", "taboola", "outbrain", "branch.io",
    "app-measurement", "crashlytics", "bugsnag", "sentry.io", "mixpanel",
    "segment.io", "amplitude", "hotjar", "fullstory", "clarity.ms",
]

#: Processes that phoning home is expected for — noted, not flagged.
EXPECTED_TALKERS = {
    "svchost.exe", "system", "lsass.exe", "services.exe",
    "backgroundtaskhost.exe", "runtimebroker.exe", "searchapp.exe",
}


@dataclass
class Connection:
    proto: str = "TCP"
    local: str = ""
    remote: str = ""
    remote_ip: str = ""
    remote_port: int = 0
    state: str = ""
    pid: int = 0
    process: str = ""
    hostname: str = ""
    suspicious: bool = False
    reason: str = ""

    def describe(self) -> str:
        target = self.hostname or self.remote_ip
        return f"{self.process or f'PID {self.pid}'} → {target}:{self.remote_port}"


def _tasklist_map() -> Dict[int, str]:
    """PID → image name, via tasklist CSV."""
    if not sysinfo.IS_WINDOWS:
        return {}
    res = shell.run(["tasklist", "/fo", "csv", "/nh"], check_rc=False, timeout=30)
    out: Dict[int, str] = {}
    import csv
    import io
    for row in csv.reader(io.StringIO(res.out)):
        if len(row) >= 2:
            try:
                out[int(row[1])] = row[0]
            except ValueError:
                continue
    return out


def _psutil_connections() -> Optional[List[Connection]]:
    try:
        import psutil  # type: ignore
    except Exception:
        return None
    conns: List[Connection] = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if not c.raddr or c.status not in ("ESTABLISHED", "SYN_SENT"):
                continue
            name = ""
            if c.pid:
                try:
                    name = psutil.Process(c.pid).name()
                except Exception:
                    name = ""
            conns.append(Connection(
                proto="TCP" if c.type == socket.SOCK_STREAM else "UDP",
                local=f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                remote=f"{c.raddr.ip}:{c.raddr.port}",
                remote_ip=c.raddr.ip, remote_port=c.raddr.port,
                state=c.status, pid=c.pid or 0, process=name,
            ))
    except Exception:
        return None
    return conns


def _netstat_connections() -> List[Connection]:
    if not sysinfo.IS_WINDOWS:
        return []
    res = shell.run(["netstat", "-ano", "-p", "TCP"], check_rc=False, timeout=40)
    conns: List[Connection] = []
    pattern = re.compile(
        r"^\s*(TCP|UDP)\s+(\S+)\s+(\S+)\s+(\w+)?\s*(\d+)\s*$", re.MULTILINE)
    for m in pattern.finditer(res.out):
        proto, local, remote, state, pid = m.groups()
        if state and state.upper() not in ("ESTABLISHED", "SYN_SENT", "CLOSE_WAIT"):
            continue
        ip, port = _split_addr(remote)
        if not ip or ip in ("0.0.0.0", "*", "::", "127.0.0.1", "[::1]"):
            continue
        conns.append(Connection(proto=proto, local=local, remote=remote,
                                remote_ip=ip, remote_port=port,
                                state=state or "", pid=int(pid)))
    return conns


def _split_addr(addr: str) -> tuple:
    """Split ``host:port``, handling bracketed IPv6."""
    if addr.startswith("["):
        host, _, port = addr.rpartition("]:")
        return host.lstrip("["), int(port) if port.isdigit() else 0
    host, _, port = addr.rpartition(":")
    return host, int(port) if port.isdigit() else 0


def list_connections(resolve_names: bool = True,
                     limit: int = 200) -> List[Connection]:
    """
    Current outbound connections, annotated.

    ``resolve_names`` does reverse DNS, which is what makes the list readable —
    but it is also slow and each lookup is itself a DNS query, so the caller can
    turn it off.
    """
    conns = _psutil_connections()
    if conns is None:
        conns = _netstat_connections()
        pids = _tasklist_map()
        for c in conns:
            c.process = pids.get(c.pid, "")

    conns = [c for c in conns if not _is_local(c.remote_ip)][:limit]

    if resolve_names:
        cache: Dict[str, str] = {}
        for c in conns:
            if c.remote_ip in cache:
                c.hostname = cache[c.remote_ip]
                continue
            try:
                socket.setdefaulttimeout(1.0)
                c.hostname = socket.gethostbyaddr(c.remote_ip)[0]
            except Exception:
                c.hostname = ""
            cache[c.remote_ip] = c.hostname

    for c in conns:
        _flag(c)
    conns.sort(key=lambda c: (not c.suspicious, c.process.lower(), c.remote_ip))
    return conns


def _is_local(ip: str) -> bool:
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
    except Exception:
        return True


def _flag(c: Connection) -> None:
    blob = f"{c.hostname} {c.process}".lower()
    for frag in SUSPICIOUS_HOSTS:
        if frag in blob:
            c.suspicious = True
            c.reason = f"matches known telemetry/tracking pattern '{frag}'"
            return
    if c.remote_port in (80,) and c.process.lower() not in EXPECTED_TALKERS:
        c.suspicious = False
        c.reason = "plaintext HTTP — contents visible to the network"


def summarise(conns: List[Connection]) -> dict:
    by_process: Dict[str, int] = {}
    for c in conns:
        key = c.process or f"PID {c.pid}"
        by_process[key] = by_process.get(key, 0) + 1
    return {
        "total": len(conns),
        "suspicious": sum(1 for c in conns if c.suspicious),
        "plaintext_http": sum(1 for c in conns if c.remote_port == 80),
        "unique_processes": len(by_process),
        "top_processes": sorted(by_process.items(), key=lambda kv: -kv[1])[:8],
    }


def listening_ports() -> List[dict]:
    """
    Ports this machine is listening on — its attack surface.

    Every open listener is something a hostile network can reach. On a café
    Wi-Fi, file sharing on 445 or RDP on 3389 being open is worth knowing about.
    """
    if not sysinfo.IS_WINDOWS:
        return []
    res = shell.run(["netstat", "-ano", "-p", "TCP"], check_rc=False, timeout=40)
    pids = _tasklist_map()
    out, seen = [], set()
    for line in res.out.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] != "TCP" or "LISTENING" not in line:
            continue
        local = parts[1]
        pid = int(parts[-1]) if parts[-1].isdigit() else 0
        _, port = _split_addr(local)
        if port in seen:
            continue
        seen.add(port)
        out.append({
            "port": port, "address": local, "pid": pid,
            "process": pids.get(pid, ""),
            "risk": _port_risk(port),
        })
    return sorted(out, key=lambda d: d["port"])


_RISKY_PORTS = {
    135: ("RPC endpoint mapper", "high"),
    139: ("NetBIOS session", "high"),
    445: ("SMB file sharing", "high"),
    3389: ("Remote Desktop", "high"),
    5357: ("WSDAPI web services", "medium"),
    1900: ("UPnP/SSDP discovery", "medium"),
    5353: ("mDNS/Bonjour", "medium"),
    5040: ("Windows connected devices", "low"),
}


def _port_risk(port: int) -> str:
    info = _RISKY_PORTS.get(port)
    if info:
        return f"{info[0]} ({info[1]} exposure on untrusted networks)"
    if port < 1024:
        return "well-known service port"
    return ""
