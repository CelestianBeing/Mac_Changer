"""
Tor control-protocol client (control-spec compliant, no dependencies).

This talks directly to Tor's control port over TCP, implementing the parts of
the protocol PrivacyKit needs:

  * ``PROTOCOLINFO``  — discover which authentication methods are on offer
  * ``AUTHENTICATE``  — NULL, HASHEDPASSWORD, COOKIE
  * ``AUTHCHALLENGE`` — SAFECOOKIE (HMAC challenge/response), which is the
    default on modern Tor and the reason a hand-rolled client usually fails
  * ``SIGNAL NEWNYM`` — request a fresh circuit ("new identity")
  * ``GETINFO``       — bootstrap phase, version, circuit status, exit IP
  * ``SETCONF``       — pin exit-node country at runtime

Port conventions
----------------
    Tor Browser        SOCKS 9150, control 9151
    Tor Expert Bundle  SOCKS 9050, control 9051

Both are probed automatically, Tor Browser first since it is what most people
actually have running.

A caveat the UI states honestly: NEWNYM asks Tor to use fresh circuits for
*new* connections. Existing connections keep their circuit, and Tor rate-limits
NEWNYM internally, so hammering the button does not give you an endless supply
of exit IPs.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import socket
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from . import netclient, shell, socks5, sysinfo

# (socks_port, control_port, label)
KNOWN_ENDPOINTS = [
    (9150, 9151, "Tor Browser"),
    (9050, 9051, "Tor service / Expert Bundle"),
]

SAFECOOKIE_SERVER_CONST = b"Tor safe cookie authentication server-to-controller hash"
SAFECOOKIE_CLIENT_CONST = b"Tor safe cookie authentication controller-to-server hash"

#: Two-letter country codes offered in the exit-node picker.
EXIT_COUNTRIES = {
    "": "Any country (default)",
    "de": "Germany", "nl": "Netherlands", "se": "Sweden", "ch": "Switzerland",
    "fr": "France", "gb": "United Kingdom", "us": "United States",
    "ca": "Canada", "no": "Norway", "fi": "Finland", "at": "Austria",
    "is": "Iceland", "ro": "Romania", "cz": "Czechia", "es": "Spain",
    "it": "Italy", "pl": "Poland", "jp": "Japan", "sg": "Singapore",
    "au": "Australia", "lu": "Luxembourg", "dk": "Denmark", "ie": "Ireland",
}


class TorError(Exception):
    """Any failure talking to the Tor control port."""


@dataclass
class TorStatus:
    running: bool = False
    socks_port: int = 0
    control_port: int = 0
    label: str = ""
    controllable: bool = False
    version: str = ""
    bootstrap: str = ""
    exit_ip: str = ""
    exit_country: str = ""
    circuits: List[str] = field(default_factory=list)
    error: str = ""

    def summary(self) -> str:
        if not self.running:
            return "Tor not detected"
        base = f"{self.label} on SOCKS {self.socks_port}"
        if self.controllable:
            return f"{base} — control port open"
        return f"{base} — control port unavailable"


# ──────────────────────────────────────────────────────────────────────────────
# Discovery
# ──────────────────────────────────────────────────────────────────────────────

def detect() -> TorStatus:
    """Find a running Tor by probing the well-known port pairs."""
    for socks_port, ctrl_port, label in KNOWN_ENDPOINTS:
        if socks5.probe("127.0.0.1", socks_port, timeout=1.5):
            st = TorStatus(running=True, socks_port=socks_port,
                           control_port=ctrl_port, label=label)
            st.controllable = netclient.tcp_reachable("127.0.0.1", ctrl_port, timeout=1.5)
            return st
    # SOCKS closed but control open: Tor is starting or misconfigured.
    for socks_port, ctrl_port, label in KNOWN_ENDPOINTS:
        if netclient.tcp_reachable("127.0.0.1", ctrl_port, timeout=1.0):
            return TorStatus(running=False, socks_port=socks_port,
                             control_port=ctrl_port, label=label, controllable=True,
                             error="Control port is open but SOCKS is not accepting "
                                   "connections yet — Tor may still be bootstrapping.")
    return TorStatus(running=False, error="No Tor SOCKS or control port found on localhost.")


def is_running() -> bool:
    return any(socks5.probe("127.0.0.1", p, 1.0) for p, _, _ in KNOWN_ENDPOINTS)


# ──────────────────────────────────────────────────────────────────────────────
# Control connection
# ──────────────────────────────────────────────────────────────────────────────

class TorController:
    """
    A single authenticated control-port session.

    Use as a context manager::

        with TorController(9151) as c:
            c.new_identity()
    """

    def __init__(self, port: int = 9051, host: str = "127.0.0.1",
                 password: Optional[str] = None, timeout: float = 12.0):
        self.host, self.port = host, port
        self.password = password
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self._file = None
        self.authenticated = False

    # ── lifecycle ──
    def __enter__(self) -> "TorController":
        self.connect()
        self.authenticate()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def connect(self) -> None:
        try:
            self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            self.sock.settimeout(self.timeout)
            self._file = self.sock.makefile("rwb")
        except Exception as exc:
            raise TorError(
                f"Cannot reach the Tor control port on {self.host}:{self.port} ({exc}). "
                "If you are using Tor Browser it must be running; for a standalone "
                "Tor, add 'ControlPort 9051' to your torrc."
            ) from exc

    def close(self) -> None:
        for obj in (self._file, self.sock):
            try:
                if obj:
                    obj.close()
            except Exception:
                pass
        self._file, self.sock = None, None
        self.authenticated = False

    # ── raw protocol ──
    def _send(self, line: str) -> None:
        if not self._file:
            raise TorError("not connected")
        self._file.write((line + "\r\n").encode("utf-8"))
        self._file.flush()

    def _read_reply(self) -> Tuple[int, List[str]]:
        """
        Read one control-protocol reply.

        Replies are a series of lines; a '-' or '+' after the status code means
        more lines follow, a space means this is the last one. '+' introduces a
        multi-line data block terminated by a lone '.'.
        """
        if not self._file:
            raise TorError("not connected")
        lines: List[str] = []
        status = 0
        while True:
            raw = self._file.readline()
            if not raw:
                raise TorError("Tor closed the control connection unexpectedly")
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if len(line) < 4:
                lines.append(line)
                continue
            status = int(line[:3]) if line[:3].isdigit() else status
            sep, body = line[3], line[4:]
            if sep == "+":
                lines.append(body)
                while True:
                    data = self._file.readline().decode("utf-8", errors="replace").rstrip("\r\n")
                    if data == ".":
                        break
                    lines.append(data)
            elif sep == "-":
                lines.append(body)
            else:                      # ' ' — final line of the reply
                lines.append(body)
                break
        return status, lines

    def command(self, cmd: str) -> Tuple[int, List[str]]:
        self._send(cmd)
        return self._read_reply()

    # ── authentication ──
    def protocol_info(self) -> dict:
        """Ask Tor which auth methods it accepts, before authenticating."""
        status, lines = self.command("PROTOCOLINFO 1")
        if status != 250:
            raise TorError(f"PROTOCOLINFO refused (status {status})")
        info = {"methods": [], "cookie_file": None, "version": ""}
        for line in lines:
            if line.startswith("AUTH "):
                m = re.search(r"METHODS=([A-Z,]+)", line)
                if m:
                    info["methods"] = m.group(1).split(",")
                cf = re.search(r'COOKIEFILE="((?:[^"\\]|\\.)*)"', line)
                if cf:
                    info["cookie_file"] = cf.group(1).replace("\\\\", "\\").replace('\\"', '"')
            elif line.startswith("VERSION "):
                v = re.search(r'Tor="([^"]+)"', line)
                if v:
                    info["version"] = v.group(1)
        return info

    def authenticate(self) -> None:
        """Authenticate using the strongest method Tor offers."""
        info = self.protocol_info()
        methods = info["methods"]

        if self.password and "HASHEDPASSWORD" in methods:
            self._auth_or_raise(f'AUTHENTICATE "{self._escape(self.password)}"',
                                "password")
            return
        if "SAFECOOKIE" in methods and info["cookie_file"]:
            self._auth_safecookie(info["cookie_file"])
            return
        if "COOKIE" in methods and info["cookie_file"]:
            cookie = self._read_cookie(info["cookie_file"])
            self._auth_or_raise(f"AUTHENTICATE {binascii.hexlify(cookie).decode()}",
                                "cookie")
            return
        if "NULL" in methods:
            self._auth_or_raise("AUTHENTICATE", "null")
            return
        if self.password:
            self._auth_or_raise(f'AUTHENTICATE "{self._escape(self.password)}"',
                                "password")
            return
        raise TorError(
            "Tor requires authentication but no usable method is available. "
            f"Offered: {', '.join(methods) or 'none'}. Either enable "
            "CookieAuthentication in torrc, or set a control password and enter "
            "it in the Tor tab."
        )

    def _auth_or_raise(self, cmd: str, label: str) -> None:
        status, lines = self.command(cmd)
        if status != 250:
            raise TorError(f"{label} authentication rejected by Tor: {' '.join(lines)[:160]}")
        self.authenticated = True

    def _auth_safecookie(self, cookie_path: str) -> None:
        """
        SAFECOOKIE handshake.

        Proves we can read the cookie file without ever putting its contents on
        the wire, and simultaneously proves to us that we are talking to the
        real Tor (we verify the server's hash too, which is the whole point of
        SAFECOOKIE over plain COOKIE).
        """
        cookie = self._read_cookie(cookie_path)
        client_nonce = os.urandom(32)
        status, lines = self.command(
            "AUTHCHALLENGE SAFECOOKIE " + binascii.hexlify(client_nonce).decode()
        )
        if status != 250:
            raise TorError(f"AUTHCHALLENGE refused: {' '.join(lines)[:160]}")

        blob = " ".join(lines)
        sh = re.search(r"SERVERHASH=([0-9A-Fa-f]+)", blob)
        sn = re.search(r"SERVERNONCE=([0-9A-Fa-f]+)", blob)
        if not sh or not sn:
            raise TorError("Malformed AUTHCHALLENGE reply from Tor")
        server_hash = binascii.unhexlify(sh.group(1))
        server_nonce = binascii.unhexlify(sn.group(1))

        message = cookie + client_nonce + server_nonce
        expected = hmac.new(SAFECOOKIE_SERVER_CONST, message, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, server_hash):
            raise TorError(
                "SAFECOOKIE server hash mismatch — the process on the control "
                "port could not prove it holds the cookie. Refusing to "
                "authenticate."
            )

        client_hash = hmac.new(SAFECOOKIE_CLIENT_CONST, message, hashlib.sha256).digest()
        self._auth_or_raise("AUTHENTICATE " + binascii.hexlify(client_hash).decode(),
                            "safecookie")

    @staticmethod
    def _read_cookie(path: str) -> bytes:
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except PermissionError as exc:
            raise TorError(
                f"Cannot read Tor's cookie file ({path}). Run PrivacyKit as the "
                "same user that runs Tor, or as Administrator."
            ) from exc
        except FileNotFoundError as exc:
            raise TorError(f"Tor's cookie file is missing: {path}") from exc
        if len(data) != 32:
            raise TorError(f"Cookie file has unexpected length {len(data)} (expected 32)")
        return data

    @staticmethod
    def _escape(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

    # ── operations ──
    def new_identity(self) -> Tuple[bool, str]:
        status, lines = self.command("SIGNAL NEWNYM")
        if status == 250:
            return True, "New Tor identity requested — fresh circuits for new connections."
        return False, f"NEWNYM refused: {' '.join(lines)[:160]}"

    def getinfo(self, key: str) -> str:
        status, lines = self.command(f"GETINFO {key}")
        if status != 250:
            return ""
        out = []
        for line in lines:
            if line.startswith(key + "="):
                out.append(line[len(key) + 1:])
            elif line not in ("OK",):
                out.append(line)
        return "\n".join(out).strip()

    def version(self) -> str:
        return self.getinfo("version")

    def bootstrap_phase(self) -> str:
        raw = self.getinfo("status/bootstrap-phase")
        m = re.search(r'SUMMARY="([^"]+)"', raw)
        pct = re.search(r"PROGRESS=(\d+)", raw)
        if m and pct:
            return f"{pct.group(1)}% — {m.group(1)}"
        return raw or "unknown"

    def circuits(self) -> List[str]:
        """Human-readable list of built circuits."""
        raw = self.getinfo("circuit-status")
        out = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            cid, state, path = parts[0], parts[1], parts[2]
            if state != "BUILT":
                continue
            hops = [h.split("~")[-1] for h in path.split(",")]
            out.append(f"#{cid}  {'  →  '.join(hops)}")
        return out

    def set_exit_country(self, code: str) -> Tuple[bool, str]:
        """
        Pin (or unpin) the exit-node country at runtime.

        StrictNodes=1 is deliberately *not* set: with it, if no exit exists in
        the chosen country Tor simply stops working. Without it, Tor prefers the
        country and falls back rather than failing closed — which is the right
        default for a general-purpose tool.
        """
        code = (code or "").strip().lower()
        if code and code not in EXIT_COUNTRIES:
            return False, f"Unknown country code '{code}'."
        if not code:
            status, lines = self.command("RESETCONF ExitNodes StrictNodes")
            ok = status == 250
            return ok, "Exit-node country restriction removed." if ok else " ".join(lines)[:160]
        status, lines = self.command(f"SETCONF ExitNodes={{{code}}} StrictNodes=0")
        if status == 250:
            return True, (f"Exit nodes preferred in {EXIT_COUNTRIES[code]}. "
                          "Request a new identity for it to take effect.")
        return False, f"SETCONF refused: {' '.join(lines)[:160]}"

    def get_exit_country(self) -> str:
        raw = self.getinfo("config/defaults")  # cheap no-op if unsupported
        status, lines = self.command("GETCONF ExitNodes")
        for line in lines:
            if line.startswith("ExitNodes="):
                return line.split("=", 1)[1].strip("{}")
        return ""


# ──────────────────────────────────────────────────────────────────────────────
# High-level helpers used by the UI
# ──────────────────────────────────────────────────────────────────────────────

def full_status(password: Optional[str] = None, fetch_exit_ip: bool = True) -> TorStatus:
    """Everything the Tor tab needs, in one call."""
    st = detect()
    if not st.running and not st.controllable:
        return st
    if st.controllable:
        try:
            with TorController(st.control_port, password=password) as c:
                st.version = c.version()
                st.bootstrap = c.bootstrap_phase()
                st.circuits = c.circuits()[:8]
                st.exit_country = c.get_exit_country()
        except TorError as exc:
            st.error = str(exc)
            st.controllable = False
    if fetch_exit_ip and st.running:
        ip, country = exit_ip(st.socks_port)
        st.exit_ip, st.exit_country = ip, country or st.exit_country
    return st


def exit_ip(socks_port: int = 9050) -> Tuple[str, str]:
    """
    Ask an external service what IP it sees, *through* Tor.

    This is the only trustworthy confirmation that traffic is really leaving via
    Tor — the control port can claim a circuit exists while the application
    still talks direct.
    """
    for url, ip_key, cc_key in (
        ("https://ipinfo.io/json", "ip", "country"),
        ("https://api.ipify.org?format=json", "ip", None),
    ):
        r = netclient.get(url, via_tor=True, proxy_port=socks_port, timeout=25)
        data = r.json() if r.ok else None
        if data and data.get(ip_key):
            return str(data[ip_key]), str(data.get(cc_key) or "") if cc_key else ""
    return "", ""


def new_identity(password: Optional[str] = None) -> Tuple[bool, str]:
    """Request NEWNYM, then report the resulting exit IP if it changed."""
    st = detect()
    if not st.controllable:
        return False, (
            "Tor's control port is not reachable. Tor Browser exposes it on "
            "9151; a standalone Tor needs 'ControlPort 9051' plus either "
            "'CookieAuthentication 1' or a HashedControlPassword in torrc."
        )
    before, _ = exit_ip(st.socks_port) if st.running else ("", "")
    try:
        with TorController(st.control_port, password=password) as c:
            ok, msg = c.new_identity()
    except TorError as exc:
        return False, str(exc)
    if not ok:
        return False, msg

    # Tor needs a moment to build the replacement circuit.
    time.sleep(4.0)
    after, country = exit_ip(st.socks_port) if st.running else ("", "")
    if before and after and before != after:
        return True, f"New identity: exit IP {before} → {after}" + (f" ({country})" if country else "")
    if after:
        return True, (f"NEWNYM accepted. Exit IP still {after} — Tor rate-limits "
                      "identity changes and may reuse an exit; try again shortly.")
    return True, msg


def find_tor_executable() -> Optional[str]:
    """Locate a tor.exe we could start, for the 'Tor not running' case."""
    from pathlib import Path
    candidates = [
        r"%LOCALAPPDATA%\Programs\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
        r"%PROGRAMFILES%\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
        r"%PROGRAMFILES(X86)%\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
        r"%USERPROFILE%\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
        r"%PROGRAMFILES%\Tor\tor.exe",
        r"C:\tor\tor.exe",
    ]
    for c in candidates:
        p = Path(shell.expand(c))
        if p.exists():
            return str(p)
    if shell.which("tor"):
        return "tor"
    return None


def torrc_hint() -> str:
    """Configuration snippet shown when the control port is unavailable."""
    return (
        "# Add to your torrc, then restart Tor:\n"
        "ControlPort 9051\n"
        "CookieAuthentication 1\n"
        "\n"
        "# Tor Browser already listens on 9151 — just make sure it is running.\n"
        "# torrc locations:\n"
        r"#   Tor Browser: <install>\Browser\TorBrowser\Data\Tor\torrc" "\n"
        r"#   Expert bundle: <install>\Data\Tor\torrc"
    )


def snapshot() -> dict:
    st = detect()
    return {"running": st.running, "socks_port": st.socks_port,
            "control_port": st.control_port, "label": st.label}
