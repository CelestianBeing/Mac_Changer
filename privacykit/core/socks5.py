"""
A minimal, dependency-free SOCKS5 client (RFC 1928).

PrivacyKit needs to make HTTP requests *through Tor* to prove that traffic is
actually leaving via the Tor exit node. Rather than requiring PySocks, this
module implements just enough of SOCKS5 to open a TCP tunnel, which is then
handed to :mod:`http.client` as a pre-connected socket.

Only what we need is implemented: CONNECT, with no-auth and username/password
authentication. BIND and UDP ASSOCIATE are out of scope.
"""

from __future__ import annotations

import socket
import struct

SOCKS_VERSION = 0x05

# Address types
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

# Auth methods
AUTH_NONE = 0x00
AUTH_USERPASS = 0x02
AUTH_NO_ACCEPTABLE = 0xFF

_REPLY_ERRORS = {
    0x00: "succeeded",
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
}


class Socks5Error(Exception):
    """Raised when the SOCKS handshake or CONNECT request fails."""


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes or raise — short reads are a protocol error here."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise Socks5Error("proxy closed the connection during handshake")
        buf += chunk
    return buf


def create_connection(dest_host: str, dest_port: int,
                      proxy_host: str = "127.0.0.1", proxy_port: int = 9050,
                      username: str | None = None, password: str | None = None,
                      timeout: float = 20.0) -> socket.socket:
    """
    Open a TCP connection to ``dest_host:dest_port`` through a SOCKS5 proxy.

    The hostname is sent to the proxy *as a domain name* rather than resolved
    locally. This is essential: resolving locally would leak the destination to
    your ISP's DNS server, defeating the point of tunnelling through Tor.
    """
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        sock.settimeout(timeout)

        # ── greeting: offer the methods we support ──
        methods = [AUTH_NONE]
        if username is not None:
            methods.append(AUTH_USERPASS)
        sock.sendall(bytes([SOCKS_VERSION, len(methods)]) + bytes(methods))

        ver, method = _recv_exactly(sock, 2)
        if ver != SOCKS_VERSION:
            raise Socks5Error(f"proxy replied with SOCKS version {ver}, expected 5")
        if method == AUTH_NO_ACCEPTABLE:
            raise Socks5Error("proxy rejected all offered authentication methods")

        # ── optional username/password sub-negotiation (RFC 1929) ──
        if method == AUTH_USERPASS:
            if username is None:
                raise Socks5Error("proxy demands username/password but none supplied")
            u = username.encode("utf-8")
            p = (password or "").encode("utf-8")
            if len(u) > 255 or len(p) > 255:
                raise Socks5Error("SOCKS5 username/password limited to 255 bytes")
            sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            _, status = _recv_exactly(sock, 2)
            if status != 0x00:
                raise Socks5Error("proxy rejected the supplied credentials")
        elif method != AUTH_NONE:
            raise Socks5Error(f"proxy chose unsupported auth method 0x{method:02x}")

        # ── CONNECT request ──
        host_bytes = dest_host.encode("idna") if _is_hostname(dest_host) else dest_host.encode()
        if _is_hostname(dest_host):
            if len(host_bytes) > 255:
                raise Socks5Error("hostname too long for SOCKS5")
            addr = bytes([ATYP_DOMAIN, len(host_bytes)]) + host_bytes
        elif ":" in dest_host:
            addr = bytes([ATYP_IPV6]) + socket.inet_pton(socket.AF_INET6, dest_host)
        else:
            addr = bytes([ATYP_IPV4]) + socket.inet_aton(dest_host)

        sock.sendall(bytes([SOCKS_VERSION, 0x01, 0x00]) + addr + struct.pack(">H", dest_port))

        ver, rep, _rsv, atyp = _recv_exactly(sock, 4)
        if ver != SOCKS_VERSION:
            raise Socks5Error("malformed SOCKS reply")
        if rep != 0x00:
            raise Socks5Error(_REPLY_ERRORS.get(rep, f"SOCKS error 0x{rep:02x}"))

        # Drain the bound-address field so the socket is left at the start of
        # the tunnelled stream.
        if atyp == ATYP_IPV4:
            _recv_exactly(sock, 4)
        elif atyp == ATYP_IPV6:
            _recv_exactly(sock, 16)
        elif atyp == ATYP_DOMAIN:
            ln = _recv_exactly(sock, 1)[0]
            _recv_exactly(sock, ln)
        else:
            raise Socks5Error(f"unknown address type in reply: 0x{atyp:02x}")
        _recv_exactly(sock, 2)  # bound port

        return sock
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        raise


def _is_hostname(value: str) -> bool:
    """True if ``value`` is a name rather than a literal IP address."""
    try:
        socket.inet_aton(value)
        return False
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, value)
        return False
    except (OSError, AttributeError, ValueError):
        pass
    return True


def probe(proxy_host: str = "127.0.0.1", proxy_port: int = 9050,
          timeout: float = 3.0) -> bool:
    """Cheap check: is something speaking SOCKS5 on this port?"""
    try:
        with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(bytes([SOCKS_VERSION, 1, AUTH_NONE]))
            reply = s.recv(2)
            return len(reply) == 2 and reply[0] == SOCKS_VERSION
    except Exception:
        return False
