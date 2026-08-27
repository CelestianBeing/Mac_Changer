"""
HTTP client used by the leak-test and IP-lookup features.

Two paths, one interface:

  * ``get()``          — a normal direct request (via urllib),
  * ``get(via_tor=…)`` — the same request tunnelled through a SOCKS5 proxy
    using :mod:`privacykit.core.socks5`, so we can compare what the internet
    sees with and without Tor.

Both deliberately send a neutral browser-ish User-Agent. Sending
``Python-urllib/3.11`` would make every request from this tool trivially
fingerprintable, which is the opposite of the point.
"""

from __future__ import annotations

import http.client
import json
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

from . import socks5

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

DEFAULT_TIMEOUT = 12.0


@dataclass
class Response:
    ok: bool
    status: int = 0
    body: str = ""
    error: str = ""
    elapsed_ms: int = 0

    def json(self):
        try:
            return json.loads(self.body)
        except Exception:
            return None


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def get(url: str, timeout: float = DEFAULT_TIMEOUT, via_tor: bool = False,
        proxy_host: str = "127.0.0.1", proxy_port: int = 9050,
        headers: Optional[dict] = None) -> Response:
    """GET ``url``, optionally through a SOCKS5 proxy. Never raises."""
    import time
    started = time.time()
    hdrs = {"User-Agent": DEFAULT_UA, "Accept": "*/*", "Connection": "close"}
    if headers:
        hdrs.update(headers)

    try:
        if via_tor:
            resp = _get_via_socks(url, timeout, proxy_host, proxy_port, hdrs)
        else:
            resp = _get_direct(url, timeout, hdrs)
        resp.elapsed_ms = int((time.time() - started) * 1000)
        return resp
    except Exception as exc:
        return Response(False, 0, "", f"{type(exc).__name__}: {exc}",
                        int((time.time() - started) * 1000))


def _get_direct(url: str, timeout: float, hdrs: dict) -> Response:
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as r:
            body = r.read(1_000_000).decode("utf-8", errors="replace")
            return Response(200 <= r.status < 400, r.status, body)
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(200_000).decode("utf-8", errors="replace")
        except Exception:
            pass
        return Response(False, e.code, body, f"HTTP {e.code}")
    except urllib.error.URLError as e:
        return Response(False, 0, "", f"network error: {e.reason}")


def _get_via_socks(url: str, timeout: float, proxy_host: str, proxy_port: int,
                   hdrs: dict) -> Response:
    """
    Tunnel an HTTP(S) GET through SOCKS5.

    We open the SOCKS tunnel ourselves, wrap it in TLS for https URLs, and then
    hand the live socket to http.client so we don't have to re-implement HTTP.
    """
    from urllib.parse import urlparse
    parts = urlparse(url)
    if parts.scheme not in ("http", "https"):
        return Response(False, 0, "", f"unsupported scheme: {parts.scheme}")
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    raw = socks5.create_connection(host, port, proxy_host, proxy_port, timeout=timeout)
    try:
        if parts.scheme == "https":
            sock = _ssl_context().wrap_socket(raw, server_hostname=host)
        else:
            sock = raw

        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.sock = sock  # inject the already-connected (and possibly TLS) socket
        conn.request("GET", path, headers=hdrs)
        r = conn.getresponse()
        body = r.read(1_000_000).decode("utf-8", errors="replace")
        conn.close()
        return Response(200 <= r.status < 400, r.status, body)
    finally:
        try:
            raw.close()
        except Exception:
            pass


def tcp_reachable(host: str, port: int, timeout: float = 2.0) -> bool:
    """Is a TCP port accepting connections? Used for Tor/proxy detection."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def resolve(hostname: str) -> list:
    """Resolve a hostname to a list of addresses (used by the DNS leak test)."""
    out = []
    try:
        for fam, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            addr = sockaddr[0]
            if addr not in out:
                out.append(addr)
    except Exception:
        pass
    return out
