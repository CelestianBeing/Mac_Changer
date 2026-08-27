"""
Auto-updating blocklist.

The static ~90-domain list shipped in v2 was hand-curated and immediately
out of date. This replaces it with feeds maintained by people who do that work
full time, merged, deduplicated, and filtered.

Safety rules the merge enforces, because a bad blocklist is worse than none:

* **Never block an allowlisted domain.** Windows Update, activation, certificate
  revocation, and time sync stay reachable no matter what a feed says. A machine
  that silently stops receiving security updates because a blocklist grew a bad
  entry is a serious outcome, and it is very hard to trace back months later.
* **Reject implausible entries** — wildcards, IP literals, and single-label
  names that would blackhole an entire TLD.
* **Cap the total size.** A hosts file with a million entries measurably slows
  name resolution on Windows.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

from . import netclient, sysinfo

#: Public feeds, all in hosts or plain-domain format.
FEEDS = {
    "stevenblack": {
        "name": "StevenBlack unified hosts",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "description": "Widely used merge of ad, malware, and tracking lists.",
        "default": True,
    },
    "adguard_tracking": {
        "name": "AdGuard tracking protection",
        "url": "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/"
               "master/data/combined_disguised_trackers_justdomains.txt",
        "description": "CNAME-disguised trackers that ordinary lists miss.",
        "default": True,
    },
    "notracking": {
        "name": "Peter Lowe's tracking list",
        "url": "https://pgl.yoyo.org/adservers/serverlist.php?"
               "hostformat=nohtml&showintro=0&mimetype=plaintext",
        "description": "Long-maintained advertising and tracking server list.",
        "default": True,
    },
    "urlhaus": {
        "name": "URLhaus malware domains",
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "description": "Active malware distribution hosts from abuse.ch.",
        "default": False,
    },
}

#: Never blocked, whatever a feed says. Blocking any of these breaks Windows in
#: ways that are hard to diagnose long after the fact.
CRITICAL_ALLOWLIST = {
    # Updates, activation, licensing
    "windowsupdate.com", "windowsupdate.microsoft.com", "update.microsoft.com",
    "download.windowsupdate.com", "dl.delivery.mp.microsoft.com",
    "activation.sls.microsoft.com", "activation-v2.sls.microsoft.com",
    "licensing.mp.microsoft.com", "displaycatalog.mp.microsoft.com",
    "purchase.mp.microsoft.com", "go.microsoft.com",
    # Certificate revocation and trust
    "ocsp.digicert.com", "crl.microsoft.com", "ctldl.windowsupdate.com",
    "ocsp.msocsp.com", "www.microsoft.com", "microsoft.com",
    "ocsp.sectigo.com", "crl.sectigo.com", "ocsp.pki.goog", "r3.o.lencr.org",
    # Time
    "time.windows.com", "time.nist.gov", "pool.ntp.org",
    # Connectivity checks — breaking these makes Windows report "no internet"
    "msftconnecttest.com", "www.msftconnecttest.com", "msftncsi.com",
    "dns.msftncsi.com", "captive.apple.com", "connectivitycheck.gstatic.com",
    # Store and Defender
    "storeedgefd.dwmwd.microsoft.com", "wdcp.microsoft.com",
    "wdcpalt.microsoft.com", "definitionupdates.microsoft.com",
}

MAX_ENTRIES = 250_000
_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?"
                      r"(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$")


@dataclass
class FeedResult:
    key: str
    name: str
    ok: bool
    domains: int = 0
    error: str = ""
    bytes_fetched: int = 0


@dataclass
class UpdateReport:
    feeds: List[FeedResult] = field(default_factory=list)
    total_unique: int = 0
    allowlisted_skipped: int = 0
    malformed_skipped: int = 0
    truncated: bool = False
    elapsed: float = 0.0
    domains: List[str] = field(default_factory=list)

    def summary(self) -> str:
        ok = sum(1 for f in self.feeds if f.ok)
        return (f"{self.total_unique:,} unique domains from {ok}/{len(self.feeds)} "
                f"feed(s) in {self.elapsed:.1f}s")


def cache_path() -> Path:
    return sysinfo.appdata_dir() / "blocklist.txt"


def cache_meta_path() -> Path:
    return sysinfo.appdata_dir() / "blocklist.meta"


def cached_count() -> int:
    p = cache_path()
    if not p.exists():
        return 0
    try:
        with open(p, "r", encoding="utf-8") as fh:
            return sum(1 for line in fh if line.strip() and not line.startswith("#"))
    except Exception:
        return 0


def cache_age() -> Optional[float]:
    """Days since the cached list was written, or None if there is no cache."""
    p = cache_path()
    if not p.exists():
        return None
    return (time.time() - p.stat().st_mtime) / 86400.0


def _is_allowlisted(domain: str) -> bool:
    if domain in CRITICAL_ALLOWLIST:
        return True
    # Also protect subdomains of allowlisted names.
    return any(domain.endswith("." + allowed) for allowed in CRITICAL_ALLOWLIST)


def _parse_feed(text: str) -> Tuple[Set[str], int, int]:
    """
    Extract domains from hosts-format or plain-domain text.

    Returns ``(domains, allowlisted_skipped, malformed_skipped)``.
    """
    domains: Set[str] = set()
    allowlisted = malformed = 0

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        line = line.split("#", 1)[0].strip()
        if not line:
            continue

        parts = line.split()
        # hosts format: "0.0.0.0 example.com" — take the second field.
        candidate = parts[1] if len(parts) >= 2 and _looks_like_ip(parts[0]) else parts[0]
        candidate = candidate.strip().lower().rstrip(".")

        if not candidate or candidate in ("localhost", "localhost.localdomain",
                                          "broadcasthost", "local"):
            continue
        if "*" in candidate or "/" in candidate or _looks_like_ip(candidate):
            malformed += 1
            continue
        if "." not in candidate:
            # A single-label entry would blackhole an entire TLD.
            malformed += 1
            continue
        if not _HOST_RE.match(candidate) or len(candidate) > 253:
            malformed += 1
            continue
        if _is_allowlisted(candidate):
            allowlisted += 1
            continue
        domains.add(candidate)

    return domains, allowlisted, malformed


def _looks_like_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def update(selected: Optional[List[str]] = None,
           progress: Optional[Callable[[str], None]] = None,
           via_tor: bool = False, tor_port: int = 9050) -> UpdateReport:
    """Fetch, merge, and cache the selected feeds."""
    started = time.time()
    keys = selected or [k for k, v in FEEDS.items() if v["default"]]
    report = UpdateReport()
    merged: Set[str] = set()

    for key in keys:
        feed = FEEDS.get(key)
        if not feed:
            continue
        if progress:
            progress(f"Fetching {feed['name']}…")

        resp = netclient.get(feed["url"], timeout=45, via_tor=via_tor,
                             proxy_port=tor_port)
        if not resp.ok or not resp.body:
            report.feeds.append(FeedResult(
                key, feed["name"], False,
                error=resp.error or f"HTTP {resp.status}"))
            if progress:
                progress(f"  {feed['name']} failed: {resp.error or resp.status}")
            continue

        domains, allowed, malformed = _parse_feed(resp.body)
        report.allowlisted_skipped += allowed
        report.malformed_skipped += malformed
        merged |= domains
        report.feeds.append(FeedResult(key, feed["name"], True, len(domains),
                                       bytes_fetched=len(resp.body)))
        if progress:
            progress(f"  {feed['name']}: {len(domains):,} domains")

    if len(merged) > MAX_ENTRIES:
        report.truncated = True
        merged = set(sorted(merged)[:MAX_ENTRIES])

    report.domains = sorted(merged)
    report.total_unique = len(merged)
    report.elapsed = time.time() - started

    if report.total_unique:
        _write_cache(report)
    return report


def _write_cache(report: UpdateReport) -> None:
    try:
        with open(cache_path(), "w", encoding="utf-8") as fh:
            fh.write(f"# PrivacyKit blocklist cache\n")
            fh.write(f"# Generated {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            fh.write(f"# {report.total_unique} domains from "
                     f"{sum(1 for f in report.feeds if f.ok)} feed(s)\n")
            for d in report.domains:
                fh.write(d + "\n")
        with open(cache_meta_path(), "w", encoding="utf-8") as fh:
            fh.write(f"{time.time()}\n{report.total_unique}\n")
    except Exception:
        pass


def load_cached() -> List[str]:
    p = cache_path()
    if not p.exists():
        return []
    try:
        with open(p, "r", encoding="utf-8") as fh:
            return [line.strip() for line in fh
                    if line.strip() and not line.startswith("#")]
    except Exception:
        return []


def feed_list() -> List[dict]:
    return [{"key": k, **v} for k, v in FEEDS.items()]
