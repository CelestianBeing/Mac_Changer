#!/usr/bin/env python3
"""
PrivacyKit self-test.

Runs the parts of the toolkit that can be verified without touching the system:
cryptography against published test vectors, the journal's record/undo cycle,
MAC validation and generation rules, SOCKS5 wire framing, metadata stripping on
files built in memory, and the scoring engine's arithmetic.

Deliberately does NOT test the system-mutating paths — verifying MAC spoofing
means actually spoofing a MAC. Those are exercised by using the tool.

    python selftest.py
"""

from __future__ import annotations

import io
import os
import struct
import sys
import tempfile
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

PASS, FAIL = [], []


def check(name: str, condition, detail: str = ""):
    if condition:
        PASS.append(name)
        print(f"  \033[32mPASS\033[0m  {name}" + (f" — {detail}" if detail else ""))
    else:
        FAIL.append((name, detail))
        print(f"  \033[31mFAIL\033[0m  {name}" + (f" — {detail}" if detail else ""))


def section(title: str):
    print(f"\n\033[36m── {title} {'─' * max(2, 58 - len(title))}\033[0m")


# ──────────────────────────────────────────────────────────────────────────────

def test_aes():
    section("AES (FIPS-197)")
    from privacykit.core import aes
    ok, msg = aes.self_test()
    check("AES known-answer vectors (128/192/256)", ok, msg)

    key = os.urandom(32)
    data = b"round trip payload \x00\xff" * 137
    iv, ct = aes.encrypt_cbc(key, data)
    check("AES-CBC round-trip", aes.decrypt_cbc(key, iv, ct) == data,
          f"{len(data)} bytes -> {len(ct)} bytes ciphertext")

    iv2, ct2 = aes.encrypt_cbc(key, b"")
    check("AES-CBC handles empty input", aes.decrypt_cbc(key, iv2, ct2) == b"")

    # Padding must be rejected, not silently accepted.
    try:
        aes.decrypt_cbc(key, iv, ct[:-16] + b"\x00" * 16)
        check("AES-CBC rejects corrupted padding", False, "corrupt data accepted")
    except ValueError:
        check("AES-CBC rejects corrupted padding", True)

    # Same plaintext twice must not give the same ciphertext (random IV).
    _, a = aes.encrypt_cbc(key, data)
    _, b = aes.encrypt_cbc(key, data)
    check("AES-CBC uses a fresh IV per encryption", a != b)


def test_crypto():
    section("Vault (scrypt + authenticated encryption)")
    from privacykit.core import crypto
    ok, msg = crypto.self_test()
    check("vault round-trip / wrong-password / tamper detection", ok, msg)

    blob = crypto.encrypt_bytes(b"hello", "pw")
    check("vault container carries the magic header",
          blob[:8] == crypto.MAGIC, blob[:8].decode())

    # Two encryptions of identical data must differ (fresh salt + nonce).
    b1 = crypto.encrypt_bytes(b"same", "pw")
    b2 = crypto.encrypt_bytes(b"same", "pw")
    check("vault salts every file separately", b1 != b2)

    text = "Attack at dawn — ünicode ✓"
    armoured = crypto.encrypt_text(text, "pw")
    check("encrypted notes round-trip through base64",
          crypto.decrypt_text(armoured, "pw") == text)

    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "secret.txt"
        src.write_bytes(b"file vault payload" * 200)
        res = crypto.encrypt_file(str(src), "correct horse")
        check("encrypt_file writes a .pkv container", res.ok, res.message)
        if res.ok:
            info = crypto.inspect(res.path)
            check("inspect reads the header without the password",
                  info.get("valid"), f"{info.get('cipher')} · {info.get('kdf')}")
            src.unlink()
            dec = crypto.decrypt_file(res.path, "correct horse")
            check("decrypt_file restores the original bytes",
                  dec.ok and src.read_bytes() == b"file vault payload" * 200,
                  dec.message)

    check("file hashing produces a stable digest",
          crypto.hash_text("abc", "sha256") ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "SHA-256('abc') matches the published value")


def test_mac():
    section("MAC address handling")
    from privacykit.core import mac, oui

    check("rejects multicast first octet", not mac.is_valid("01:23:45:67:89:ab")[0])
    check("rejects all-zero address", not mac.is_valid("00:00:00:00:00:00")[0])
    check("rejects broadcast address", not mac.is_valid("ff:ff:ff:ff:ff:ff")[0])
    check("rejects malformed input", not mac.is_valid("not-a-mac")[0])
    check("rejects short address", not mac.is_valid("aa:bb:cc:dd:ee")[0])
    check("accepts a valid unicast address", mac.is_valid("aa:bb:cc:dd:ee:ff")[0])

    check("normalises dashes", mac.normalise("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff")
    check("normalises bare hex", mac.normalise("AABBCCDDEEFF") == "aa:bb:cc:dd:ee:ff")

    # Every generated address must be assignable.
    bad = []
    for _ in range(400):
        m, _d = mac.generate("vendor")
        if not mac.is_valid(m)[0]:
            bad.append(m)
    check("400 vendor-generated addresses are all valid", not bad,
          f"first bad: {bad[:1]}" if bad else "no multicast or reserved values")

    bad_local = [m for m in (mac.generate("local")[0] for _ in range(400))
                 if not mac.is_valid(m)[0]]
    check("400 locally-administered addresses are all valid", not bad_local)

    # A vendor address must NOT look locally administered — that is the point.
    flagged = 0
    for _ in range(200):
        m, _d = mac.generate("vendor")
        if int(m.split(":")[0], 16) & 0x02:
            flagged += 1
    check("vendor addresses keep the locally-administered bit clear", flagged == 0,
          f"{flagged}/200 wrongly flagged")

    # Locally-administered addresses must set it.
    unset = sum(1 for _ in range(200)
                if not int(mac.generate("local")[0].split(":")[0], 16) & 0x02)
    check("locally-administered addresses set the LAA bit", unset == 0)

    check("vendor lookup resolves a known prefix",
          oui.lookup("a4:c3:f0:11:22:33") == "Intel",
          oui.describe("a4:c3:f0:11:22:33"))
    check(f"OUI table populated ({oui.total_prefixes()} prefixes, "
          f"{len(oui.VENDOR_NAMES)} vendors)", oui.total_prefixes() > 100)

    problems = oui.validate()
    check("every embedded OUI is a plausible factory prefix", not problems,
          "; ".join(problems) if problems else
          "all unicast and globally unique")

    kept = mac.keep_oui_randomise("a4:c3:f0:aa:bb:cc")
    check("keep-OUI preserves the vendor prefix", kept.startswith("a4:c3:f0"), kept)


def test_journal():
    section("Change journal and undo dispatch")
    from privacykit.core import journal

    # Redirect the journal to a scratch directory so the real one is untouched.
    with tempfile.TemporaryDirectory() as d:
        original = journal.journal_path
        journal.journal_path = lambda: Path(d) / "journal.json"        # type: ignore
        try:
            journal.clear_history(keep_pending=False)
            start = journal.pending_count()

            log = []

            @journal.register_undo("selftest.demo")
            def _undo(payload):
                log.append(payload.get("value"))
                return True, f"reverted {payload.get('value')}"

            e1 = journal.record("test", "first change",
                                {"kind": "selftest.demo", "value": 1},
                                before={"was": "a"})
            e2 = journal.record("test", "second change",
                                {"kind": "selftest.demo", "value": 2})

            check("entries are recorded", journal.pending_count() == start + 2,
                  f"{journal.pending_count()} pending")

            ok, msg = journal.undo_by_id(e1.id)
            check("single entry undo dispatches to its handler", ok and log == [1], msg)
            check("undone entry stops counting as pending",
                  journal.pending_count() == start + 1)
            check("undoing an already-reverted entry is safe",
                  journal.undo_by_id(e1.id)[0])

            log.clear()
            journal.record("test", "third change",
                           {"kind": "selftest.demo", "value": 3})
            result = journal.panic_restore()
            check("panic restore reverts everything outstanding",
                  journal.pending_count() == 0,
                  f"{result['restored']} restored, {result['failed']} failed")
            check("panic restore works newest-first", log == [3, 2],
                  f"undo order was {log}")

            # An unknown handler must be skipped, not crash the whole restore.
            journal.record("test", "orphan", {"kind": "selftest.missing"})
            res2 = journal.panic_restore()
            check("unknown undo handler is skipped, not fatal",
                  res2["skipped"] == 1 and res2["failed"] == 0)

            # drop() must remove a failed change's entry entirely.
            e4 = journal.record("test", "will be dropped",
                                {"kind": "selftest.demo", "value": 9})
            journal.drop(e4.id)
            check("drop() removes an entry for a change that failed",
                  all(e.id != e4.id for e in journal.load()))

            # A corrupt journal must not be fatal.
            (Path(d) / "journal.json").write_text("{ this is not json")
            check("corrupt journal recovers instead of crashing",
                  isinstance(journal.load(), list))
        finally:
            journal.journal_path = original                             # type: ignore


def test_socks5():
    section("SOCKS5 client framing (RFC 1928)")
    from privacykit.core import socks5

    check("hostname is detected as a name, not an IP",
          socks5._is_hostname("example.com"))
    check("IPv4 literal is not treated as a hostname",
          not socks5._is_hostname("1.2.3.4"))
    check("IPv6 literal is not treated as a hostname",
          not socks5._is_hostname("2001:4860:4860::8888"))

    # Verify the greeting we would put on the wire.
    class FakeSock:
        def __init__(self):
            self.sent = b""
            self.script = []

        def settimeout(self, _t):
            pass

        def sendall(self, data):
            self.sent += data

        def recv(self, n):
            return self.script.pop(0) if self.script else b""

        def close(self):
            pass

    import socket as _socket
    real = _socket.create_connection
    fake = FakeSock()
    # greeting reply, then CONNECT reply (IPv4, success)
    fake.script = [bytes([5, 0]), bytes([5, 0, 0, 1]), b"\x00\x00\x00\x00", b"\x00\x00"]
    _socket.create_connection = lambda *a, **k: fake                    # type: ignore
    try:
        socks5.create_connection("example.com", 443, timeout=1)
        greeting_ok = fake.sent[:3] == bytes([5, 1, 0])
        connect = fake.sent[3:]
        check("greeting offers SOCKS5 with no-auth", greeting_ok,
              f"sent {fake.sent[:3].hex()}")
        check("CONNECT uses the domain address type (no local DNS lookup)",
              connect[:4] == bytes([5, 1, 0, 3]),
              "hostname is resolved by the proxy, so the destination never "
              "leaks to your ISP's resolver")
        check("destination port is encoded big-endian",
              connect[-2:] == struct.pack(">H", 443))
    except Exception as exc:
        check("SOCKS5 CONNECT handshake", False, f"{type(exc).__name__}: {exc}")
    finally:
        _socket.create_connection = real                                # type: ignore

    # A refused connection must raise a readable error.
    fake2 = FakeSock()
    fake2.script = [bytes([5, 0]), bytes([5, 5, 0, 1]), b"\x00\x00\x00\x00", b"\x00\x00"]
    _socket.create_connection = lambda *a, **k: fake2                   # type: ignore
    try:
        socks5.create_connection("example.com", 443, timeout=1)
        check("SOCKS5 error reply raises", False, "no exception raised")
    except socks5.Socks5Error as exc:
        check("SOCKS5 error reply raises a readable message",
              "refused" in str(exc).lower(), str(exc))
    except Exception as exc:
        check("SOCKS5 error reply raises", False, f"wrong type: {exc}")
    finally:
        _socket.create_connection = real                                # type: ignore


def test_passwords():
    section("Password generation")
    from privacykit.core import passwords as pw

    check("word list has no duplicates",
          len(pw.WORDS) == len(set(pw.WORDS)), f"{len(pw.WORDS):,} words")
    check("5-word passphrase exceeds 50 bits",
          pw.passphrase_entropy(5) > 50, f"{pw.passphrase_entropy(5):.1f} bits")

    p = pw.generate_password(24)
    check("generated password has the requested length", len(p) == 24)

    # Every enabled class must appear, or sites with complexity rules reject it.
    misses = 0
    for _ in range(300):
        c = pw.generate_password(12, True, True, True)
        if not (any(x.islower() for x in c) and any(x.isupper() for x in c)
                and any(x.isdigit() for x in c)
                and any(not x.isalnum() for x in c)):
            misses += 1
    check("every character class appears in each password", misses == 0,
          f"{misses}/300 missing a class")

    amb = pw.generate_password(200, unambiguous=True)
    check("unambiguous mode excludes 0/O/1/l/I",
          not any(c in amb for c in "0O1lI"))

    check("1000 generated passwords are all unique",
          len(set(pw.generate_password(16) for _ in range(1000))) == 1000)

    check("short passwords rate as weak", pw.estimate("abc123").label == "weak")
    check("long random passwords rate strongly",
          pw.estimate(pw.generate_password(24)).label in ("very strong", "excellent"))
    check("PIN generator returns the requested digit count",
          len(pw.generate_pin(6)) == 6 and pw.generate_pin(6).isdigit())
    check("hex key is 64 characters for 32 bytes",
          len(pw.generate_hex_key(32)) == 64)


def test_metadata():
    section("Metadata inspection and stripping")
    from privacykit.core import metadata

    with tempfile.TemporaryDirectory() as d:
        # Build a minimal JPEG carrying an EXIF APP1 segment and a comment.
        exif_payload = b"Exif\x00\x00" + b"II*\x00\x08\x00\x00\x00\x00\x00"
        app1 = b"\xFF\xE1" + struct.pack(">H", len(exif_payload) + 2) + exif_payload
        comment = b"secret note"
        com = b"\xFF\xFE" + struct.pack(">H", len(comment) + 2) + comment
        jpeg = (b"\xFF\xD8"
                + b"\xFF\xE0" + struct.pack(">H", 16) + b"JFIF\x00" + b"\x00" * 9
                + app1 + com
                + b"\xFF\xDA\x00\x08\x01\x01\x00\x00\x3F\x00" + b"\xAA" * 64
                + b"\xFF\xD9")
        jp = Path(d) / "photo.jpg"
        jp.write_bytes(jpeg)

        rep = metadata.inspect(str(jp))
        check("JPEG inspector finds the EXIF block",
              any("EXIF" in k for k in rep.findings), str(list(rep.findings)))
        check("JPEG inspector finds the embedded comment",
              any("comment" in k.lower() for k in rep.findings))

        ok, msg, out = metadata.strip(str(jp))
        check("JPEG stripping succeeds", ok, msg)
        if ok:
            cleaned = Path(out).read_bytes()
            check("EXIF segment is gone after stripping",
                  b"Exif\x00\x00" not in cleaned)
            check("comment is gone after stripping", comment not in cleaned)
            check("image scan data is preserved byte-for-byte",
                  b"\xAA" * 64 in cleaned,
                  "stripping is lossless — pixels are never re-encoded")
            check("cleaned JPEG keeps valid start/end markers",
                  cleaned[:2] == b"\xFF\xD8" and cleaned[-2:] == b"\xFF\xD9")
            after = metadata.inspect(out)
            check("re-inspecting the cleaned file finds nothing",
                  not after.findings, str(list(after.findings)))

        # Office documents are ZIP containers.
        import zipfile
        docx = Path(d) / "doc.docx"
        with zipfile.ZipFile(docx, "w") as z:
            z.writestr("word/document.xml", "<w:document>body text</w:document>")
            z.writestr("docProps/core.xml",
                       '<?xml version="1.0"?><cp:coreProperties '
                       'xmlns:cp="x" xmlns:dc="y">'
                       "<dc:creator>Nilotpal Vyas</dc:creator>"
                       "<cp:lastModifiedBy>Someone Else</cp:lastModifiedBy>"
                       "</cp:coreProperties>")
        rep2 = metadata.inspect(str(docx))
        check("DOCX inspector extracts the author",
              rep2.findings.get("Author") == "Nilotpal Vyas", str(rep2.findings))

        ok2, msg2, out2 = metadata.strip(str(docx))
        check("DOCX stripping succeeds", ok2, msg2)
        if ok2:
            with zipfile.ZipFile(out2) as z:
                names = z.namelist()
                check("docProps removed from the cleaned DOCX",
                      not any(n.startswith("docProps/") for n in names))
                check("document body survives stripping",
                      b"body text" in z.read("word/document.xml"))


def test_score():
    section("Privacy score engine")
    from privacykit.core.score import Check, ScoreReport

    rep = ScoreReport(checks=[
        Check("a", "A", 20, passed=True),
        Check("b", "B", 20, passed=False),
        Check("c", "C", 10, partial=True),
    ])
    check("score is weighted correctly", rep.score == 50,
          f"20 + 0 + 5 of 50 = {rep.score}%")
    check("grade maps from score", rep.grade == "D", rep.grade)
    check("failing checks sort worst-first",
          [c.key for c in rep.failing()] == ["b", "c"])
    check("empty report does not divide by zero", ScoreReport().score == 0)


def test_shell_and_paths():
    section("Infrastructure")
    from privacykit.core import shell, sysinfo, journal

    r = shell.run(["definitely-not-a-real-command-xyz"])
    check("missing command returns a Result instead of raising",
          not r.ok and r.code == 127, r.err[:60])

    check("appdata directory is creatable", sysinfo.appdata_dir().exists(),
          str(sysinfo.appdata_dir()))
    check("os_summary returns the expected keys",
          {"system", "hostname", "admin"} <= set(sysinfo.os_summary()))
    check("optional module detection runs",
          isinstance(sysinfo.optional_modules(), dict),
          ", ".join(k for k, (found, _) in sysinfo.optional_modules().items()
                    if found) or "none installed")


def test_dns_providers():
    section("DNS provider table")
    import ipaddress
    from privacykit.core import dnsconf

    bad = []
    for key, p in dnsconf.PROVIDERS.items():
        for s in p.servers:
            try:
                ipaddress.ip_address(s)
            except ValueError:
                bad.append(f"{key}:{s}")
        if p.doh and not p.doh.startswith("https://"):
            bad.append(f"{key}: DoH template is not https")
    check("every provider address parses as a valid IP", not bad, str(bad))
    check("every ordered provider key exists",
          all(k in dnsconf.PROVIDERS for k in dnsconf.PROVIDER_ORDER))
    check("discontinued dns0.eu is not shipped",
          not any("dns0" in k for k in dnsconf.PROVIDERS),
          "the service shut down; shipping its IPs would break resolution")


def test_presets():
    section("Presets")
    from privacykit.core import presets

    check("every ordered preset exists",
          all(k in presets.PRESETS for k in presets.PRESET_ORDER))
    for key in presets.PRESET_ORDER:
        steps = presets.build_steps(key, "Wi-Fi")
        check(f"preset '{key}' builds {len(steps)} step(s)", len(steps) > 0)
        p = presets.PRESETS[key]
        check(f"preset '{key}' documents its changes", len(p.changes) > 0)




def test_ed25519():
    section("Ed25519 verifier (RFC 8032)")
    from privacykit.core import ed25519
    ok, msg = ed25519.self_test()
    check("RFC 8032 vector 1 and tamper rejection", ok, msg)


def test_licensing():
    section("Licensing")
    from privacykit.core import licensing as L

    fp = L.machine_fingerprint()
    check("machine fingerprint is 16 bytes", len(fp) == 16,
          L.fingerprint_display())
    check("fingerprint is stable across calls",
          L.machine_fingerprint() == fp)

    check("feature table covers free and paid tiers",
          any(f.minimum == L.Edition.FREE for f in L.FEATURES)
          and any(f.minimum == L.Edition.PRO for f in L.FEATURES),
          f"{len(L.FEATURES)} features")

    # A licence block that was never signed by the vendor key must be refused.
    forged = (L.LICENSE_HEADER + "\nLicensed to: Attacker\n\n"
              + "A" * 200 + "\n" + L.LICENSE_FOOTER)
    lic = L.verify_license_text(forged)
    check("forged licence is rejected", not lic.valid, lic.reason[:70])

    check("garbage input is rejected without raising",
          not L.verify_license_text("hello").valid)
    check("empty input is rejected", not L.verify_license_text("").valid)

    # Free edition must gate paid features and allow free ones.
    ent = L.entitlement(refresh=True)
    if ent.source == "free":
        check("free edition allows a free feature", L.has_feature("mac"))
        check("free edition blocks a pro feature", not L.has_feature("tor"))
        ok, msg = L.require("tor")
        check("require() explains the gate", not ok and "Pro" in msg)
    else:
        check(f"entitlement resolved ({ent.name})", True)


def test_geo():
    section("Location matching")
    from privacykit.core import geo

    check("country profiles present", len(geo.COUNTRIES) > 20,
          f"{len(geo.COUNTRIES)} countries")

    bad = []
    for code, c in geo.COUNTRIES.items():
        if not (-90 <= c.lat <= 90 and -180 <= c.lon <= 180):
            bad.append(f"{code}: coordinates out of range")
        if len(c.code) != 2:
            bad.append(f"{code}: bad ISO code {c.code!r}")
        if not c.timezone or not c.locale:
            bad.append(f"{code}: missing timezone or locale")
        if code != c.code.lower():
            bad.append(f"{code}: key does not match ISO code {c.code}")
    check("every country profile is well formed", not bad, "; ".join(bad[:3]))

    check("picker list matches the table",
          len(geo.country_list()) == len(geo.COUNTRIES))
    check("GeoID fallback covers every country",
          all(c.code in geo._GEOID_FALLBACK for c in geo.COUNTRIES.values()),
          f"{len(geo._GEOID_FALLBACK)} entries")

    check("unknown country is handled",
          geo.apply_country("zz")["ok"] is False)
    check("mismatch detection returns nothing for an unknown country",
          geo.detect_mismatch("zz") == [])


def test_noise():
    section("Profile poisoning")
    from privacykit.core import noise

    g = noise.NoiseGenerator()
    msg = g.configure(99999)
    check("rate is capped at the ceiling",
          g.requests_per_hour == noise.MAX_REQUESTS_PER_HOUR,
          f"requested 99999, got {g.requests_per_hour}/hour")
    check("capping is explained to the caller", "ceiling" in msg)

    g.configure(1)
    intervals = [g._next_interval() for _ in range(200)]
    check("interval never drops below the hard minimum",
          min(intervals) >= noise.MIN_INTERVAL,
          f"min was {min(intervals):.1f}s, floor is {noise.MIN_INTERVAL}s")
    check("intervals are jittered, not fixed",
          len(set(round(i, 2) for i in intervals)) > 50,
          f"{len(set(round(i, 2) for i in intervals))} distinct values")

    g.configure(10)
    g._sent_times = [__import__("time").time()] * 10
    check("hourly budget blocks further sends", not g._budget_available())

    guids = {noise.new_guid() for _ in range(500)}
    check("500 generated identifiers are unique", len(guids) == 500)
    check("identifiers are brace-wrapped GUIDs",
          all(x.startswith("{") and len(x) == 38 for x in guids))
    check("identifier table excludes MachineGUID",
          not any("Cryptography" in i.path for i in noise.IDENTIFIERS),
          "changing it breaks unrelated software activation")


def test_threatfeed():
    section("Threat feed")
    from privacykit.core import threatfeed

    sample = """# comment
0.0.0.0 ads.example.com
127.0.0.1 tracker.test
windowsupdate.com
0.0.0.0 sub.windowsupdate.com
0.0.0.0 *.wildcard.com
0.0.0.0 com
1.2.3.4
plain-domain.org
0.0.0.0 ocsp.digicert.com
0.0.0.0 msftconnecttest.com
"""
    domains, allowed, malformed = threatfeed._parse_feed(sample)

    check("legitimate entries are parsed",
          {"ads.example.com", "tracker.test", "plain-domain.org"} <= domains,
          f"{len(domains)} parsed")
    check("Windows Update is never blocked",
          "windowsupdate.com" not in domains)
    check("subdomains of allowlisted names are protected",
          "sub.windowsupdate.com" not in domains)
    check("certificate revocation is protected",
          "ocsp.digicert.com" not in domains)
    check("connectivity checks are protected",
          "msftconnecttest.com" not in domains,
          "blocking these makes Windows report 'no internet'")
    check("a bare TLD cannot be blackholed", "com" not in domains)
    check("wildcards are rejected",
          not any("*" in d for d in domains))
    check("IP literals are rejected", "1.2.3.4" not in domains)
    check("allowlist and malformed counts are reported",
          allowed >= 4 and malformed >= 3,
          f"{allowed} allowlisted, {malformed} malformed")

    check("feeds are declared", len(threatfeed.FEEDS) >= 3)
    check("every feed URL is https",
          all(f["url"].startswith("https://")
              for f in threatfeed.FEEDS.values()))


def test_protection():
    section("Live protection")
    from privacykit.core import protection

    svc = protection.ProtectionService()
    check("watchers are registered", len(svc.watchers) >= 4,
          ", ".join(w.name for w in svc.watchers))
    check("every watcher declares an interval and description",
          all(w.interval > 0 and w.description for w in svc.watchers))

    now = __import__("time").time()
    watcher = svc.watchers[0]
    check("a watcher is due on first check", watcher.due(now))
    watcher.run(now)
    check("a watcher is not due immediately after running",
          not watcher.due(now))

    watcher.enabled = False
    check("a disabled watcher is never due", not watcher.due(now + 10_000))

    # A watcher that raises must not take down the service.
    class Exploding(protection.Watcher):
        name = "exploding"
        interval = 1

        def check(self):
            raise RuntimeError("boom")

    events = Exploding().run(now)
    check("a failing watcher yields an event instead of propagating",
          len(events) == 1 and "boom" in events[0].detail)

    svc._emit(protection.Event("t", "Test", "detail", "warning"))
    check("events are recorded newest-first", svc.recent()[0].title == "Test")


def test_runner():
    section("Profile action runner")
    from privacykit.core import runner
    from privacykit.core.settings import ACTIONS_BY_KEY

    result = runner.run_actions([{"action": "does.not.exist", "args": {}}])
    check("an unknown action fails without raising",
          result["failed"] == 1 and result["succeeded"] == 0)

    check("empty action list is handled",
          runner.run_actions([])["steps"] == 0)

    # Every catalogued action must be dispatchable, or a profile could silently
    # do nothing.
    import inspect
    source = inspect.getsource(runner._dispatch)
    missing = [k for k in ACTIONS_BY_KEY if f'"{k}"' not in source]
    check("every catalogued action has a dispatch branch", not missing,
          f"missing: {missing}" if missing else
          f"{len(ACTIONS_BY_KEY)} actions wired")


def test_settings():
    section("Settings and profiles")
    from privacykit.core.settings import (ACTION_CATALOGUE, DEFAULTS,
                                          CustomProfile, Settings)

    s = Settings()
    check("defaults load", s.get("theme") in ("dark", "light"))
    check("unknown keys fall back safely",
          s.get("no_such_key", "fallback") == "fallback")

    seen = []
    s.on_change(lambda k, v: seen.append(k))
    original = s.get("accent")
    s.set("accent", "violet")
    check("change listeners fire", "accent" in seen)
    s.set("accent", original)

    check("action catalogue is populated", len(ACTION_CATALOGUE) > 15,
          f"{len(ACTION_CATALOGUE)} actions")
    check("every action declares a feature gate",
          all("feature" in a for a in ACTION_CATALOGUE))

    prof = CustomProfile(key="t", name="Test",
                         actions=[{"action": "dns.flush", "args": {}}])
    restored = CustomProfile.from_dict(prof.to_dict())
    check("profiles round-trip through serialisation",
          restored.name == prof.name and restored.actions == prof.actions)


def test_gui_importable():
    section("GUI layer")
    try:
        import PySide6  # noqa: F401
    except ImportError:
        check("PySide6 available", False,
              "not installed — GUI checks skipped (pip install PySide6)")
        return

    modules = [
        "privacykit.gui.theme", "privacykit.gui.workers",
        "privacykit.gui.dialogs", "privacykit.gui.onboarding",
        "privacykit.gui.tray", "privacykit.gui.profile_editor",
        "privacykit.gui.widgets.gauges", "privacykit.gui.widgets.controls",
        "privacykit.gui.widgets.chrome",
        "privacykit.gui.pages.base", "privacykit.gui.pages.dashboard",
        "privacykit.gui.pages.identity", "privacykit.gui.pages.connection",
        "privacykit.gui.pages.location", "privacykit.gui.pages.protection",
        "privacykit.gui.pages.privacy", "privacykit.gui.pages.diagnostics",
        "privacykit.gui.pages.cleanup", "privacykit.gui.pages.vault",
        "privacykit.gui.pages.journal", "privacykit.gui.pages.settings_page",
        "privacykit.gui.app",
    ]
    failed = []
    for mod in modules:
        try:
            __import__(mod)
        except Exception as exc:
            failed.append(f"{mod}: {type(exc).__name__}: {exc}")
    check(f"all {len(modules)} GUI modules import", not failed,
          "; ".join(failed[:2]) if failed else "no import errors")

    from privacykit.gui.theme import ACCENTS, DARK, LIGHT, build_stylesheet
    for palette in (DARK, LIGHT):
        css = build_stylesheet(palette)
        check(f"{palette.name} stylesheet generates", len(css) > 2000,
              f"{len(css)} characters")
    check("accent palettes are complete",
          all(len(v) == 4 for v in ACCENTS.values()),
          f"{len(ACCENTS)} accents")


def main() -> int:
    print("\033[1mPrivacyKit self-test\033[0m")
    for fn in (test_aes, test_crypto, test_ed25519, test_licensing, test_mac,
               test_geo, test_noise, test_threatfeed, test_protection,
               test_journal, test_runner, test_settings, test_socks5,
               test_passwords, test_metadata, test_score, test_shell_and_paths,
               test_dns_providers, test_presets, test_gui_importable):
        try:
            fn()
        except Exception:
            FAIL.append((fn.__name__, "raised"))
            print(f"  \033[31mFAIL\033[0m  {fn.__name__} raised an exception")
            traceback.print_exc()

    print(f"\n\033[1m{'─' * 64}\033[0m")
    if FAIL:
        print(f"\033[31m{len(FAIL)} failed\033[0m, {len(PASS)} passed")
        for name, detail in FAIL:
            print(f"  - {name}: {detail}")
        return 1
    print(f"\033[32mAll {len(PASS)} checks passed.\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
