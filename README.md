# PrivacyKit

**A Windows privacy & anti-forensics toolkit — every change reversible.**

Started as a single-file MAC address changer. Now a twenty-thousand-line
desktop application: network identity, Tor, DNS, location matching, firewall
kill switch, telemetry hardening, profile poisoning, live monitoring,
anti-forensics, and an encryption vault — behind a PySide6 interface built on a
custom design system.

---

## The organising principle

Every system change is written to a change journal **before** it is made,
together with the state needed to reverse it. One button reverses all of it.

That is what makes it safe to experiment with settings you do not fully
understand yet — and it is why "forget this Wi-Fi network" exports the profile
first, why disabling a service records its previous *start mode* rather than
assuming `Automatic`, and why telemetry scheduled tasks are disabled rather than
deleted.

Where something genuinely cannot be undone — deleted files — the journal entry
says so instead of pretending.

---

## Screens

| | |
|---|---|
| **Dashboard** | Animated privacy score, eight live status tiles, one-click profiles |
| **Identity** | MAC spoofing with 143 real vendor OUIs, local IP, hostname, Wi-Fi profiles |
| **Connection** | Tor control protocol, exit-node country, system proxy, 8 DNS providers with DoH |
| **Location** | Aligns timezone, region, and coordinates with your exit IP |
| **Protection** | Firewall kill switch, LAN/SMB isolation, live watchers, auto-updating threat feed |
| **Privacy** | 14 Windows telemetry settings, service control, identifier rotation, decoy traffic |
| **Diagnostics** | Leak tests, connection monitor with process attribution, listening ports |
| **Cleanup** | 19-location trace cleaner, secure shredder, metadata scrubber, USB history |
| **Vault** | AES-256 file encryption, encrypted notes, password generator, hashes |
| **Journal** | Every change, individually undoable, plus the baseline snapshot |
| **Settings** | Licensing, custom profiles, automation, themes |

---

## What is new in 2.1

### Location matching

The gap almost no consumer tool closes. You route through a Frankfurt exit node
and a site sees:

```
IP address    185.220.101.x   →  Germany
Timezone      UTC+05:30       →  India
Region        IN              →  India
```

That mismatch is a stronger identifier than either signal alone, because almost
nobody has it by accident — and `Intl.DateTimeFormat().resolvedOptions().timeZone`
reads it from JavaScript in one line, with no permission prompt.

PrivacyKit detects the country of your current exit IP and aligns the Windows
timezone, home region (GeoID resolved at runtime from .NET's `RegionInfo`, so
the mapping comes from Windows itself), default coordinates, and optionally the
display locale. The consistency check shows you the exact contradictions a
fingerprinting script would see.

### Profile poisoning

Blocking a tracker leaves a shaped hole. Poisoning lets the data flow but makes
it false, so the profile is confidently wrong rather than merely incomplete.

Two mechanisms, honestly ranked. **Identifier rotation** is the one that
reliably works — local, supported by Windows, and it genuinely severs
yesterday's profile from today's. **Decoy traffic** is more speculative: it is
opt-in, hard-capped at 120 requests/hour, jittered, and the UI states plainly
that large analytics operators can often separate synthetic events from real
ones, and that it means sending more traffic attributable to you.

### Live protection

Continuous watchers rather than on-demand checks: DNS being rewritten by another
program, joining an unencrypted network, Tor stopping, the kill switch
disappearing, new devices on your subnet.

### Auto-updating threat feed

Replaces the static 90-domain list with merged public feeds — tens of thousands
of domains. The merge protects a critical allowlist: Windows Update, activation,
certificate revocation, time sync, and connectivity checks are never blocked
whatever a feed says, and single-label entries that would blackhole an entire
TLD are rejected.

### Ship-ready

Ed25519-signed offline licensing with a 14-day trial, PyInstaller + Inno Setup
build pipeline with a code-signing hook, first-run wizard, persistent settings,
user-defined profiles, and a tray agent that applies a profile automatically
when you join an untrusted network.

---

## Quick start

```
python run.py
```

Requires Windows 10/11, Python 3.9+, and PySide6:

```
pip install PySide6
```

Optional accelerators, auto-detected if present:

```
pip install cryptography pypdf psutil
```

Other entry points:

```
python run.py --tray          start minimised to the tray
python run.py --no-elevate    skip the UAC prompt
python run.py --restore-all   revert every change, headless
python run.py --version       print the version and exit
python selftest.py            142 checks, touches nothing
```

---

## Building a release

```
pip install pyinstaller pillow
python build.py --all
```

Produces `dist/PrivacyKit-Setup-2.1.0.exe`. Set `PRIVACYKIT_CERT` and
`PRIVACYKIT_CERT_PASS` first — see the warning below.

### Licensing

```
python tools/keygen.py --new                      # once; keep the key secret
python tools/keygen.py --issue "Jane Smith" --edition pro
python tools/keygen.py --issue "ACME" --edition business --seats 25 --days 365
```

Paste the resulting public key into `VENDOR_PUBLIC_KEY` in
`privacykit/core/licensing.py` before your first build.

---

## Before you sell this

Three things block distribution regardless of features:

1. **Code signing is not optional.** Unsigned, SmartScreen blocks the download
   outright, and a tool that changes MAC addresses and clears forensic traces is
   exactly the behaviour profile antivirus heuristics flag. Budget for an OV or
   EV certificate, or use Azure Trusted Signing. The build script has the hook
   ready and warns loudly when it runs unsigned.
2. **Expect antivirus false positives anyway.** Submit the signed binary to the
   major vendors for whitelisting before launch. Publish SHA-256 sums —
   `build.py` generates them.
3. **Have the legal text reviewed.** `LICENSE.txt` is a starting point, not
   advice. Software whose headline feature can be used to evade network controls
   needs a lawyer's eye on the permitted-use clause in your jurisdiction.

---

## Layout

```
privacykit/
  core/            backend — no Qt imports anywhere
    journal.py       the undo system everything else depends on
    licensing.py     Ed25519 offline licensing, trial, feature gates
    ed25519.py       pure-Python verifier, so licensing cannot fail open
    geo.py           location matching
    noise.py         identifier rotation and rate-capped decoy traffic
    protection.py    live watchers
    threatfeed.py    blocklist merge with a critical allowlist
    tor.py           control protocol incl. SAFECOOKIE
    aes.py           FIPS-197 AES, S-box derived not transcribed
    …
  gui/             PySide6 interface
    theme.py         design tokens, palettes, generated stylesheets
    widgets/         custom-painted gauges, controls, window chrome
    pages/           one module per screen
build_tools/       PyInstaller spec, Inno Setup script
tools/keygen.py    vendor licence generator — do not ship
docs/              user manual
selftest.py        142 checks
```

---

## Documentation

**[Read the user manual →](docs/USER_MANUAL.md)**

Every feature, what it changes on your system, how to reverse it, what it costs
you, and — in section 17 — what this toolkit **cannot** protect you from. Worth
reading before relying on any of it.

---

## What it is not

- **Not anonymity software.** It can route through Tor, but proxying an ordinary
  browser leaves you trivially fingerprintable. Use Tor Browser for that.
- **Not anti-forensics against a real examination.** It defeats someone browsing
  your computer, not an examiner with the disk.
- **Not a substitute for full-disk encryption.** Turn on BitLocker.

---

## Disclaimer

For education, personal privacy, and authorised testing only. Use only on
machines and networks you own or have explicit permission to test. Spoofing
identifiers to evade access controls, bans, or billing may violate laws or terms
of service in your jurisdiction.

---

*PrivacyKit 2.1.0 · Nilotpal Vyas*
