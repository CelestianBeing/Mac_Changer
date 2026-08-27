# PrivacyKit — User Manual

**Version 2.1.0 · Windows Privacy & Anti-Forensics Toolkit**

---

## Contents

1. [What this is, and what it isn't](#1-what-this-is-and-what-it-isnt)
2. [Installing and starting](#2-installing-and-starting)
3. [The interface at a glance](#3-the-interface-at-a-glance)
4. [Panic Restore — read this first](#4-panic-restore-read-this-first)
5. [Dashboard](#5-dashboard)
6. [Identity](#6-identity)
7. [Connection](#7-connection)
8. [Location](#8-location)
9. [Protection](#9-protection)
10. [Privacy](#10-privacy)
11. [Diagnostics](#11-diagnostics)
12. [Cleanup](#12-cleanup)
13. [Vault](#13-vault)
14. [Journal](#14-journal)
15. [Settings](#15-settings)
16. [Troubleshooting](#16-troubleshooting)
17. [What this cannot protect you from](#17-what-this-cannot-protect-you-from)
18. [Reference: every file it touches](#18-reference-every-file-it-touches)
19. [Building and distributing](#19-building-and-distributing)

---

## 1. What this is, and what it isn't

PrivacyKit is a desktop toolkit for reducing how identifiable and traceable a
Windows machine is. It grew out of a single-file MAC address changer and now
covers network identity, DNS, Tor, firewall rules, Windows telemetry, local
forensic traces, and file encryption.

**The organising principle is reversibility.** Every change to your system is
written to a change journal *before* it is made, together with the information
needed to put it back. One button reverses all of it. That is what makes it
safe to experiment with settings you don't fully understand yet.

### What it is good at

- Making your machine less identifiable on networks you join
- Stopping your ISP and router from logging every domain you visit
- Verifying that your privacy settings are actually working, rather than just
  set
- Removing local traces that reveal your activity to anyone using the machine
- Encrypting files with a strong, well-constructed scheme

### What it is not

- **It is not anonymity software.** Tor Browser, used properly, is anonymity
  software. This tool can route traffic through Tor, but proxying an ordinary
  browser still leaves you trivially fingerprintable by canvas, fonts, screen
  size, and a dozen other signals Tor Browser normalises and this cannot.
- **It is not anti-forensics against a real examination.** Clearing temp files
  and jump lists defeats someone browsing your computer. It does not defeat a
  forensic examiner with the disk, who has the filesystem journal, shadow
  copies, the page file, and unallocated space to work with.
- **It is not a substitute for full-disk encryption.** If your threat model
  includes someone taking the machine, turn on BitLocker.

### Legal note

Use it on machines and networks you own or have written permission to test.
Changing a MAC address to get around a network ban, a paywall, or a device
limit may breach the terms of service or the law where you live. That is on
you.

---

## 2. Installing and starting

### Requirements

- Windows 10 or 11 (the registry mechanism is the same on both)
- Python 3.9 or newer
- PySide6 (`pip install PySide6`) — the interface is built on it
- Administrator rights for most features

### No installation step

There isn't one. Unzip the folder anywhere and run it. The interface needs
**PySide6**; `Run-PrivacyKit.bat` installs it for you on first launch if it is
missing. Nothing else is required — the SOCKS5 client, the Tor control
protocol, AES, and the metadata parsers are all implemented against the
standard library. The extras in `requirements-optional.txt` are exactly that:
optional, and the Dashboard shows which ones are active.

### Starting it

Double-click **`Run-PrivacyKit.bat`**, or from a terminal:

```
python run.py
```

If it isn't already elevated it offers to restart through UAC. You can decline —
status views, leak tests, the vault, the password generator, the metadata
scrubber, and the file shredder all work as a normal user. Anything that writes
to `HKEY_LOCAL_MACHINE` or the firewall will refuse and tell you why.

To skip the elevation prompt entirely: `python run.py --no-elevate`

### Optional speed-ups

Everything works without these. If they happen to be installed, richer paths
light up automatically, and the Dashboard tells you which ones are active:

| Package | What it improves |
|---|---|
| `cryptography` | Hardware-accelerated AES-256-GCM in the vault |
| `pypdf` | Reading and stripping PDF metadata |
| `psutil` | Faster connection monitor with full process paths |
| `requests` | Slightly faster leak tests |

```
pip install cryptography pypdf psutil
```

### Verifying the build

```
python selftest.py
```

Runs 87 checks: AES against the FIPS-197 published vectors, vault round-trip and
tamper detection, journal record/undo ordering, MAC validation rules, SOCKS5
wire framing, metadata stripping, and the scoring arithmetic. It touches nothing
on your system.

---

## 3. The interface at a glance

The window is frameless, opens at 1320x860, and will not shrink below
1120x720. A sidebar on the left groups eleven pages under three headings; the
page you pick fills the rest.

```
+----------------------------------------------------------------------+
|  PrivacyKit 2.1.0        [0 changes] [ADMINISTRATOR] [(!) PANIC]      |
+----------------+-----------------------------------------------------+
| @ Dashboard    |                                                     |
|                |                                                     |
| NETWORK        |                                                     |
|  # Identity    |                                                     |
|  ~ Connection  |    Cards, tiles, and controls for the page          |
|  o Location    |                                                     |
|                |                                                     |
| DEFENCE        |                                                     |
|  U Protection  |                                                     |
|  * Privacy     |                                                     |
|  = Diagnostics |                                                     |
|                |                                                     |
| DATA           |                                                     |
|  x Cleanup     |                                                     |
|  # Vault       |                                                     |
|  = Journal     |                                                     |
+----------------+-----------------------------------------------------+
|  Edition badge | Settings | version                                  |
+----------------------------------------------------------------------+
```

Three things are always visible:

- **The changes counter** in the header -- how many changes are currently applied
  to your machine. When this reads 0, PrivacyKit has left nothing behind.
- **The elevation badge** -- green when you can change system settings, red when
  you can't.
- **Panic Restore** -- always one click away, from every page. See section 4.

The eight Dashboard tiles are clickable: each jumps to the page that controls
it. Long operations run in the background; the window stays responsive.

---

## 4. Panic Restore — read this first

The red **PANIC RESTORE** button in the top right reverses every change
PrivacyKit has made, in reverse order.

### How it works

Before making any change, PrivacyKit writes a journal entry containing the
previous state. For example, changing your DNS records the servers that were
configured, and whether they came from DHCP. Panic Restore walks these entries
newest-first and dispatches each to its undo handler.

Newest-first matters. If you changed DNS twice — first to Cloudflare, then to
Quad9 — replaying in reverse order lands on your original setting rather than on
Cloudflare.

### What it restores

MAC addresses · IP configuration · DNS servers and DoH templates · system proxy ·
firewall rules · computer name · Windows privacy registry values · telemetry
service start modes · scheduled task states · the hosts file · forgotten Wi-Fi
profiles

### What it cannot restore

**Deleted files.** Trace cleaning and shredding are permanent. Those journal
entries exist as a *record* of what was removed, and their undo handler says so
plainly rather than pretending a restore happened.

### If you close the app with changes applied

You get a three-way prompt: restore everything and quit, leave the changes and
quit, or cancel and stay. Leaving changes applied is a legitimate choice — a
spoofed MAC and private DNS are things you may want to persist.

### The baseline snapshot

The first time PrivacyKit runs it also records a one-time snapshot of your
original settings, separate from the journal. This is the safety net behind the
safety net: if the journal is deleted, or something was changed outside this
tool, the baseline still shows what "factory" looked like. View it on the
Journal page.

---

## 5. Dashboard

### Live status tiles

Eight tiles read directly from the machine each time you open the page. Click any
tile to jump to the section that controls it.

| Tile | Green when | Amber/red when |
|---|---|---|
| Active adapter | — | no physical adapter found |
| MAC address | currently spoofed | using the factory address |
| DNS resolver | private resolver + DoH | ISP or router resolver |
| Tor | running | not detected |
| System proxy | enabled | direct connection |
| Kill switch | armed | off |
| Pending changes | none applied | changes outstanding |
| Computer name | — | always shown (it is always broadcast) |

### Privacy score

A weighted 0–100 assessment across eleven checks. The weights reflect real
day-to-day impact rather than how impressive a feature sounds:

| Check | Weight | Why this weight |
|---|---:|---|
| Privacy DNS resolver | 18 | Your resolver sees every domain, continuously |
| DNS encrypted (DoH) | 15 | Plaintext DNS is readable by anyone on the path |
| Traffic through Tor/proxy | 16 | Hides your IP from every site |
| Windows telemetry reduced | 12 | Constant background reporting |
| Firewall enabled | 10 | Baseline exposure control |
| LLMNR disabled | 7 | Credential-theft vector on hostile networks |
| MAC address masked | 8 | Identifies the device to the local network only |
| Kill switch armed | 6 | Matters only when using Tor or a VPN |
| Telemetry domains blocked | 5 | Useful, overlaps with other measures |
| Wi-Fi list kept small | 5 | Each saved network is a place you've been |
| Running elevated | 3 | Determines what you can fix |

The panel lists your unmet checks worst-first, each with the specific remedy and
a clickable link to the page that fixes it. A number with no path to improving it
is decoration, not information.

### One-click profiles

The value isn't saving clicks — it's that the individual settings interact.
Arming a kill switch without starting Tor just breaks your internet; spoofing a
MAC while leaving the hostname alone barely helps. A profile is a combination
that makes sense together.

Each lists exactly what it will do before it runs, and every step is journalled
individually, so Panic Restore unwinds a profile the same way it unwinds manual
changes.

### 🏠 Everyday Sensible

Changes worth leaving on permanently. Nothing interferes with printers, games,
video calls, or corporate VPNs.

DNS → Quad9 with DoH · low-impact privacy tweaks · telemetry domain blocklist ·
advertising ID and activity history off · flush DNS cache

### ☕ Public Wi-Fi

For a network where you don't trust the other people on it. Focused on not being
identifiable and not being reachable, without breaking normal browsing.

Spoof MAC (vendor-realistic) · DNS → Cloudflare with DoH · disable LLMNR · block
SMB/NetBIOS · isolate from the local subnet · flush DNS cache

*Cost: network printers and shared drives stop working until you switch back.*

### 🛡 Maximum Privacy

The strongest posture available here. Routes through Tor with a kill switch
behind it, so a Tor failure stops traffic rather than leaking it.

Spoof MAC + randomise computer name · DNS → Mullvad with DoH · route system
traffic through Tor · arm kill switch · disable IPv6 · disable LLMNR + block SMB ·
all privacy tweaks + telemetry blocklist

*Requires Tor to already be running. Expect things to break — that's the trade.*

### 🧹 Clean Exit

Wipe today's traces and hand the machine back. Useful on a shared or borrowed
computer.

Clear temp, Recent, jump lists, thumbnails, DNS cache, clipboard, Run history,
PowerShell history, crash dumps · restore all network settings to their
originals

*The cleaning part cannot be undone.*

### If a step fails

A failing step does **not** abort the run. If Tor isn't available, the DNS and
firewall hardening in the same profile are still worth having. The summary
reports exactly what succeeded, so you're never misled about which protections
are actually active.

---

## 6. Identity

Four identifiers travel with your machine onto every network. Changing one and
leaving the others is largely pointless — this page handles all four.

### 6.1 MAC address

**What it is.** The hardware address of your network card, visible to every
device on the local network and logged by most routers and captive portals.

**How PrivacyKit changes it.** Windows lets a NIC's address be overridden by the
`NetworkAddress` value under the adapter's driver key in the registry. The tool
writes that value and cycles the adapter so the driver re-reads it. Restoring
deletes the value, which reverts to the burned-in address.

**Generating an address — three modes:**

| Mode | Result | When to use it |
|---|---|---|
| **Vendor** (recommended) | Inside a real Intel/Apple/Samsung/etc. OUI range | Almost always — it looks like an ordinary factory NIC |
| **Locally-administered** | Random with the LAA bit set | When you specifically want to be honest that it's assigned, and to guarantee no collision with a real device |
| **Keep OUI** | Same first 3 bytes, new last 3 | Staying "the same brand" while changing identity |

Vendor mode matters more than it sounds. A purely random MAC has the
locally-administered bit set, which any network looking for it can spot
instantly — it's a flashing sign saying "spoofed". Some captive portals and
enterprise access-control systems reject such addresses outright. PrivacyKit
embeds 143 genuine IEEE-registered prefixes across 21 vendors, and a self-test
verifies every one of them is unicast and globally unique.

**Validation.** The tool refuses addresses that Windows would reject anyway, and
explains why rather than just saying "invalid":
- multicast first octet (a NIC address must be unicast — it suggests the
  corrected octet)
- all-zeros and broadcast, both reserved

**Auto-rotate.** Changes the address on a schedule, from 5 seconds to hours,
with a live countdown. The 5-second floor exists because each rotation disables
and re-enables the adapter, which takes ~2 seconds to settle; anything faster
leaves the adapter cycling and never connecting.

> **If the MAC doesn't change:** some Wi-Fi chipsets — notably several Intel and
> Broadcom models — ignore the `NetworkAddress` override entirely. The tool
> detects this and tells you, rather than reporting false success. Check Device
> Manager → your adapter → Properties → Advanced for a "Network Address" or
> "Locally Administered Address" entry. If it's missing, the driver doesn't
> support software MAC spoofing and no tool will change that.

> **Consider the built-in option first.** Windows 10/11 can randomise the Wi-Fi
> MAC natively (Settings → Network & Internet → Wi-Fi → *Random hardware
> addresses*). Where the driver supports it, that's *better* than registry
> spoofing: it survives reboots cleanly and rotates per network. PrivacyKit
> doesn't force this on, because the switch is driver-dependent and Windows
> manages the rotation itself.

### 6.2 Local IP address

**Important distinction, because this is the most common misconception about
"IP changers":** this changes your **local network address** (192.168.x.x). It
does **not** change the public IP that websites see. Only a VPN, proxy, or Tor
can do that — see the Connection page.

What you can usefully do locally:

- **Release & renew DHCP** — asks the router for a lease again. On some ISPs
  with short lease times this also yields a new public IP.
- **New random IP in this subnet** — keeps your subnet and gateway but picks a
  different host address. Useful on a network you rejoin often: you land
  somewhere different each time rather than being handed the same reserved
  address.
- **Static IP** — pins an address so the router stops logging a new lease.
- **Back to automatic** — returns to DHCP.

### 6.3 Computer name

Your hostname is broadcast constantly — in DHCP requests, in NetBIOS/LLMNR/mDNS
chatter, and in the client list of every router you join. `NILOTPAL-LAPTOP`
following you between coffee shops identifies you as surely as a MAC address.
Spoofing the MAC while leaving the hostname alone defeats the purpose.

- **Windows-style** generates names in the `DESKTOP-XXXXXXX` form Windows
  assigns itself, so the name is unremarkable on any network.
- **Random** is pure noise — more unique, but also more memorable to anyone
  watching.

A restart is required before the change is fully visible to the network. The
original name is journalled and restorable.

> Domain-joined machines need domain credentials to rename. PrivacyKit detects
> this and tells you rather than half-applying the change.

### 6.4 Wi-Fi profiles

**Saved networks.** Windows remembers every network you have ever joined. Older
clients actively probe for saved SSIDs, broadcasting a list of the places you
have been — `HOTEL_MARRIOTT_LHR`, `CorpNet-Guest` — to anyone with a receiver.
Forgetting networks you no longer need shrinks that list.

Forgetting is journalled with the profile's exported XML, so it can be undone —
without that, "forget" would be the one irreversible action in a toolkit that
promises reversibility.

**Nearby scan / evil-twin check.** Lists visible access points with their
BSSIDs. If one SSID is advertised by access points whose hardware addresses come
from *different vendors*, that's flagged. A legitimate multi-AP network uses
hardware from one vendor, so mixed prefixes is a reasonable evil-twin heuristic —
worth a warning, not an accusation.

---

## 7. Connection

Everything that decides how your traffic leaves the machine:
the Tor client, your DNS resolvers, and the system proxy.

### Connecting to Tor

PrivacyKit talks directly to Tor's control port, implementing the control
protocol including **SAFECOOKIE** authentication (the HMAC challenge/response
that is the default on modern Tor, and the reason most hand-rolled clients
fail). It probes the standard endpoints automatically:

| Setup | SOCKS | Control |
|---|---|---|
| Tor Browser | 9150 | 9151 |
| Tor service / Expert Bundle | 9050 | 9051 |

**The simplest route is to install Tor Browser and leave it running.** It
exposes both ports with no configuration at all.

For a standalone Tor, add to your `torrc` and restart:

```
ControlPort 9051
CookieAuthentication 1
```

If your torrc sets a `HashedControlPassword`, type the password into the small
field next to the New Identity button.

### Status tiles

**Tor** (running or not) · **Exit IP** (what sites actually see) · **Exit
country** · **Control port** (open or closed)

The exit IP is fetched *through* the SOCKS proxy. This is the only trustworthy
confirmation that traffic is really leaving via Tor — the control port can
report a healthy circuit while your applications still talk direct.

### New identity

Sends `SIGNAL NEWNYM`, waits for the circuit to rebuild, then re-checks the exit
IP and reports the before/after.

An honest caveat the tool states rather than hiding: NEWNYM asks Tor to use
fresh circuits for *new* connections. Existing connections keep their circuit,
and Tor rate-limits identity changes internally. If you press it repeatedly and
get the same exit IP, that's Tor working as designed, not a bug.

### Exit-node country

Pins exit selection to a chosen country at runtime via `SETCONF`. Request a new
identity afterwards for it to take effect.

`StrictNodes` is deliberately **not** set. With it, if no exit exists in your
chosen country, Tor stops working entirely. Without it, Tor prefers that country
and falls back — the right default for a general-purpose tool.

### Routing system traffic through Tor

Points the Windows system proxy at Tor's SOCKS listener.

**Scope, stated plainly:** this is respected by Edge, Chrome, and most
applications using WinINET/WinHTTP. It is **not** respected by Firefox (which
has its own proxy settings) or by software that opens raw sockets. The firewall
kill switch is what turns "should go through Tor" into "cannot go anywhere
else".

> **Routing traffic through Tor is not the same as using Tor Browser.** Tor
> Browser also blocks WebRTC, resists fingerprinting, and isolates circuits per
> site. Proxying an ordinary browser hides your IP address and leaves everything
> else about you as identifiable as before.

### Circuit view

Lists built circuits as guard → middle → exit, by relay nickname.

### Why DNS is the weak link

Even behind a VPN, if your resolver is still your ISP's, every domain you visit
is handed to them — in plaintext, timestamped, regardless of HTTPS. Fixing this
is the single highest-value change in the toolkit, which is why it carries the
most score weight.

There are two separate problems, and you need both fixed:

1. **Who answers your queries** → switch resolver
2. **Who can read them in transit** → enable DNS-over-HTTPS

### Providers

All addresses and DoH endpoints were verified against each operator's own
documentation.

| Provider | Servers | Blocks | Notes |
|---|---|---|---|
| Cloudflare | 1.1.1.1, 1.0.0.1 | nothing | Fast, widely available |
| Cloudflare (malware) | 1.1.1.2, 1.0.0.2 | malware | |
| Quad9 | 9.9.9.9, 149.112.112.112 | malware, phishing | Swiss non-profit |
| Mullvad | 194.242.2.2 | nothing | No-logging policy, no account needed |
| Mullvad (ad blocking) | 194.242.2.3 | ads, trackers | |
| AdGuard | 94.140.14.14, 94.140.15.15 | ads, trackers, malware | |
| AdGuard (unfiltered) | 94.140.14.140, .141 | nothing | |
| Google | 8.8.8.8, 8.8.4.4 | nothing | Included for completeness — it is Google |

> **dns0.eu is deliberately absent.** The service was discontinued. Shipping its
> addresses would silently break name resolution for anyone who selected it.

### DNS-over-HTTPS

Uses the native Windows 11 mechanism (`netsh dns add encryption`). PrivacyKit
registers the DoH template *before* assigning the server, so there's no window
where queries go out in the clear.

**UDP fallback is turned off** by default. With fallback on, Windows silently
drops to plaintext DNS whenever the encrypted endpoint is unreachable — which is
precisely the moment you'd want it to fail loudly instead.

If your Windows build doesn't expose the DoH commands, the page says so rather
than silently doing nothing.

### DNS cache

`ipconfig /displaydns` lists every domain your machine has recently looked up.
**No admin rights are needed to read it.** Anyone who sits down at your keyboard
can read a recent browsing history in one command. The page shows what's cached
and flushes it.

### System proxy

Sets the Windows-wide proxy (Settings → Network → Proxy). Same scope caveats as
the Connection page.

**WinHTTP** is a separate, machine-wide setting used by Windows services and
background updaters. A proxy set only for your user account still leaves
`svchost` traffic going direct. "Copy to WinHTTP" closes that gap.

---

## 8. Location

### The problem

You route your traffic through a Frankfurt exit node. A website sees:

| Signal | Value | Says |
|---|---|---|
| IP address | 185.220.101.x | Germany |
| Timezone | UTC+05:30 | India |
| Windows region | IN | India |
| Locale | en-IN | India |

That combination is a **stronger identifier than either signal alone**, because
almost nobody has it by accident. Commercial VPNs do not fix it. A web page
reads your timezone with one line of JavaScript —
`Intl.DateTimeFormat().resolvedOptions().timeZone` — and needs no permission to
do it.

### What PrivacyKit aligns

| Signal | Mechanism | Notes |
|---|---|---|
| **Timezone** | `tzutil /s` | The highest-value fix. Needs Administrator. |
| **Home region** | `Set-WinHomeLocation` | GeoID resolved at runtime from .NET `RegionInfo`, so the mapping comes from Windows itself rather than a table baked in months ago. |
| **Default coordinates** | Registry | What the Windows Geolocation API hands to apps that ask. |
| **Display locale** | `Set-Culture` | **Off by default** — it changes date and number formatting in every application, which people find alarming, and it is the smallest win of the four. |

### Using it

**Match to my exit IP** detects the country of your current public IP (through
Tor if Tor is running) and aligns everything you have ticked. Or pick a country
manually from the list of 32 profiles covering the common VPN and Tor exit
locations.

The **consistency check** at the top shows the exact contradictions a
fingerprinting script would see, so you can tell at a glance whether anything is
out of step.

### The one signal that cannot be faked

Windows reports the **BSSIDs of nearby Wi-Fi access points** to Microsoft to
work out where you are. That runs on real observed hardware — no amount of
registry editing changes what your radio can hear. The only remedy is switching
the location service off, which the page offers.

### What it does not claim

It cannot change what a **browser** reports through the JavaScript Geolocation
API if you have granted that site location permission, and it cannot alter GPS
hardware. It aligns the signals Windows gives away without being asked, which is
where the mismatch almost always is.

### Reversing it

Every change is journalled with its previous value. Panic Restore puts the
timezone, region, coordinates, and locale back. The timezone and locale changes
take effect immediately; applications already running may need restarting to
notice.

---

## 9. Protection

### Kill switch

A system proxy is advisory — a program can ignore it and connect direct. A
firewall rule is not.

With the kill switch armed, outbound traffic is **blocked** unless it's going to
the local proxy. A program that tries to bypass Tor fails to connect instead of
silently leaking.

**Rules created** (all prefixed `PrivacyKit-`, so they can always be found and
removed even if the journal is lost):

| Rule | Purpose |
|---|---|
| `AllowLoopback` | Local proxies keep working |
| `AllowTor` | TCP to 127.0.0.1:\<SOCKS port\> |
| `AllowDHCP` | UDP 67/68 — keeps your lease renewing |
| `AllowLAN` | Optional, off by default |
| `BlockAll` | Everything else, outbound |

**Order matters and is deliberate:** allow rules are created *first*. Creating
the block rule first and then failing would leave the machine with no network at
all.

**Keep "Allow DHCP" on.** Without it the machine loses its address at lease
renewal and drops off the network entirely — which looks like the tool broke
your computer. DHCP is link-local, so allowing it costs nothing in privacy
terms.

> **When armed, expect things to stop working — that is the point.** If your
> browser won't load pages, the kill switch is doing its job because that
> traffic isn't going through the proxy.

### Network isolation

- **Block LAN traffic** — stops other devices on the same café or hotel Wi-Fi
  from reaching you, and you from reaching them, without touching internet
  access. Breaks printers, network shares, and casting.
- **Block SMB/NetBIOS** — closes ports 135, 139, 445 inbound. The classic
  Windows attack surface on an untrusted network, almost never needed outside an
  office.

### Protocol hardening

**LLMNR.** When DNS fails, Windows shouts the name across the entire local
network. On a hostile network, an attacker answers "that's me" and harvests the
credentials your machine sends. Disabling it is standard hardening with
essentially no downside on a home or public network.

**IPv6 (per adapter).** The standard fix for the IPv6-bypasses-your-IPv4-VPN
leak. Done per-adapter via the network binding, *not* via the global
`DisabledComponents` registry value that Microsoft warns against.

**NetBIOS over TCP/IP.** Broadcasts your hostname and workgroup constantly and
is the vector for classic name-poisoning attacks. Almost nothing modern needs
it.

### Watchers

A one-off audit tells you the machine was fine when you looked. It does not tell
you that a VPN client rewrote your DNS an hour later.

| Watcher | Interval | What it catches |
|---|---|---|
| **Network changes** | 20s | Joining a different Wi-Fi network, flagging unencrypted ones |
| **DNS integrity** | 45s | Another program changing your resolvers |
| **Protection state** | 60s | Tor stopping, the proxy dropping, the kill switch disappearing |
| **Network neighbours** | 120s | New devices appearing on your subnet |

Events appear on the Protection page and, with the tray agent running, as
desktop notifications. Each carries a suggested remedy rather than just an
alarm.

Intervals are chosen against how fast the thing being watched actually changes —
there is no value in checking every five seconds, and a watcher that fires
constantly gets ignored.

### Threat feed

Replaces the built-in 90-domain list with merged public feeds — typically tens
of thousands of domains.

| Feed | Content |
|---|---|
| StevenBlack unified hosts | Widely used merge of ad, malware, and tracking lists |
| AdGuard CNAME trackers | CNAME-disguised trackers ordinary lists miss |
| Peter Lowe's list | Long-maintained ad and tracking servers |
| URLhaus | Active malware distribution hosts (off by default) |

**The merge protects a critical allowlist.** Windows Update, activation,
licensing, certificate revocation, time sync, Defender definitions, and
connectivity checks are never blocked whatever a feed says — including their
subdomains. A machine that silently stops receiving security updates because a
blocklist grew a bad entry is a serious outcome and very hard to trace back
months later.

It also rejects wildcards, IP literals, and **single-label entries that would
blackhole an entire TLD**, and caps the total at 250,000 domains because a
hosts file beyond that measurably slows name resolution on Windows.

---

## 10. Privacy

Privacy hardening advice online is full of changes that break things without
saying so. Here **the cost is printed next to every switch**.

### Privacy tweaks

Fourteen registry settings. Each records its previous value before changing —
including the case where the value *didn't exist*, in which case restoring
deletes it rather than writing a guess.

| Setting | Cost of enabling |
|---|---|
| Disable advertising ID | Ads still appear, just not personalised by this ID |
| Minimum telemetry | Feedback Hub and some diagnostics stop working |
| Disable activity history | Task View no longer shows past activity |
| Stop publishing activity | Cross-device "pick up where you left off" stops |
| Stop uploading activity | Cross-device Timeline stops |
| Disable tailored experiences | Suggestions become generic |
| Stop tracking app launches | Start menu "Most used" stops updating |
| Disable app location access | Maps, Weather, Find My Device lose location |
| Stop feedback prompts | No feedback prompts |
| Disable Cortana in search | Voice assistant features stop |
| Disable web results in Start | Start search finds only local files and apps |
| Disable Wi-Fi Sense reporting | No impact on normal Wi-Fi use |
| Disable inking/typing personalisation | Typing suggestions less tailored |
| Disable error reporting | Crashes no longer reported; harder to diagnose |

> On Home and Pro editions Microsoft treats telemetry level 0 as "Basic" rather
> than truly off. The tool says so rather than implying it achieved more than it
> did.

### Telemetry services

Five services whose only job is diagnostics. Disabling records the previous
**start mode**, so restoring puts back "Manual" rather than assuming
"Automatic".

`DiagTrack` is the main Windows telemetry service and the single biggest
reduction available.

### Scheduled tasks

Ten known telemetry tasks. They are **disabled, not deleted** — a deleted task
can't be restored, and this toolkit doesn't do anything it can't undo.

### Hosts blocklist

Points ~90 telemetry, advertising, and analytics domains at `0.0.0.0`.

Safety design:
- The original hosts file is copied to a timestamped backup **first**, and the
  backup path is recorded in the journal. Undo restores it byte for byte.
- Entries sit inside clearly marked `BEGIN`/`END` blocks, so removing them never
  touches lines you or another tool added.

> The list deliberately **excludes** Microsoft domains that also carry Windows
> Update, activation, and licensing. Aggressive blocklists that include those
> break Windows in ways that are very hard to trace back to the hosts file
> months later.

### Blocking versus poisoning

These are **alternative strategies against the same endpoint**, not
complementary ones:

- **Blocking** stops data reaching a tracker. It leaves a shaped hole — no data
  is itself a signal, and a profile with gaps can still be joined to other
  profiles.
- **Poisoning** lets data flow but makes it false, so the profile is
  confidently wrong rather than merely incomplete.

If the hosts blocklist is active, decoy requests to those same domains go
nowhere. PrivacyKit detects that conflict and says so rather than letting you
run a feature that silently does nothing.

### Identifier rotation — the part that works

Advertising and analytics systems key on stable identifiers. Rotating the ones
Windows lets you reset breaks the thread between yesterday's profile and
today's: the old profile still exists but can no longer be extended.

| Identifier | What it is |
|---|---|
| Advertising ID | The per-user ID apps use to join your behaviour across everything you install. Windows itself offers a reset button for this. |
| Cloud experience client ID | Attached to cloud-backed personalisation features. |
| SQM client ID | Ties separate Windows telemetry submissions to one machine. Machine-wide; needs Administrator. |

This is purely local, generates no network traffic, and has no downside. It is
the recommended feature on this page.

> **MachineGUID and the Windows installation ID are deliberately excluded.**
> They are load-bearing for software activation and licensing, and changing them
> breaks unrelated applications in ways that are very hard to diagnose later.

### Decoy traffic — opt in, and read this first

Low-rate requests to analytics collectors, carrying randomised fake identifiers
and plausible-but-mundane interests, diluting any profile keyed to you.

**Three honest caveats, stated in the UI as well as here:**

1. **It contradicts blocking.** Pick one strategy per endpoint.
2. **Effectiveness is unproven** against sophisticated correlation. Large
   analytics operators can often separate synthetic events from real ones using
   timing regularity, TLS fingerprints, and the absence of corroborating
   signals.
3. **It generates traffic attributable to you** — the opposite of quiet, and it
   cuts against everything else this toolkit does. Route it through Tor if you
   use it at all.

**Rate limiting is enforced two independent ways** — a per-hour budget and a
minimum 20-second gap — and hard-capped at 120 requests/hour. Beyond that this
stops being noise about you and starts being abusive traffic to someone else's
servers, which is a line the software will not cross regardless of what you type
into the box. Intervals are jittered because perfectly periodic traffic is
trivially separable from human activity, which would defeat the purpose.

---

## 11. Diagnostics

Every other page *configures* something. This one checks whether the
configuration is doing what it claims. That distinction matters: a proxy an
application ignores, a DoH template Windows silently fell back from, or an IPv6
route bypassing your IPv4 VPN all look fine in Settings and leak anyway.

### Tests run

| Test | What it establishes |
|---|---|
| **Public IP** | What every site you visit sees, with geolocation and ISP |
| **Via Tor** | The exit IP, fetched through the SOCKS proxy — compared against the direct answer |
| **DNS resolver** | Which resolver external services see answering for you |
| **IPv6 exposure** | Whether you're reachable over IPv6 |
| **DNS cache** | How many domains are readable locally |
| **WebRTC** | Reported with the per-browser remedy (see below) |

### Findings

Ranked critical → warning → info → good, each with a concrete remedy. Notable
ones:

**"Tor is running but its exit IP matches your real IP"** — critical. Traffic
sent through the SOCKS port came back with the same address as a direct request.
That should be impossible in a working Tor setup and means the SOCKS port isn't
really Tor. Stop and investigate.

**"IPv6 is publicly reachable"** — the classic VPN bypass. Your tunnel carries
IPv4 while Windows quietly prefers IPv6 for any site with an AAAA record,
sending that traffic outside the tunnel. Fix: disable IPv6 on the adapter
(Protection page), or confirm your VPN handles IPv6.

**WebRTC** — reported, not tested, because it lives inside the browser. A web
page can ask your browser directly for its local and public IP addresses,
bypassing the system proxy entirely. **No external process can test or fix
this** — claiming otherwise would be a lie. The remedies:

- Firefox: set `media.peerconnection.enabled` to `false` in `about:config`
- Chrome/Edge: uBlock Origin → *Prevent WebRTC from leaking local IP addresses*
- Tor Browser: blocks it by default, nothing to do

### Connection monitor

Lists what your machine is talking to right now, with the owning process,
resolved hostnames, and flags for known telemetry/advertising/analytics
destinations. This answers the question no settings screen can: *is something
still phoning home?*

Flagged rows match known patterns. Some are benign — a flag is a prompt to look,
not a verdict.

### Listening ports

Every open listener is something a hostile network can reach. On café Wi-Fi,
SMB on 445 or Remote Desktop on 3389 being open is worth knowing about. High-
exposure ports are highlighted.

---

## 12. Cleanup

### Trace cleaner

Eighteen locations Windows uses to record what you do. Each shows its size
before you delete anything, and states what you lose.

The ones people are usually surprised by:

- **Prefetch** — every program you've launched, with timestamps and run counts.
  One of the first places a forensic examiner looks.
- **Jump lists** — per-application recent-file lists. They survive clearing the
  Recent folder and are highly revealing.
- **Thumbnail cache** — cached previews of images *including files you've since
  deleted*. The thumbnail often outlives the picture.
- **Crash dumps** — can contain fragments of whatever the program had open:
  documents, passwords, keys.
- **PowerShell history** — a plaintext file of every command you've run,
  including any that contained a password or token.
- **DNS cache** — readable by anyone at your keyboard, no admin needed.

"Select recommended" picks the ten with real privacy value and low cost.

> **Event logs carry a serious warning.** Clearing the Security log is itself a
> logged, suspicious event, and it breaks troubleshooting. Only do this on a
> machine you own and understand.

> **What this achieves:** it removes convenience traces — the things that reveal
> your activity to someone browsing your machine. It is **not** anti-forensics
> against a proper examination. The filesystem journal, volume shadow copies,
> the page file, and unallocated space all retain evidence that user-level
> deletion doesn't touch.

### Secure shredder

Overwrites a file's contents, renames it to random characters, truncates it,
then deletes it.

The rename matters: the filename is metadata stored in the directory entry, and
`2026 tax return.pdf` left in the MFT is informative even with the contents
gone.

**Patterns:** single random pass (recommended), zeros, DoD 3-pass, DoD 7-pass,
35-pass Gutmann-style. Multi-pass patterns are a holdover from 1990s drive
densities — against any practical recovery, one pass is sufficient on a magnetic
disk.

> **The SSD caveat, stated where you act on it.** On an SSD, NVMe, or USB flash
> drive, overwriting largely **does not work**. Wear levelling means the
> controller writes your overwrite to *different physical cells* and leaves the
> originals marked stale but intact until garbage collection reaches them. The
> only reliable equivalents are full-disk encryption from the start, or the
> drive's own secure-erase command. PrivacyKit detects the drive type and warns
> you before shredding. A tool that promises unrecoverable deletion on an SSD
> and doesn't deliver leaves you worse off than one that's honest.

**Wipe free space** overwrites unallocated space so previously-deleted files
become unrecoverable. Uses Windows' own `cipher /w`, which understands NTFS
internals and won't fill your disk in a way that breaks the system. Slow — tens
of minutes on a large drive.

### Metadata scrubber

The problem is concrete: a photo straight off a phone carries GPS coordinates
accurate to a few metres, the device model, and on some cameras a serial number.
A Word document carries the author name, the organisation, total editing time,
and often everyone who revised it. People share these files believing they're
sharing only the visible content.

| Format | Support | Method |
|---|---|---|
| JPEG | Inspect + strip | Drops EXIF, XMP, IPTC, and comment segments |
| PNG | Inspect + strip | Drops text, EXIF, and timestamp chunks |
| DOCX/XLSX/PPTX | Inspect + strip | Rebuilds the ZIP without `docProps/`, normalises timestamps |
| PDF | Inspect + strip | Needs `pypdf`; without it, inspection only |

**JPEG and PNG stripping is lossless.** The image data is copied byte for byte —
only the metadata segments are dropped. There is no re-encoding and no quality
loss.

**A cleaned copy is written alongside the original** rather than overwriting it.
The original may be your only copy, and a bug in a stripper that overwrites in
place destroys data.

**Scan folder** inspects every supported file in a folder — the "what am I about
to share" check before sending a batch of photos.

> PDFs are reported rather than stripped without `pypdf` installed. Stripping
> properly means rewriting the cross-reference table, and a half-rewritten PDF
> is a corrupt PDF. PrivacyKit won't hand-edit a structure it can't guarantee.

### USB device history

Every USB storage device ever connected to the machine, with serial numbers and
friendly names — often going back years. This is genuinely surprising to most
people.

**Read-only on purpose.** These registry keys are load-bearing for driver
installation, and deleting them can stop USB devices working until they're
reinstalled.

---

## 13. Vault

### File encryption

**Format:**

```
magic       8 bytes   "PKVAULT1"
cipher id   1 byte    1 = AES-256-GCM, 2 = AES-256-CBC + HMAC-SHA256
salt       16 bytes   random, per file
kdf params  9 bytes   scrypt N, r, p
nonce/iv   16 bytes
ciphertext  variable
tag        16 or 32   GCM tag, or HMAC-SHA256
```

**Key derivation: scrypt, N=2^15, r=8, p=1.** Memory-hard, roughly 32 MB and a
tenth of a second per attempt — enough to make guessing expensive without an
unpleasant wait. Parameters are stored in the file, so files stay readable if
the defaults are raised later. `hashlib.scrypt` is standard library, so this
costs no dependency.

**Two cipher paths.** With `cryptography` installed: AES-256-GCM, with the
header authenticated as associated data so the salt and KDF parameters can't be
tampered with. Without it: PrivacyKit's own AES-256 in CBC mode with
**encrypt-then-MAC** using HMAC-SHA256. The MAC is verified *before* decrypting —
without that, CBC padding errors become a padding oracle, and "wrong password"
becomes indistinguishable from "tampered file".

The built-in AES implementation derives its S-box from the field inverse and
affine transform rather than pasting in 256 hex literals — transcribing tables
by hand is a classic source of silent, catastrophic bugs. It's verified against
the FIPS-197 published vectors for all three key sizes in the self-test.

**Separate keys.** The 64-byte scrypt output is split into independent
encryption and MAC keys rather than reusing one key for both.

> **There is no password recovery, no hint field, and no escrow.** If the
> passphrase is lost, the data is gone — that's what makes the encryption
> meaningful. Write it down somewhere safe before encrypting anything you can't
> afford to lose.

### Encrypted notes

Same cipher and key derivation, base64-armoured so you can paste the result into
an email, a chat message, or a file.

### Password generator

Uses the OS cryptographic random source. **Nothing is sent anywhere** — no
breach lookup, no "check my password" API call.

| Type | Default | Entropy |
|---|---|---|
| Password | 20 chars, mixed | ~128 bits |
| Passphrase | 5 words | 55 bits |
| PIN | 6 digits | ~20 bits |
| Hex key | 32 bytes | 256 bits |

**Every enabled character class is guaranteed to appear**, then the result is
shuffled with a CSPRNG. Without that, a 20-character password can legitimately
contain no digit and fail a site's complexity rule, sending you back to invent
one by hand.

**Ambiguous characters (0/O, 1/l/I) are excluded by default.** A password you
can't read aloud or retype from a screen gets written down, which is a bigger
risk than the two bits of entropy it saves.

The word list holds 2,038 unique words, so five words is 55 bits — comparable to
a nine-character random password and far easier to type on a phone.

**On strength estimation:** the figure shown is entropy-based, derived from how
the password was *generated*. It is a lower bound on the generator, not an
analysis of the string. A password taken from a wordlist scores high here and
falls in seconds to a dictionary attack — which is why the tool shows this
figure for passwords it generated itself. Character-class rules ("has an
uppercase, a digit, and a symbol") are what produced `Password1!` rated as
strong, and are deliberately not used.

### File hashes

MD5, SHA-1, SHA-256, SHA-384, SHA-512, BLAKE2b, SHA3-256. Files are hashed in
1 MB chunks, so multi-gigabyte files don't exhaust memory.

---

## 14. Journal

The page that makes everything else safe to experiment with.

### Entry list

Every change, newest first, showing when, which area, what changed, and whether
it's still applied or already reverted. Select an entry to see its detail — the
exact state before the change, and which undo handler will reverse it.

### Undo selected

Reverse specific changes without touching the rest. Multi-select works, and
undo runs newest-first so a setting changed repeatedly ends on its original
value.

### Export

Writes the full journal plus the baseline snapshot to JSON — useful as a record
of what was done to a machine.

### Clear reverted history

Purges entries that have already been undone. Entries for changes still applied
are kept, so nothing becomes irreversible.

### Where it lives

```
%LOCALAPPDATA%\PrivacyKit\journal.json      the change journal
%LOCALAPPDATA%\PrivacyKit\baseline.json     first-run snapshot
%LOCALAPPDATA%\PrivacyKit\backups\          hosts file backups
```

Deliberately *not* the install directory: the toolkit should work from a
read-only folder or a USB stick, and the journal must survive that. It's written
atomically (temp file + replace), so a crash mid-write can't leave an
unparseable journal — a corrupt journal would mean an unrecoverable machine,
which is the one failure mode the design exists to prevent.

---

## 15. Settings

### How licence verification works

Licences are Ed25519-signed blobs verified **locally** against a public key
embedded in the application. There is no licence server and no network call,
ever — a privacy tool that phones home to check a licence is self-defeating, and
users of this category of software notice immediately.

Because verification is asymmetric, extracting the public key from the binary
gains an attacker nothing. Only the holder of the private key can mint a
licence.

The verifier is implemented in pure Python inside the application. That is
deliberate: if the check were skipped whenever an optional package was missing,
licensing would be defeated by uninstalling a library.

### Editions

| | Free | Pro | Business |
|---|:---:|:---:|:---:|
| MAC spoofing, IP, hostname, Wi-Fi | ✓ | ✓ | ✓ |
| DNS switching and DoH | ✓ | ✓ | ✓ |
| Leak tests and privacy score | ✓ | ✓ | ✓ |
| Trace cleaning | ✓ | ✓ | ✓ |
| Windows privacy tweaks | ✓ | ✓ | ✓ |
| Change journal and Panic Restore | ✓ | ✓ | ✓ |
| Tor control and exit-node selection | | ✓ | ✓ |
| Firewall kill switch | | ✓ | ✓ |
| Location matching | | ✓ | ✓ |
| Profile poisoning | | ✓ | ✓ |
| Live protection and threat feed | | ✓ | ✓ |
| Encryption vault, shredder, metadata | | ✓ | ✓ |
| Tray agent and network automation | | ✓ | ✓ |
| Custom profiles | | ✓ | ✓ |
| Multi-machine deployment, CLI | | | ✓ |

The Free edition is the whole original toolkit, not a crippled demo.

### Trial

Fourteen days of Pro, started from the first-run wizard or Settings. The record
is kept in **two independent stores** — a file and a registry value — each
authenticated with an HMAC keyed to the machine. Deleting one is detected by the
other; editing either breaks its HMAC; when the two disagree the *earlier* start
date wins; and rolling the system clock back is detected.

### Activating

Settings → Licence → **Enter a licence** and paste the block, or **Load licence
file**. If a licence is machine-bound, the seller needs the machine ID shown on
that screen — there is a copy button.

### Custom profiles

Build your own combination from 24 catalogued actions — spoof MAC, set DNS,
route through Tor, arm the kill switch, match location, rotate identifiers,
clean traces, restore everything — in whatever order you like, and run it from
the Dashboard in one click.

A failing step never aborts the rest: if Tor is not running, the DNS and
firewall hardening in the same profile are still worth having. The summary
reports exactly what succeeded, so you are never misled about which protections
are actually live.

### Tray agent

Runs quietly and reacts to events rather than waiting to be asked.

- **Automatic profile on network change.** Joining a network that is not on your
  trusted list applies your chosen profile. The tray notification tells you what
  happened.
- **Trusted networks.** A comma-separated list in Settings that suppresses the
  automatic profile — your home and office Wi-Fi.
- **Notifications** for protection events at warning severity and above.
- **Panic shortcut**, scoped to the application window.
- **Clean traces on exit**, off by default.
- **Run at Windows startup**, which writes a single `Run` key entry that the
  uninstaller removes.

The tray icon changes colour with the protection state, so a glance tells you
whether the kill switch is armed.

---

## 16. Troubleshooting

### "Not running as Administrator"

Close it and use `Run-PrivacyKit.bat`, or right-click → Run as administrator.
Most features write to `HKEY_LOCAL_MACHINE` or the firewall.

### The MAC address doesn't change

In order of likelihood:

1. **The driver doesn't support it.** Check Device Manager → adapter →
   Properties → Advanced for "Network Address" or "Locally Administered
   Address". Missing means no software tool can spoof it.
2. **Try a vendor-range address** rather than locally-administered — a few
   drivers silently reject the latter.
3. **The adapter didn't come back up.** Check Network Connections and re-enable
   it manually.

### The internet stopped working

Almost always the kill switch. Either:
- Protection page → **Disarm**, or
- **PANIC RESTORE** in the header, or
- From an elevated Command Prompt:
  `netsh advfirewall firewall delete rule name=PrivacyKit-KillSwitch-BlockAll`

### Tor is running but "control port closed"

Tor Browser must actually be running (not just installed). For a standalone Tor,
you need `ControlPort 9051` and `CookieAuthentication 1` in torrc, then a
restart. If cookie auth fails with a permission error, run PrivacyKit as the
same user that runs Tor.

### Websites won't load after changing DNS

Some captive portals hijack DNS and break when you use an external resolver.
Set DNS back to automatic, sign in to the portal, then switch back.

### DNS-over-HTTPS isn't available

Your Windows build doesn't expose the `netsh dns` encryption commands. Windows
11 and recent Windows 10 builds do. The resolver change still works — only the
encryption is unavailable.

### "Access denied" cleaning temp files

Normal. Files held open by running programs can't be deleted. Close applications
and re-run; the count of skipped files is reported.

### Decryption fails on a file I encrypted

Either the passphrase is wrong or the file was modified. The tool can't
distinguish these, by design — the authentication check is what tells you the
file is intact, and a system that said "right password, corrupt file" would be
leaking information about the key.

If the file was encrypted on a machine with `cryptography` installed and you're
now on one without it, install it: `pip install cryptography`.

### The window freezes

It shouldn't — long operations run on background threads. If it does, the
operation is probably a `netsh` call waiting on a timeout; give it 30 seconds.

---

## 17. What this cannot protect you from

Stated plainly, because a privacy tool that oversells itself is worse than none —
you'd act on protection you don't have.

**Browser fingerprinting.** Your canvas rendering, installed fonts, screen
dimensions, timezone, and WebGL signature identify you across sites regardless
of IP address. Only Tor Browser meaningfully addresses this.

**Being logged in.** If you sign into an account, you've identified yourself.
Nothing at the network layer changes that.

**Traffic analysis by a global observer.** An adversary who can watch both ends
of a Tor circuit can correlate timing. Tor's own documentation says this.

**Malware already on the machine.** Software running as you can read whatever
you can read, before any of this applies.

**Physical access to the disk.** Trace cleaning is not disk encryption. Turn on
BitLocker.

**Your own habits.** Same username, same writing style, same posting times.

**Legal compulsion.** Providers can be compelled to hand over what they hold.
The defence is choosing providers who hold less — which is why the DNS table
lists each operator's logging stance.

---

## 18. Reference: every file it touches

### Registry

| Key | Purpose |
|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-…}\<nnnn>\NetworkAddress` | MAC override |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` | System proxy |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection` | Telemetry level |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` | Activity history |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo` | Advertising ID |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy` | Tailored experiences |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient` | LLMNR |
| `HKLM\SYSTEM\…\Services\NetBT\Parameters\Interfaces\Tcpip_{guid}` | NetBIOS |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` | Run history (cleared) |
| `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` | USB history (read-only) |

### Files

| Path | Purpose |
|---|---|
| `%SystemRoot%\System32\drivers\etc\hosts` | Telemetry blocklist (backed up first) |
| `%LOCALAPPDATA%\PrivacyKit\journal.json` | Change journal |
| `%LOCALAPPDATA%\PrivacyKit\baseline.json` | First-run snapshot |
| `%LOCALAPPDATA%\PrivacyKit\backups\` | Hosts file backups |

### Commands

`netsh` (interface, advfirewall, dns, wlan, winhttp) · `ipconfig` · `getmac` ·
`sc` · `schtasks` · `wevtutil` · `cipher` · `netstat` · `tasklist` · `arp` ·
PowerShell (`Get-NetAdapter`, `Rename-Computer`, `Get-NetIPConfiguration`,
adapter bindings)

Every one is invoked with arguments passed as a list, never through a shell, so
an adapter name containing a quote or ampersand can't become command injection.

---

## 19. Building and distributing

### Building

```
pip install pyinstaller pillow
python build.py --all
```

Produces `dist/PrivacyKit-Setup-2.1.0.exe` plus `SHA256SUMS.txt`. The spec
excludes the Qt modules PrivacyKit never touches — WebEngine, 3D, multimedia,
QML — which takes the bundle from around 400 MB to under 100. UPX compression is
deliberately **off**: packed binaries are a major antivirus trigger.

### Code signing is not optional

This is the step that decides whether anyone can actually install the software.

- **Unsigned executables are blocked by SmartScreen** when downloaded.
- **A MAC changer plus a trace cleaner is exactly the behaviour profile
  antivirus heuristics flag.** Signing does not eliminate that, but it is the
  precondition for getting a false positive reviewed.

Set `PRIVACYKIT_CERT` (a `.pfx` path) and `PRIVACYKIT_CERT_PASS`, then build
with `--sign`. The script warns loudly when it produces an unsigned build rather
than letting it pass silently.

Before launch: submit the signed binary to the major antivirus vendors for
whitelisting, and publish the SHA-256 sums.

### Issuing licences

```
python tools/keygen.py --new
```

Run once. Paste the printed public key into `VENDOR_PUBLIC_KEY` in
`privacykit/core/licensing.py`, and keep `vendor_private_key.pem` secret and
backed up — losing it means you cannot issue licences; leaking it means anyone
can.

```
python tools/keygen.py --issue "Jane Smith" --edition pro
python tools/keygen.py --issue "ACME Ltd" --edition business --seats 25 --days 365
python tools/keygen.py --issue "Jane" --edition pro --bind 26465879-8AFB4C47-...
```

`tools/` is a vendor directory. Do not ship it.

### What copy protection does and does not achieve

This stops casual sharing: a licence cannot be forged, and one cannot be
machine-bound to someone else's hardware. It does **not** stop a determined
attacker who patches the binary — that is not achievable in a Python
application, and pretending otherwise means spending effort on obfuscation that
only inconveniences paying customers.

---

## Disclaimer

For education, personal privacy, and authorised testing only. Use only on
machines and networks you own or have explicit permission to test. Spoofing
identifiers to evade access controls, bans, or billing on networks you don't
control may violate laws or terms of service in your jurisdiction. The author
accepts no responsibility for misuse.

---

*PrivacyKit 2.1.0 · Nilotpal Vyas*
