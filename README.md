# MAC Changer — Windows 11

A lightweight GUI tool to spoof your network adapter's MAC address on Windows 11.
Built with Python and Tkinter — no third-party dependencies required.

## Features

- Detects all network adapters automatically (via `getmac`, with an `ipconfig` fallback)
- Change to a custom or randomly generated MAC address
- Auto-rotate MAC on a timer (seconds / minutes / hours) with a live countdown
- Restore each adapter's original hardware MAC with one click
- Changes persist across reboots (written to the adapter's registry key)
- Dark-themed UI with a live activity log

## Requirements

- Windows 11 (or Windows 10 — same registry mechanism)
- Python 3.10+
- Administrator privileges (the tool writes to `HKEY_LOCAL_MACHINE`)

No pip packages needed — everything used (`tkinter`, `winreg`, `ctypes`, etc.) ships with a standard Python install on Windows.

## Usage

1. Right-click `macchange_gui.py` → **Run as administrator**
   (the app will still open without this, but changes will fail — it shows a warning if it's not elevated)
2. Pick an adapter from the dropdown
3. Enter a MAC address (format `AA:BB:CC:DD:EE:FF`) or click **Random MAC**
4. Click **Apply Change** — the adapter is briefly disabled/re-enabled to apply it
5. Click **Restore Original** at any time to revert to the adapter's real hardware MAC

### Auto-rotate

Set an interval and unit (seconds/minutes/hours) and click **Start** to have the MAC change automatically on a schedule. A live countdown shows time until the next rotation. Minimum interval is 5 seconds, since each rotation briefly cycles the adapter and needs time to reconnect.

## How it works

Windows lets you override a NIC's MAC address via the `NetworkAddress` registry value under its adapter class key (`...\Control\Class\{4D36E972-...}\<nnnn>`), rather than editing hardware. This tool:

1. Looks up the adapter's GUID and matching registry subkey
2. Writes the new MAC as `NetworkAddress`
3. Disables and re-enables the adapter (via `netsh`) so Windows picks up the change
4. **Restore** simply deletes the `NetworkAddress` override, which reverts to the burned-in hardware address

## Notes on this version

A few stability fixes were made on top of the original:

- **Cross-platform crash fixed** — previously, running this on non-Windows failed with a raw `ImportError` on `winreg` before the window even opened. It now shows a clear "Windows only" dialog and exits.
- **Per-adapter "original MAC" tracking** — the original code stored a single "original MAC" for the whole session. If you switched adapters, Restore could apply the wrong adapter's original MAC. It's now tracked per adapter.
- **MAC validation tightened** — addresses with the multicast bit set, or all-zero/broadcast (`00:00:00:00:00:00`, `FF:FF:FF:FF:FF:FF`), are now rejected, since Windows adapters can't actually use them.
- **Minimum auto-rotate interval** — each rotation cycles the adapter, which takes ~1.5s+ to settle. Intervals under 5 seconds are now blocked to avoid leaving the adapter in a broken state.
- **Background threads no longer fail silently** — unexpected errors during apply/restore/auto-rotate are now caught and logged in the activity log instead of leaving a button stuck (e.g. "Applying…" forever) or crashing a worker thread.

## Troubleshooting

- **"Not running as Administrator"** — right-click the script and choose *Run as administrator*.
- **MAC doesn't change after Apply** — some adapters (especially certain Wi-Fi chipsets) don't support the `NetworkAddress` override at all. Check Device Manager → your adapter → Properties → Advanced tab for a "Network Address"/"Locally Administered Address" entry; if it's missing, the driver doesn't support software MAC spoofing.
- **No adapters listed** — the tool relies on the `getmac` and `ipconfig` system commands; make sure they haven't been removed/blocked by policy.

## Disclaimer

This tool is intended for educational and authorized testing purposes only — for example, protecting your privacy on public Wi-Fi, or testing network configurations you own. Only use it on networks and devices you own or have explicit permission to test. Spoofing a MAC address to evade network access controls, bans, or billing on networks you don't control may violate laws or terms of service in your jurisdiction. The author is not responsible for misuse.
