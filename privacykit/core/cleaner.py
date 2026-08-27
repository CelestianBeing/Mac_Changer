"""
Trace cleaner — the forensic artefacts Windows leaves behind.

Each cleanable location is a :class:`Target` that can report its size before
anything is deleted, so the UI can show what will happen and the user decides.
Nothing here runs automatically.

An honest note carried into the manual: this removes *convenience* traces —
the things that reveal your activity to someone browsing your machine. It is
not anti-forensics against a proper examination. File system journals, volume
shadow copies, the page file, and slack space all retain evidence that user-
level deletion does not touch. Claiming otherwise would be dangerous.

Deletion here is genuinely irreversible, which is why cleaning is the one
category that does **not** write undo entries — it writes a record of what was
removed instead, so the journal stays honest about it.
"""

from __future__ import annotations

import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from . import journal, shell, sysinfo


@dataclass
class Target:
    key: str
    title: str
    description: str
    paths: List[str] = field(default_factory=list)
    pattern: str = "*"
    recursive: bool = True
    command: Optional[List[str]] = None      # for non-file targets
    risk: str = ""                           # what the user loses
    requires_admin: bool = False

    def resolved(self) -> List[Path]:
        out = []
        for p in self.paths:
            expanded = Path(shell.expand(p))
            if expanded.exists():
                out.append(expanded)
        return out

    def measure(self) -> dict:
        """Count files and bytes without deleting anything."""
        files, size = 0, 0
        for root in self.resolved():
            if root.is_file():
                files += 1
                try:
                    size += root.stat().st_size
                except OSError:
                    pass
                continue
            it = root.rglob(self.pattern) if self.recursive else root.glob(self.pattern)
            for f in it:
                try:
                    if f.is_file():
                        files += 1
                        size += f.stat().st_size
                except OSError:
                    continue
        return {"files": files, "bytes": size}


#: Everything the cleaner knows how to clear.
TARGETS: List[Target] = [
    Target("temp_user", "User temporary files",
           "Everything in your %TEMP% folder. Installers, half-written documents, "
           "and browser downloads-in-progress all pass through here.",
           [r"%TEMP%"], risk="Open applications may lose scratch data."),
    Target("temp_windows", "Windows temporary files",
           "The system-wide temp folder.",
           [r"%SystemRoot%\Temp"], risk="Harmless; some files will be locked and skipped.",
           requires_admin=True),
    Target("prefetch", "Prefetch data",
           "Windows records every program you launch here, with timestamps and "
           "run counts. It is one of the first places a forensic examiner looks.",
           [r"%SystemRoot%\Prefetch"], pattern="*.pf",
           risk="Application launch times get slightly slower until it rebuilds.",
           requires_admin=True),
    Target("recent", "Recent documents list",
           "Shortcuts to every file you have opened, in Explorer's Recent folder.",
           [r"%APPDATA%\Microsoft\Windows\Recent"], pattern="*.lnk",
           risk="The 'Recent files' list in Explorer and Office is emptied."),
    Target("jumplists", "Jump lists",
           "Per-application recent-file lists shown when you right-click a taskbar "
           "icon. They survive clearing the Recent folder and are highly revealing.",
           [r"%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations",
            r"%APPDATA%\Microsoft\Windows\Recent\CustomDestinations"],
           risk="Taskbar right-click menus lose their recent-file entries."),
    Target("thumbnails", "Thumbnail cache",
           "Cached previews of images and documents — including files you have "
           "since deleted. The thumbnail often outlives the picture.",
           [r"%LOCALAPPDATA%\Microsoft\Windows\Explorer"], pattern="thumbcache_*.db",
           risk="Folder thumbnails regenerate on next view, briefly slower."),
    Target("iconcache", "Icon cache",
           "Cached application icons, which reveal what software has been installed.",
           [r"%LOCALAPPDATA%\Microsoft\Windows\Explorer"], pattern="iconcache_*.db",
           risk="Icons rebuild automatically."),
    Target("crash_dumps", "Crash dumps",
           "Memory dumps written when a program crashes. These can contain "
           "fragments of whatever the program had open — documents, passwords, keys.",
           [r"%LOCALAPPDATA%\CrashDumps", r"%SystemRoot%\Minidump"],
           risk="Past crashes can no longer be diagnosed."),
    Target("windows_error_reports", "Windows Error Reporting queue",
           "Reports queued for upload to Microsoft, plus their attached data.",
           [r"%LOCALAPPDATA%\Microsoft\Windows\WER",
            r"%PROGRAMDATA%\Microsoft\Windows\WER"],
           risk="None."),
    Target("recycle_bin", "Recycle Bin",
           "Files you deleted but which are still fully recoverable.",
           [], command=["cmd", "/c", "rd", "/s", "/q", "C:\\$Recycle.Bin"],
           risk="Deleted files become unrecoverable through normal means."),
    Target("dns_cache", "DNS resolver cache",
           "The list of domains this machine has recently looked up. Readable by "
           "anyone at the keyboard with 'ipconfig /displaydns'.",
           [], command=["ipconfig", "/flushdns"],
           risk="First visit to each site is marginally slower."),
    Target("arp_cache", "ARP cache",
           "Records of other devices seen on networks you have joined.",
           [], command=["arp", "-d", "*"], risk="None.", requires_admin=True),
    Target("edge_cache", "Microsoft Edge cache and history",
           "Browsing cache, cookies, and history for Edge.",
           [r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache",
            r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Code Cache"],
           risk="You will be logged out of sites; Edge must be closed first."),
    Target("chrome_cache", "Google Chrome cache",
           "Chrome's on-disk cache of pages, images, and scripts.",
           [r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache",
            r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Code Cache"],
           risk="Sites reload more slowly once; Chrome must be closed first."),
    Target("firefox_cache", "Firefox cache",
           "Firefox's on-disk cache.",
           [r"%LOCALAPPDATA%\Mozilla\Firefox\Profiles"], pattern="cache2*",
           risk="Sites reload more slowly once; Firefox must be closed first."),
    Target("run_mru", "Run dialog history",
           "Everything ever typed into Win+R, stored in the registry.",
           [], command=None, risk="The Run box loses its dropdown history."),
    Target("powershell_history", "PowerShell command history",
           "A plaintext file of every PowerShell command you have run — including "
           "any that contained a password or token.",
           [r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadline"],
           pattern="ConsoleHost_history.txt",
           risk="Up-arrow history in PowerShell is lost."),
    Target("clipboard", "Clipboard contents",
           "Whatever is currently copied, plus Windows' clipboard history if enabled.",
           [], command=["cmd", "/c", "echo off | clip"], risk="None."),
    Target("event_logs", "Windows event logs",
           "System, Application, and Security logs. These record logons, service "
           "starts, and USB insertions.",
           [], command=None,
           risk="SERIOUS: clearing security logs is itself a logged, suspicious "
                "event and breaks troubleshooting. Only do this on a machine you "
                "own and understand.",
           requires_admin=True),
]

TARGETS_BY_KEY = {t.key: t for t in TARGETS}

#: A sensible default selection — traces with real privacy value and low cost.
SAFE_DEFAULTS = ["temp_user", "recent", "jumplists", "thumbnails", "dns_cache",
                 "crash_dumps", "windows_error_reports", "clipboard",
                 "powershell_history", "run_mru"]


def measure_all(keys: Optional[List[str]] = None) -> dict:
    keys = keys or [t.key for t in TARGETS]
    out = {}
    for key in keys:
        t = TARGETS_BY_KEY.get(key)
        if t:
            out[key] = t.measure()
    return out


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} GB"


def clean(keys: List[str], progress: Optional[Callable[[str, bool], None]] = None,
          secure: bool = False) -> dict:
    """
    Delete the selected targets.

    ``secure`` overwrites file contents before unlinking. That is meaningfully
    slower and only helps on spinning disks — on an SSD, wear levelling means
    the original blocks may survive regardless, which the UI says plainly.
    """
    freed, removed, errors = 0, 0, []

    for key in keys:
        t = TARGETS_BY_KEY.get(key)
        if not t:
            continue
        if t.requires_admin and not sysinfo.is_admin():
            errors.append(f"{t.title}: needs Administrator rights")
            if progress:
                progress(f"SKIP  {t.title} — needs Administrator", False)
            continue

        if progress:
            progress(f"Cleaning {t.title}…", True)

        if key == "run_mru":
            ok, msg = _clear_run_mru()
            if progress:
                progress(f"{'OK  ' if ok else 'FAIL'}  {t.title}: {msg}", ok)
            continue
        if key == "event_logs":
            ok, msg = _clear_event_logs()
            if progress:
                progress(f"{'OK  ' if ok else 'FAIL'}  {t.title}: {msg}", ok)
            continue

        if t.command:
            res = shell.run(t.command, check_rc=False, timeout=60)
            ok = res.code == 0 or key in ("recycle_bin",)
            if progress:
                progress(f"{'OK  ' if ok else 'FAIL'}  {t.title}", ok)
            continue

        stats = _delete_target(t, secure=secure)
        freed += stats["bytes"]
        removed += stats["files"]
        if stats["errors"]:
            errors.append(f"{t.title}: {stats['errors']} file(s) locked or in use")
        if progress:
            progress(f"OK    {t.title} — {stats['files']} file(s), "
                     f"{human_size(stats['bytes'])}", True)

    journal.record(
        module="cleaner",
        action=f"Cleaned {len(keys)} trace location(s): {removed} files, {human_size(freed)}",
        undo={"kind": "cleaner.noop"},
        before={"targets": keys, "files": removed, "bytes": freed},
        note="Deletion cannot be undone — this entry is a record, not a restore point.",
    )

    return {"files": removed, "bytes": freed, "human": human_size(freed),
            "errors": errors}


@journal.register_undo("cleaner.noop")
def _undo_clean(payload: dict) -> tuple:
    """
    Deleted files cannot come back.

    Returning True marks the entry resolved so it stops appearing as an
    outstanding change — but the message is explicit that nothing was restored.
    Silently pretending a restore happened would be worse than useless.
    """
    return True, ("nothing to restore — deleted traces are permanently gone "
                  "(this entry is a record of what was removed)")


def _delete_target(t: Target, secure: bool = False) -> dict:
    files, size, errs = 0, 0, 0
    for root in t.resolved():
        targets = [root] if root.is_file() else list(
            root.rglob(t.pattern) if t.recursive else root.glob(t.pattern))
        for f in targets:
            try:
                if not f.is_file():
                    continue
                n = f.stat().st_size
                if secure:
                    _overwrite(f, n)
                f.unlink()
                files += 1
                size += n
            except (OSError, PermissionError):
                errs += 1
        # Prune the empty directories left behind, but never the root itself.
        if root.is_dir():
            for d in sorted(root.rglob("*"), key=lambda p: len(p.parts), reverse=True):
                try:
                    if d.is_dir() and not any(d.iterdir()):
                        d.rmdir()
                except OSError:
                    pass
    return {"files": files, "bytes": size, "errors": errs}


def _overwrite(path: Path, size: int) -> None:
    """Single-pass random overwrite before unlinking."""
    try:
        with open(path, "r+b", buffering=0) as fh:
            chunk = 1 << 16
            written = 0
            while written < size:
                block = os.urandom(min(chunk, size - written))
                fh.write(block)
                written += len(block)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        pass


def _clear_run_mru() -> tuple:
    """Wipe the Win+R dialog's typed-command history from the registry."""
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    import winreg
    path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0,
                            winreg.KEY_READ | winreg.KEY_WRITE) as k:
            names = []
            i = 0
            while True:
                try:
                    names.append(winreg.EnumValue(k, i)[0])
                    i += 1
                except OSError:
                    break
            for n in names:
                try:
                    winreg.DeleteValue(k, n)
                except OSError:
                    pass
        return True, f"cleared {len(names)} entries"
    except FileNotFoundError:
        return True, "no history present"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _clear_event_logs() -> tuple:
    """Clear the main Windows event logs."""
    if not sysinfo.is_admin():
        return False, "Administrator rights are required."
    cleared = 0
    for log in ("Application", "System", "Setup"):
        res = shell.run(["wevtutil", "cl", log], check_rc=False, timeout=45)
        if res.code == 0:
            cleared += 1
    return cleared > 0, (f"cleared {cleared} log(s). Note: clearing the Security "
                         "log writes an event saying so — it is not invisible.")


def usb_history() -> List[dict]:
    """
    Every USB storage device ever plugged into this machine.

    Read-only on purpose. The list is a genuine surprise for most people — the
    registry keeps serial numbers and friendly names of drives connected years
    ago. Removing these keys is deliberately not offered: the entries are load-
    bearing for driver installation and deleting them can stop USB devices
    working until reinstalled.
    """
    if not sysinfo.IS_WINDOWS:
        return []
    import winreg
    out = []
    path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
            i = 0
            while True:
                try:
                    device = winreg.EnumKey(k, i)
                    i += 1
                except OSError:
                    break
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                        rf"{path}\{device}") as dk:
                        j = 0
                        while True:
                            try:
                                serial = winreg.EnumKey(dk, j)
                                j += 1
                            except OSError:
                                break
                            friendly = ""
                            try:
                                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                                    rf"{path}\{device}\{serial}") as sk:
                                    friendly = str(winreg.QueryValueEx(sk, "FriendlyName")[0])
                            except Exception:
                                pass
                            out.append({"device": device, "serial": serial,
                                        "name": friendly})
                except OSError:
                    continue
    except Exception:
        pass
    return out
