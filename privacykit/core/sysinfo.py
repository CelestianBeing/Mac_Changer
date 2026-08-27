"""
Platform detection, privilege checks, and app data paths.

Importing this module is safe on any OS: nothing here raises on Linux/macOS,
which lets the self-test suite run outside Windows.
"""

from __future__ import annotations

import ctypes
import getpass
import os
import platform
import socket
import sys
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"


def is_admin() -> bool:
    """True when the current process holds an elevated (Administrator) token."""
    if not IS_WINDOWS:
        try:
            return os.geteuid() == 0  # type: ignore[attr-defined]
        except AttributeError:
            return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """
    Re-launch this program elevated via the UAC prompt.

    Returns True if the elevated process was started (in which case the caller
    should exit). Returns False if elevation failed or the user declined.
    """
    if not IS_WINDOWS or is_admin():
        return False
    try:
        params = " ".join(f'"{a}"' for a in sys.argv)
        # ShellExecuteW returns >32 on success.
        rc = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
            None, "runas", sys.executable, params, None, 1
        )
        return rc > 32
    except Exception:
        return False


def appdata_dir() -> Path:
    """
    Per-user directory for the change journal, backups, and the vault index.

    Deliberately *not* the install directory: the toolkit should work from a
    read-only folder or a USB stick, and the journal must survive that.
    """
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or str(Path.home())
    else:
        base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    d = Path(base) / "PrivacyKit"
    try:
        d.mkdir(parents=True, exist_ok=True)
        (d / "backups").mkdir(exist_ok=True)
    except Exception:
        d = Path.home() / ".privacykit"
        d.mkdir(parents=True, exist_ok=True)
        (d / "backups").mkdir(exist_ok=True)
    return d


def backups_dir() -> Path:
    return appdata_dir() / "backups"


def os_summary() -> dict:
    """Human-readable snapshot of the host, shown on the dashboard."""
    info = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "hostname": socket.gethostname(),
        "user": _safe_user(),
        "python": platform.python_version(),
        "admin": is_admin(),
        "is_windows": IS_WINDOWS,
    }
    if IS_WINDOWS:
        info["edition"] = _windows_edition()
    return info


def _safe_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"


def _windows_edition() -> str:
    """Read the marketing product name straight out of the registry."""
    try:
        import winreg  # noqa: WPS433 - Windows-only, guarded by IS_WINDOWS
        key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
            name, _ = winreg.QueryValueEx(k, "ProductName")
            try:
                build = int(winreg.QueryValueEx(k, "CurrentBuildNumber")[0])
                # Microsoft never changed ProductName for Windows 11; build
                # 22000+ is the real dividing line.
                if build >= 22000 and "Windows 10" in name:
                    name = name.replace("Windows 10", "Windows 11")
                return f"{name} (build {build})"
            except Exception:
                return str(name)
    except Exception:
        return "Windows"


def optional_modules() -> dict:
    """
    Report which optional accelerator libraries are installed.

    PrivacyKit is fully functional on a bare Python install; these libraries
    only make certain paths faster or richer, and the dashboard surfaces which
    ones are active so behaviour is never mysterious.
    """
    found = {}
    for mod, purpose in (
        ("cryptography", "hardware-accelerated AES for the vault"),
        ("requests", "faster HTTP for leak tests"),
        ("socks", "PySocks proxying (built-in SOCKS5 used otherwise)"),
        ("stem", "richer Tor controller features"),
        ("PIL", "deeper image metadata scrubbing"),
        ("psutil", "process names for the connection monitor"),
    ):
        try:
            __import__(mod)
            found[mod] = (True, purpose)
        except Exception:
            found[mod] = (False, purpose)
    return found
