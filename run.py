#!/usr/bin/env python3
"""
PrivacyKit launcher.

    python run.py                start normally
    python run.py --no-elevate   skip the UAC prompt
    python run.py --tray         start minimised to the system tray
    python run.py --restore-all  revert every change, no window (uninstaller)
    python run.py --version      print the version and exit

Most of the toolkit writes to HKEY_LOCAL_MACHINE and the Windows Firewall, both
of which need Administrator rights. You can decline elevation and still use the
diagnostics, the encryption vault, the password generator, the metadata
scrubber, and the file shredder.

Disclaimer: for education, personal privacy, and authorised testing only.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def _maybe_elevate() -> bool:
    """Offer a UAC relaunch. Returns True if this process should now exit."""
    from privacykit.core import sysinfo
    if not sysinfo.IS_WINDOWS or sysinfo.is_admin():
        return False
    if "--no-elevate" in sys.argv or "--tray" in sys.argv:
        return False
    return sysinfo.relaunch_as_admin()


def _check_qt() -> bool:
    try:
        import PySide6  # noqa: F401
        return True
    except ImportError:
        return False


def _restore_all_silent() -> int:
    """
    Headless Panic Restore.

    Called by the uninstaller so removing PrivacyKit does not strand a machine
    with a spoofed MAC, a kill switch, and rewritten DNS that nothing is left
    to reverse. Prints a summary and returns non-zero if anything failed, so
    the installer can react.
    """
    from privacykit.core import journal
    pending = journal.pending_count()
    if pending == 0:
        print("PrivacyKit has no outstanding changes to revert.")
        return 0

    print(f"Reverting {pending} change(s)…")
    result = journal.panic_restore(
        progress=lambda msg, ok: print("  " + msg))
    print(f"Restored {result['restored']}, failed {result['failed']}, "
          f"skipped {result['skipped']}.")
    return 0 if result["failed"] == 0 else 2


def main() -> int:
    if sys.version_info < (3, 9):
        print("PrivacyKit needs Python 3.9 or newer.")
        return 1

    if "--restore-all" in sys.argv:
        return _restore_all_silent()

    if "--version" in sys.argv:
        from privacykit import __version__
        print(f"PrivacyKit {__version__}")
        return 0

    if not _check_qt():
        print("PrivacyKit's interface needs PySide6:\n\n"
              "    pip install PySide6\n")
        return 1

    if _maybe_elevate():
        return 0

    from privacykit.gui.app import run
    return run()


if __name__ == "__main__":
    sys.exit(main())
