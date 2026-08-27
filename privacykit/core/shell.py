"""
Thin, safe wrappers around subprocess.

Everything in PrivacyKit that shells out to a Windows utility goes through
here, so that we have exactly one place that:

  * hides the console window (otherwise every netsh call flashes a black box
    over the GUI),
  * enforces a timeout (a hung ``netsh`` should never freeze the app),
  * decodes output defensively (Windows console codepages are not UTF-8),
  * never uses ``shell=True`` (arguments are passed as a list, so an adapter
    name containing a quote or ampersand cannot turn into command injection).
"""

from __future__ import annotations

import locale
import os
import subprocess
import sys
from dataclasses import dataclass, field

#: Windows-only flag that stops a console window appearing for each call.
_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0

# Console output on Windows is usually the OEM codepage (cp437/cp850/cp1252),
# not UTF-8. Guess once at import time and always fall back to "replace".
try:
    _CONSOLE_ENCODING = locale.getpreferredencoding(False) or "utf-8"
except Exception:  # pragma: no cover - defensive
    _CONSOLE_ENCODING = "utf-8"


@dataclass
class Result:
    """Outcome of a shell command."""

    ok: bool
    code: int
    out: str = ""
    err: str = ""
    cmd: list = field(default_factory=list)

    @property
    def text(self) -> str:
        """stdout plus stderr, for the common 'just show me everything' case."""
        return (self.out + ("\n" + self.err if self.err.strip() else "")).strip()

    def __bool__(self) -> bool:
        return self.ok


def _decode(raw: bytes) -> str:
    if not raw:
        return ""
    for enc in (_CONSOLE_ENCODING, "utf-8", "cp1252"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


def run(args, timeout: int = 25, check_rc: bool = True) -> Result:
    """
    Run ``args`` (a list) and return a :class:`Result`.

    ``check_rc=False`` marks the result ok regardless of exit status, which is
    what we want for commands like ``netsh`` that return non-zero for benign
    "nothing to do" conditions.
    """
    if isinstance(args, str):  # guard against accidental string usage
        args = [args]
    args = [str(a) for a in args]
    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            creationflags=_NO_WINDOW,
        )
    except FileNotFoundError:
        return Result(False, 127, "", f"command not found: {args[0]}", args)
    except subprocess.TimeoutExpired:
        return Result(False, 124, "", f"timed out after {timeout}s: {' '.join(args)}", args)
    except Exception as exc:  # pragma: no cover - defensive
        return Result(False, 1, "", f"{type(exc).__name__}: {exc}", args)

    out, err = _decode(proc.stdout), _decode(proc.stderr)
    ok = (proc.returncode == 0) if check_rc else True
    return Result(ok, proc.returncode, out, err, args)


def run_powershell(script: str, timeout: int = 40) -> Result:
    """
    Run a PowerShell snippet.

    Used only where there is no plain-Win32 equivalent (WMI queries, Defender
    state, scheduled tasks). ``-NoProfile`` keeps a user's profile script from
    polluting output; ``-NonInteractive`` stops it blocking on a prompt.
    """
    return run(
        [
            "powershell", "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass", "-Command", script,
        ],
        timeout=timeout,
        check_rc=False,
    )


def which(name: str) -> bool:
    """True if ``name`` is an executable on PATH."""
    from shutil import which as _which
    return _which(name) is not None


def expand(path: str) -> str:
    """Expand ``%VARS%`` and ``~`` in a Windows path."""
    return os.path.expandvars(os.path.expanduser(path))
