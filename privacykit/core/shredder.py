"""
Secure file deletion.

What overwriting actually achieves, stated up front because most shredder
tools overstate it:

* On a **magnetic hard disk**, overwriting a file's blocks does destroy the
  data in place. A single pass is sufficient against any practical recovery;
  multi-pass patterns are a holdover from 1990s drive densities.
* On an **SSD, NVMe drive, or USB flash**, it largely does not work. Wear
  levelling means the controller writes your overwrite to *different* physical
  cells and leaves the originals marked stale but intact until garbage
  collection gets to them. The only reliable equivalents are full-disk
  encryption from the start, or the drive's own secure-erase command.
* Either way, copies may survive elsewhere: shadow copies, backups, the page
  file, hibernation file, and the filesystem journal.

The UI states this before shredding. A tool that promises unrecoverable
deletion on an SSD and does not deliver leaves the user worse off than one that
is honest, because they act on a guarantee they do not have.
"""

from __future__ import annotations

import os
import random
import secrets
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from . import journal, shell, sysinfo

#: Named overwrite schemes. "random" is the sane default.
PATTERNS = {
    "zero": ("Single pass of zeros", [b"\x00"]),
    "random": ("Single random pass (recommended)", [None]),
    "dod3": ("DoD 5220.22-M three-pass (zeros, ones, random)",
             [b"\x00", b"\xFF", None]),
    "dod7": ("DoD seven-pass", [b"\x00", b"\xFF", None, b"\x96", b"\x00", b"\xFF", None]),
    "gutmann_lite": ("35-pass Gutmann-style (very slow, no practical benefit)",
                     [None] * 35),
}


@dataclass
class ShredResult:
    ok: bool
    message: str
    files: int = 0
    bytes_wiped: int = 0
    errors: List[str] = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


def drive_type(path: str) -> str:
    """
    Best-effort guess: is this file on an SSD or a spinning disk?

    Used to warn the user when overwriting will not do what they expect.
    """
    if not sysinfo.IS_WINDOWS:
        return "unknown"
    try:
        drive = Path(path).resolve().drive.rstrip(":")
        if not drive:
            return "unknown"
        res = shell.run_powershell(
            f"$p=Get-Partition -DriveLetter {drive} -ErrorAction SilentlyContinue;"
            "if($p){(Get-PhysicalDisk | Where-Object {$_.DeviceId -eq "
            "(Get-Disk -Number $p.DiskNumber).Number}).MediaType}", timeout=25)
        out = res.out.strip().lower()
        if "ssd" in out:
            return "SSD"
        if "hdd" in out:
            return "HDD"
        return out or "unknown"
    except Exception:
        return "unknown"


def shred_file(path: str, passes: int = 1, pattern: str = "random",
               rename: bool = True,
               progress: Optional[Callable[[str], None]] = None) -> ShredResult:
    """
    Overwrite and delete a single file.

    Also renames the file to random characters and truncates it before
    unlinking. That matters: the filename itself is metadata stored in the
    directory entry, and "2026 tax return.pdf" left in the MFT is informative
    even with the contents gone.
    """
    p = Path(path)
    if not p.is_file():
        return ShredResult(False, f"'{path}' is not a file.")

    try:
        size = p.stat().st_size
    except OSError as exc:
        return ShredResult(False, f"Cannot read file size: {exc}")

    scheme = PATTERNS.get(pattern, PATTERNS["random"])[1]
    if passes > 1 and pattern == "random":
        scheme = [None] * passes

    try:
        # Clear read-only, which would otherwise block the overwrite.
        try:
            os.chmod(p, 0o666)
        except OSError:
            pass

        with open(p, "r+b", buffering=0) as fh:
            for idx, fill in enumerate(scheme, 1):
                if progress:
                    progress(f"{p.name}: pass {idx}/{len(scheme)}")
                fh.seek(0)
                remaining = size
                chunk_size = 1 << 20
                while remaining > 0:
                    n = min(chunk_size, remaining)
                    block = os.urandom(n) if fill is None else fill * n
                    fh.write(block)
                    remaining -= n
                fh.flush()
                os.fsync(fh.fileno())

            # Truncate so the file length stops being a clue.
            fh.seek(0)
            fh.truncate(0)
            fh.flush()
            os.fsync(fh.fileno())

        final = p
        if rename:
            for _ in range(3):
                new_name = "".join(secrets.choice(string.ascii_lowercase + string.digits)
                                   for _ in range(len(p.name)))
                candidate = p.with_name(new_name)
                if candidate.exists():
                    continue
                try:
                    final.rename(candidate)
                    final = candidate
                except OSError:
                    break

        final.unlink()
    except PermissionError:
        return ShredResult(False, f"'{p.name}' is in use or protected — close it and retry.")
    except Exception as exc:
        return ShredResult(False, f"{type(exc).__name__}: {exc}")

    media = drive_type(str(p.parent))
    caveat = ""
    if media == "SSD":
        caveat = (" Note: this file was on an SSD, where wear levelling means the "
                  "original blocks may still exist physically.")
    return ShredResult(True, f"Shredded '{p.name}' ({len(scheme)} pass(es)).{caveat}",
                       files=1, bytes_wiped=size)


def shred_paths(paths: List[str], passes: int = 1, pattern: str = "random",
                progress: Optional[Callable[[str, bool], None]] = None) -> ShredResult:
    """Shred several files and/or whole directory trees."""
    files, total, errors = 0, 0, []
    expanded: List[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            expanded.extend(f for f in p.rglob("*") if f.is_file())
        elif p.is_file():
            expanded.append(p)
        else:
            errors.append(f"not found: {raw}")

    for f in expanded:
        res = shred_file(str(f), passes=passes, pattern=pattern)
        if progress:
            progress(f"{'OK  ' if res.ok else 'FAIL'}  {f.name}"
                     + ("" if res.ok else f" — {res.message}"), res.ok)
        if res.ok:
            files += 1
            total += res.bytes_wiped
        else:
            errors.append(f"{f.name}: {res.message}")

    # Remove the now-empty directories the user asked to shred.
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for d in sorted(p.rglob("*"), key=lambda q: len(q.parts), reverse=True):
                try:
                    if d.is_dir():
                        d.rmdir()
                except OSError:
                    pass
            try:
                p.rmdir()
            except OSError:
                pass

    if files:
        journal.record(
            module="shredder",
            action=f"Shredded {files} file(s), {total:,} bytes",
            undo={"kind": "shredder.noop"},
            before={"files": files, "bytes": total},
            note="Shredded files cannot be recovered — this entry is a record only.",
        )

    return ShredResult(files > 0, f"Shredded {files} file(s).", files, total, errors)


@journal.register_undo("shredder.noop")
def _undo_shred(payload: dict) -> tuple:
    return True, "nothing to restore — shredded files are gone by design"


def wipe_free_space(drive: str = "C:",
                    progress: Optional[Callable[[str], None]] = None) -> ShredResult:
    """
    Overwrite unallocated space so previously-deleted files become unrecoverable.

    Uses Windows' own ``cipher /w``, which is the right tool: it is built in,
    understands NTFS internals, and does not risk filling the disk in a way that
    breaks the system. It is slow — expect tens of minutes on a large drive.
    """
    if not sysinfo.IS_WINDOWS:
        return ShredResult(False, "Windows-only.")
    letter = drive.rstrip("\\").rstrip(":")
    if progress:
        progress(f"Wiping free space on {letter}: — this can take a long time…")
    res = shell.run(["cipher", "/w:" + letter + ":\\"], check_rc=False, timeout=600)
    ok = res.code == 0
    return ShredResult(ok, ("Free space wiped — previously deleted files on "
                            f"{letter}: are no longer recoverable by normal means."
                            if ok else f"cipher failed: {res.text[:200]}"))


def estimate_time(paths: List[str], passes: int = 1) -> str:
    """Rough duration estimate, so the user is not surprised by a long wait."""
    total = 0
    for raw in paths:
        p = Path(raw)
        try:
            if p.is_file():
                total += p.stat().st_size
            elif p.is_dir():
                total += sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
        except OSError:
            continue
    # ~80 MB/s is a conservative figure for random-fill writes.
    seconds = (total * passes) / (80 * 1024 * 1024) if total else 0
    if seconds < 5:
        return "a few seconds"
    if seconds < 90:
        return f"about {int(seconds)} seconds"
    if seconds < 3600:
        return f"about {int(seconds / 60)} minutes"
    return f"about {seconds / 3600:.1f} hours"
