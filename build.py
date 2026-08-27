#!/usr/bin/env python3
"""
Release build script.

    python build.py                 build the application
    python build.py --installer     build, then compile the Inno Setup installer
    python build.py --sign          sign the executable and installer
    python build.py --clean         remove build artefacts first
    python build.py --all           clean, build, sign, package

Signing is the step that decides whether anyone can actually install this.
Windows SmartScreen blocks unsigned executables downloaded from the internet,
and a MAC changer plus trace cleaner is exactly the behaviour profile that
antivirus heuristics flag. Set PRIVACYKIT_CERT and PRIVACYKIT_CERT_PASS (or use
Azure Trusted Signing) before shipping to anyone.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
BUILD = ROOT / "build"
SPEC = ROOT / "build_tools" / "privacykit.spec"
ISS = ROOT / "build_tools" / "installer.iss"

VERSION = "2.1.0"

# Common Inno Setup install locations.
ISCC_CANDIDATES = [
    r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    r"C:\Program Files\Inno Setup 6\ISCC.exe",
]

# Windows SDK signtool.
SIGNTOOL_GLOBS = [
    r"C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe",
    r"C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe",
]

TIMESTAMP_URL = "http://timestamp.digicert.com"


def log(message: str, kind: str = "info") -> None:
    prefix = {"info": "  ", "ok": "OK ", "warn": "!! ", "err": "XX "}[kind]
    print(f"{prefix} {message}", flush=True)


def clean() -> None:
    for path in (DIST, BUILD):
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)
            log(f"removed {path.name}/", "ok")
    for pycache in ROOT.rglob("__pycache__"):
        shutil.rmtree(pycache, ignore_errors=True)


def write_version_info() -> None:
    """Generate the Windows VERSIONINFO resource embedded in the executable."""
    major, minor, patch = (VERSION.split(".") + ["0", "0"])[:3]
    content = f"""VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({major}, {minor}, {patch}, 0),
    prodvers=({major}, {minor}, {patch}, 0),
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0,
    date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'Nilotpal Vyas'),
      StringStruct('FileDescription', 'PrivacyKit — Windows privacy toolkit'),
      StringStruct('FileVersion', '{VERSION}'),
      StringStruct('InternalName', 'PrivacyKit'),
      StringStruct('LegalCopyright', 'Copyright (c) 2026 Nilotpal Vyas'),
      StringStruct('OriginalFilename', 'PrivacyKit.exe'),
      StringStruct('ProductName', 'PrivacyKit'),
      StringStruct('ProductVersion', '{VERSION}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""
    (ROOT / "build_tools" / "version_info.txt").write_text(content,
                                                           encoding="utf-8")
    log("version resource written", "ok")


def make_icon() -> None:
    """
    Generate the application icon if one is not already present.

    Drawn rather than shipped so the repository has no binary blobs and the
    icon always matches the accent colour in the theme.
    """
    icon = ROOT / "build_tools" / "privacykit.ico"
    if icon.exists():
        return
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        log("Pillow not installed — building without a custom icon "
            "(pip install Pillow to generate one)", "warn")
        return

    layers = []
    for size in (16, 24, 32, 48, 64, 128, 256):
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        s = size / 64.0
        shield = [(32 * s, 4 * s), (57 * s, 15 * s), (57 * s, 34 * s),
                  (32 * s, 60 * s), (7 * s, 34 * s), (7 * s, 15 * s)]
        d.polygon(shield, fill=(76, 141, 255, 255))
        if size >= 32:
            d.ellipse([(25 * s, 25 * s), (39 * s, 39 * s)],
                      fill=(10, 12, 17, 255))
        layers.append(img)
    layers[0].save(icon, format="ICO",
                   sizes=[(i.width, i.height) for i in layers])
    log(f"icon generated ({icon.name})", "ok")


def build_app() -> bool:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        log("PyInstaller is not installed:  pip install pyinstaller", "err")
        return False

    write_version_info()
    make_icon()

    log("running PyInstaller (this takes a few minutes)…")
    result = subprocess.run(
        [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
         str(SPEC)],
        cwd=str(ROOT))
    if result.returncode != 0:
        log("PyInstaller failed", "err")
        return False

    target = DIST / "PrivacyKit" / "PrivacyKit.exe"
    if not target.exists():
        log(f"expected executable not found at {target}", "err")
        return False

    total = sum(f.stat().st_size for f in (DIST / "PrivacyKit").rglob("*")
                if f.is_file())
    log(f"built {target.name} — bundle is {total / 1024 / 1024:.0f} MB", "ok")
    return True


def find_tool(candidates, globs=()) -> str | None:
    for path in candidates:
        if Path(path).exists():
            return path
    import glob as globmod
    for pattern in globs:
        matches = sorted(globmod.glob(pattern), reverse=True)
        if matches:
            return matches[0]
    return None


def sign(paths) -> bool:
    """
    Authenticode-sign the given files.

    Reads the certificate from PRIVACYKIT_CERT (a .pfx path) and
    PRIVACYKIT_CERT_PASS. If neither is set, signing is skipped with a loud
    warning rather than silently producing an unsigned build that will be
    blocked on every machine it reaches.
    """
    cert = os.environ.get("PRIVACYKIT_CERT")
    password = os.environ.get("PRIVACYKIT_CERT_PASS", "")

    if not cert:
        log("PRIVACYKIT_CERT is not set — build is UNSIGNED.", "warn")
        log("  SmartScreen will block this for end users, and several "
            "antivirus engines flag unsigned MAC-changing tools.", "warn")
        log("  Options: an OV/EV code-signing certificate from a CA, or "
            "Azure Trusted Signing.", "warn")
        return False

    signtool = find_tool([], SIGNTOOL_GLOBS)
    if not signtool:
        log("signtool.exe not found — install the Windows SDK", "err")
        return False

    ok = True
    for target in paths:
        if not Path(target).exists():
            continue
        cmd = [signtool, "sign", "/fd", "SHA256", "/f", cert]
        if password:
            cmd += ["/p", password]
        cmd += ["/tr", TIMESTAMP_URL, "/td", "SHA256", str(target)]
        result = subprocess.run(cmd)
        if result.returncode == 0:
            log(f"signed {Path(target).name}", "ok")
        else:
            log(f"signing failed for {Path(target).name}", "err")
            ok = False
    return ok


def build_installer() -> bool:
    iscc = find_tool(ISCC_CANDIDATES)
    if not iscc:
        log("Inno Setup 6 not found — install it from jrsoftware.org", "err")
        return False
    log("compiling installer…")
    result = subprocess.run([iscc, str(ISS)], cwd=str(ISS.parent))
    if result.returncode != 0:
        log("installer compilation failed", "err")
        return False
    setup = DIST / f"PrivacyKit-Setup-{VERSION}.exe"
    if setup.exists():
        log(f"{setup.name} — {setup.stat().st_size / 1024 / 1024:.0f} MB", "ok")
    return True


def checksums() -> None:
    """Write SHA-256 sums so users can verify what they downloaded."""
    import hashlib
    lines = []
    for target in sorted(DIST.glob("*.exe")):
        h = hashlib.sha256()
        with open(target, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        lines.append(f"{h.hexdigest()}  {target.name}")
    if lines:
        (DIST / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n",
                                             encoding="utf-8")
        log("SHA256SUMS.txt written", "ok")


def main() -> int:
    ap = argparse.ArgumentParser(description="Build PrivacyKit for release")
    ap.add_argument("--clean", action="store_true")
    ap.add_argument("--installer", action="store_true")
    ap.add_argument("--sign", action="store_true")
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()

    if sys.platform != "win32":
        log("Release builds must run on Windows — PyInstaller does not "
            "cross-compile.", "err")
        return 1

    started = time.time()
    print(f"\nPrivacyKit {VERSION} — release build\n" + "─" * 52)

    if args.clean or args.all:
        clean()

    if not build_app():
        return 1

    if args.sign or args.all:
        sign([DIST / "PrivacyKit" / "PrivacyKit.exe"])

    if args.installer or args.all:
        if not build_installer():
            return 1
        if args.sign or args.all:
            sign([DIST / f"PrivacyKit-Setup-{VERSION}.exe"])
        checksums()

    print("─" * 52)
    log(f"done in {time.time() - started:.0f}s", "ok")
    log(f"output in {DIST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
