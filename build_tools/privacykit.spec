# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for PrivacyKit.

Build with:  python build.py

Notes that matter for this particular application:

* ``console=False`` — a console window flashing behind a privacy tool looks
  like malware and alarms people.
* ``uac_admin=False`` — the application asks for elevation itself, with an
  explanation, rather than demanding it before the user knows what it is.
  Forcing UAC at launch means anyone who wants to look around first cannot.
* The Qt modules PrivacyKit does not use are excluded. A default PySide6 bundle
  drags in WebEngine, 3D, and multimedia and lands around 400 MB; trimming gets
  it under 100.
"""

import sys
from pathlib import Path

BLOCK_CIPHER = None
ROOT = Path(SPECPATH).parent

a = Analysis(
    [str(ROOT / "run.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[
        (str(ROOT / "docs"), "docs"),
        (str(ROOT / "LICENSE.txt"), "."),
    ],
    hiddenimports=[
        "privacykit.gui.pages.dashboard",
        "privacykit.gui.pages.identity",
        "privacykit.gui.pages.connection",
        "privacykit.gui.pages.location",
        "privacykit.gui.pages.protection",
        "privacykit.gui.pages.privacy",
        "privacykit.gui.pages.diagnostics",
        "privacykit.gui.pages.cleanup",
        "privacykit.gui.pages.vault",
        "privacykit.gui.pages.journal",
        "privacykit.gui.pages.settings_page",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Qt modules PrivacyKit never touches. Each of these is tens of MB.
        "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets",
        "PySide6.QtWebEngineQuick", "PySide6.QtWebChannel",
        "PySide6.Qt3DCore", "PySide6.Qt3DRender", "PySide6.Qt3DAnimation",
        "PySide6.Qt3DExtras", "PySide6.Qt3DInput", "PySide6.Qt3DLogic",
        "PySide6.QtMultimedia", "PySide6.QtMultimediaWidgets",
        "PySide6.QtQuick", "PySide6.QtQuick3D", "PySide6.QtQml",
        "PySide6.QtCharts", "PySide6.QtDataVisualization",
        "PySide6.QtBluetooth", "PySide6.QtNfc", "PySide6.QtPositioning",
        "PySide6.QtSensors", "PySide6.QtSerialPort", "PySide6.QtSql",
        "PySide6.QtTest", "PySide6.QtDesigner", "PySide6.QtHelp",
        "PySide6.QtOpenGL", "PySide6.QtPdf", "PySide6.QtPdfWidgets",
        # Scientific stack occasionally pulled in transitively.
        "matplotlib", "numpy", "scipy", "pandas", "PIL", "tkinter",
        "pytest", "IPython", "notebook",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=BLOCK_CIPHER,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=BLOCK_CIPHER)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="PrivacyKit",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,           # UPX-packed binaries are a major antivirus trigger
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / "build_tools" / "privacykit.ico")
        if (ROOT / "build_tools" / "privacykit.ico").exists() else None,
    version=str(ROOT / "build_tools" / "version_info.txt")
        if (ROOT / "build_tools" / "version_info.txt").exists() else None,
    uac_admin=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="PrivacyKit",
)
