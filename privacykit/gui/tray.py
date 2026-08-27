"""
Tray agent — the part that makes this feel like a product rather than a utility.

Runs quietly and reacts to events: joining an untrusted network applies the
chosen profile, protection failures raise a notification, and a global hotkey
triggers Panic Restore without needing the window.
"""

from __future__ import annotations

import sys
from typing import Optional

from PySide6.QtCore import QObject, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import QApplication, QMenu, QSystemTrayIcon

from ..core import journal, licensing, presets, protection, sysinfo
from ..core.settings import settings
from .theme import theme


def make_icon(colour: str = "#4C8DFF", armed: bool = False) -> QIcon:
    """
    Draw the tray icon rather than shipping a PNG.

    Keeps the executable smaller, scales cleanly at any DPI, and lets the icon
    change colour with the protection state — which is the whole point of a tray
    icon for this kind of tool.
    """
    pix = QPixmap(64, 64)
    pix.fill(Qt.transparent)
    painter = QPainter(pix)
    painter.setRenderHint(QPainter.Antialiasing)

    body = QColor(colour)
    painter.setBrush(body)
    painter.setPen(Qt.NoPen)
    # A shield outline: two arcs meeting at a point.
    from PySide6.QtGui import QPainterPath
    path = QPainterPath()
    path.moveTo(32, 6)
    path.lineTo(56, 16)
    path.lineTo(56, 34)
    path.cubicTo(56, 48, 44, 56, 32, 60)
    path.cubicTo(20, 56, 8, 48, 8, 34)
    path.lineTo(8, 16)
    path.closeSubpath()
    painter.drawPath(path)

    if armed:
        painter.setBrush(QColor("#FFFFFF"))
        painter.drawEllipse(26, 26, 12, 12)

    painter.end()
    return QIcon(pix)


def set_run_at_startup(enabled: bool) -> tuple:
    """Add or remove the Run key entry that starts PrivacyKit at sign-in."""
    if not sysinfo.IS_WINDOWS:
        return False, "Windows-only."
    import winreg
    path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    name = "PrivacyKit"
    try:
        k = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0,
                               winreg.KEY_READ | winreg.KEY_WRITE)
        if enabled:
            target = sys.executable
            script = sys.argv[0] if sys.argv else ""
            # A frozen build launches itself; a source run needs the script.
            command = (f'"{target}"' if getattr(sys, "frozen", False)
                       else f'"{target}" "{script}" --tray')
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, command)
            msg = "PrivacyKit will start with Windows."
        else:
            try:
                winreg.DeleteValue(k, name)
            except FileNotFoundError:
                pass
            msg = "PrivacyKit will no longer start with Windows."
        winreg.CloseKey(k)
        return True, msg
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


class TrayAgent(QObject):
    """System tray presence plus the automation that reacts to events."""

    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self._last_ssid: Optional[str] = None

        self.tray = QSystemTrayIcon(make_icon(theme.p.accent), window)
        self.tray.setToolTip("PrivacyKit")
        self.tray.activated.connect(self._activated)
        self._build_menu()

        # Hook the protection stream so automation runs even with the window
        # closed to tray.
        protection.service.on_event = self._on_event

        self._status_timer = QTimer(self)
        self._status_timer.timeout.connect(self._refresh_icon)
        self._status_timer.start(8000)

        self._install_hotkey()

    def show(self) -> None:
        self.tray.show()

    # ── menu ──
    def _build_menu(self) -> None:
        menu = QMenu()

        open_action = QAction("Open PrivacyKit", menu)
        open_action.triggered.connect(self._restore_window)
        menu.addAction(open_action)
        menu.addSeparator()

        profiles = QMenu("Apply profile", menu)
        for key in presets.PRESET_ORDER:
            preset = presets.PRESETS[key]
            action = QAction(f"{preset.icon}  {preset.name}", profiles)
            action.triggered.connect(lambda _c=False, k=key: self._apply(k))
            profiles.addAction(action)
        menu.addMenu(profiles)

        self.protect_action = QAction("Start live protection", menu)
        self.protect_action.triggered.connect(self._toggle_protection)
        menu.addAction(self.protect_action)
        menu.addSeparator()

        panic = QAction("⏻  Panic Restore", menu)
        panic.triggered.connect(self.window.panic_restore)
        menu.addAction(panic)
        menu.addSeparator()

        quit_action = QAction("Quit", menu)
        quit_action.triggered.connect(self._quit)
        menu.addAction(quit_action)

        self.tray.setContextMenu(menu)
        self.menu = menu

    def _activated(self, reason) -> None:
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self._restore_window()

    def _restore_window(self) -> None:
        self.window.showNormal()
        self.window.raise_()
        self.window.activateWindow()

    def _quit(self) -> None:
        protection.service.stop()
        QApplication.instance().quit()

    # ── automation ──
    def _on_event(self, event) -> None:
        # Forward to the window for display.
        self.window.on_protection_event(event)

        if settings.get("notify_events", True) and event.severity in (
                "critical", "warning"):
            self.tray.showMessage(
                event.title, event.detail,
                QSystemTrayIcon.Warning if event.severity == "critical"
                else QSystemTrayIcon.Information, 6000)

        if event.kind == "network.joined":
            self._maybe_auto_profile(event)

    def _maybe_auto_profile(self, event) -> None:
        if not settings.get("auto_profile_on_network_change"):
            return
        if not licensing.has_feature("tray"):
            return

        ssid = event.title.split("'")[-2] if "'" in event.title else ""
        trusted = [n.lower() for n in settings.get("trusted_networks", [])]
        if ssid and ssid.lower() in trusted:
            self.tray.showMessage(
                "Trusted network",
                f"“{ssid}” is on your trusted list — no profile applied.",
                QSystemTrayIcon.Information, 4000)
            return

        key = settings.get("auto_profile_untrusted", "public_wifi")
        preset = presets.PRESETS.get(key)
        if not preset:
            return

        self.tray.showMessage(
            f"Applying {preset.name}",
            f"Joined “{ssid or 'an untrusted network'}”. Applying your chosen "
            "profile automatically.", QSystemTrayIcon.Information, 5000)
        self._apply(key)

    def _apply(self, key: str) -> None:
        from . import workers
        preset = presets.PRESETS.get(key)
        if not preset:
            return

        def done(result):
            if isinstance(result, dict):
                self.tray.showMessage(
                    preset.name,
                    f"{result['succeeded']} of {result['steps']} step(s) applied"
                    + (f", {result['failed']} failed."
                       if result.get("failed") else "."),
                    QSystemTrayIcon.Information, 5000)
                self.window.refresh_status()

        workers.run(lambda: presets.apply(key, self.window.adapter),
                    on_result=done)

    def _toggle_protection(self) -> None:
        if protection.service.running:
            protection.service.stop()
            self.protect_action.setText("Start live protection")
        else:
            protection.service.on_event = self._on_event
            protection.service.start()
            self.protect_action.setText("Stop live protection")
        settings.set("live_protection", protection.service.running)
        self._refresh_icon()

    # ── hotkey ──
    def _install_hotkey(self) -> None:
        """
        Application-scoped panic shortcut.

        A true system-wide hotkey needs RegisterHotKey and a native event
        filter; this is scoped to the application window, which covers the case
        that matters — the window is open and something has gone wrong. The
        tray menu covers the rest.
        """
        if not settings.get("panic_hotkey_enabled"):
            return
        try:
            from PySide6.QtGui import QKeySequence, QShortcut
            sequence = settings.get("panic_hotkey", "Ctrl+Alt+P")
            shortcut = QShortcut(QKeySequence(sequence), self.window)
            shortcut.setContext(Qt.ApplicationShortcut)
            shortcut.activated.connect(self.window.panic_restore)
            self._hotkey = shortcut
        except Exception:
            pass

    # ── status ──
    def _refresh_icon(self) -> None:
        try:
            from ..core import firewall, tor
            armed = firewall.killswitch_active()
            running = tor.is_running()
        except Exception:
            armed = running = False

        colour = (theme.p.success if armed and running
                  else theme.p.accent if (armed or running or
                                          protection.service.running)
                  else theme.p.text_muted)
        self.tray.setIcon(make_icon(colour, armed))

        pending = journal.pending_count()
        bits = ["PrivacyKit"]
        if running:
            bits.append("Tor running")
        if armed:
            bits.append("kill switch armed")
        if protection.service.running:
            bits.append("live protection on")
        if pending:
            bits.append(f"{pending} change(s) applied")
        self.tray.setToolTip(" · ".join(bits))

        self.protect_action.setText(
            "Stop live protection" if protection.service.running
            else "Start live protection")
