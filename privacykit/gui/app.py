"""
Main window.

A frameless shell holding the titlebar, sidebar, and a stacked page area.
Pages are constructed lazily the first time they are opened, which keeps
start-up fast despite the amount of surface area behind the nav.
"""

from __future__ import annotations

import sys
from typing import Dict, Optional

from PySide6.QtCore import (QEasingCurve, QPoint, QPropertyAnimation, QRect,
                            QSize, Qt, QTimer, Signal)
from PySide6.QtGui import QColor, QGuiApplication, QIcon, QKeySequence, QShortcut
from PySide6.QtWidgets import (QApplication, QFrame, QGraphicsOpacityEffect,
                               QHBoxLayout, QLabel, QMainWindow, QStackedWidget,
                               QVBoxLayout, QWidget)

from .. import __appname__, __version__
from ..core import journal, licensing, protection, sysinfo
from ..core.settings import settings
from .dialogs import confirm, inform, show_log
from .theme import Fonts, SECTION_COLOURS, theme
from .widgets.chrome import Sidebar, TitleBar, Toast
from .widgets.controls import Badge, button, muted
from . import workers

#: (key, label, icon, group)
SECTIONS = [
    ("Dashboard", "Dashboard", "◈", ""),
    ("Identity", "Identity", "⬡", "Network"),
    ("Connection", "Connection", "⚯", "Network"),
    ("Location", "Location", "◎", "Network"),
    ("Protection", "Protection", "⛨", "Defence"),
    ("Privacy", "Privacy", "⚙", "Defence"),
    ("Diagnostics", "Diagnostics", "◉", "Defence"),
    ("Cleanup", "Cleanup", "✂", "Data"),
    ("Vault", "Vault", "🔒", "Data"),
    ("Journal", "Journal", "≡", "Data"),
    ("Settings", "Settings", "⚙", ""),
]


class MainWindow(QMainWindow):
    protection_event = Signal(object)

    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground, False)
        self.setWindowTitle(f"{__appname__} {__version__}")
        self.resize(1320, 860)
        self.setMinimumSize(1120, 720)

        self.adapter: str = ""
        self.pages: Dict[str, QWidget] = {}
        self._current: Optional[str] = None
        self._log_lines: list = []
        self._resize_edge = None
        self._resize_origin = None

        self._build()
        self._restore_geometry()

        self.protection_event.connect(self._handle_protection_event)
        self.navigate("Dashboard")

        QTimer.singleShot(400, self._post_start)

    # ── construction ──
    def _build(self) -> None:
        root = QWidget()
        root.setObjectName("Root")
        self.setCentralWidget(root)

        outer = QVBoxLayout(root)
        outer.setContentsMargins(1, 1, 1, 1)
        outer.setSpacing(0)

        self.titlebar = TitleBar()
        self.titlebar.minimise_requested.connect(self.showMinimized)
        self.titlebar.maximise_requested.connect(self._toggle_maximise)
        self.titlebar.close_requested.connect(self.close)
        self.titlebar.panic_requested.connect(self.panic_restore)
        outer.addWidget(self.titlebar)

        middle = QHBoxLayout()
        middle.setContentsMargins(0, 0, 0, 0)
        middle.setSpacing(0)
        outer.addLayout(middle, 1)

        self.sidebar = Sidebar(SECTIONS)
        self.sidebar.navigate.connect(self.navigate)
        middle.addWidget(self.sidebar)

        self._build_sidebar_footer()

        self.stack = QStackedWidget()
        self.stack.setObjectName("Content")
        middle.addWidget(self.stack, 1)

        self.toast = Toast(self)

    def _build_sidebar_footer(self) -> None:
        ent = licensing.entitlement()
        self.edition_label = QLabel()
        self.edition_label.setStyleSheet(
            f"color: {theme.p.text_faint}; font-size: 11px;")
        self.sidebar.add_footer_widget(self.edition_label)

        self.upgrade_btn = button("View licence", "ghost",
                                  lambda: self.navigate("Settings"))
        self.upgrade_btn.setStyleSheet(
            "QPushButton { font-size: 11px; padding: 5px 10px; }")
        self.sidebar.add_footer_widget(self.upgrade_btn)

        version = QLabel(f"v{__version__}")
        version.setStyleSheet(
            f"color: {theme.p.text_faint}; font-size: 10px; padding-top: 4px;")
        self.sidebar.add_footer_widget(version)

    # ── navigation ──
    def navigate(self, key: str) -> None:
        if key == self._current:
            return
        page = self.pages.get(key)
        if page is None:
            page = self._create_page(key)
            if page is None:
                return
            self.pages[key] = page
            self.stack.addWidget(page)

        self.stack.setCurrentWidget(page)
        self.sidebar.set_active(key)
        self._current = key

        # Fade the page in — a hard swap between two dense screens reads as a
        # flicker, and this is cheap.
        effect = QGraphicsOpacityEffect(page)
        page.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", page)
        anim.setDuration(140)
        anim.setStartValue(0.35)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        anim.finished.connect(lambda: page.setGraphicsEffect(None))
        anim.start(QPropertyAnimation.DeleteWhenStopped)
        page._fade_anim = anim   # keep a reference alive

        if hasattr(page, "on_show"):
            try:
                page.on_show()
            except Exception as exc:
                self.notify(f"{key}: {exc}", "warning")

    def _create_page(self, key: str) -> Optional[QWidget]:
        from .pages import (cleanup, connection, dashboard, diagnostics,
                            identity, journal as journal_page, location,
                            privacy, protection as protection_page,
                            settings_page, vault)
        builders = {
            "Dashboard": dashboard.DashboardPage,
            "Identity": identity.IdentityPage,
            "Connection": connection.ConnectionPage,
            "Location": location.LocationPage,
            "Protection": protection_page.ProtectionPage,
            "Privacy": privacy.PrivacyPage,
            "Diagnostics": diagnostics.DiagnosticsPage,
            "Cleanup": cleanup.CleanupPage,
            "Vault": vault.VaultPage,
            "Journal": journal_page.JournalPage,
            "Settings": settings_page.SettingsPage,
        }
        cls = builders.get(key)
        if cls is None:
            return None
        try:
            return cls(self)
        except Exception as exc:
            import traceback
            traceback.print_exc()
            holder = QWidget()
            lay = QVBoxLayout(holder)
            lay.addWidget(QLabel(f"Could not open “{key}”:\n\n"
                                 f"{type(exc).__name__}: {exc}"))
            lay.addStretch()
            return holder

    def rebuild_pages(self) -> None:
        """
        Discard and rebuild pages after a licence change.

        Feature gating is baked in at build time — an upsell panel is a
        different widget tree from the real controls — so a licence change has
        to rebuild rather than just refresh.
        """
        current = self._current
        for key, page in list(self.pages.items()):
            self.stack.removeWidget(page)
            page.deleteLater()
        self.pages.clear()
        self._current = None
        self.navigate(current or "Dashboard")

    def refresh_dashboard(self) -> None:
        page = self.pages.get("Dashboard")
        if page and hasattr(page, "refresh"):
            page.refresh()

    # ── shared services for pages ──
    def set_adapter(self, name: str) -> None:
        self.adapter = name

    def notify(self, message: str, kind: str = "good") -> None:
        self.toast.show_message(message, kind)
        self.log(message)

    def log(self, line: str) -> None:
        self._log_lines.append(line)
        del self._log_lines[:-500]

    def refresh_status(self) -> None:
        workers.run(self._gather_status, on_result=self._paint_status)

    @staticmethod
    def _gather_status() -> dict:
        from ..core import firewall, proxy, tor
        try:
            return {
                "pending": journal.pending_count(),
                "tor": tor.is_running(),
                "proxy": proxy.get_state().enabled,
                "killswitch": firewall.killswitch_active(),
                "live": protection.service.running,
            }
        except Exception:
            return {}

    def _paint_status(self, d) -> None:
        if not isinstance(d, dict):
            return
        p = theme.p
        self.titlebar.set_changes(d.get("pending", 0))

        ent = licensing.entitlement(refresh=True)
        colour = (p.success if ent.source == "license"
                  else p.info if ent.source == "trial" else p.text_muted)
        self.titlebar.set_edition(
            "PRO" if ent.edition >= licensing.Edition.PRO else "FREE", colour)
        self.edition_label.setText(ent.name)
        self.upgrade_btn.setVisible(ent.source != "license")

        score = sum([d.get("tor", False), d.get("proxy", False),
                     d.get("killswitch", False)])
        if d.get("killswitch") and d.get("tor") and d.get("proxy"):
            self.titlebar.set_status("Fully protected", p.success, True)
        elif score >= 2:
            self.titlebar.set_status("Partially protected", p.info)
        elif d.get("live"):
            self.titlebar.set_status("Monitoring", p.info, True)
        else:
            self.titlebar.set_status("Not protected", p.text_muted)

        self.sidebar.set_badge(
            "Journal", str(d.get("pending", 0)) if d.get("pending") else "")

    def on_protection_event(self, event) -> None:
        """Called from the watcher thread — hop to the GUI thread via a signal."""
        self.protection_event.emit(event)

    def _handle_protection_event(self, event) -> None:
        if settings.get("notify_events", True):
            self.notify(f"{event.title} — {event.detail}", event.severity)
        page = self.pages.get("Protection")
        if page and hasattr(page, "_refresh_events"):
            page._refresh_events()

    # ── theme ──
    def apply_theme(self) -> None:
        theme.set_mode(settings.get("theme", "dark"))
        theme.set_accent(settings.get("accent", "blue"))
        QApplication.instance().setStyleSheet(theme.stylesheet())
        self.rebuild_pages()

    # ── panic ──
    def panic_restore(self) -> None:
        count = journal.pending_count()
        if count == 0:
            return inform(self, "Nothing to restore",
                          "PrivacyKit has no outstanding changes recorded.\n\n"
                          "Anything changed outside this application, or before "
                          "the journal existed, is not tracked here.", "info")

        if not confirm(self, "Revert every change?",
                       f"Revert all {count} change(s) PrivacyKit has made?\n\n"
                       "This restores MAC addresses, IP and DNS settings, "
                       "proxy, firewall rules, computer name, location "
                       "signals, and Windows privacy settings to the state "
                       "they were in before each change.\n\n"
                       "Deleted files cannot be brought back.",
                       "Revert everything", "critical"):
            return

        self.titlebar.panic_btn.setEnabled(False)
        self.titlebar.panic_btn.setText("  Restoring…  ")

        def done(result):
            self.titlebar.panic_btn.setEnabled(True)
            self.titlebar.panic_btn.setText("  ⏻  Panic Restore  ")
            if not isinstance(result, dict):
                return
            self.notify(
                f"Restore finished — {result['restored']} reverted, "
                f"{result['failed']} failed, {result['skipped']} skipped.",
                "good" if not result["failed"] else "warning")
            show_log(self, "Panic Restore results", result["details"],
                     "good" if not result["failed"] else "warning")
            for page in self.pages.values():
                if hasattr(page, "refresh"):
                    try:
                        page.refresh()
                    except Exception:
                        pass
            self.refresh_status()

        workers.run(journal.panic_restore, on_result=done)

    # ── window management ──
    def _toggle_maximise(self) -> None:
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    def _restore_geometry(self) -> None:
        stored = settings.get("window_geometry", "")
        if not stored:
            screen = QGuiApplication.primaryScreen()
            if screen:
                area = screen.availableGeometry()
                self.move(area.center() - QPoint(self.width() // 2,
                                                 self.height() // 2))
            return
        try:
            x, y, w, h = (int(v) for v in stored.split(","))
            self.setGeometry(x, y, w, h)
        except Exception:
            pass

    def _save_geometry(self) -> None:
        if self.isMaximized():
            return
        g = self.geometry()
        settings.set("window_geometry",
                     f"{g.x()},{g.y()},{g.width()},{g.height()}")

    # ── lifecycle ──
    def _post_start(self) -> None:
        self.refresh_status()

        if not sysinfo.is_admin() and sysinfo.IS_WINDOWS:
            self.notify(
                "Not running as Administrator — most system changes will be "
                "refused. Restart elevated for full function.", "warning")

        if settings.get("auto_capture_baseline", True) and not journal.has_baseline():
            workers.run(self._capture_baseline)

        if settings.get("live_protection") and licensing.has_feature("protection"):
            protection.service.on_event = self.on_protection_event
            protection.service.start()

        stored = settings.get("protection_watchers", {})
        for watcher in protection.service.watchers:
            if watcher.name in stored:
                watcher.enabled = bool(stored[watcher.name])

    @staticmethod
    def _capture_baseline() -> None:
        from ..core import (dnsconf, firewall, geo, hostname, ipconf, mac,
                            proxy, wifi)
        data = {}
        for name, fn in (("mac", mac.snapshot), ("ip", ipconf.snapshot),
                         ("dns", dnsconf.snapshot), ("proxy", proxy.snapshot),
                         ("hostname", hostname.snapshot),
                         ("firewall", firewall.snapshot), ("wifi", wifi.snapshot),
                         ("geo", geo.snapshot)):
            try:
                data[name] = fn()
            except Exception as exc:
                data[name] = {"error": str(exc)}
        journal.save_baseline(data)

    def closeEvent(self, event) -> None:
        self._save_geometry()

        if settings.get("clean_on_shutdown"):
            try:
                from ..core import cleaner
                cleaner.clean(cleaner.SAFE_DEFAULTS)
            except Exception:
                pass

        count = journal.pending_count()
        if count and settings.get("restore_on_exit_prompt", True):
            from .dialogs import Dialog
            dlg = Dialog(self, "Outstanding changes",
                         f"PrivacyKit has {count} change(s) still applied to "
                         "this machine — a spoofed MAC, DNS settings, firewall "
                         "rules, and so on.\n\nLeaving them applied is a "
                         "legitimate choice; they persist across reboots.",
                         "warning")
            dlg.add_button("Stay open", "ghost", 0)
            dlg.add_button("Leave changes and quit", "ghost", 2)
            dlg.add_button("Restore and quit", "primary", 1)
            result = dlg.exec()
            if result == 0:
                event.ignore()
                return
            if result == 1:
                journal.panic_restore()

        protection.service.stop()
        try:
            from ..core import noise
            noise.generator.stop()
        except Exception:
            pass
        event.accept()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if self.toast.isVisible():
            self.toast.move(self.width() - self.toast.width() - 26,
                            self.height() - self.toast.height() - 22)


def run() -> int:
    """Create the application and show the window."""
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName(__appname__)
    app.setApplicationVersion(__version__)
    app.setOrganizationName("PrivacyKit")

    Fonts.resolve()
    theme.set_mode(settings.get("theme", "dark"))
    theme.set_accent(settings.get("accent", "blue"))
    app.setStyleSheet(theme.stylesheet())

    if not settings.get("onboarding_complete"):
        from .onboarding import OnboardingWizard
        wizard = OnboardingWizard()
        if wizard.exec() != 1:
            return 0
        settings.set("onboarding_complete", True)

    window = MainWindow()
    window.show()

    tray = None
    if settings.get("tray_enabled", True):
        try:
            from .tray import TrayAgent
            tray = TrayAgent(window)
            tray.show()
        except Exception:
            tray = None

    return app.exec()
