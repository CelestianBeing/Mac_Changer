"""
First-run wizard.

Four short steps. The goal is not to configure everything — it is to explain
what the application does to a machine, confirm the user understands that it
makes real changes, and capture the baseline before anything is touched.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QDialog, QHBoxLayout, QLabel,
                               QStackedWidget, QVBoxLayout, QWidget)

from .. import __version__
from ..core import journal, licensing, sysinfo
from ..core.settings import settings
from .theme import theme
from .widgets.controls import (Card, NoteBox, SettingRow, ToggleSwitch, button,
                               divider, muted, section_label)
from .widgets.gauges import StatusDot


class OnboardingWizard(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setModal(True)
        self.setFixedSize(720, 620)
        self.setStyleSheet(f"background: {theme.p.base};")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        root = QWidget()
        root.setObjectName("Root")
        root.setStyleSheet(
            f"#Root {{ background: {theme.p.base};"
            f"border: 1px solid {theme.p.border}; border-radius: 12px; }}")
        outer.addWidget(root)

        lay = QVBoxLayout(root)
        lay.setContentsMargins(38, 34, 38, 28)
        lay.setSpacing(18)

        self.stack = QStackedWidget()
        lay.addWidget(self.stack, 1)

        self.stack.addWidget(self._welcome())
        self.stack.addWidget(self._how_it_works())
        self.stack.addWidget(self._elevation())
        self.stack.addWidget(self._licence())

        lay.addWidget(divider())

        nav = QHBoxLayout()
        nav.setSpacing(10)
        self.dots = QHBoxLayout()
        self.dots.setSpacing(6)
        self._dot_widgets = []
        for i in range(self.stack.count()):
            dot = StatusDot(theme.p.border_strong, 6)
            self._dot_widgets.append(dot)
            self.dots.addWidget(dot)
        nav.addLayout(self.dots)
        nav.addStretch()

        self.back_btn = button("Back", "ghost", self._back)
        nav.addWidget(self.back_btn)
        self.next_btn = button("Continue", "primary", self._next)
        nav.addWidget(self.next_btn)
        lay.addLayout(nav)

        self._update_nav()

    # ── steps ──
    def _welcome(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setSpacing(16)

        mark = QLabel("◆")
        mark.setStyleSheet(f"color: {theme.p.accent}; font-size: 44px;")
        mark.setAlignment(Qt.AlignCenter)
        lay.addWidget(mark)

        title = QLabel("Welcome to PrivacyKit")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(
            f"color: {theme.p.text}; font-size: 26px; font-weight: 700;")
        lay.addWidget(title)

        sub = QLabel(f"Version {__version__} · Windows privacy toolkit")
        sub.setAlignment(Qt.AlignCenter)
        sub.setStyleSheet(f"color: {theme.p.text_muted}; font-size: 13px;")
        lay.addWidget(sub)

        lay.addSpacing(10)
        for icon, title_text, desc in (
            ("⬡", "Change what identifies you",
             "MAC address, computer name, local IP, and the location signals "
             "Windows gives away."),
            ("⚯", "Control where traffic goes",
             "Tor, system proxy, and encrypted DNS — with a firewall kill "
             "switch behind them so a failure blocks rather than leaks."),
            ("✂", "Remove what you leave behind",
             "Trace cleaning, secure deletion, and metadata stripping."),
            ("≡", "Undo all of it",
             "Every change is recorded before it is made. One button puts the "
             "machine back."),
        ):
            row = QHBoxLayout()
            row.setSpacing(14)
            ic = QLabel(icon)
            ic.setFixedWidth(28)
            ic.setStyleSheet(f"color: {theme.p.accent}; font-size: 18px;")
            ic.setAlignment(Qt.AlignTop | Qt.AlignHCenter)
            row.addWidget(ic)
            text = QVBoxLayout()
            text.setSpacing(2)
            t = QLabel(title_text)
            t.setStyleSheet(
                f"color: {theme.p.text}; font-size: 14px; font-weight: 600;")
            text.addWidget(t)
            text.addWidget(muted(desc, 12))
            row.addLayout(text, 1)
            lay.addLayout(row)

        lay.addStretch()
        return page

    def _how_it_works(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setSpacing(16)

        title = QLabel("This makes real changes to Windows")
        title.setStyleSheet(
            f"color: {theme.p.text}; font-size: 21px; font-weight: 700;")
        lay.addWidget(title)

        lay.addWidget(muted(
            "PrivacyKit is not a dashboard that reports on your settings. It "
            "edits the registry, rewrites firewall rules, changes DNS servers, "
            "and modifies the hosts file. Those changes persist across reboots.",
            13))

        lay.addWidget(NoteBox(
            "Everything is recorded in a change journal before it is applied, "
            "together with the exact state it is replacing. The Panic Restore "
            "button in the titlebar reverts all of it, newest change first.\n\n"
            "The exceptions are deletions — cleaned traces and shredded files "
            "cannot come back. Those are always confirmed first.", "info"))

        lay.addWidget(divider())
        lay.addWidget(section_label("Before we start"))

        self.baseline_toggle = ToggleSwitch(True)
        lay.addWidget(SettingRow(
            "Capture a baseline snapshot",
            "Records this machine's current settings as a safety net behind the "
            "journal. Strongly recommended — it costs nothing and is the only "
            "record of “before” if the journal is ever lost.",
            self.baseline_toggle))

        lay.addStretch()
        return page

    def _elevation(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setSpacing(16)

        elevated = sysinfo.is_admin()
        title = QLabel("Administrator rights"
                       if not elevated else "Running with full access")
        title.setStyleSheet(
            f"color: {theme.p.text}; font-size: 21px; font-weight: 700;")
        lay.addWidget(title)

        if elevated:
            lay.addWidget(NoteBox(
                "PrivacyKit is running elevated, so every feature is available.",
                "good"))
        else:
            lay.addWidget(NoteBox(
                "PrivacyKit is not running as Administrator. Changing MAC "
                "addresses, DNS servers, firewall rules, and Windows privacy "
                "settings all write to protected areas and will be refused.\n\n"
                "You can continue — leak tests, the encryption vault, the "
                "password generator, the metadata scrubber, and the file "
                "shredder all work without elevation. To unlock the rest, close "
                "PrivacyKit and start it again with 'Run as administrator'.",
                "warning"))

        lay.addWidget(divider())
        lay.addWidget(section_label("What gets stored, and where"))
        lay.addWidget(muted(
            "The change journal, baseline snapshot, settings, and licence live "
            f"in your user profile:\n\n{sysinfo.appdata_dir()}\n\n"
            "Nothing is sent anywhere. PrivacyKit makes no network requests "
            "except the ones you trigger — leak tests, blocklist updates, and "
            "Tor exit-IP checks.", 12))
        lay.addStretch()
        return page

    def _licence(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setSpacing(16)

        title = QLabel("Choose how to start")
        title.setStyleSheet(
            f"color: {theme.p.text}; font-size: 21px; font-weight: 700;")
        lay.addWidget(title)

        trial = licensing.get_trial()
        lay.addWidget(muted(
            "The Free edition covers MAC spoofing, DNS, leak tests, trace "
            "cleaning, Windows hardening, and the change journal — the whole "
            "original toolkit.\n\n"
            "Pro adds Tor control, the kill switch, location matching, profile "
            "poisoning, live protection, the encryption vault, and tray "
            "automation.", 13))

        self.trial_toggle = ToggleSwitch(not trial.ever_started)
        self.trial_toggle.setEnabled(not trial.ever_started)
        lay.addWidget(SettingRow(
            f"Start the {licensing.TRIAL_DAYS}-day Pro trial",
            trial.describe()
            + ("" if not trial.ever_started else
               " — a licence will still activate normally."),
            self.trial_toggle))

        lay.addWidget(divider())
        lay.addWidget(muted(
            "You can enter a licence at any time from Settings. Licences are "
            "verified offline against an embedded key — PrivacyKit never "
            "contacts a licence server.", 12))
        lay.addStretch()
        return page

    # ── navigation ──
    def _update_nav(self) -> None:
        index = self.stack.currentIndex()
        last = self.stack.count() - 1
        self.back_btn.setVisible(index > 0)
        self.next_btn.setText("Get started" if index == last else "Continue")
        for i, dot in enumerate(self._dot_widgets):
            dot.set_state(theme.p.accent if i <= index else theme.p.border_strong)

    def _next(self) -> None:
        index = self.stack.currentIndex()
        if index < self.stack.count() - 1:
            self.stack.setCurrentIndex(index + 1)
            self._update_nav()
            return
        self._finish()

    def _back(self) -> None:
        index = self.stack.currentIndex()
        if index > 0:
            self.stack.setCurrentIndex(index - 1)
            self._update_nav()

    def _finish(self) -> None:
        settings.set("auto_capture_baseline", self.baseline_toggle.isChecked())
        if self.trial_toggle.isEnabled() and self.trial_toggle.isChecked():
            licensing.start_trial()
        settings.set("onboarding_complete", True)
        settings.set("version_seen", __version__)
        self.done(1)
