"""Settings — preferences, custom profiles, licence, and about."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QComboBox, QFileDialog, QGridLayout, QHBoxLayout,
                               QLabel, QLineEdit, QPlainTextEdit, QVBoxLayout,
                               QWidget)
from PySide6.QtGui import QColor

from ... import __version__
from ...core import licensing, sysinfo
from ...core.settings import (ACTION_CATALOGUE, ACTIONS_BY_KEY, CustomProfile,
                              profile_store, settings)
from ..dialogs import confirm, inform, prompt
from ..theme import ACCENTS, SECTION_COLOURS, theme
from ..widgets.controls import (Badge, Card, InfoRow, NoteBox, SettingRow,
                                ToggleSwitch, button, divider, muted,
                                section_label)
from .. import workers
from .base import Page

ACCENT = SECTION_COLOURS["Settings"]


class SettingsPage(Page):
    title = "Settings"
    subtitle = "Preferences, your own profiles, and licensing."
    icon = "⚙"

    def build(self) -> None:
        self._build_licence()
        self._build_appearance()
        self._build_behaviour()
        self._build_automation()
        self._build_profiles()
        self._build_about()

    # ── licence ──
    def _build_licence(self) -> None:
        card = Card("Licence", "Verified offline against an embedded public "
                    "key. PrivacyKit never contacts a licence server — a "
                    "privacy tool that phones home to check a licence would be "
                    "self-defeating.", ACCENT, "◆")

        self.licence_rows = {}
        for key, label in (("edition", "Edition"), ("licensee", "Licensed to"),
                           ("expires", "Expires"), ("trial", "Trial"),
                           ("fingerprint", "This machine"),
                           ("locked", "Locked features")):
            r = InfoRow(label, "—", mono=(key == "fingerprint"))
            card.body.addWidget(r)
            self.licence_rows[key] = r

        r = QHBoxLayout()
        r.setSpacing(10)
        r.addWidget(button("Start 14-day trial", "primary", self._start_trial))
        r.addWidget(button("Enter a licence…", "ghost", self._enter_licence))
        r.addWidget(button("Load licence file…", "ghost", self._load_licence))
        r.addWidget(button("Remove licence", "ghost", self._remove_licence))
        r.addWidget(button("Copy machine ID", "ghost", self._copy_fingerprint))
        r.addStretch()
        card.body.addLayout(r)

        self.locked_box = QVBoxLayout()
        self.locked_box.setSpacing(4)
        card.body.addLayout(self.locked_box)
        self.content.addWidget(card)

    # ── appearance ──
    def _build_appearance(self) -> None:
        card = Card("Appearance", accent=ACCENT, icon="◑")

        theme_combo = QComboBox()
        theme_combo.addItems(["dark", "light"])
        theme_combo.setCurrentText(settings.get("theme", "dark"))
        theme_combo.setMaximumWidth(150)
        theme_combo.currentTextChanged.connect(self._set_theme)
        card.body.addWidget(SettingRow(
            "Theme", "Dark is the default and what the palette was designed "
            "around.", theme_combo))

        accent_row = QWidget()
        arow = QHBoxLayout(accent_row)
        arow.setContentsMargins(0, 0, 0, 0)
        arow.setSpacing(7)
        for name, (colour, _h, _p, _fg) in ACCENTS.items():
            swatch = button("", "ghost", lambda n=name: self._set_accent(n))
            swatch.setFixedSize(28, 28)
            swatch.setToolTip(name.capitalize())
            swatch.setStyleSheet(
                f"QPushButton {{ background: {colour}; border-radius: 14px;"
                f"border: 2px solid {'#FFFFFF' if name == theme.accent_name else 'transparent'}; }}")
            arow.addWidget(swatch)
        card.body.addWidget(SettingRow("Accent colour", "", accent_row))
        self.content.addWidget(card)

    # ── behaviour ──
    def _build_behaviour(self) -> None:
        card = Card("Behaviour", accent=ACCENT, icon="⚙")
        self.behaviour_toggles = {}
        for key, title, desc in (
            ("confirm_destructive", "Confirm before destructive actions",
             "Ask before cleaning, shredding, or anything else that cannot be "
             "undone."),
            ("restore_on_exit_prompt", "Ask about outstanding changes on exit",
             "Offer to revert applied changes when you close the application."),
            ("auto_capture_baseline", "Capture a baseline snapshot on first run",
             "Records the machine's original settings as a safety net behind "
             "the journal."),
            ("minimise_to_tray", "Minimise to the system tray",
             "Keeps the tray agent running when you close the window."),
            ("run_at_startup", "Run at Windows startup",
             "Starts the tray agent when you sign in."),
        ):
            toggle = ToggleSwitch(bool(settings.get(key)))
            toggle.toggled.connect(lambda v, k=key: self._set(k, v))
            card.body.addWidget(SettingRow(title, desc, toggle))
            self.behaviour_toggles[key] = toggle
        self.content.addWidget(card)

    # ── automation ──
    def _build_automation(self) -> None:
        card = Card("Automation",
                    "The tray agent reacts to what happens on the machine "
                    "rather than waiting to be asked.", ACCENT, "⚡")
        if not licensing.has_feature("tray"):
            card.body.addWidget(Badge("PRO", theme.p.warning))

        self.auto_toggle = ToggleSwitch(
            bool(settings.get("auto_profile_on_network_change")))
        self.auto_toggle.toggled.connect(
            lambda v: self._set("auto_profile_on_network_change", v))
        card.body.addWidget(SettingRow(
            "Apply a profile when I join an untrusted network",
            "Joining a network that is not on your trusted list applies the "
            "chosen profile automatically.", self.auto_toggle))

        from ...core import presets
        profile_combo = QComboBox()
        for key in presets.PRESET_ORDER:
            profile_combo.addItem(presets.PRESETS[key].name, key)
        current = settings.get("auto_profile_untrusted", "public_wifi")
        idx = profile_combo.findData(current)
        if idx >= 0:
            profile_combo.setCurrentIndex(idx)
        profile_combo.setMaximumWidth(220)
        profile_combo.currentIndexChanged.connect(
            lambda: self._set("auto_profile_untrusted",
                              profile_combo.currentData()))
        card.body.addWidget(SettingRow(
            "Profile to apply", "", profile_combo))

        trusted = QWidget()
        trow = QHBoxLayout(trusted)
        trow.setContentsMargins(0, 0, 0, 0)
        trow.setSpacing(8)
        self.trusted_input = QLineEdit(
            ", ".join(settings.get("trusted_networks", [])))
        self.trusted_input.setPlaceholderText("Home WiFi, Office-5G")
        self.trusted_input.setMinimumWidth(260)
        trow.addWidget(self.trusted_input)
        trow.addWidget(button("Save", "ghost", self._save_trusted))
        card.body.addWidget(SettingRow(
            "Trusted networks",
            "Comma-separated network names that will not trigger the automatic "
            "profile.", trusted))

        self.clean_toggle = ToggleSwitch(bool(settings.get("clean_on_shutdown")))
        self.clean_toggle.toggled.connect(
            lambda v: self._set("clean_on_shutdown", v))
        card.body.addWidget(SettingRow(
            "Clean traces when the application exits",
            "Runs the recommended trace cleaning on shutdown. Deletion cannot "
            "be undone.", self.clean_toggle))

        self.notify_toggle = ToggleSwitch(bool(settings.get("notify_events")))
        self.notify_toggle.toggled.connect(
            lambda v: self._set("notify_events", v))
        card.body.addWidget(SettingRow(
            "Desktop notifications for protection events",
            "Alerts when DNS changes, a protection drops, or you join an "
            "unencrypted network.", self.notify_toggle))
        self.content.addWidget(card)

    # ── profiles ──
    def _build_profiles(self) -> None:
        card = Card("Your profiles",
                    "Build your own combination of actions and run it from the "
                    "Dashboard in one click.", ACCENT, "★")

        r = QHBoxLayout()
        r.setSpacing(10)
        r.addWidget(button("New profile…", "primary", self._new_profile))
        r.addStretch()
        card.body.addLayout(r)

        self.profile_box = QVBoxLayout()
        self.profile_box.setSpacing(6)
        card.body.addLayout(self.profile_box)
        self.content.addWidget(card)

    # ── about ──
    def _build_about(self) -> None:
        card = Card("About", accent=ACCENT, icon="◆")
        info = sysinfo.os_summary()
        for label, value in (
                ("Version", f"PrivacyKit {__version__}"),
                ("Operating system",
                 info.get("edition", info.get("system", "?"))),
                ("Python", info.get("python", "?")),
                ("Journal", str(__import__(
                    "privacykit.core.journal", fromlist=["journal"]
                ).journal_path())),
        ):
            card.body.addWidget(InfoRow(label, str(value)))

        opt = sysinfo.optional_modules()
        present = [m for m, (found, _) in opt.items() if found]
        card.body.addWidget(InfoRow(
            "Optional libraries",
            ", ".join(present) if present
            else "none — everything works using built-in code"))

        card.body.addWidget(divider())
        card.body.addWidget(NoteBox(
            "For education, personal privacy, and authorised testing only. Use "
            "only on machines and networks you own or have explicit permission "
            "to test. Spoofing identifiers to evade access controls, bans, or "
            "billing may violate laws or terms of service where you live.",
            "info"))
        self.content.addWidget(card)

    # ── refresh ──
    def refresh(self) -> None:
        summary = licensing.summary()
        p = theme.p
        ent = licensing.entitlement()

        self.licence_rows["edition"].set(
            summary["edition"],
            p.success if ent.source == "license"
            else (p.info if ent.source == "trial" else p.text_muted))
        self.licence_rows["licensee"].set(summary["licensee"] or "—")
        self.licence_rows["expires"].set(summary["expires"])
        self.licence_rows["trial"].set(summary["trial"] or "—")
        self.licence_rows["fingerprint"].set(summary["fingerprint"])
        self.licence_rows["locked"].set(
            f"{summary['locked']} feature(s) not in this edition"
            if summary["locked"] else "none — everything is unlocked",
            p.warning if summary["locked"] else p.success)

        self._clear(self.locked_box)
        locked = licensing.locked_features()
        if locked:
            self.locked_box.addWidget(section_label("Not in your edition"))
            for f in locked[:10]:
                self.locked_box.addWidget(muted(f"   • {f.title}", 11))

        self._refresh_profiles()

    def _refresh_profiles(self) -> None:
        self._clear(self.profile_box)
        profiles = profile_store.all()
        if not profiles:
            self.profile_box.addWidget(muted(
                "No custom profiles yet. Create one to combine any actions you "
                "like into a single button.", 12))
            return
        for prof in profiles:
            controls = QWidget()
            crow = QHBoxLayout(controls)
            crow.setContentsMargins(0, 0, 0, 0)
            crow.setSpacing(7)
            crow.addWidget(button("Edit", "ghost",
                                  lambda p=prof: self._edit_profile(p)))
            crow.addWidget(button("Delete", "ghost",
                                  lambda p=prof: self._delete_profile(p)))
            self.profile_box.addWidget(SettingRow(
                f"{prof.icon}  {prof.name}",
                f"{prof.description or 'No description'} · {prof.summary()}",
                controls))

    @staticmethod
    def _clear(layout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    # ── actions ──
    def _set(self, key: str, value) -> None:
        settings.set(key, value)
        if key == "run_at_startup":
            self._apply_startup(value)

    def _apply_startup(self, enabled: bool) -> None:
        from ..tray import set_run_at_startup
        ok, msg = set_run_at_startup(enabled)
        self.notify(msg, "good" if ok else "warning")

    def _set_theme(self, mode: str) -> None:
        settings.set("theme", mode)
        self.app.apply_theme()

    def _set_accent(self, name: str) -> None:
        settings.set("accent", name)
        self.app.apply_theme()

    def _save_trusted(self) -> None:
        names = [n.strip() for n in self.trusted_input.text().split(",")
                 if n.strip()]
        settings.set("trusted_networks", names)
        self.notify(f"{len(names)} trusted network(s) saved.", "good")

    # ── licence actions ──
    def _start_trial(self) -> None:
        ok, msg = licensing.start_trial()
        self.notify(msg, "good" if ok else "warning")
        self.refresh()
        self.app.refresh_status()
        self.app.rebuild_pages()

    def _enter_licence(self) -> None:
        from ..dialogs import Dialog
        dlg = Dialog(self, "Enter your licence",
                     "Paste the complete licence block, including the BEGIN and "
                     "END lines.", "info", 620)
        box = QPlainTextEdit()
        box.setObjectName("Mono")
        box.setMinimumHeight(200)
        box.setPlaceholderText(licensing.LICENSE_HEADER + "\n…\n"
                               + licensing.LICENSE_FOOTER)
        dlg.extra.addWidget(box)
        dlg.add_button("Cancel", "ghost", 0)
        dlg.add_button("Activate", "primary", 1)
        if dlg.exec() != 1:
            return
        self._install(box.toPlainText())

    def _load_licence(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select a licence file", filter="Licence (*.pklic *.txt);;All files (*.*)")
        if not path:
            return
        try:
            self._install(open(path, "r", encoding="utf-8").read())
        except Exception as exc:
            self.notify(f"Could not read the file: {exc}", "critical")

    def _install(self, text: str) -> None:
        ok, msg, _lic = licensing.install_license(text)
        self.notify(msg, "good" if ok else "critical")
        if ok:
            inform(self, "Licence activated", msg, "good")
            self.app.rebuild_pages()
        self.refresh()
        self.app.refresh_status()

    def _remove_licence(self) -> None:
        if not confirm(self, "Remove the licence?",
                       "The application will revert to the Free edition."):
            return
        ok, msg = licensing.remove_license()
        self.notify(msg, "good" if ok else "critical")
        self.refresh()
        self.app.refresh_status()
        self.app.rebuild_pages()

    def _copy_fingerprint(self) -> None:
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(licensing.fingerprint_display())
        self.notify("Machine ID copied — quote it when buying a bound licence.",
                    "info")

    # ── profile editing ──
    def _new_profile(self) -> None:
        ok, message = licensing.require("profiles")
        if not ok:
            return self.notify(message, "warning")
        name = prompt(self, "New profile", "What should this profile be called?",
                      "Coffee shop")
        if not name:
            return
        prof = CustomProfile(key=profile_store.next_key(name), name=name)
        self._edit_profile(prof, is_new=True)

    def _edit_profile(self, profile, is_new: bool = False) -> None:
        from ..profile_editor import ProfileEditor
        editor = ProfileEditor(self, profile)
        if editor.exec() == 1:
            profile_store.add(editor.profile)
            self.notify(f"Profile “{editor.profile.name}” saved.", "good")
            self._refresh_profiles()
            self.app.refresh_dashboard()

    def _delete_profile(self, profile) -> None:
        if not confirm(self, f"Delete “{profile.name}”?",
                       "This removes the profile. The actions it performed are "
                       "not affected."):
            return
        profile_store.remove(profile.key)
        self._refresh_profiles()
        self.app.refresh_dashboard()
        self.notify("Profile deleted.", "good")
