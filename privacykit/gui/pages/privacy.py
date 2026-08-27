"""Privacy — Windows telemetry hardening and profile poisoning."""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (QCheckBox, QGridLayout, QHBoxLayout, QLabel,
                               QVBoxLayout, QWidget)

from ...core import hardening, licensing, noise, sysinfo
from ...core.settings import settings
from ..dialogs import confirm, inform
from ..theme import SECTION_COLOURS, Fonts, theme
from ..widgets.controls import (Badge, Card, InfoRow, NoteBox, StatCard,
                                SettingRow, ToggleSwitch, button, divider,
                                muted, section_label)
from .. import workers
from .base import Page

ACCENT = SECTION_COLOURS["Privacy"]


class PrivacyPage(Page):
    title = "Privacy"
    subtitle = ("Windows telemetry, tracking identifiers, and what trackers "
                "learn about you. Every switch shows its real cost.")
    icon = "⚙"

    def build(self) -> None:
        self.add_header_button("Refresh", self.refresh)
        self._build_tiles()
        self._build_tweaks()
        self._build_services()
        self._build_hosts()
        self._build_noise()

    def _build_tiles(self) -> None:
        grid = QGridLayout()
        grid.setSpacing(12)
        self.tiles = {}
        for i, (key, label, icon) in enumerate([
                ("hardened", "Settings hardened", "✔"),
                ("services", "Telemetry services", "⚙"),
                ("hosts", "Domains blocked", "⊘"),
                ("noise", "Decoy traffic", "◈")]):
            tile = StatCard(label, icon, ACCENT)
            grid.addWidget(tile, 0, i)
            grid.setColumnStretch(i, 1)
            self.tiles[key] = tile
        holder = QWidget()
        holder.setLayout(grid)
        self.content.addWidget(holder)

    def _build_tweaks(self) -> None:
        card = Card("Windows privacy settings",
                    "Each records its previous value before changing — including "
                    "the case where the value did not exist, in which case "
                    "restoring deletes it rather than writing a guess.",
                    ACCENT, "◈")

        r = QHBoxLayout()
        r.setSpacing(10)
        r.addWidget(button("Select all", "ghost",
                           lambda: self._select_tweaks(True)))
        r.addWidget(button("Select none", "ghost",
                           lambda: self._select_tweaks(False)))
        r.addWidget(button("Apply selected", "primary", self._apply_tweaks))
        r.addStretch()
        card.body.addLayout(r)

        self.tweak_box = QVBoxLayout()
        self.tweak_box.setSpacing(4)
        card.body.addLayout(self.tweak_box)
        self.content.addWidget(card)

    def _build_services(self) -> None:
        card = Card("Telemetry services and tasks",
                    "Disabling records the previous start mode, so restoring "
                    "puts back “Manual” rather than assuming “Automatic”. "
                    "Scheduled tasks are disabled rather than deleted — a "
                    "deleted task cannot be restored.", ACCENT, "⚙")
        self.service_box = QVBoxLayout()
        self.service_box.setSpacing(4)
        card.body.addLayout(self.service_box)

        card.body.addWidget(divider())
        r = QHBoxLayout()
        r.setSpacing(10)
        r.addWidget(button("Disable telemetry tasks", "ghost",
                           lambda: self._set_tasks(True)))
        r.addWidget(button("Re-enable all tasks", "ghost",
                           lambda: self._set_tasks(False)))
        r.addStretch()
        card.body.addLayout(r)
        self.content.addWidget(card)

    def _build_hosts(self) -> None:
        card = Card("Telemetry blocklist",
                    f"Points {len(hardening.TELEMETRY_DOMAINS)} built-in domains "
                    "at 0.0.0.0. The Protection page can replace this with a "
                    "much larger auto-updating feed.", ACCENT, "⊘")
        r = QHBoxLayout()
        r.setSpacing(10)
        r.addWidget(button("Apply built-in blocklist", "primary",
                           self._apply_hosts))
        r.addWidget(button("Remove blocklist", "ghost", self._remove_hosts))
        r.addStretch()
        card.body.addLayout(r)
        card.body.addWidget(NoteBox(
            "The list deliberately excludes Microsoft domains that also carry "
            "Windows Update, activation, and licensing. Aggressive blocklists "
            "that include those break Windows in ways that are very hard to "
            "trace back months later.", "info"))
        self.content.addWidget(card)

    def _build_noise(self) -> None:
        card = Card("Profile poisoning",
                    "Blocking a tracker leaves a shaped hole. Poisoning lets the "
                    "data flow but makes it false, so the profile is "
                    "confidently wrong rather than merely incomplete.",
                    ACCENT, "◈")
        if not licensing.has_feature("noise"):
            self.add_pro_badge()

        card.body.addWidget(section_label("Identifier rotation — recommended"))
        card.body.addWidget(muted(
            "Purely local, no network traffic, and genuinely effective: it "
            "severs yesterday's profile from today's. Windows itself offers a "
            "reset for the advertising ID.", 12))

        self.identifier_box = QVBoxLayout()
        self.identifier_box.setSpacing(4)
        card.body.addLayout(self.identifier_box)

        r = QHBoxLayout()
        r.setSpacing(10)
        r.addWidget(button("Rotate identifiers now", "primary", self._rotate))
        r.addStretch()
        card.body.addLayout(r)

        card.body.addWidget(divider())
        card.body.addWidget(section_label("Decoy traffic — opt in"))

        dr = QHBoxLayout()
        dr.setSpacing(12)
        self.noise_toggle = ToggleSwitch(noise.generator.running)
        self.noise_toggle.toggled.connect(self._toggle_noise)
        dr.addWidget(self.noise_toggle)
        self.noise_status = muted("Not running", 12)
        dr.addWidget(self.noise_status, 1)
        dr.addStretch()
        card.body.addLayout(dr)

        rate = QHBoxLayout()
        rate.setSpacing(10)
        rate.addWidget(QLabel("Requests per hour"))
        from PySide6.QtWidgets import QSpinBox
        self.rate_spin = QSpinBox()
        self.rate_spin.setRange(1, noise.MAX_REQUESTS_PER_HOUR)
        self.rate_spin.setValue(settings.get("noise_rate", 20))
        self.rate_spin.setMaximumWidth(90)
        rate.addWidget(self.rate_spin)
        rate.addWidget(muted(
            f"capped at {noise.MAX_REQUESTS_PER_HOUR}/hour — beyond that this "
            "stops being noise and becomes abusive traffic to someone else's "
            "servers", 11), 1)
        card.body.addLayout(rate)

        self.noise_tor = ToggleSwitch(settings.get("noise_via_tor", True))
        card.body.addWidget(SettingRow(
            "Send decoys through Tor",
            "Strongly recommended. Decoy traffic sent directly is attributable "
            "to your connection, which cuts against everything else here.",
            self.noise_tor))

        card.body.addWidget(section_label("Recent decoys"))
        self.decoy_box = QVBoxLayout()
        self.decoy_box.setSpacing(3)
        card.body.addLayout(self.decoy_box)

        card.body.addWidget(NoteBox(noise.effectiveness_note(), "warning"))
        self.conflict_note = QVBoxLayout()
        card.body.addLayout(self.conflict_note)
        self.content.addWidget(card)

        self._noise_timer = QTimer(self)
        self._noise_timer.timeout.connect(self._refresh_noise)
        self._noise_timer.start(3000)

    # ── refresh ──
    def refresh(self) -> None:
        def work():
            return {
                "audit": hardening.audit(),
                "services": {n: hardening.service_state(n)
                             for n in hardening.TELEMETRY_SERVICES},
                "hosts": hardening.hosts_blocked_count(),
                "identifiers": noise.identifier_report(),
                "conflict": noise.blocklist_conflict(),
            }

        workers.run(work, on_result=self._paint,
                    on_error=lambda e: self.notify(str(e), "warning"))
        self._refresh_noise()

    def _paint(self, d) -> None:
        if not isinstance(d, dict):
            return
        p = theme.p
        audit = d["audit"]

        hardened = sum(1 for t in audit if t["private"])
        self.tiles["hardened"].set(
            f"{hardened}/{len(audit)}", "privacy settings applied",
            p.success if hardened > len(audit) * 0.7 else p.warning)

        services = d["services"]
        disabled = sum(1 for s in services.values()
                       if (s.get("start_mode") or "").lower() == "disabled")
        present = sum(1 for s in services.values() if s.get("exists"))
        self.tiles["services"].set(f"{disabled}/{present}",
                                   "telemetry services disabled",
                                   p.success if disabled else p.text_muted)

        blocked = d["hosts"]
        self.tiles["hosts"].set(f"{blocked:,}" if blocked else "0",
                                "domains in the hosts file",
                                p.success if blocked else p.text_muted)

        # tweaks
        self._clear(self.tweak_box)
        self.tweak_checks = {}
        for t in audit:
            row = QHBoxLayout()
            row.setSpacing(12)
            check = QCheckBox()
            check.setChecked(not t["private"])
            check.setEnabled(not t["private"])
            row.addWidget(check)
            self.tweak_checks[t["key"]] = check

            text = QVBoxLayout()
            text.setSpacing(2)
            head = QHBoxLayout()
            head.setSpacing(8)
            title = QLabel(t["title"])
            title.setStyleSheet(
                f"color: {p.text}; font-size: 13px; font-weight: 600;")
            head.addWidget(title)
            if t["private"]:
                head.addWidget(Badge("applied", p.success))
            elif t["admin"] and not sysinfo.is_admin():
                head.addWidget(Badge("needs admin", p.warning))
            head.addStretch()
            text.addLayout(head)
            text.addWidget(muted(t["description"], 11))
            cost = muted("Cost: " + t["impact"], 11)
            cost.setStyleSheet(f"color: {p.warning}; font-size: 11px;")
            text.addWidget(cost)
            row.addLayout(text, 1)

            holder = QWidget()
            holder.setLayout(row)
            self.tweak_box.addWidget(holder)

        # services
        self._clear(self.service_box)
        for name, (title, what, impact) in hardening.TELEMETRY_SERVICES.items():
            state = services.get(name, {})
            exists = state.get("exists", False)
            mode = (state.get("start_mode") or "").lower()
            is_disabled = mode == "disabled"

            controls = QWidget()
            crow = QHBoxLayout(controls)
            crow.setContentsMargins(0, 0, 0, 0)
            crow.setSpacing(7)
            if exists:
                crow.addWidget(Badge("disabled" if is_disabled else mode or "?",
                                     p.success if is_disabled else p.text_muted))
                crow.addWidget(button(
                    "Enable" if is_disabled else "Disable", "ghost",
                    lambda n=name, dis=is_disabled: self._set_service(n, not dis)))
            else:
                crow.addWidget(Badge("not present", p.text_faint))

            self.service_box.addWidget(SettingRow(
                f"{title}  ({name})",
                f"{what}  ·  Cost: {impact}", controls))

        # identifiers
        self._clear(self.identifier_box)
        for ident in d["identifiers"]:
            current = ident["current"] or "not set"
            controls = QWidget()
            crow = QHBoxLayout(controls)
            crow.setContentsMargins(0, 0, 0, 0)
            crow.setSpacing(7)
            crow.addWidget(button("Rotate", "ghost",
                                  lambda k=ident["key"]: self._rotate_one(k)))
            self.identifier_box.addWidget(SettingRow(
                ident["title"],
                f"{ident['description']}\nCurrent: {current}",
                controls,
                Badge("caution", p.warning) if not ident["safe"] else None))

        self._clear(self.conflict_note)
        if d.get("conflict"):
            self.conflict_note.addWidget(NoteBox(d["conflict"], "warning"))

    def _refresh_noise(self) -> None:
        if not hasattr(self, "noise_status"):
            return
        stats = noise.generator.stats
        p = theme.p
        if noise.generator.running:
            self.noise_status.setText(
                f"Running · {stats.sent} sent · {stats.rate} · up {stats.uptime}")
            self.tiles["noise"].set("ON", f"{stats.sent} decoys sent",
                                    p.success, pulse=True)
        else:
            self.noise_status.setText("Not running")
            self.tiles["noise"].set("OFF", "no decoy traffic", p.text_muted)

        self._clear(self.decoy_box)
        if stats.recent:
            for line in stats.recent[:6]:
                lbl = muted(line, 11)
                lbl.setStyleSheet(
                    f"color: {p.text_faint}; font-size: 11px;"
                    f"font-family: '{Fonts.mono}';")
                self.decoy_box.addWidget(lbl)
        else:
            self.decoy_box.addWidget(muted("Nothing sent yet.", 11))

    @staticmethod
    def _clear(layout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    # ── actions ──
    def _select_tweaks(self, value: bool) -> None:
        for check in getattr(self, "tweak_checks", {}).values():
            if check.isEnabled():
                check.setChecked(value)

    def _apply_tweaks(self) -> None:
        keys = [k for k, c in getattr(self, "tweak_checks", {}).items()
                if c.isChecked() and c.isEnabled()]
        if not keys:
            return self.notify("Tick at least one setting.", "warning")

        def done(result):
            if isinstance(result, dict):
                self.notify(f"{result['applied']} setting(s) applied.", "good")
                for f in result.get("failed", []):
                    self.app.log(f)
            self.refresh()
            self.app.refresh_status()

        workers.run(lambda: hardening.apply_tweaks(keys), on_result=done)

    def _set_service(self, name: str, disable: bool) -> None:
        workers.run(lambda: hardening.set_service(name, disable),
                    on_result=self.show_result)

    def _set_tasks(self, disable: bool) -> None:
        if not sysinfo.is_admin():
            return self.notify("Administrator rights are required.", "critical")

        def work():
            return [hardening.set_task(p, disable)
                    for p in hardening.TELEMETRY_TASKS]

        def done(results):
            ok = sum(1 for r in results if r[0])
            self.notify(
                f"{ok} of {len(results)} task(s) "
                f"{'disabled' if disable else 're-enabled'}.",
                "good" if ok else "warning")
            self.refresh()

        workers.run(work, on_result=done)

    def _apply_hosts(self) -> None:
        if not confirm(self, "Apply the built-in blocklist?",
                       f"Block {len(hardening.TELEMETRY_DOMAINS)} telemetry and "
                       "advertising domains?\n\nYour hosts file is backed up "
                       "first and can be restored from the Journal."):
            return
        workers.run(lambda: hardening.apply_hosts_blocklist(),
                    on_result=self.show_result)

    def _remove_hosts(self) -> None:
        workers.run(hardening.remove_hosts_blocklist, on_result=self.show_result)

    def _rotate_one(self, key: str) -> None:
        ok, message = licensing.require("noise")
        if not ok:
            return self.notify(message, "warning")
        workers.run(lambda: noise.rotate_identifier(key),
                    on_result=self.show_result)

    def _rotate(self) -> None:
        ok, message = licensing.require("noise")
        if not ok:
            return self.notify(message, "warning")

        def done(result):
            if isinstance(result, dict):
                self.notify(f"{result['rotated']} identifier(s) rotated.", "good")
            self.refresh()

        workers.run(lambda: noise.rotate_all(safe_only=False), on_result=done)

    def _toggle_noise(self, enabled: bool) -> None:
        ok, message = licensing.require("noise")
        if not ok:
            self.noise_toggle.blockSignals(True)
            self.noise_toggle.setChecked(False)
            self.noise_toggle.blockSignals(False)
            return self.notify(message, "warning")

        if enabled:
            conflict = noise.blocklist_conflict()
            if conflict and not confirm(
                    self, "Blocking and poisoning conflict",
                    conflict + "\n\nStart decoy traffic anyway?"):
                self.noise_toggle.blockSignals(True)
                self.noise_toggle.setChecked(False)
                self.noise_toggle.blockSignals(False)
                return
            from ...core import tor as tormod
            st = tormod.detect()
            noise.generator.configure(
                self.rate_spin.value(), via_tor=self.noise_tor.isChecked(),
                tor_port=st.socks_port or 9050)
            settings.update({"noise_rate": self.rate_spin.value(),
                             "noise_via_tor": self.noise_tor.isChecked()})
            ok2, msg = noise.generator.start()
        else:
            ok2, msg = noise.generator.stop()
        self.notify(msg, "good" if ok2 else "critical")
        self._refresh_noise()
