"""Location — align what Windows says about where you are with your exit IP."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QComboBox, QGridLayout, QHBoxLayout, QLabel,
                               QVBoxLayout, QWidget)

from ...core import geo, leaks, licensing, tor
from ..dialogs import confirm
from ..theme import SECTION_COLOURS, theme
from ..widgets.controls import (Card, FindingRow, InfoRow, NoteBox, StatCard,
                                ToggleSwitch, button, divider, muted,
                                section_label)
from .. import workers
from .base import Page

ACCENT = SECTION_COLOURS["Location"]


class LocationPage(Page):
    title = "Location"
    subtitle = ("A Frankfurt exit IP with an Indian timezone is a stronger "
                "identifier than either signal alone — almost nobody has that "
                "combination by accident.")
    icon = "◎"
    feature_key = "geo"

    def __init__(self, app, parent=None):
        self._ip_country = ""
        super().__init__(app, parent)

    def build(self) -> None:
        if self.locked():
            self.add_pro_badge()
        self.add_header_button("Refresh", self.refresh)

        self._build_tiles()
        self._build_mismatch()
        self._build_apply()
        self._build_service()

    def _build_tiles(self) -> None:
        grid = QGridLayout()
        grid.setSpacing(12)
        self.tiles = {}
        for i, (key, label, icon) in enumerate([
                ("ip", "Exit IP says", "⇥"),
                ("timezone", "Timezone", "◷"),
                ("region", "Windows region", "⚑"),
                ("coords", "Reported position", "◉")]):
            tile = StatCard(label, icon, ACCENT)
            grid.addWidget(tile, 0, i)
            grid.setColumnStretch(i, 1)
            self.tiles[key] = tile
        holder = QWidget()
        holder.setLayout(grid)
        self.content.addWidget(holder)

    def _build_mismatch(self) -> None:
        self.mismatch_card = Card(
            "Consistency check",
            "What a fingerprinting script would see if it compared your IP "
            "against the signals your browser and Windows hand over for free.",
            ACCENT, "⚖")
        self.mismatch_box = QVBoxLayout()
        self.mismatch_box.setSpacing(8)
        self.mismatch_card.body.addLayout(self.mismatch_box)
        self.content.addWidget(self.mismatch_card)

    def _build_apply(self) -> None:
        card = Card("Match your location", "", ACCENT, "◎")

        auto = QHBoxLayout()
        auto.setSpacing(10)
        self.match_btn = button("⚡  Match to my exit IP", "primary",
                                self._match_to_ip)
        auto.addWidget(self.match_btn)
        auto.addWidget(muted("Detects the country of your current public IP and "
                             "aligns everything below to it.", 12))
        auto.addStretch()
        card.body.addLayout(auto)

        card.body.addWidget(divider())

        manual = QHBoxLayout()
        manual.setSpacing(10)
        manual.addWidget(QLabel("Or pick a country"))
        self.country_combo = QComboBox()
        for code, label in geo.country_list():
            self.country_combo.addItem(label, code)
        self.country_combo.setMinimumWidth(260)
        manual.addWidget(self.country_combo)
        manual.addWidget(button("Apply", "ghost", self._apply_manual))
        manual.addStretch()
        card.body.addLayout(manual)

        card.body.addWidget(section_label("What to align"))

        self.opts = {}
        for key, label, desc, default in (
            ("timezone", "Timezone",
             "The highest-value signal. Readable from JavaScript in one line, "
             "with no permission prompt.", True),
            ("region", "Windows home region",
             "What Windows reports as your country to applications and the "
             "Store.", True),
            ("coordinates", "Default coordinates",
             "The position Windows hands to apps that ask for your location.",
             True),
            ("locale", "Display locale",
             "Drives Accept-Language and date formats. Off by default — it "
             "changes number and date formatting in every application, which "
             "is jarring and is the smallest win of the four.", False),
        ):
            r = QHBoxLayout()
            r.setSpacing(12)
            toggle = ToggleSwitch(default)
            r.addWidget(toggle)
            text = QVBoxLayout()
            text.setSpacing(2)
            t = QLabel(label)
            t.setStyleSheet(
                f"color: {theme.p.text}; font-size: 13px; font-weight: 600;")
            text.addWidget(t)
            text.addWidget(muted(desc, 11))
            r.addLayout(text, 1)
            card.body.addLayout(r)
            self.opts[key] = toggle

        card.body.addWidget(NoteBox(
            "This cannot change what a browser reports through the JavaScript "
            "Geolocation API if you have granted that site location permission, "
            "and it cannot alter GPS hardware. It aligns the signals Windows "
            "gives away without being asked, which is where the mismatch "
            "usually is.", "info"))
        self.content.addWidget(card)

    def _build_service(self) -> None:
        card = Card("Windows location service",
                    "Windows reports nearby Wi-Fi access points to Microsoft to "
                    "work out where you are. That runs on real observed "
                    "hardware, so it cannot be faked — only switched off.",
                    ACCENT, "⛔")

        r = QHBoxLayout()
        r.setSpacing(12)
        self.service_toggle = ToggleSwitch(True)
        self.service_toggle.toggled.connect(self._set_service)
        r.addWidget(self.service_toggle)
        text = QVBoxLayout()
        text.setSpacing(2)
        t = QLabel("Allow apps to use the location service")
        t.setStyleSheet(
            f"color: {theme.p.text}; font-size: 13px; font-weight: 600;")
        text.addWidget(t)
        text.addWidget(muted(
            "Turning this off also stops the Wi-Fi positioning reports, which "
            "is the part no amount of spoofing can address.", 11))
        r.addLayout(text, 1)
        card.body.addLayout(r)
        self.content.addWidget(card)

    # ── refresh ──
    def refresh(self) -> None:
        def work():
            state = geo.get_state()
            st = tor.detect()
            info = leaks.public_ip(via_tor=st.running,
                                   socks_port=st.socks_port or 9050)
            country = (info.get("country") or "").lower()
            mismatches = geo.detect_mismatch(country) if country else []
            return state, info, country, mismatches

        workers.run(work, on_result=self._paint,
                    on_error=lambda e: self.notify(str(e), "warning"))

    def _paint(self, data) -> None:
        if not isinstance(data, tuple):
            return
        state, info, country, mismatches = data
        self._ip_country = country
        p = theme.p

        known = geo.COUNTRIES.get(country)
        self.tiles["ip"].set(
            (country or "—").upper(),
            f"{info.get('city', '')} {info.get('ip', '')}".strip() or "unknown",
            ACCENT)
        self.tiles["timezone"].set(
            (state.timezone_display or state.timezone or "—")[:22],
            "matches your exit IP" if (known and state.timezone == known.timezone)
            else "does not match your exit IP",
            p.success if (known and state.timezone == known.timezone)
            else p.warning)
        self.tiles["region"].set(
            (state.region or "—").upper(),
            f"GeoID {state.geoid}" if state.geoid else "not set",
            p.success if (known and state.region.upper() == known.code)
            else p.warning)
        self.tiles["coords"].set(
            f"{state.lat:.2f}, {state.lon:.2f}" if state.lat is not None else "not set",
            "default position given to apps", ACCENT)

        self.service_toggle.blockSignals(True)
        self.service_toggle.setChecked(state.location_service)
        self.service_toggle.blockSignals(False)

        while self.mismatch_box.count():
            item = self.mismatch_box.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not country:
            self.mismatch_box.addWidget(FindingRow(
                "Could not determine the country of your public IP", "info",
                "The consistency check needs to know where the internet thinks "
                "you are. Check your connection and refresh."))
        elif not known:
            self.mismatch_box.addWidget(FindingRow(
                f"No location profile for '{country.upper()}'", "info",
                "PrivacyKit has profiles for the common VPN and Tor exit "
                "countries. You can still pick a country manually below."))
        elif not mismatches:
            self.mismatch_box.addWidget(FindingRow(
                f"Everything is consistent with {known.name}", "good",
                "Your timezone, region, and reported position all agree with "
                "your exit IP. Nothing here contradicts anything else."))
        else:
            for m in mismatches:
                self.mismatch_box.addWidget(FindingRow(
                    f"{m.signal} contradicts your exit IP", m.severity,
                    f"Windows reports “{m.reported}” — consistent with "
                    f"{known.name} would be “{m.expected}”."))

    # ── actions ──
    def _selected_options(self) -> dict:
        return {
            "set_timezone": self.opts["timezone"].isChecked(),
            "set_region": self.opts["region"].isChecked(),
            "set_locale": self.opts["locale"].isChecked(),
            "set_coordinates": self.opts["coordinates"].isChecked(),
        }

    def _match_to_ip(self) -> None:
        ok, message = licensing.require("geo")
        if not ok:
            return self.notify(message, "warning")
        if not self._ip_country:
            return self.notify(
                "The country of your public IP is not known yet — refresh first.",
                "warning")
        country = geo.COUNTRIES.get(self._ip_country)
        if not country:
            return self.notify(
                f"No location profile for '{self._ip_country.upper()}'. "
                "Pick a country manually instead.", "warning")
        self._apply_country(self._ip_country, country.name)

    def _apply_manual(self) -> None:
        ok, message = licensing.require("geo")
        if not ok:
            return self.notify(message, "warning")
        code = self.country_combo.currentData()
        country = geo.COUNTRIES.get(code)
        if country:
            self._apply_country(code, country.name)

    def _apply_country(self, code: str, name: str) -> None:
        opts = self._selected_options()
        parts = [k.replace("set_", "") for k, v in opts.items() if v]
        if not parts:
            return self.notify("Nothing selected to align.", "warning")

        extra = ("\n\nChanging the display locale reformats dates and numbers "
                 "in every application. It is reversible, but you will notice."
                 if opts["set_locale"] else "")
        if not confirm(self, f"Make this machine look like it is in {name}?",
                       f"Will align: {', '.join(parts)}.{extra}\n\n"
                       "Every change is journalled and reversible."):
            return

        self.match_btn.setEnabled(False)
        self.notify(f"Aligning location signals to {name}…", "info")

        def done(result):
            self.match_btn.setEnabled(True)
            if isinstance(result, dict):
                self.notify(result.get("message", "done"),
                            "good" if result.get("ok") else "critical")
                for line in result.get("steps", []):
                    self.app.log(line)
            self.refresh()
            self.app.refresh_status()

        workers.run(lambda: geo.apply_country(code, **opts), on_result=done)

    def _set_service(self, enabled: bool) -> None:
        workers.run(lambda: geo.set_location_service(enabled),
                    on_result=self.show_result)
