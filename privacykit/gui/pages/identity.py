"""Identity — MAC address, local IP, computer name, and Wi-Fi profiles."""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (QComboBox, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from ...core import hostname as hostmod
from ...core import ipconf, mac, oui, sysinfo, wifi
from ..dialogs import confirm, inform
from ..theme import SECTION_COLOURS, theme
from ..widgets.controls import (Card, InfoRow, NoteBox, ToggleSwitch, button,
                                divider, muted, row, section_label)
from .. import workers
from .base import Page

ACCENT = SECTION_COLOURS["Identity"]


class IdentityPage(Page):
    title = "Identity"
    subtitle = ("Four identifiers travel with this machine onto every network. "
                "Changing one and leaving the others is largely pointless.")
    icon = "⬡"

    def __init__(self, app, parent=None):
        self._adapters = []
        self._rotate_timer = None
        super().__init__(app, parent)

    def build(self) -> None:
        self.add_header_button("Refresh", self.refresh)
        self._build_adapter()
        self._build_mac()
        self._build_rotate()
        self._build_ip()
        self._build_hostname()
        self._build_wifi()

    # ── adapter ──
    def _build_adapter(self) -> None:
        card = Card("Adapter", "Everything on this page applies to the selected "
                    "adapter. The choice is shared with the Connection and "
                    "Protection pages.", ACCENT, "⬡")

        top = QHBoxLayout()
        top.setSpacing(10)
        self.adapter_combo = QComboBox()
        self.adapter_combo.setMinimumWidth(300)
        self.adapter_combo.currentTextChanged.connect(self._on_adapter)
        top.addWidget(self.adapter_combo)

        self.virtual_toggle = ToggleSwitch(False)
        self.virtual_toggle.toggled.connect(lambda _: self.refresh())
        top.addWidget(QLabel("Show virtual"))
        top.addWidget(self.virtual_toggle)
        top.addStretch()
        card.body.addLayout(top)

        card.body.addWidget(divider())

        self.info = {}
        for key, label, mono in (("desc", "Adapter", False),
                                 ("mac", "Current MAC", True),
                                 ("perm", "Hardware MAC", True),
                                 ("vendor", "Reads as", False),
                                 ("status", "Status", False),
                                 ("ip", "IP configuration", False)):
            r = InfoRow(label, "—", mono)
            card.body.addWidget(r)
            self.info[key] = r
        self.content.addWidget(card)

    # ── MAC ──
    def _build_mac(self) -> None:
        card = Card("MAC address",
                    "Windows lets a network card's address be overridden in the "
                    "registry. The change survives reboots; restoring deletes "
                    "the override.", ACCENT, "⬢")

        entry_row = QHBoxLayout()
        entry_row.setSpacing(10)
        self.mac_input = QLineEdit()
        self.mac_input.setObjectName("Mono")
        self.mac_input.setPlaceholderText("AA:BB:CC:DD:EE:FF")
        self.mac_input.setMaximumWidth(230)
        self.mac_input.textChanged.connect(self._describe_mac)
        entry_row.addWidget(self.mac_input)

        self.vendor_combo = QComboBox()
        self.vendor_combo.addItem("Random vendor")
        self.vendor_combo.addItems(oui.VENDOR_NAMES)
        self.vendor_combo.setMaximumWidth(180)
        entry_row.addWidget(self.vendor_combo)

        entry_row.addWidget(button("Generate", "ghost", self._gen_vendor))
        entry_row.addWidget(button("Local", "ghost", self._gen_local,
                                   "Random address with the locally-administered "
                                   "bit set"))
        entry_row.addWidget(button("Keep OUI", "ghost", self._gen_keep))
        entry_row.addStretch()
        card.body.addLayout(entry_row)

        self.mac_note = muted("", 12)
        card.body.addWidget(self.mac_note)

        card.body.addWidget(divider())

        actions = QHBoxLayout()
        actions.setSpacing(10)
        self.apply_btn = button("Apply MAC change", "primary", self._apply_mac)
        actions.addWidget(self.apply_btn)
        actions.addWidget(button("Restore hardware MAC", "ghost", self._restore_mac))
        actions.addStretch()
        card.body.addLayout(actions)

        card.body.addWidget(NoteBox(
            f"{oui.total_prefixes()} genuine IEEE vendor prefixes are embedded. "
            "A vendor-shaped address is far less conspicuous than a random one — "
            "networks can spot the locally-administered bit instantly, and some "
            "captive portals reject such addresses outright.", "info"))
        self.content.addWidget(card)

    def _build_rotate(self) -> None:
        card = Card("Auto-rotate", "Change the address on a schedule. Each "
                    "rotation briefly cycles the adapter, so the connection "
                    "drops for a second or two.", ACCENT, "↻")

        r = QHBoxLayout()
        r.setSpacing(10)
        r.addWidget(QLabel("Every"))
        self.interval_input = QLineEdit("10")
        self.interval_input.setMaximumWidth(70)
        r.addWidget(self.interval_input)
        self.unit_combo = QComboBox()
        self.unit_combo.addItems(["seconds", "minutes", "hours"])
        self.unit_combo.setCurrentText("minutes")
        self.unit_combo.setMaximumWidth(120)
        r.addWidget(self.unit_combo)
        self.rot_mode = QComboBox()
        self.rot_mode.addItems(["Random vendor", "Locally-administered"])
        self.rot_mode.setMaximumWidth(190)
        r.addWidget(self.rot_mode)
        self.rot_btn = button("Start", "primary", self._toggle_rotate)
        r.addWidget(self.rot_btn)
        r.addStretch()
        card.body.addLayout(r)

        self.countdown = muted("", 12)
        card.body.addWidget(self.countdown)
        self.content.addWidget(card)

    # ── IP ──
    def _build_ip(self) -> None:
        card = Card("Local IP address",
                    "This is your address on the local network. It is NOT the "
                    "public IP websites see — only a VPN, proxy, or Tor changes "
                    "that.", ACCENT, "⇢")

        r = QHBoxLayout()
        r.setSpacing(10)
        r.addWidget(button("Release & renew DHCP", "ghost", self._renew))
        r.addWidget(button("New address in this subnet", "ghost", self._random_ip))
        r.addWidget(button("Back to automatic", "ghost", self._dhcp))
        r.addStretch()
        card.body.addLayout(r)

        card.body.addWidget(divider())

        static = QHBoxLayout()
        static.setSpacing(10)
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("192.168.1.50")
        self.ip_input.setMaximumWidth(160)
        static.addWidget(QLabel("Static IP"))
        static.addWidget(self.ip_input)
        self.prefix_input = QLineEdit("24")
        self.prefix_input.setMaximumWidth(60)
        static.addWidget(QLabel("/"))
        static.addWidget(self.prefix_input)
        self.gw_input = QLineEdit()
        self.gw_input.setPlaceholderText("192.168.1.1")
        self.gw_input.setMaximumWidth(160)
        static.addWidget(QLabel("Gateway"))
        static.addWidget(self.gw_input)
        static.addWidget(button("Set static", "ghost", self._static))
        static.addStretch()
        card.body.addLayout(static)
        self.content.addWidget(card)

    # ── hostname ──
    def _build_hostname(self) -> None:
        card = Card("Computer name",
                    "Broadcast in DHCP requests and shown in the client list of "
                    "every router you join. Spoofing the MAC while keeping a "
                    "personal hostname defeats the purpose.",
                    SECTION_COLOURS["Privacy"], "▣")

        r = QHBoxLayout()
        r.setSpacing(10)
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText(hostmod.current() or "DESKTOP-XXXXXXX")
        self.host_input.setMaximumWidth(240)
        r.addWidget(self.host_input)
        r.addWidget(button("Windows-style", "ghost",
                           lambda: self.host_input.setText(
                               hostmod.generate("windows"))))
        r.addWidget(button("Random", "ghost",
                           lambda: self.host_input.setText(
                               hostmod.generate("random"))))
        r.addWidget(button("Rename", "primary", self._rename))
        r.addStretch()
        card.body.addLayout(r)

        card.body.addWidget(NoteBox(
            "A rename needs a restart before it fully applies. The original "
            "name is recorded, so Panic Restore puts it back.", "warning"))
        self.content.addWidget(card)

    # ── Wi-Fi ──
    def _build_wifi(self) -> None:
        card = Card("Saved Wi-Fi networks",
                    "Windows remembers every network you have joined. Older "
                    "clients actively probe for saved names, broadcasting a list "
                    "of the places you have been.", ACCENT, "≋")

        r = QHBoxLayout()
        r.setSpacing(10)
        r.addWidget(button("Load saved networks", "ghost", self._load_wifi))
        r.addWidget(button("Scan nearby", "ghost", self._scan_wifi,
                           "Check for two access points claiming the same name"))
        r.addWidget(button("Forget selected", "danger", self._forget_wifi))
        r.addStretch()
        card.body.addLayout(r)

        self.wifi_table = QTableWidget(0, 3)
        self.wifi_table.setHorizontalHeaderLabels(
            ["Network", "Security", "Auto-connect"])
        self.wifi_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.Stretch)
        self.wifi_table.verticalHeader().setVisible(False)
        self.wifi_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.wifi_table.setMinimumHeight(180)
        self.wifi_table.setAlternatingRowColors(True)
        card.body.addWidget(self.wifi_table)
        self.content.addWidget(card)

    # ── refresh ──
    def refresh(self) -> None:
        show_virtual = (self.virtual_toggle.isChecked()
                        if hasattr(self, "virtual_toggle") else False)
        workers.run(lambda: mac.list_adapters(include_virtual=show_virtual),
                    on_result=self._paint_adapters,
                    on_error=lambda e: self.notify(str(e), "warning"))

    def _paint_adapters(self, adapters) -> None:
        if not isinstance(adapters, list):
            return
        self._adapters = adapters
        names = [a.name for a in adapters]

        self.adapter_combo.blockSignals(True)
        current = self.app.adapter
        self.adapter_combo.clear()
        self.adapter_combo.addItems(names)
        if names:
            if current in names:
                self.adapter_combo.setCurrentText(current)
            else:
                active = next((a.name for a in adapters
                               if a.status.lower() == "up"), names[0])
                self.adapter_combo.setCurrentText(active)
                self.app.set_adapter(active)
        self.adapter_combo.blockSignals(False)
        self._on_adapter()

    def _selected(self):
        name = self.adapter_combo.currentText()
        return next((a for a in self._adapters if a.name == name), None)

    def _on_adapter(self) -> None:
        name = self.adapter_combo.currentText()
        if name:
            self.app.set_adapter(name)
        a = self._selected()
        if not a:
            for r in self.info.values():
                r.set("—")
            return
        p = theme.p
        self.info["desc"].set(a.description or "—")
        self.info["mac"].set(a.mac.upper() or "—",
                             p.success if a.spoofed else p.text_dim)
        self.info["perm"].set(a.permanent_mac.upper() or "not reported by driver")
        self.info["vendor"].set(oui.describe(a.mac))
        self.info["status"].set(
            f"{a.status or 'unknown'}"
            + (f" · {a.link_speed}" if a.link_speed else "")
            + ("  ·  SPOOFED" if a.spoofed else ""),
            p.success if a.spoofed else p.text_dim)

        workers.run(lambda: ipconf.get_config(a.name),
                    on_result=lambda cfg: self.info["ip"].set(
                        cfg.describe() if cfg else "unavailable"))

    def _describe_mac(self) -> None:
        value = self.mac_input.text().strip()
        if not value:
            self.mac_note.setText("")
            return
        ok, reason = mac.is_valid(value)
        p = theme.p
        if ok:
            self.mac_note.setText("✔  " + oui.describe(mac.normalise(value)))
            self.mac_note.setStyleSheet(f"color: {p.success}; font-size: 12px;")
        else:
            self.mac_note.setText("✖  " + reason)
            self.mac_note.setStyleSheet(f"color: {p.danger}; font-size: 12px;")

    # ── MAC actions ──
    def _gen_vendor(self) -> None:
        vendor = self.vendor_combo.currentText()
        new_mac, _ = (mac.generate("vendor", vendor)
                      if vendor != "Random vendor" else mac.generate("vendor"))
        self.mac_input.setText(new_mac.upper())

    def _gen_local(self) -> None:
        self.mac_input.setText(mac.generate("local")[0].upper())

    def _gen_keep(self) -> None:
        a = self._selected()
        if a and a.mac:
            self.mac_input.setText(mac.keep_oui_randomise(a.mac).upper())

    def _apply_mac(self) -> None:
        a = self._selected()
        if not a:
            return self.notify("Select an adapter first.", "warning")
        value = self.mac_input.text().strip()
        ok, reason = mac.is_valid(value)
        if not ok:
            return self.notify(reason, "critical")
        if not sysinfo.is_admin():
            return self.notify(
                "Administrator rights are required to write to the registry.",
                "critical")

        self.apply_btn.setEnabled(False)
        self.apply_btn.setText("Applying…")
        self.notify(f"Setting MAC on {a.name}…", "info")

        def done(res):
            self.apply_btn.setEnabled(True)
            self.apply_btn.setText("Apply MAC change")
            if res.ok:
                self.notify(res.message, "good")
            else:
                self.notify(res.message, "critical")
                if res.hints:
                    inform(self, "MAC change did not take effect",
                           res.message + "\n\n" + "\n\n".join(res.hints),
                           "warning")
            self.refresh()
            self.app.refresh_status()

        workers.run(lambda: mac.set_mac(a.name, value), on_result=done,
                    on_error=lambda e: self.notify(str(e), "critical"))

    def _restore_mac(self) -> None:
        a = self._selected()
        if not a:
            return
        workers.run(lambda: mac.restore_mac(a.name),
                    on_result=lambda r: self.show_result(r))

    # ── rotation ──
    def _toggle_rotate(self) -> None:
        if self._rotate_timer and self._rotate_timer.isActive():
            self._rotate_timer.stop()
            self.rot_btn.setText("Start")
            self.countdown.setText("")
            self.notify("Auto-rotate stopped.", "info")
            return

        a = self._selected()
        if not a:
            return self.notify("Select an adapter first.", "warning")
        try:
            value = int(self.interval_input.text())
            if value <= 0:
                raise ValueError
        except ValueError:
            return self.notify("Interval must be a positive whole number.",
                               "critical")

        mult = {"seconds": 1, "minutes": 60, "hours": 3600}[
            self.unit_combo.currentText()]
        seconds = value * mult
        if seconds < 5:
            return self.notify(
                "Minimum interval is 5 seconds — each rotation cycles the "
                "adapter and needs time to reconnect.", "critical")

        self._rotate_seconds = seconds
        self._rotate_remaining = seconds
        self._rotate_timer = QTimer(self)
        self._rotate_timer.timeout.connect(self._rotate_tick)
        self._rotate_timer.start(1000)
        self.rot_btn.setText("Stop")
        self.notify(f"Auto-rotate started on {a.name}.", "good")

    def _rotate_tick(self) -> None:
        self._rotate_remaining -= 1
        if self._rotate_remaining > 0:
            m, s = divmod(self._rotate_remaining, 60)
            self.countdown.setText(
                f"Next rotation in {m}m {s:02d}s" if m else
                f"Next rotation in {s}s")
            return

        self._rotate_remaining = self._rotate_seconds
        a = self._selected()
        if not a:
            return
        mode = ("local" if "Locally" in self.rot_mode.currentText() else "vendor")
        new_mac, desc = mac.generate(mode)
        self.notify(f"Rotating to {new_mac.upper()} ({desc})…", "info")
        workers.run(lambda: mac.set_mac(a.name, new_mac),
                    on_result=lambda r: (self.notify(r.message,
                                                     "good" if r.ok else "critical"),
                                         self.refresh()))

    # ── IP actions ──
    def _ip_action(self, fn) -> None:
        a = self._selected()
        if not a:
            return self.notify("Select an adapter first.", "warning")
        workers.run(lambda: fn(a.name), on_result=self.show_result)

    def _renew(self):
        self._ip_action(ipconf.release_renew)

    def _random_ip(self):
        self._ip_action(ipconf.randomise_host_octet)

    def _dhcp(self):
        self._ip_action(ipconf.set_dhcp)

    def _static(self) -> None:
        a = self._selected()
        if not a:
            return
        ip = self.ip_input.text().strip()
        if not ip:
            return self.notify("Enter a static IP address.", "warning")
        try:
            prefix = int(self.prefix_input.text() or 24)
        except ValueError:
            return self.notify("Prefix must be a number.", "critical")
        gw = self.gw_input.text().strip()
        workers.run(lambda: ipconf.set_static(a.name, ip, prefix, gw),
                    on_result=self.show_result)

    # ── hostname ──
    def _rename(self) -> None:
        new = self.host_input.text().strip()
        if not new:
            return self.notify("Enter or generate a name first.", "warning")
        ok, reason = hostmod.is_valid(new)
        if not ok:
            return self.notify(reason, "critical")
        if not confirm(self, "Rename this computer?",
                       f"Change the name from “{hostmod.current()}” to “{new}”?\n\n"
                       "A restart is required before it fully applies. The "
                       "original name is recorded and restorable."):
            return
        workers.run(lambda: hostmod.set_hostname(new), on_result=self.show_result)

    # ── Wi-Fi ──
    def _load_wifi(self) -> None:
        self.notify("Reading saved Wi-Fi profiles…", "info")

        def done(profiles):
            self.wifi_table.setRowCount(0)
            if not profiles:
                return self.notify(
                    "No saved Wi-Fi profiles (or no wireless adapter).", "info")
            for prof in profiles:
                r = self.wifi_table.rowCount()
                self.wifi_table.insertRow(r)
                self.wifi_table.setItem(r, 0, QTableWidgetItem(prof.name))
                self.wifi_table.setItem(r, 1, QTableWidgetItem(prof.auth or "—"))
                self.wifi_table.setItem(
                    r, 2, QTableWidgetItem("yes" if prof.auto_connect else "no"))
            self.notify(f"{len(profiles)} saved network(s).", "good")

        workers.run(wifi.list_profiles, on_result=done)

    def _scan_wifi(self) -> None:
        self.notify("Scanning nearby access points…", "info")

        def done(nets):
            if not nets:
                return self.notify("No networks visible.", "warning")
            dupes = wifi.find_duplicate_ssids(nets)
            open_nets = [n.ssid for n in nets if n.open_network]
            if dupes:
                self.notify(
                    "Possible evil twin — one SSID advertised by access points "
                    f"from different vendors: {', '.join(dupes)}", "critical")
            elif open_nets:
                self.notify(
                    f"{len(nets)} networks. Unencrypted nearby: "
                    f"{', '.join(open_nets[:4])}", "warning")
            else:
                self.notify(f"{len(nets)} networks, nothing suspicious.", "good")

        workers.run(wifi.scan_nearby, on_result=done)

    def _forget_wifi(self) -> None:
        rows = {i.row() for i in self.wifi_table.selectedIndexes()}
        names = [self.wifi_table.item(r, 0).text() for r in sorted(rows)
                 if self.wifi_table.item(r, 0)]
        if not names:
            return self.notify("Select one or more networks first.", "warning")
        if not confirm(self, "Forget these networks?",
                       f"Remove {len(names)} saved network(s)?\n\n"
                       + "\n".join("   • " + n for n in names[:10])
                       + "\n\nEach profile is exported into the journal first, "
                         "so this can be undone."):
            return

        def work():
            return [wifi.forget_profile(n) for n in names]

        def done(results):
            ok = sum(1 for r in results if r[0])
            self.notify(f"{ok} of {len(results)} network(s) forgotten.",
                        "good" if ok else "warning")
            self._load_wifi()
            self.app.refresh_status()

        workers.run(work, on_result=done)
