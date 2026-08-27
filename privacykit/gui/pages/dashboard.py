"""Dashboard — score, live status, and one-click profiles."""

from __future__ import annotations

from typing import Dict

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QGridLayout, QHBoxLayout, QLabel, QVBoxLayout,
                               QWidget)

from ...core import (dnsconf, firewall, journal, licensing, mac,
                                 presets, protection, proxy, score, sysinfo, tor)
from ..theme import SECTION_COLOURS, theme
from ..widgets.controls import (Card, InfoRow, StatCard, button, divider,
                                muted, section_label)
from ..widgets.gauges import MeterBar, ScoreRing
from .. import workers
from .base import Page


class DashboardPage(Page):
    title = "Dashboard"
    subtitle = "Live status, privacy score, and one-click postures."
    icon = "◈"

    def build(self) -> None:
        self.add_header_button("Refresh", self.refresh)

        self._build_hero()
        self._build_tiles()
        self._build_profiles()
        self._build_system()

    # ── hero: score + breakdown ──
    def _build_hero(self) -> None:
        card = Card(accent=SECTION_COLOURS["Dashboard"], padding=22)
        row = QHBoxLayout()
        row.setSpacing(30)

        left = QVBoxLayout()
        left.setSpacing(10)
        left.setAlignment(Qt.AlignTop | Qt.AlignHCenter)
        self.ring = ScoreRing(176, 14)
        left.addWidget(self.ring, 0, Qt.AlignHCenter)
        self.recheck_btn = button("Re-assess", "ghost", self.refresh_score)
        left.addWidget(self.recheck_btn, 0, Qt.AlignHCenter)
        row.addLayout(left)

        right = QVBoxLayout()
        right.setSpacing(9)

        self.headline = QLabel("Assessing this machine…")
        self.headline.setStyleSheet(
            f"color: {theme.p.text}; font-size: 17px; font-weight: 600;")
        self.headline.setWordWrap(True)
        right.addWidget(self.headline)

        self.headline_sub = muted(
            "Every point is explained below, with the specific fix and where to "
            "apply it.")
        right.addWidget(self.headline_sub)
        right.addSpacing(6)

        self.checks_box = QVBoxLayout()
        self.checks_box.setSpacing(7)
        right.addLayout(self.checks_box)
        right.addStretch()

        row.addLayout(right, 1)
        card.body.addLayout(row)
        self.content.addWidget(card)

    # ── status tiles ──
    def _build_tiles(self) -> None:
        self.content.addWidget(section_label("Live status"))

        grid = QGridLayout()
        grid.setSpacing(12)
        self.tiles: Dict[str, StatCard] = {}

        specs = [
            ("adapter", "Active adapter", "⬡", "Identity", SECTION_COLOURS["Identity"]),
            ("mac", "MAC address", "⬢", "Identity", SECTION_COLOURS["Identity"]),
            ("dns", "DNS resolver", "⇄", "Connection", SECTION_COLOURS["Connection"]),
            ("tor", "Tor", "⚯", "Connection", SECTION_COLOURS["Connection"]),
            ("location", "Location match", "◎", "Location", SECTION_COLOURS["Location"]),
            ("killswitch", "Kill switch", "⛨", "Protection", SECTION_COLOURS["Protection"]),
            ("protection", "Live protection", "◉", "Protection", SECTION_COLOURS["Protection"]),
            ("changes", "Pending changes", "≡", "Journal", SECTION_COLOURS["Journal"]),
        ]
        for i, (key, label, icon, target, colour) in enumerate(specs):
            tile = StatCard(label, icon, colour)
            tile.clicked.connect(lambda t=target: self.app.navigate(t))
            grid.addWidget(tile, i // 4, i % 4)
            self.tiles[key] = tile
        for c in range(4):
            grid.setColumnStretch(c, 1)

        holder = QWidget()
        holder.setLayout(grid)
        self.content.addWidget(holder)

    # ── profiles ──
    def _build_profiles(self) -> None:
        self.content.addWidget(section_label("One-click profiles"))

        card = Card(subtitle=(
            "Coherent combinations rather than single switches — arming a kill "
            "switch without starting Tor just breaks your connection. Each "
            "lists what it will change before it runs, and every step is "
            "individually reversible."), padding=20)

        grid = QGridLayout()
        grid.setSpacing(12)
        for i, key in enumerate(presets.PRESET_ORDER):
            grid.addWidget(self._profile_card(presets.PRESETS[key]), 0, i)
            grid.setColumnStretch(i, 1)
        holder = QWidget()
        holder.setLayout(grid)
        card.body.addWidget(holder)

        self.custom_row = QVBoxLayout()
        self.custom_row.setSpacing(8)
        card.body.addLayout(self.custom_row)

        self.content.addWidget(card)

    def _profile_card(self, preset) -> QWidget:
        from ..widgets.controls import Card as InnerCard
        box = InnerCard(accent=preset.accent, padding=15)
        box.setObjectName("CardInner")

        title = QLabel(f"{preset.icon}  {preset.name}")
        title.setStyleSheet(
            f"color: {theme.p.text}; font-size: 13px; font-weight: 700;")
        box.body.addWidget(title)

        tag = muted(preset.tagline, 11)
        box.body.addWidget(tag)

        for change in preset.changes[:3]:
            lbl = muted("• " + change, 11)
            lbl.setStyleSheet(f"color: {theme.p.text_faint}; font-size: 11px;")
            box.body.addWidget(lbl)
        if len(preset.changes) > 3:
            more = muted(f"• and {len(preset.changes) - 3} more…", 11)
            more.setStyleSheet(f"color: {theme.p.text_faint}; font-size: 11px;")
            box.body.addWidget(more)

        box.body.addSpacing(4)
        box.body.addWidget(
            button("Apply", "primary", lambda p=preset: self._apply_preset(p)))
        return box

    # ── system info ──
    def _build_system(self) -> None:
        card = Card("This machine", icon="▤",
                    accent=SECTION_COLOURS["Settings"])
        info = sysinfo.os_summary()
        self.sys_rows = {}
        for key, label, value in (
                ("os", "Operating system",
                 info.get("edition", info.get("system", "?"))),
                ("host", "Computer name", info.get("hostname", "?")),
                ("user", "Signed in as", info.get("user", "?")),
                ("admin", "Elevated",
                 "yes — full access to system settings" if info.get("admin")
                 else "NO — system changes will be refused"),
                ("edition", "Edition", licensing.entitlement().name),
        ):
            r = InfoRow(label, str(value))
            if key == "admin" and not info.get("admin"):
                r.set(str(value), theme.p.danger)
            card.body.addWidget(r)
            self.sys_rows[key] = r
        self.content.addWidget(card)

    # ── refresh ──
    def refresh(self) -> None:
        self.refresh_tiles()
        self.refresh_score()
        self._refresh_custom_profiles()
        self.sys_rows["edition"].set(licensing.entitlement(refresh=True).name)

    def _refresh_custom_profiles(self) -> None:
        from ...core.settings import profile_store
        while self.custom_row.count():
            item = self.custom_row.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        customs = profile_store.all()
        if not customs:
            return
        self.custom_row.addWidget(divider())
        lbl = muted(f"Your profiles ({len(customs)})", 11)
        self.custom_row.addWidget(lbl)
        row = QHBoxLayout()
        row.setSpacing(9)
        for prof in customs[:6]:
            row.addWidget(button(f"{prof.icon}  {prof.name}", "ghost",
                                 lambda p=prof: self._apply_custom(p)))
        row.addStretch()
        holder = QWidget()
        holder.setLayout(row)
        self.custom_row.addWidget(holder)

    def refresh_tiles(self) -> None:
        def work():
            data = {}
            adapters = mac.list_adapters(include_virtual=False)
            active = next((a for a in adapters if a.status.lower() == "up"),
                          adapters[0] if adapters else None)
            data["adapter"] = active
            if active:
                self.app.set_adapter(active.name)
                data["dns"] = dnsconf.get_state(active.name)
            data["tor"] = tor.detect()
            data["killswitch"] = firewall.killswitch_active()
            data["pending"] = journal.pending_count()
            data["protection"] = protection.service.running
            from ...core import geo
            data["geo"] = geo.get_state()
            return data

        workers.run(work, on_result=self._paint_tiles,
                    on_error=lambda e: self.notify(f"Status refresh failed: {e}",
                                                   "warning"))

    def _paint_tiles(self, d) -> None:
        if not isinstance(d, dict):
            return
        p = theme.p

        a = d.get("adapter")
        if a:
            self.tiles["adapter"].set(a.name[:18], a.description[:34] or "—",
                                      SECTION_COLOURS["Identity"])
            self.tiles["mac"].set(
                a.mac.upper() or "—",
                f"spoofed · looks like {a.vendor}" if a.spoofed
                else "hardware address — identifies this device",
                p.success if a.spoofed else p.warning)
        else:
            self.tiles["adapter"].set("none", "no physical adapter", p.text_muted)
            self.tiles["mac"].set("—", "", p.text_muted)

        dns = d.get("dns")
        if dns:
            private = not dns.automatic
            self.tiles["dns"].set(
                dns.provider_name().split("(")[0].strip()[:18],
                "encrypted (DoH)" if dns.doh_enabled else "queries in plaintext",
                p.success if (private and dns.doh_enabled)
                else (p.info if private else p.warning))
        else:
            self.tiles["dns"].set("unknown", "", p.text_muted)

        t = d.get("tor")
        if t and t.running:
            self.tiles["tor"].set("RUNNING", f"{t.label} · SOCKS {t.socks_port}",
                                  p.success)
        else:
            self.tiles["tor"].set("OFF", "not detected on localhost", p.text_muted)

        g = d.get("geo")
        if g:
            self.tiles["location"].set(
                (g.region or "—").upper(),
                f"{g.timezone_display or g.timezone or 'unknown timezone'}"[:34],
                SECTION_COLOURS["Location"])

        ks = d.get("killswitch")
        self.tiles["killswitch"].set(
            "ARMED" if ks else "OFF",
            "non-proxy traffic blocked" if ks else "traffic flows if Tor drops",
            p.success if ks else p.text_muted)

        live = d.get("protection")
        self.tiles["protection"].set(
            "ON" if live else "OFF",
            f"{len(protection.service.recent())} event(s) recorded" if live
            else "not watching for changes",
            p.success if live else p.text_muted, pulse=bool(live))

        n = d.get("pending", 0)
        self.tiles["changes"].set(
            str(n), "click to review and undo" if n else "nothing applied",
            p.warning if n else p.text_muted)

        self.app.refresh_status()

    def refresh_score(self) -> None:
        self.headline.setText("Assessing this machine…")
        workers.run(lambda: score.compute(quick=True), on_result=self._paint_score,
                    on_error=lambda e: self.notify(f"Score failed: {e}", "warning"))

    def _paint_score(self, rep) -> None:
        if not hasattr(rep, "score"):
            return
        self.ring.set_score(rep.score, f"Grade {rep.grade}",
                            f"{len(rep.passing())} of {len(rep.checks)} checks pass")

        failing = rep.failing()
        if failing:
            self.headline.setText(
                f"{len(failing)} thing{'s' if len(failing) != 1 else ''} worth fixing")
            self.headline_sub.setText(
                "Ordered by how much each one actually affects you.")
        else:
            self.headline.setText("Every check passes")
            self.headline_sub.setText("Nothing outstanding on this machine.")

        while self.checks_box.count():
            item = self.checks_box.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for check in failing[:5]:
            self.checks_box.addWidget(self._check_row(check))
        if not failing:
            for check in rep.passing()[:5]:
                self.checks_box.addWidget(self._check_row(check, passing=True))

    def _check_row(self, check, passing: bool = False) -> QWidget:
        p = theme.p
        colour = p.success if passing else (p.warning if check.partial else p.danger)

        holder = QWidget()
        lay = QVBoxLayout(holder)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)

        top = QHBoxLayout()
        top.setSpacing(9)
        dot = QLabel("✔" if passing else "●")
        dot.setStyleSheet(f"color: {colour}; font-size: 11px;")
        dot.setFixedWidth(13)
        top.addWidget(dot)

        title = QLabel(check.title)
        title.setStyleSheet(
            f"color: {p.text_dim}; font-size: 12px; font-weight: 600;")
        top.addWidget(title, 1)

        if not passing:
            pts = QLabel(f"−{check.weight if not check.partial else check.weight // 2}")
            pts.setStyleSheet(f"color: {colour}; font-size: 11px;")
            top.addWidget(pts)
        lay.addLayout(top)

        if not passing and check.tab:
            link = button(check.fix, "link",
                          lambda t=check.tab: self.app.navigate(_map_tab(t)))
            link.setStyleSheet(
                f"QPushButton {{ color: {p.accent}; background: transparent;"
                "border: none; font-size: 11px; text-align: left;"
                "padding: 0 0 0 22px; }")
            lay.addWidget(link)

        bar = MeterBar(5)
        bar.set_value(1.0 if passing else (0.5 if check.partial else 0.06), colour)
        lay.addWidget(bar)
        return holder

    # ── actions ──
    def _apply_preset(self, preset) -> None:
        from ..dialogs import confirm
        lines = "\n".join(f"   •  {c}" for c in preset.changes)
        warn = ("\n\nWarnings:\n"
                + "\n".join(f"   !  {w}" for w in preset.warnings)
                if preset.warnings else "")
        if not confirm(self, f"Apply “{preset.name}”?",
                       f"{preset.description}\n\nThis will:\n{lines}{warn}\n\n"
                       "Every step is recorded and reversible with Panic Restore."):
            return

        adapter = self.app.adapter
        self.notify(f"Applying {preset.name}…", "info")

        workers.run(
            lambda: presets.apply(preset.key, adapter),
            on_result=self._preset_done,
            on_error=lambda e: self.notify(f"Preset failed: {e}", "critical"))

    def _preset_done(self, result) -> None:
        if not isinstance(result, dict):
            return
        kind = "good" if not result.get("failed") else "warning"
        self.notify(
            f"{result['succeeded']} of {result['steps']} step(s) applied"
            + (f", {result['failed']} failed" if result.get("failed") else ""),
            kind)
        for line in result.get("details", []):
            self.app.log(line)
        self.refresh()

    def _apply_custom(self, profile) -> None:
        from ..dialogs import confirm
        from ...core import runner
        if not confirm(self, f"Apply “{profile.name}”?",
                       f"{profile.description}\n\n{profile.summary()} will run. "
                       "Every step is reversible."):
            return
        self.notify(f"Applying {profile.name}…", "info")
        workers.run(lambda: runner.run_actions(profile.actions, self.app.adapter),
                    on_result=self._preset_done,
                    on_error=lambda e: self.notify(str(e), "critical"))


def _map_tab(name: str) -> str:
    """Translate score-engine tab names onto the new page names."""
    return {
        "DNS": "Connection", "Tor": "Connection",
        "Network Identity": "Identity", "Firewall": "Protection",
        "Windows Hardening": "Privacy", "Dashboard": "Dashboard",
    }.get(name, name)
