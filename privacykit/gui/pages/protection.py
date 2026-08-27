"""Protection — firewall kill switch, hardening toggles, and live monitoring."""

from __future__ import annotations

import time

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (QGridLayout, QHBoxLayout, QLabel, QVBoxLayout,
                               QWidget)

from ...core import firewall, licensing, protection, sysinfo, threatfeed, tor
from ...core.settings import settings
from ..dialogs import confirm, show_log
from ..theme import SECTION_COLOURS, theme
from ..widgets.controls import (Card, FindingRow, InfoRow, NoteBox, StatCard,
                                SettingRow, ToggleSwitch, button, divider,
                                muted, section_label)
from ..widgets.gauges import ActivityGraph
from .. import workers
from .base import Page

ACCENT = SECTION_COLOURS["Protection"]


class ProtectionPage(Page):
    title = "Protection"
    subtitle = ("A proxy setting is advisory — a program can ignore it. "
                "A firewall rule is not.")
    icon = "⛨"

    def build(self) -> None:
        self.add_header_button("Refresh", self.refresh)
        self._build_tiles()
        self._build_killswitch()
        self._build_live()
        self._build_isolation()
        self._build_feed()

    def _build_tiles(self) -> None:
        grid = QGridLayout()
        grid.setSpacing(12)
        self.tiles = {}
        for i, (key, label, icon) in enumerate([
                ("firewall", "Windows Firewall", "⛨"),
                ("killswitch", "Kill switch", "⏻"),
                ("live", "Live protection", "◉"),
                ("blocked", "Domains blocked", "⊘")]):
            tile = StatCard(label, icon, ACCENT)
            grid.addWidget(tile, 0, i)
            grid.setColumnStretch(i, 1)
            self.tiles[key] = tile
        holder = QWidget()
        holder.setLayout(grid)
        self.content.addWidget(holder)

    def _build_killswitch(self) -> None:
        card = Card("Kill switch",
                    "Blocks outbound traffic that is not going to the local "
                    "proxy, so a program trying to bypass Tor fails to connect "
                    "instead of silently leaking.", ACCENT, "⏻")

        r = QHBoxLayout()
        r.setSpacing(10)
        self.arm_btn = button("Arm kill switch", "danger", self._arm)
        r.addWidget(self.arm_btn)
        r.addWidget(button("Disarm", "ghost", self._disarm))
        r.addStretch()
        card.body.addLayout(r)

        self.allow_lan = ToggleSwitch(False)
        card.body.addWidget(SettingRow(
            "Allow local network traffic",
            "Keeps printers and network shares working. Turn off on a public "
            "network where you do not trust the other devices.", self.allow_lan))

        self.allow_dhcp = ToggleSwitch(True)
        card.body.addWidget(SettingRow(
            "Allow DHCP (strongly recommended)",
            "Without this the machine loses its address at lease renewal and "
            "drops off the network entirely. DHCP is link-local, so allowing it "
            "costs nothing in privacy terms.", self.allow_dhcp))

        card.body.addWidget(NoteBox(
            "When armed, expect things to stop working — that is the point. If "
            "your browser will not load pages, the kill switch is doing its job "
            "because that traffic is not going through the proxy.", "critical"))
        self.content.addWidget(card)

    def _build_live(self) -> None:
        card = Card("Live protection",
                    "Continuous watchers instead of on-demand checks. A one-off "
                    "audit tells you the machine was fine when you looked.",
                    ACCENT, "◉")
        if not licensing.has_feature("protection"):
            self.add_pro_badge()

        r = QHBoxLayout()
        r.setSpacing(12)
        self.live_toggle = ToggleSwitch(protection.service.running)
        self.live_toggle.toggled.connect(self._toggle_live)
        r.addWidget(self.live_toggle)
        self.live_status = muted("Not running", 12)
        r.addWidget(self.live_status, 1)
        r.addWidget(button("Clear events", "ghost", self._clear_events))
        card.body.addLayout(r)

        self.activity = ActivityGraph(46, 50)
        card.body.addWidget(self.activity)

        card.body.addWidget(section_label("Watchers"))
        self.watcher_toggles = {}
        for watcher in protection.service.watchers:
            toggle = ToggleSwitch(watcher.enabled)
            toggle.toggled.connect(
                lambda v, w=watcher: self._set_watcher(w, v))
            card.body.addWidget(SettingRow(
                watcher.name, watcher.description, toggle))
            self.watcher_toggles[watcher.name] = toggle

        card.body.addWidget(section_label("Recent events"))
        self.events_box = QVBoxLayout()
        self.events_box.setSpacing(7)
        card.body.addLayout(self.events_box)
        self.content.addWidget(card)

        self._event_timer = QTimer(self)
        self._event_timer.timeout.connect(self._refresh_events)
        self._event_timer.start(2500)

    def _build_isolation(self) -> None:
        card = Card("Network isolation and protocols", "", ACCENT, "⊘")

        self.lan_toggle = ToggleSwitch(False)
        self.lan_toggle.toggled.connect(
            lambda v: workers.run(lambda: firewall.block_lan(v),
                                  on_result=self.show_result))
        card.body.addWidget(SettingRow(
            "Block local network traffic",
            "Stops other devices on the same café or hotel Wi-Fi reaching this "
            "machine. Breaks printers, shares, and casting.", self.lan_toggle))

        self.smb_toggle = ToggleSwitch(False)
        self.smb_toggle.toggled.connect(
            lambda v: workers.run(lambda: firewall.block_smb(v),
                                  on_result=self.show_result))
        card.body.addWidget(SettingRow(
            "Block SMB and NetBIOS",
            "Closes ports 135, 139, and 445 inbound — the classic Windows "
            "attack surface on an untrusted network.", self.smb_toggle))

        self.llmnr_toggle = ToggleSwitch(False)
        self.llmnr_toggle.toggled.connect(
            lambda v: workers.run(lambda: firewall.set_llmnr(not v),
                                  on_result=self.show_result))
        card.body.addWidget(SettingRow(
            "Disable LLMNR",
            "When DNS fails, Windows shouts the name across the whole local "
            "network and an attacker can answer “that's me” to harvest "
            "credentials.", self.llmnr_toggle))

        self.ipv6_toggle = ToggleSwitch(False)
        self.ipv6_toggle.toggled.connect(self._set_ipv6)
        card.body.addWidget(SettingRow(
            "Disable IPv6 on the selected adapter",
            "The classic VPN bypass: your tunnel carries IPv4 while Windows "
            "quietly prefers IPv6 for any site with an AAAA record.",
            self.ipv6_toggle))

        card.body.addWidget(divider())
        r = QHBoxLayout()
        r.addWidget(button("Remove all PrivacyKit firewall rules", "ghost",
                           self._cleanup))
        r.addStretch()
        card.body.addLayout(r)
        self.content.addWidget(card)

    def _build_feed(self) -> None:
        card = Card("Threat feed",
                    "Replaces the static built-in list with feeds maintained by "
                    "people who do that full time — merged, deduplicated, and "
                    "filtered against an allowlist so Windows Update and "
                    "activation are never blocked.", ACCENT, "⇊")
        if not licensing.has_feature("threatfeed"):
            pass

        self.feed_rows = {}
        for key, label in (("cached", "Cached list"), ("age", "Last updated")):
            r = InfoRow(label, "—")
            card.body.addWidget(r)
            self.feed_rows[key] = r

        self.feed_toggles = {}
        for feed in threatfeed.feed_list():
            toggle = ToggleSwitch(feed["key"] in settings.get("threatfeed_sources", []))
            card.body.addWidget(SettingRow(feed["name"], feed["description"],
                                           toggle))
            self.feed_toggles[feed["key"]] = toggle

        r = QHBoxLayout()
        r.setSpacing(10)
        self.update_btn = button("Update blocklist now", "primary",
                                 self._update_feed)
        r.addWidget(self.update_btn)
        r.addWidget(button("Apply to hosts file", "ghost", self._apply_feed))
        r.addStretch()
        card.body.addLayout(r)

        self.feed_status = muted("", 12)
        card.body.addWidget(self.feed_status)
        self.content.addWidget(card)

    # ── refresh ──
    def refresh(self) -> None:
        adapter = self.app.adapter

        def work():
            return {
                "profiles": firewall.profiles(),
                "killswitch": firewall.killswitch_active(),
                "llmnr": firewall.llmnr_enabled(),
                "lan": firewall._rule_exists(firewall.LAN_BLOCK),
                "smb": firewall._rule_exists(firewall.SMB_BLOCK),
                "ipv6": firewall.ipv6_enabled(adapter) if adapter else None,
                "cached": threatfeed.cached_count(),
                "age": threatfeed.cache_age(),
            }

        workers.run(work, on_result=self._paint,
                    on_error=lambda e: self.notify(str(e), "warning"))
        self._refresh_events()

    def _paint(self, d) -> None:
        if not isinstance(d, dict):
            return
        p = theme.p

        on = any("ON" in (pr.state or "").upper() for pr in d.get("profiles", []))
        self.tiles["firewall"].set("ON" if on else "OFF",
                                   f"{len(d.get('profiles', []))} profile(s)",
                                   p.success if on else p.danger)

        ks = d.get("killswitch")
        self.tiles["killswitch"].set("ARMED" if ks else "OFF",
                                     "non-proxy traffic blocked" if ks
                                     else "traffic flows if the proxy drops",
                                     p.success if ks else p.text_muted)

        live = protection.service.running
        self.tiles["live"].set(
            "ON" if live else "OFF",
            f"{protection.service.uptime} · {len(protection.service.recent())} events"
            if live else "not watching", p.success if live else p.text_muted,
            pulse=live)

        cached = d.get("cached", 0)
        self.tiles["blocked"].set(f"{cached:,}" if cached else "0",
                                  "domains in the cached list",
                                  p.success if cached else p.text_muted)

        for toggle, value in ((self.lan_toggle, d.get("lan")),
                              (self.smb_toggle, d.get("smb")),
                              (self.llmnr_toggle, not d.get("llmnr", True))):
            toggle.blockSignals(True)
            toggle.setChecked(bool(value))
            toggle.blockSignals(False)

        if d.get("ipv6") is not None:
            self.ipv6_toggle.blockSignals(True)
            self.ipv6_toggle.setChecked(not d["ipv6"])
            self.ipv6_toggle.blockSignals(False)

        self.feed_rows["cached"].set(
            f"{cached:,} domains" if cached else "no list cached yet")
        age = d.get("age")
        self.feed_rows["age"].set(
            f"{age:.1f} day(s) ago" if age is not None else "never",
            p.warning if (age or 0) > 14 else p.text_dim)

    def _refresh_events(self) -> None:
        if not hasattr(self, "events_box"):
            return
        events = protection.service.recent(6)
        self.activity.push(len([e for e in protection.service.recent(200)
                                if time.time() - e.ts < 5]))

        self.live_status.setText(
            f"Running · {protection.service.uptime} · "
            f"{len(protection.service.recent(999))} event(s)"
            if protection.service.running else "Not running")

        while self.events_box.count():
            item = self.events_box.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not events:
            self.events_box.addWidget(muted(
                "No events recorded. Watchers report changes as they happen — "
                "joining a network, DNS being rewritten, protections dropping.",
                12))
            return
        for e in events:
            self.events_box.addWidget(FindingRow(
                f"{e.when}  ·  {e.title}", e.severity, e.detail, e.action))

    # ── actions ──
    def _arm(self) -> None:
        st = tor.detect()
        port = st.socks_port or 9050
        if not st.running and not confirm(
                self, "Tor is not running",
                f"The kill switch will block all outbound traffic except to "
                f"127.0.0.1:{port} — which means nothing reaches the internet "
                "until Tor is running.\n\nArm it anyway?", "Arm anyway",
                "critical"):
            return
        workers.run(lambda: firewall.arm_killswitch(
            port, self.allow_lan.isChecked(), self.allow_dhcp.isChecked()),
            on_result=self.show_result)

    def _disarm(self) -> None:
        workers.run(firewall.disarm_killswitch, on_result=self.show_result)

    def _set_ipv6(self, disabled: bool) -> None:
        if not self.app.adapter:
            return self.notify("Select an adapter on the Identity page.",
                               "warning")
        workers.run(lambda: firewall.set_ipv6(self.app.adapter, not disabled),
                    on_result=self.show_result)

    def _cleanup(self) -> None:
        if not confirm(self, "Remove all PrivacyKit firewall rules?",
                       "Deletes every rule this application created, including "
                       "the kill switch and any blocks."):
            return
        workers.run(firewall.cleanup_all_rules, on_result=self.show_result)

    def _toggle_live(self, enabled: bool) -> None:
        ok, message = licensing.require("protection")
        if not ok:
            self.live_toggle.blockSignals(True)
            self.live_toggle.setChecked(False)
            self.live_toggle.blockSignals(False)
            return self.notify(message, "warning")

        if enabled:
            protection.service.on_event = self.app.on_protection_event
            ok, msg = protection.service.start()
        else:
            ok, msg = protection.service.stop()
        settings.set("live_protection", enabled)
        self.notify(msg, "good" if ok else "critical")
        self.refresh()

    def _set_watcher(self, watcher, enabled: bool) -> None:
        watcher.enabled = enabled
        stored = dict(settings.get("protection_watchers", {}))
        stored[watcher.name] = enabled
        settings.set("protection_watchers", stored)

    def _clear_events(self) -> None:
        protection.service.clear()
        self._refresh_events()

    def _update_feed(self) -> None:
        ok, message = licensing.require("threatfeed")
        if not ok:
            return self.notify(message, "warning")

        selected = [k for k, t in self.feed_toggles.items() if t.isChecked()]
        if not selected:
            return self.notify("Select at least one feed.", "warning")
        settings.set("threatfeed_sources", selected)

        self.update_btn.setEnabled(False)
        self.update_btn.setText("Updating…")
        self.feed_status.setText("Fetching feeds…")

        def done(report):
            self.update_btn.setEnabled(True)
            self.update_btn.setText("Update blocklist now")
            if not hasattr(report, "summary"):
                return self.notify("Feed update failed.", "critical")
            self.feed_status.setText(
                report.summary()
                + f" · {report.allowlisted_skipped} critical domain(s) protected"
                + f" · {report.malformed_skipped} malformed entr(ies) rejected")
            self.notify(f"Blocklist updated — {report.total_unique:,} domains.",
                        "good" if report.total_unique else "warning")
            self.refresh()

        workers.run(lambda: threatfeed.update(selected), on_result=done,
                    on_progress=lambda m, _o: self.feed_status.setText(m),
                    pass_progress=True)

    def _apply_feed(self) -> None:
        domains = threatfeed.load_cached()
        if not domains:
            return self.notify("No cached blocklist — update it first.", "warning")
        if not sysinfo.is_admin():
            return self.notify("Administrator rights are required.", "critical")
        if not confirm(self, "Apply the blocklist to the hosts file?",
                       f"{len(domains):,} domains will be pointed at 0.0.0.0.\n\n"
                       "Your existing hosts file is backed up first and can be "
                       "restored from the Journal. Windows Update, activation, "
                       "and certificate checks are protected by an allowlist."):
            return
        from ...core import hardening
        workers.run(lambda: hardening.apply_hosts_blocklist(domains),
                    on_result=self.show_result)
