"""Connection — Tor, system proxy, and DNS resolvers."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QComboBox, QGridLayout, QHBoxLayout, QLabel,
                               QLineEdit, QPlainTextEdit, QVBoxLayout, QWidget)

from ...core import dnsconf, licensing, mac, proxy, sysinfo, tor
from ..dialogs import inform
from ..theme import SECTION_COLOURS, theme
from ..widgets.controls import (Card, InfoRow, NoteBox, StatCard, ToggleSwitch,
                                button, divider, muted, section_label)
from .. import workers
from .base import Page

ACCENT = SECTION_COLOURS["Connection"]


class ConnectionPage(Page):
    title = "Connection"
    subtitle = ("Where your traffic goes and who resolves your domains. Even "
                "behind a VPN, an ISP resolver still sees every site you visit.")
    icon = "⚯"

    def build(self) -> None:
        self.add_header_button("Refresh", self.refresh)
        self._build_tiles()
        self._build_tor()
        self._build_dns()
        self._build_proxy()

    def _build_tiles(self) -> None:
        grid = QGridLayout()
        grid.setSpacing(12)
        self.tiles = {}
        for i, (key, label, icon) in enumerate([
                ("tor", "Tor", "⚯"), ("exit", "Exit IP", "⇥"),
                ("dns", "DNS resolver", "⇄"), ("proxy", "System proxy", "⇉")]):
            tile = StatCard(label, icon, ACCENT)
            grid.addWidget(tile, 0, i)
            grid.setColumnStretch(i, 1)
            self.tiles[key] = tile
        holder = QWidget()
        holder.setLayout(grid)
        self.content.addWidget(holder)

    # ── Tor ──
    def _build_tor(self) -> None:
        card = Card("Tor", "PrivacyKit speaks the Tor control protocol directly, "
                    "including SAFECOOKIE authentication. Tor Browser listens on "
                    "9151; a standalone Tor needs ControlPort in its torrc.",
                    ACCENT, "⚯")

        if licensing.has_feature("tor"):
            self.tor_rows = {}
            for key, label in (("version", "Tor version"),
                               ("bootstrap", "Bootstrap"),
                               ("socks", "SOCKS listener"),
                               ("real", "Your real IP"),
                               ("exitc", "Exit country")):
                r = InfoRow(label, "—")
                card.body.addWidget(r)
                self.tor_rows[key] = r

            card.body.addWidget(divider())

            actions = QHBoxLayout()
            actions.setSpacing(10)
            self.newnym_btn = button("⟳  New identity", "primary",
                                     self._new_identity)
            actions.addWidget(self.newnym_btn)
            actions.addWidget(button("Route traffic through Tor", "ghost",
                                     self._route_tor))
            actions.addWidget(button("Stop routing", "ghost", self._unroute))

            self.tor_password = QLineEdit()
            self.tor_password.setEchoMode(QLineEdit.Password)
            self.tor_password.setPlaceholderText("control password (if set)")
            self.tor_password.setMaximumWidth(200)
            actions.addWidget(self.tor_password)
            actions.addStretch()
            card.body.addLayout(actions)

            exit_row = QHBoxLayout()
            exit_row.setSpacing(10)
            exit_row.addWidget(QLabel("Prefer exit in"))
            self.country_combo = QComboBox()
            for code, name in tor.EXIT_COUNTRIES.items():
                self.country_combo.addItem(name, code)
            self.country_combo.setMaximumWidth(260)
            exit_row.addWidget(self.country_combo)
            exit_row.addWidget(button("Apply", "ghost", self._set_country))
            exit_row.addStretch()
            card.body.addLayout(exit_row)

            card.body.addWidget(muted(
                "StrictNodes is deliberately left off: with it, Tor refuses to "
                "connect at all when no exit exists in your chosen country. "
                "Without it, Tor prefers that country and falls back.", 11))

            card.body.addWidget(section_label("Built circuits"))
            self.circuits = QPlainTextEdit()
            self.circuits.setObjectName("Mono")
            self.circuits.setReadOnly(True)
            self.circuits.setMaximumHeight(120)
            card.body.addWidget(self.circuits)

            card.body.addWidget(NoteBox(
                "Routing traffic through Tor is not the same as using Tor "
                "Browser. Tor Browser also blocks WebRTC, resists "
                "fingerprinting, and isolates circuits per site. Proxying an "
                "ordinary browser hides your IP and leaves everything else "
                "about you as identifiable as before.", "warning"))
        else:
            card.body.addWidget(self._upsell("tor"))

        self.content.addWidget(card)

    # ── DNS ──
    def _build_dns(self) -> None:
        card = Card("DNS resolver",
                    "Two separate problems: who answers your queries, and who "
                    "can read them in transit. You need both fixed.",
                    ACCENT, "⇄")

        self.dns_rows = {}
        for key, label in (("provider", "Current resolver"),
                           ("servers", "Server addresses"),
                           ("doh", "Encryption"),
                           ("cache", "Cached domains")):
            r = InfoRow(label, "—")
            card.body.addWidget(r)
            self.dns_rows[key] = r

        card.body.addWidget(divider())

        grid = QGridLayout()
        grid.setSpacing(10)
        self._provider_buttons = {}
        for i, key in enumerate(dnsconf.PROVIDER_ORDER):
            provider = dnsconf.PROVIDERS[key]
            btn = self._provider_button(provider)
            grid.addWidget(btn, i // 4, i % 4)
            self._provider_buttons[key] = btn
        for c in range(4):
            grid.setColumnStretch(c, 1)
        holder = QWidget()
        holder.setLayout(grid)
        card.body.addWidget(holder)

        opts = QHBoxLayout()
        opts.setSpacing(10)
        self.doh_toggle = ToggleSwitch(True)
        opts.addWidget(self.doh_toggle)
        opts.addWidget(muted("Enable DNS-over-HTTPS (recommended)", 12))
        opts.addStretch()
        opts.addWidget(button("Back to automatic", "ghost", self._dns_auto))
        opts.addWidget(button("Flush cache", "ghost", self._flush))
        card.body.addLayout(opts)

        card.body.addWidget(muted(
            "UDP fallback is turned off, so DNS fails loudly rather than "
            "silently reverting to plaintext when the encrypted endpoint is "
            "unreachable — which is precisely when you would want to know.", 11))
        self.content.addWidget(card)

    def _provider_button(self, provider):
        selected_key = getattr(self, "_selected_dns", "cloudflare")
        box = Card(padding=13)
        box.setObjectName("CardInner")
        box.setCursor(Qt.PointingHandCursor)

        name = QLabel(provider.name)
        name.setWordWrap(True)
        name.setStyleSheet(
            f"color: {theme.p.text}; font-size: 12px; font-weight: 600;")
        box.body.addWidget(name)

        addr = QLabel(", ".join(provider.servers))
        addr.setStyleSheet(f"color: {ACCENT}; font-size: 11px;")
        box.body.addWidget(addr)

        blocks = QLabel(f"Blocks: {provider.filters}")
        blocks.setWordWrap(True)
        blocks.setStyleSheet(f"color: {theme.p.text_faint}; font-size: 11px;")
        box.body.addWidget(blocks)

        box.body.addWidget(button("Apply", "ghost",
                                  lambda p=provider: self._apply_dns(p.key)))
        return box

    # ── proxy ──
    def _build_proxy(self) -> None:
        card = Card("System proxy",
                    "The Windows-wide proxy setting. Respected by Edge, Chrome, "
                    "and most applications; ignored by Firefox and anything "
                    "using raw sockets.", ACCENT, "⇉")

        self.proxy_rows = {}
        for key, label in (("state", "Current setting"),
                           ("winhttp", "Machine-wide (WinHTTP)")):
            r = InfoRow(label, "—")
            card.body.addWidget(r)
            self.proxy_rows[key] = r

        r = QHBoxLayout()
        r.setSpacing(10)
        self.proxy_input = QLineEdit("127.0.0.1:9050")
        self.proxy_input.setObjectName("Mono")
        self.proxy_input.setMaximumWidth(200)
        r.addWidget(QLabel("Proxy"))
        r.addWidget(self.proxy_input)
        r.addWidget(button("Enable", "ghost", self._set_proxy))
        r.addWidget(button("Disable", "ghost", self._unroute))
        r.addWidget(button("Copy to WinHTTP", "ghost", self._winhttp,
                           "Services and background updaters use a separate "
                           "machine-wide proxy setting"))
        r.addStretch()
        card.body.addLayout(r)
        self.content.addWidget(card)

    def _upsell(self, feature_key: str) -> QWidget:
        from ..widgets.controls import NoteBox as NB
        _, message = licensing.require(feature_key)
        holder = QWidget()
        lay = QVBoxLayout(holder)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)
        lay.addWidget(NB(message, "info"))
        lay.addWidget(button("View licence options", "primary",
                             lambda: self.app.navigate("Settings")))
        return holder

    # ── refresh ──
    def refresh(self) -> None:
        adapter = self.app.adapter

        def work():
            data = {"tor": tor.detect(), "proxy": proxy.get_state(),
                    "winhttp": proxy.winhttp_state()}
            if adapter:
                data["dns"] = dnsconf.get_state(adapter)
            data["cache"] = len(dnsconf.cache_entries())
            if licensing.has_feature("tor") and data["tor"].controllable:
                pw = (self.tor_password.text().strip()
                      if hasattr(self, "tor_password") else "")
                data["full"] = tor.full_status(password=pw or None,
                                               fetch_exit_ip=False)
            return data

        workers.run(work, on_result=self._paint,
                    on_error=lambda e: self.notify(str(e), "warning"))

    def _paint(self, d) -> None:
        if not isinstance(d, dict):
            return
        p = theme.p

        st = d.get("tor")
        if st and st.running:
            self.tiles["tor"].set("RUNNING", f"{st.label} · SOCKS {st.socks_port}",
                                  p.success)
        else:
            self.tiles["tor"].set("OFF", "not detected", p.text_muted)

        full = d.get("full")
        if hasattr(self, "tor_rows"):
            self.tor_rows["version"].set(
                (full.version if full else "") or "unavailable")
            self.tor_rows["bootstrap"].set(
                (full.bootstrap if full else "") or "unavailable")
            self.tor_rows["socks"].set(
                f"127.0.0.1:{st.socks_port}" if st and st.socks_port else "—")
            self.tor_rows["exitc"].set(
                (full.exit_country if full else "") or "any country")
            if full and full.circuits:
                self.circuits.setPlainText("\n".join(full.circuits))
            else:
                self.circuits.setPlainText(
                    (st.error if st and st.error else
                     "No circuit information — the control port is not "
                     "reachable or Tor is not running."))

        dns = d.get("dns")
        if dns:
            private = not dns.automatic
            self.dns_rows["provider"].set(
                dns.provider_name(), p.success if private else p.warning)
            self.dns_rows["servers"].set(", ".join(dns.servers) or "from DHCP")
            self.dns_rows["doh"].set(
                "DNS-over-HTTPS active" if dns.doh_enabled
                else "plaintext — readable on the network path",
                p.success if dns.doh_enabled else p.warning)
            self.tiles["dns"].set(
                dns.provider_name().split("(")[0].strip()[:18],
                "encrypted" if dns.doh_enabled else "plaintext",
                p.success if dns.doh_enabled else p.warning)

        cached = d.get("cache", 0)
        self.dns_rows["cache"].set(
            f"{cached} domain(s) — readable by anyone at this keyboard",
            p.warning if cached > 40 else p.text_dim)

        px = d.get("proxy")
        if px:
            self.proxy_rows["state"].set(
                px.describe(), p.success if px.enabled else p.text_muted)
            self.tiles["proxy"].set("ON" if px.enabled else "OFF",
                                    px.server[:26] or "direct connection",
                                    p.success if px.enabled else p.text_muted)
        lines = [l.strip() for l in (d.get("winhttp") or "").splitlines()
                 if l.strip()]
        self.proxy_rows["winhttp"].set(lines[-1] if lines else "unavailable")

        if licensing.has_feature("tor") and st and st.running:
            workers.run(lambda: tor.exit_ip(st.socks_port),
                        on_result=self._paint_exit)
        else:
            self.tiles["exit"].set("—", "Tor not running", p.text_muted)

        workers.run(lambda: __import__(
            "privacykit.core.leaks", fromlist=["leaks"]).public_ip(),
            on_result=self._paint_real)

    def _paint_exit(self, result) -> None:
        if not isinstance(result, tuple):
            return
        ip, country = result
        self.tiles["exit"].set(ip or "—",
                              f"exit in {country}" if country else "via Tor",
                              theme.p.success if ip else theme.p.text_muted)

    def _paint_real(self, info) -> None:
        if not isinstance(info, dict) or not hasattr(self, "tor_rows"):
            return
        self.tor_rows["real"].set(
            (info.get("ip", "unknown")
             + (f"  ({info.get('org', '')})" if info.get("org") else "")),
            theme.p.warning)

    # ── actions ──
    def _new_identity(self) -> None:
        self.newnym_btn.setEnabled(False)
        self.newnym_btn.setText("Requesting…")
        pw = self.tor_password.text().strip() or None

        def done(result):
            self.newnym_btn.setEnabled(True)
            self.newnym_btn.setText("⟳  New identity")
            self.show_result(result)

        workers.run(lambda: tor.new_identity(pw), on_result=done)

    def _route_tor(self) -> None:
        st = tor.detect()
        if not st.running:
            return self.notify(
                "Tor is not running. Start Tor Browser or the Tor service first.",
                "critical")
        workers.run(lambda: proxy.route_through_tor(st.socks_port),
                    on_result=self.show_result)

    def _unroute(self) -> None:
        workers.run(proxy.disable_proxy, on_result=self.show_result)

    def _set_country(self) -> None:
        code = self.country_combo.currentData() or ""
        st = tor.detect()
        if not st.controllable:
            return self.notify(
                "Tor's control port is not reachable — see the torrc notes.",
                "critical")

        def work():
            pw = self.tor_password.text().strip() or None
            with tor.TorController(st.control_port, password=pw) as c:
                return c.set_exit_country(code)

        workers.run(work, on_result=self.show_result)

    def _apply_dns(self, key: str) -> None:
        adapter = self.app.adapter
        if not adapter:
            return self.notify("Select an adapter on the Identity page.", "warning")
        if not sysinfo.is_admin():
            return self.notify("Administrator rights are required.", "critical")
        workers.run(
            lambda: dnsconf.set_provider(adapter, key, self.doh_toggle.isChecked()),
            on_result=self.show_result)

    def _dns_auto(self) -> None:
        if self.app.adapter:
            workers.run(lambda: dnsconf.set_automatic(self.app.adapter),
                        on_result=self.show_result)

    def _flush(self) -> None:
        workers.run(dnsconf.flush_cache, on_result=self.show_result)

    def _set_proxy(self) -> None:
        value = self.proxy_input.text().strip()
        if not value:
            return
        workers.run(lambda: proxy.set_proxy(value), on_result=self.show_result)

    def _winhttp(self) -> None:
        workers.run(proxy.set_winhttp_from_ie, on_result=self.show_result)
