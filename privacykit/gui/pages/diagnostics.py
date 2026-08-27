"""Diagnostics — leak tests, connection monitor, and listening ports."""

from __future__ import annotations

from PySide6.QtWidgets import (QGridLayout, QHBoxLayout, QHeaderView, QLabel,
                               QTableWidget, QTableWidgetItem, QVBoxLayout,
                               QWidget)

from PySide6.QtGui import QColor

from ...core import leaks, monitor
from ..theme import SECTION_COLOURS, theme
from ..widgets.controls import (Card, FindingRow, StatCard, ToggleSwitch,
                                button, muted, section_label)
from .. import workers
from .base import Page

ACCENT = SECTION_COLOURS["Diagnostics"]


class DiagnosticsPage(Page):
    title = "Diagnostics"
    subtitle = ("Every other page configures something. This one checks whether "
                "the configuration is doing what it claims.")
    icon = "◎"

    def build(self) -> None:
        self._build_tiles()
        self._build_findings()
        self._build_monitor()
        self._build_ports()

    def _build_tiles(self) -> None:
        grid = QGridLayout()
        grid.setSpacing(12)
        self.tiles = {}
        for i, (key, label, icon) in enumerate([
                ("ip", "Public IP", "⇥"), ("tor", "Via Tor", "⚯"),
                ("dns", "DNS", "⇄"), ("ipv6", "IPv6", "⑥")]):
            tile = StatCard(label, icon, ACCENT)
            grid.addWidget(tile, 0, i)
            grid.setColumnStretch(i, 1)
            self.tiles[key] = tile
        holder = QWidget()
        holder.setLayout(grid)
        self.content.addWidget(holder)

        r = QHBoxLayout()
        r.setSpacing(10)
        self.run_btn = button("▶  Run all leak tests", "primary", self._run)
        r.addWidget(self.run_btn)
        self.progress = muted("", 12)
        r.addWidget(self.progress, 1)
        holder2 = QWidget()
        holder2.setLayout(r)
        self.content.addWidget(holder2)

    def _build_findings(self) -> None:
        self.findings_card = Card(
            "Findings", "Ranked by severity, each with the specific remedy.",
            ACCENT, "⚑")
        self.findings_box = QVBoxLayout()
        self.findings_box.setSpacing(8)
        self.findings_card.body.addLayout(self.findings_box)
        self.findings_box.addWidget(muted(
            "Run the tests to see what is actually leaking.", 12))
        self.content.addWidget(self.findings_card)

    def _build_monitor(self) -> None:
        card = Card("Connection monitor",
                    "What this machine is talking to right now, with the owning "
                    "process. Answers the question no settings screen can: is "
                    "something still phoning home?", ACCENT, "⇅")

        r = QHBoxLayout()
        r.setSpacing(10)
        r.addWidget(button("Scan connections", "ghost", self._scan))
        self.resolve_toggle = ToggleSwitch(True)
        r.addWidget(self.resolve_toggle)
        r.addWidget(muted("Resolve hostnames", 12))
        r.addStretch()
        card.body.addLayout(r)

        self.summary = muted("", 12)
        card.body.addWidget(self.summary)

        self.conn_table = QTableWidget(0, 5)
        self.conn_table.setHorizontalHeaderLabels(
            ["Process", "Destination", "Port", "State", "Note"])
        self.conn_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.Stretch)
        self.conn_table.verticalHeader().setVisible(False)
        self.conn_table.setAlternatingRowColors(True)
        self.conn_table.setMinimumHeight(260)
        card.body.addWidget(self.conn_table)
        self.content.addWidget(card)

    def _build_ports(self) -> None:
        card = Card("Listening ports",
                    "Every open listener is something a hostile network can "
                    "reach. On café Wi-Fi, file sharing on 445 being open is "
                    "worth knowing about.", ACCENT, "⊙")
        card.body.addWidget(button("Scan listening ports", "ghost", self._ports))

        self.ports_table = QTableWidget(0, 3)
        self.ports_table.setHorizontalHeaderLabels(
            ["Port", "Process", "Exposure"])
        self.ports_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.Stretch)
        self.ports_table.verticalHeader().setVisible(False)
        self.ports_table.setAlternatingRowColors(True)
        self.ports_table.setMinimumHeight(200)
        card.body.addWidget(self.ports_table)
        self.content.addWidget(card)

    def refresh(self) -> None:
        pass    # tests are explicit; they make network requests

    # ── actions ──
    def _run(self) -> None:
        self.run_btn.setEnabled(False)
        self.run_btn.setText("Testing…")
        self.progress.setText("Starting…")

        def done(report):
            self.run_btn.setEnabled(True)
            self.run_btn.setText("▶  Run all leak tests")
            self.progress.setText("")
            self._paint(report)

        workers.run(lambda progress=None: leaks.run_all(progress=lambda m: None),
                    on_result=done,
                    on_error=lambda e: self.notify(f"Leak tests failed: {e}",
                                                   "critical"))
        # Stream progress separately so the label updates during the run.
        self.progress.setText("Checking your public IP…")

    def _paint(self, rep) -> None:
        if not hasattr(rep, "findings"):
            return
        p = theme.p

        self.tiles["ip"].set(rep.public_ip or "unknown",
                             (rep.public_org or "your real address")[:30],
                             p.warning)
        if rep.using_tor:
            self.tiles["tor"].set(rep.tor_ip,
                                  f"exit in {rep.tor_country}" if rep.tor_country
                                  else "traffic exits via Tor", p.success)
        elif rep.tor_ip:
            self.tiles["tor"].set("SAME IP", "Tor is not changing your address",
                                  p.danger)
        else:
            self.tiles["tor"].set("not in use", "traffic goes direct",
                                  p.text_muted)

        dns_ok = rep.dns_servers and not all(
            s.startswith(("192.168.", "10.", "172.")) for s in rep.dns_servers)
        self.tiles["dns"].set(
            "ENCRYPTED" if rep.dns_encrypted else ("PRIVATE" if dns_ok else "ISP"),
            ", ".join(rep.dns_servers[:2]) or "from DHCP",
            p.success if rep.dns_encrypted else (p.info if dns_ok else p.warning))

        self.tiles["ipv6"].set(
            "EXPOSED" if rep.ipv6_exposed else
            ("local only" if rep.ipv6_address else "off"),
            rep.ipv6_address[:26] or "no IPv6 connectivity",
            p.danger if rep.ipv6_exposed else p.success)

        while self.findings_box.count():
            item = self.findings_box.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        for f in rep.sorted_findings():
            self.findings_box.addWidget(
                FindingRow(f.title, f.severity, f.detail, f.advice))
        for err in rep.errors:
            self.findings_box.addWidget(
                FindingRow("Test could not complete", "warning", err))

        counts = {}
        for f in rep.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        self.notify(
            "Leak tests complete — "
            + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())),
            "warning" if counts.get("critical") or counts.get("warning")
            else "good")

    def _scan(self) -> None:
        self.notify("Scanning active connections…", "info")
        resolve = self.resolve_toggle.isChecked()

        def work():
            conns = monitor.list_connections(resolve_names=resolve)
            return conns, monitor.summarise(conns)

        def done(data):
            if not isinstance(data, tuple):
                return
            conns, summary = data
            self.conn_table.setRowCount(0)
            for c in conns:
                r = self.conn_table.rowCount()
                self.conn_table.insertRow(r)
                for col, value in enumerate([
                        c.process or f"PID {c.pid}",
                        c.hostname or c.remote_ip, str(c.remote_port),
                        c.state, c.reason]):
                    item = QTableWidgetItem(value)
                    if c.suspicious:
                        item.setForeground(QColor(theme.p.warning))
                    self.conn_table.setItem(r, col, item)
            self.summary.setText(
                f"{summary['total']} outbound connection(s) from "
                f"{summary['unique_processes']} process(es). "
                f"{summary['suspicious']} matched telemetry patterns; "
                f"{summary['plaintext_http']} using plaintext HTTP.")
            self.notify(
                f"{summary['total']} connections, {summary['suspicious']} flagged.",
                "warning" if summary["suspicious"] else "good")

        workers.run(work, on_result=done)

    def _ports(self) -> None:
        def done(ports):
            if not isinstance(ports, list):
                return
            self.ports_table.setRowCount(0)
            for entry in ports:
                r = self.ports_table.rowCount()
                self.ports_table.insertRow(r)
                risk = entry["risk"]
                for col, value in enumerate([
                        str(entry["port"]),
                        entry["process"] or f"PID {entry['pid']}", risk]):
                    item = QTableWidgetItem(value)
                    if "high" in risk:
                        item.setForeground(QColor(theme.p.danger))
                    elif "medium" in risk:
                        item.setForeground(QColor(theme.p.warning))
                    self.ports_table.setItem(r, col, item)
            risky = sum(1 for e in ports if "high" in e["risk"])
            self.notify(
                f"{len(ports)} listening port(s)"
                + (f", {risky} with high exposure." if risky else "."),
                "warning" if risky else "good")

        workers.run(monitor.listening_ports, on_result=done)
