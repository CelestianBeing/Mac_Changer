"""Journal — every change made, and how to undo it."""

from __future__ import annotations

import json
import time

from PySide6.QtWidgets import (QFileDialog, QGridLayout, QHBoxLayout,
                               QHeaderView, QPlainTextEdit, QTableWidget,
                               QTableWidgetItem, QVBoxLayout, QWidget)
from PySide6.QtGui import QColor

from ...core import journal
from ..dialogs import confirm, show_log
from ..theme import SECTION_COLOURS, theme
from ..widgets.controls import Card, StatCard, button, muted, section_label
from .. import workers
from .base import Page

ACCENT = SECTION_COLOURS["Journal"]

MODULE_LABELS = {
    "mac": "MAC address", "ip": "IP configuration", "dns": "DNS",
    "proxy": "System proxy", "firewall": "Firewall", "hostname": "Computer name",
    "hardening": "Windows hardening", "wifi": "Wi-Fi profiles",
    "cleaner": "Trace cleaning", "shredder": "File shredding",
    "geo": "Location", "noise": "Identifiers",
}


class JournalPage(Page):
    title = "Journal"
    subtitle = ("Every system change is recorded before it is made, together "
                "with what is needed to reverse it.")
    icon = "≡"

    def __init__(self, app, parent=None):
        self._entries = []
        super().__init__(app, parent)

    def build(self) -> None:
        self.add_header_button("Refresh", self.refresh)
        self._build_tiles()
        self._build_table()
        self._build_detail()
        self._build_baseline()

    def _build_tiles(self) -> None:
        grid = QGridLayout()
        grid.setSpacing(12)
        self.tiles = {}
        for i, (key, label, icon) in enumerate([
                ("pending", "Applied changes", "●"),
                ("undone", "Reverted", "✔"),
                ("modules", "Areas touched", "◈"),
                ("baseline", "Baseline", "▣")]):
            tile = StatCard(label, icon, ACCENT)
            grid.addWidget(tile, 0, i)
            grid.setColumnStretch(i, 1)
            self.tiles[key] = tile
        holder = QWidget()
        holder.setLayout(grid)
        self.content.addWidget(holder)

    def _build_table(self) -> None:
        card = Card("Entries",
                    "Newest first. Undo runs newest-to-oldest, so reverting a "
                    "setting changed twice lands on the original value.",
                    ACCENT, "⋮")

        r = QHBoxLayout()
        r.setSpacing(10)
        r.addWidget(button("Undo selected", "ghost", self._undo_selected))
        r.addWidget(button("Revert everything", "danger",
                           self.app.panic_restore))
        r.addWidget(button("Export journal…", "ghost", self._export))
        r.addWidget(button("Clear reverted history", "ghost", self._clear))
        r.addStretch()
        card.body.addLayout(r)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["When", "Area", "Change", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setMinimumHeight(300)
        self.table.itemSelectionChanged.connect(self._show_detail)
        card.body.addWidget(self.table)
        self.content.addWidget(card)

    def _build_detail(self) -> None:
        card = Card("Entry detail", accent=ACCENT, icon="▤")
        self.detail = QPlainTextEdit()
        self.detail.setObjectName("Mono")
        self.detail.setReadOnly(True)
        self.detail.setMinimumHeight(160)
        card.body.addWidget(self.detail)
        self.content.addWidget(card)

    def _build_baseline(self) -> None:
        card = Card("Baseline snapshot",
                    "A one-time record of this machine's settings from the "
                    "first run. The safety net behind the journal: if the "
                    "journal is lost, this still shows what the original "
                    "looked like.", ACCENT, "▣")
        card.body.addWidget(button("View baseline", "ghost", self._show_baseline))
        self.baseline = QPlainTextEdit()
        self.baseline.setObjectName("Mono")
        self.baseline.setReadOnly(True)
        self.baseline.setMinimumHeight(180)
        card.body.addWidget(self.baseline)
        self.content.addWidget(card)

    # ── refresh ──
    def refresh(self) -> None:
        workers.run(lambda: (journal.load(), journal.has_baseline()),
                    on_result=self._paint)

    def _paint(self, data) -> None:
        if not isinstance(data, tuple):
            return
        entries, has_baseline = data
        p = theme.p
        self._entries = sorted(entries, key=lambda e: e.ts, reverse=True)

        pending = [e for e in entries if not e.undone]
        undone = [e for e in entries if e.undone]
        modules = sorted({e.module for e in pending})

        self.tiles["pending"].set(str(len(pending)),
                                  "still applied to this machine",
                                  p.warning if pending else p.success)
        self.tiles["undone"].set(str(len(undone)), "already reverted", p.text_muted)
        self.tiles["modules"].set(
            str(len(modules)),
            ", ".join(MODULE_LABELS.get(m, m) for m in modules[:3]) or "none",
            p.info if modules else p.text_muted)
        self.tiles["baseline"].set(
            "SAVED" if has_baseline else "NONE",
            "original settings recorded" if has_baseline else "not yet captured",
            p.success if has_baseline else p.warning)

        self.table.setRowCount(0)
        for e in self._entries:
            r = self.table.rowCount()
            self.table.insertRow(r)
            values = [e.when, MODULE_LABELS.get(e.module, e.module), e.action,
                      "reverted" if e.undone else "applied"]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(256, e.id)
                if e.undone:
                    item.setForeground(QColor(p.text_faint))
                self.table.setItem(r, col, item)

        self.app.refresh_status()

    def _selected_entries(self):
        rows = {i.row() for i in self.table.selectedIndexes()}
        ids = set()
        for row in rows:
            item = self.table.item(row, 0)
            if item:
                ids.add(item.data(256))
        return [e for e in self._entries if e.id in ids]

    def _show_detail(self) -> None:
        entries = self._selected_entries()
        if not entries:
            return
        e = entries[0]
        kind = (e.undo or {}).get("kind", "")
        lines = [
            e.action, "",
            f"  when      {e.when}",
            f"  area      {MODULE_LABELS.get(e.module, e.module)}",
            f"  status    {'reverted' if e.undone else 'still applied'}",
            f"  entry id  {e.id}",
        ]
        if kind:
            available = journal.has_handler(kind)
            lines.append(f"  undo via  {kind}"
                         + ("" if available else "   (handler not loaded)"))
        if e.note:
            lines += ["", f"  note: {e.note}"]
        if e.before:
            lines += ["", "  state before the change:"]
            for k, v in e.before.items():
                lines.append(f"    {k:<18} {v}")
        self.detail.setPlainText("\n".join(lines))

    # ── actions ──
    def _undo_selected(self) -> None:
        chosen = [e for e in self._selected_entries() if not e.undone]
        if not chosen:
            return self.notify("Select one or more applied changes.", "warning")
        if not confirm(self, "Undo these changes?",
                       f"Revert {len(chosen)} change(s)?\n\n"
                       + "\n".join("   • " + e.action for e in chosen[:8])):
            return

        chosen.sort(key=lambda e: e.ts, reverse=True)

        def work():
            results = []
            for e in chosen:
                ok, msg = journal.undo_entry(e)
                results.append(f"{'OK  ' if ok else 'FAIL'}  {e.action}"
                               + (f" — {msg}" if msg else ""))
            return results

        def done(results):
            ok = sum(1 for r in results if r.startswith("OK"))
            self.notify(f"{ok} of {len(results)} change(s) reverted.",
                        "good" if ok == len(results) else "warning")
            show_log(self, "Undo results", results,
                     "good" if ok == len(results) else "warning")
            self.refresh()

        workers.run(work, on_result=done)

    def _clear(self) -> None:
        if not confirm(self, "Clear reverted history?",
                       "Remove journal entries that have already been undone.\n\n"
                       "Entries for changes still applied are kept, so nothing "
                       "becomes irreversible."):
            return
        removed = journal.clear_history(keep_pending=True)
        self.notify(f"{removed} historical entr(ies) removed.", "good")
        self.refresh()

    def _export(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Export the change journal", "privacykit-journal.json",
            "JSON (*.json)")
        if not path:
            return
        try:
            data = {"entries": [e.to_dict() for e in journal.load()],
                    "baseline": journal.load_baseline(),
                    "exported": time.strftime("%Y-%m-%d %H:%M:%S")}
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, default=str)
            self.notify(f"Journal exported to {path}", "good")
        except Exception as exc:
            self.notify(f"Export failed: {exc}", "critical")

    def _show_baseline(self) -> None:
        data = journal.load_baseline()
        if not data:
            self.baseline.setPlainText(
                "No baseline captured yet. It is written automatically on the "
                "first run.")
            return
        when = time.strftime("%Y-%m-%d %H:%M:%S",
                             time.localtime(data.get("captured", 0)))
        self.baseline.setPlainText(
            f"Captured {when}\n\n"
            + json.dumps(data.get("data", {}), indent=2, default=str))
