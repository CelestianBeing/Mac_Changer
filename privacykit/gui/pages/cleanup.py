"""Cleanup — trace cleaning, secure shredding, and metadata scrubbing."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QGridLayout,
                               QHBoxLayout, QHeaderView, QLabel, QListWidget,
                               QPlainTextEdit, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from ...core import cleaner, licensing, metadata, shredder, sysinfo
from ..dialogs import confirm, inform
from ..theme import SECTION_COLOURS, theme
from ..widgets.controls import (Badge, Card, NoteBox, StatCard, SettingRow,
                                ToggleSwitch, button, divider, muted,
                                section_label)
from .. import workers
from .base import Page

ACCENT = SECTION_COLOURS["Cleanup"]


class CleanupPage(Page):
    title = "Cleanup"
    subtitle = ("The traces Windows leaves behind, and permanent deletion when "
                "you need it.")
    icon = "✂"

    def __init__(self, app, parent=None):
        self._shred_paths = []
        super().__init__(app, parent)

    def build(self) -> None:
        self._build_cleaner()
        self._build_shredder()
        self._build_metadata()
        self._build_usb()

    def _build_cleaner(self) -> None:
        card = Card("Trace cleaner",
                    "Windows records what you run, what you open, and what you "
                    "look up, in a dozen places.", ACCENT, "✂")

        r = QHBoxLayout()
        r.setSpacing(10)
        r.addWidget(button("Measure", "ghost", self._measure))
        r.addWidget(button("Select recommended", "ghost", self._select_safe))
        r.addWidget(button("Select none", "ghost",
                           lambda: self._select_all(False)))
        self.clean_btn = button("Clean selected", "danger", self._clean)
        r.addWidget(self.clean_btn)
        self.total_label = muted("", 12)
        r.addWidget(self.total_label)
        r.addStretch()
        card.body.addLayout(r)

        self.secure_toggle = ToggleSwitch(False)
        card.body.addWidget(SettingRow(
            "Overwrite file contents before deleting",
            "Slower. Meaningful on a spinning disk; largely ineffective on an "
            "SSD, where wear levelling means the original blocks may survive.",
            self.secure_toggle))

        self.target_box = QVBoxLayout()
        self.target_box.setSpacing(3)
        card.body.addLayout(self.target_box)

        self.target_checks = {}
        self.target_sizes = {}
        for t in cleaner.TARGETS:
            row = QHBoxLayout()
            row.setSpacing(12)
            check = QCheckBox()
            check.setChecked(t.key in cleaner.SAFE_DEFAULTS)
            row.addWidget(check)
            self.target_checks[t.key] = check

            text = QVBoxLayout()
            text.setSpacing(2)
            head = QHBoxLayout()
            head.setSpacing(8)
            title = QLabel(t.title)
            title.setStyleSheet(
                f"color: {theme.p.text}; font-size: 13px; font-weight: 600;")
            head.addWidget(title)
            size = Badge("", theme.p.accent)
            size.hide()
            head.addWidget(size)
            self.target_sizes[t.key] = size
            if t.requires_admin and not sysinfo.is_admin():
                head.addWidget(Badge("needs admin", theme.p.warning))
            head.addStretch()
            text.addLayout(head)
            text.addWidget(muted(t.description, 11))
            if t.risk:
                risky = "SERIOUS" in t.risk
                cost = muted("Cost: " + t.risk, 11)
                cost.setStyleSheet(
                    f"color: {theme.p.danger if risky else theme.p.warning};"
                    "font-size: 11px;")
                text.addWidget(cost)
            row.addLayout(text, 1)

            holder = QWidget()
            holder.setLayout(row)
            self.target_box.addWidget(holder)

        card.body.addWidget(NoteBox(
            "This removes convenience traces — what reveals your activity to "
            "someone browsing this machine. It is not anti-forensics against a "
            "proper examination: the filesystem journal, shadow copies, the "
            "page file, and unallocated space all retain evidence that "
            "user-level deletion does not touch.", "info"))
        self.content.addWidget(card)

    def _build_shredder(self) -> None:
        card = Card("Secure shredder",
                    "Overwrites contents, renames the file to random "
                    "characters, truncates it, then deletes it. The rename "
                    "matters — a filename left in the directory entry is "
                    "informative even with the contents gone.", ACCENT, "⌦")

        r = QHBoxLayout()
        r.setSpacing(10)
        r.addWidget(button("Add files…", "ghost", self._pick_files))
        r.addWidget(button("Add folder…", "ghost", self._pick_folder))
        r.addWidget(button("Clear list", "ghost", self._clear_shred))
        self.pattern_combo = QComboBox()
        for key, (desc, _passes) in shredder.PATTERNS.items():
            self.pattern_combo.addItem(desc, key)
        self.pattern_combo.setMinimumWidth(300)
        r.addWidget(self.pattern_combo)
        r.addWidget(button("Shred permanently", "danger", self._shred))
        r.addStretch()
        card.body.addLayout(r)

        self.shred_list = QListWidget()
        self.shred_list.setMaximumHeight(130)
        card.body.addWidget(self.shred_list)

        self.shred_info = muted("", 12)
        card.body.addWidget(self.shred_info)

        card.body.addWidget(divider())
        r2 = QHBoxLayout()
        r2.addWidget(button("Wipe free space on C:", "ghost", self._wipe_free))
        r2.addWidget(muted("Makes previously deleted files unrecoverable. Uses "
                           "Windows' own cipher /w. Takes a long time.", 11), 1)
        card.body.addLayout(r2)

        card.body.addWidget(NoteBox(
            "On an SSD or NVMe drive, overwriting does not reliably destroy "
            "data — the controller writes elsewhere and leaves the old cells "
            "intact until garbage collection. Full-disk encryption from the "
            "start, or the drive's own secure-erase, are the only reliable "
            "equivalents there.", "critical"))
        self.content.addWidget(card)

    def _build_metadata(self) -> None:
        card = Card("Metadata scrubber",
                    "A photo off a phone carries GPS coordinates accurate to a "
                    "few metres. A Word document carries the author and everyone "
                    "who revised it. People share these believing they are "
                    "sharing only what they can see.", ACCENT, "⌫")

        r = QHBoxLayout()
        r.setSpacing(10)
        r.addWidget(button("Inspect file…", "ghost", self._inspect))
        r.addWidget(button("Scan folder…", "ghost", self._scan_folder))
        r.addWidget(button("Strip metadata…", "primary", self._strip))
        r.addStretch()
        card.body.addLayout(r)

        self.meta_output = QPlainTextEdit()
        self.meta_output.setObjectName("Mono")
        self.meta_output.setReadOnly(True)
        self.meta_output.setMinimumHeight(200)
        card.body.addWidget(self.meta_output)

        card.body.addWidget(muted(
            "JPEG and PNG stripping is lossless — image data is copied byte for "
            "byte and only the metadata segments are dropped. A cleaned copy is "
            "written alongside the original rather than overwriting it.", 11))
        self.content.addWidget(card)

    def _build_usb(self) -> None:
        card = Card("USB device history",
                    "Every USB storage device ever connected, with serial "
                    "numbers, often going back years. Read-only on purpose: "
                    "these keys are load-bearing for driver installation.",
                    ACCENT, "⌸")
        card.body.addWidget(button("Show USB history", "ghost", self._usb))

        self.usb_table = QTableWidget(0, 2)
        self.usb_table.setHorizontalHeaderLabels(["Device", "Serial"])
        self.usb_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.Stretch)
        self.usb_table.verticalHeader().setVisible(False)
        self.usb_table.setMinimumHeight(160)
        self.usb_table.setAlternatingRowColors(True)
        card.body.addWidget(self.usb_table)
        self.content.addWidget(card)

    def refresh(self) -> None:
        pass

    # ── cleaner ──
    def _select_all(self, value: bool) -> None:
        for c in self.target_checks.values():
            c.setChecked(value)

    def _select_safe(self) -> None:
        for key, c in self.target_checks.items():
            c.setChecked(key in cleaner.SAFE_DEFAULTS)

    def _measure(self) -> None:
        self.notify("Measuring trace locations…", "info")

        def done(results):
            if not isinstance(results, dict):
                return
            total = 0
            for key, stats in results.items():
                badge = self.target_sizes.get(key)
                if badge:
                    if stats["files"]:
                        badge.set_badge(
                            f"{stats['files']} files · "
                            f"{cleaner.human_size(stats['bytes'])}",
                            theme.p.accent)
                        badge.show()
                    else:
                        badge.set_badge("empty", theme.p.text_faint)
                        badge.show()
                total += stats["bytes"]
            self.total_label.setText(f"{cleaner.human_size(total)} recoverable")
            self.notify(f"Measured — {cleaner.human_size(total)} across "
                        "file-based locations.", "good")

        workers.run(cleaner.measure_all, on_result=done)

    def _clean(self) -> None:
        keys = [k for k, c in self.target_checks.items() if c.isChecked()]
        if not keys:
            return self.notify("Select what to clean first.", "warning")
        risky = [cleaner.TARGETS_BY_KEY[k].title for k in keys
                 if "SERIOUS" in cleaner.TARGETS_BY_KEY[k].risk]
        warn = ("\n\nIncluding high-impact items:\n"
                + "\n".join("   !  " + r for r in risky)) if risky else ""
        if not confirm(self, "Clean these traces?",
                       f"Permanently delete {len(keys)} trace location(s)."
                       f"{warn}\n\nThis cannot be undone.", "Clean", "critical"):
            return

        self.clean_btn.setEnabled(False)
        self.clean_btn.setText("Cleaning…")

        def done(result):
            self.clean_btn.setEnabled(True)
            self.clean_btn.setText("Clean selected")
            if isinstance(result, dict):
                self.notify(f"{result['files']} file(s) removed, "
                            f"{result['human']} freed.", "good")
                for e in result.get("errors", []):
                    self.app.log(e)
            self._measure()
            self.app.refresh_status()

        workers.run(lambda: cleaner.clean(keys,
                                          secure=self.secure_toggle.isChecked()),
                    on_result=done)

    # ── shredder ──
    def _pick_files(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "Select files to shred")
        if paths:
            self._shred_paths.extend(paths)
            self._refresh_shred()

    def _pick_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select a folder to shred")
        if path:
            self._shred_paths.append(path)
            self._refresh_shred()

    def _clear_shred(self) -> None:
        self._shred_paths.clear()
        self._refresh_shred()

    def _refresh_shred(self) -> None:
        self.shred_list.clear()
        self.shred_list.addItems(self._shred_paths)
        if not self._shred_paths:
            self.shred_info.setText("")
            return
        pattern = self.pattern_combo.currentData() or "random"
        passes = len(shredder.PATTERNS.get(pattern, ("", [None]))[1])
        est = shredder.estimate_time(self._shred_paths, passes)
        media = shredder.drive_type(self._shred_paths[0])
        text = f"{len(self._shred_paths)} item(s) queued · estimated {est}"
        if media not in ("unknown", ""):
            text += f" · target appears to be an {media}"
        self.shred_info.setText(text)
        self.shred_info.setStyleSheet(
            f"color: {theme.p.danger if media == 'SSD' else theme.p.text_muted};"
            "font-size: 12px;")

    def _shred(self) -> None:
        ok, message = licensing.require("shredder")
        if not ok:
            return self.notify(message, "warning")
        if not self._shred_paths:
            return self.notify("Add files or a folder first.", "warning")

        pattern = self.pattern_combo.currentData() or "random"
        media = shredder.drive_type(self._shred_paths[0])
        ssd_note = ("\n\nNOTE: the target appears to be an SSD. Overwriting does "
                    "not reliably destroy data there — the controller writes to "
                    "different physical cells and leaves the originals intact "
                    "until garbage collection.") if media == "SSD" else ""

        if not confirm(self, "Shred permanently?",
                       f"Destroy {len(self._shred_paths)} item(s) using the "
                       f"“{pattern}” pattern?\n\nThis cannot be undone by any "
                       f"means.{ssd_note}", "Shred", "critical"):
            return

        paths = list(self._shred_paths)

        def done(res):
            self.notify(f"Shredded {res.files} file(s), {res.bytes_wiped:,} bytes.",
                        "good" if res.ok else "critical")
            for e in res.errors[:10]:
                self.app.log(e)
            self._clear_shred()

        workers.run(lambda: shredder.shred_paths(paths, pattern=pattern),
                    on_result=done)

    def _wipe_free(self) -> None:
        if not confirm(self, "Wipe free space on C:?",
                       "Overwrites all unallocated space so previously deleted "
                       "files become unrecoverable.\n\nUses Windows' own "
                       "cipher /w. This can take tens of minutes."):
            return
        self.notify("Wiping free space — this will take a while…", "info")
        workers.run(lambda: shredder.wipe_free_space("C:"),
                    on_result=lambda r: self.notify(
                        r.message, "good" if r.ok else "critical"))

    # ── metadata ──
    def _inspect(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Inspect a file")
        if not path:
            return

        def done(rep):
            lines = [rep.path, ""]
            if rep.note:
                lines.append(rep.note)
            if not rep.findings:
                lines.append("No metadata found in this file.")
            for k, v in rep.findings.items():
                lines.append(f"  {k:<30} {v}")
            if rep.has_gps:
                lines += ["", "This file records where it was created. Strip it "
                              "before sharing."]
            self.meta_output.setPlainText("\n".join(lines))
            self.notify(f"{rep.summary()}", "warning" if rep.has_gps else "good")

        workers.run(lambda: metadata.inspect(path), on_result=done)

    def _scan_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Scan a folder")
        if not folder:
            return
        self.notify(f"Scanning {folder}…", "info")

        def done(reports):
            if not isinstance(reports, list):
                return
            gps = sum(1 for r in reports if r.has_gps)
            lines = [f"{len(reports)} file(s) carry metadata", ""]
            for rep in reports[:250]:
                lines.append(f"  {rep.summary():<46} {rep.path}")
            self.meta_output.setPlainText("\n".join(lines))
            self.notify(
                f"{len(reports)} file(s) with metadata"
                + (f", {gps} containing GPS coordinates." if gps else "."),
                "warning" if gps else "good")

        workers.run(lambda: metadata.scan_folder(folder), on_result=done)

    def _strip(self) -> None:
        ok, message = licensing.require("metadata")
        if not ok:
            return self.notify(message, "warning")
        path, _ = QFileDialog.getOpenFileName(
            self, "Strip metadata from a file",
            filter="Supported (*.jpg *.jpeg *.png *.docx *.xlsx *.pptx *.pdf);;"
                   "All files (*.*)")
        if not path:
            return

        def done(result):
            ok2, msg, out = result
            self.notify(msg, "good" if ok2 else "critical")
            if ok2:
                self.meta_output.setPlainText(
                    msg + "\n\nThe original file is untouched — a cleaned copy "
                          "was written alongside it.")

        workers.run(lambda: metadata.strip(path), on_result=done)

    def _usb(self) -> None:
        def done(devices):
            if not isinstance(devices, list):
                return
            self.usb_table.setRowCount(0)
            for d in devices:
                r = self.usb_table.rowCount()
                self.usb_table.insertRow(r)
                self.usb_table.setItem(
                    r, 0, QTableWidgetItem(d["name"] or d["device"]))
                self.usb_table.setItem(r, 1, QTableWidgetItem(d["serial"]))
            self.notify(
                f"{len(devices)} USB storage device(s) recorded on this machine.",
                "warning" if devices else "info")

        workers.run(cleaner.usb_history, on_result=done)
