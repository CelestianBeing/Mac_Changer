"""Vault — file encryption, encrypted notes, passwords, and hashes."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QComboBox, QFileDialog, QHBoxLayout, QLabel,
                               QLineEdit, QPlainTextEdit, QSpinBox, QVBoxLayout,
                               QWidget)

from ...core import crypto, licensing, passwords
from ..theme import SECTION_COLOURS, theme
from ..widgets.controls import (Card, NoteBox, SettingRow, ToggleSwitch, button,
                                divider, muted, section_label)
from ..widgets.gauges import MeterBar
from .. import workers
from .base import Page

ACCENT = SECTION_COLOURS["Vault"]


class VaultPage(Page):
    title = "Vault"
    subtitle = "Encryption, passwords, and integrity checks — all local."
    icon = "🔒"

    def build(self) -> None:
        self._build_files()
        self._build_notes()
        self._build_passwords()
        self._build_hashes()

    def _build_files(self) -> None:
        backend = ("AES-256-GCM via the cryptography package"
                   if crypto.HAVE_CRYPTOGRAPHY else
                   "AES-256-CBC with HMAC-SHA256, using the built-in AES")
        card = Card("File encryption",
                    f"Keys derived with scrypt (N=2¹⁵), which is memory-hard and "
                    f"makes guessing expensive. Cipher: {backend}.", ACCENT, "🔒")

        r = QHBoxLayout()
        r.setSpacing(10)
        self.pass1 = QLineEdit()
        self.pass1.setEchoMode(QLineEdit.Password)
        self.pass1.setPlaceholderText("Passphrase")
        self.pass1.textChanged.connect(self._rate)
        r.addWidget(self.pass1)
        self.pass2 = QLineEdit()
        self.pass2.setEchoMode(QLineEdit.Password)
        self.pass2.setPlaceholderText("Confirm (encryption only)")
        r.addWidget(self.pass2)
        r.addWidget(button("Suggest", "ghost", self._suggest))
        r.addWidget(button("Show", "ghost", self._toggle_show))
        card.body.addLayout(r)

        self.strength_bar = MeterBar(6)
        card.body.addWidget(self.strength_bar)
        self.strength_label = muted("", 11)
        card.body.addWidget(self.strength_label)

        card.body.addWidget(divider())

        actions = QHBoxLayout()
        actions.setSpacing(10)
        actions.addWidget(button("Encrypt a file…", "primary", self._encrypt))
        actions.addWidget(button("Decrypt a .pkv file…", "ghost", self._decrypt))
        actions.addWidget(button("Inspect a vault file…", "ghost", self._inspect))
        actions.addStretch()
        card.body.addLayout(actions)

        self.shred_toggle = ToggleSwitch(False)
        card.body.addWidget(SettingRow(
            "Shred the original after encrypting",
            "Overwrites and deletes the plaintext once the encrypted copy is "
            "written. Read the SSD caveat on the Cleanup page first.",
            self.shred_toggle))

        self.vault_status = muted("", 12)
        card.body.addWidget(self.vault_status)

        card.body.addWidget(NoteBox(
            "There is no password recovery, no hint field, and no escrow. If "
            "the passphrase is lost the data is gone — that is what makes the "
            "encryption meaningful. Write it down somewhere safe before "
            "encrypting anything you cannot afford to lose.", "critical"))
        self.content.addWidget(card)

    def _build_notes(self) -> None:
        card = Card("Encrypted notes",
                    "Encrypt text into base64 you can paste into an email, a "
                    "chat, or a file. Same cipher and key derivation as the "
                    "file vault.", ACCENT, "✎")

        self.note_input = QPlainTextEdit()
        self.note_input.setObjectName("Mono")
        self.note_input.setPlaceholderText("Type or paste your note here…")
        self.note_input.setMaximumHeight(120)
        card.body.addWidget(self.note_input)

        r = QHBoxLayout()
        r.setSpacing(10)
        r.addWidget(button("Encrypt ↓", "primary", self._encrypt_note))
        r.addWidget(button("Decrypt ↑", "ghost", self._decrypt_note))
        r.addWidget(button("Copy result", "ghost", self._copy_note))
        r.addWidget(button("Clear", "ghost", self._clear_notes))
        r.addStretch()
        card.body.addLayout(r)

        self.note_output = QPlainTextEdit()
        self.note_output.setObjectName("Mono")
        self.note_output.setReadOnly(True)
        self.note_output.setMaximumHeight(120)
        card.body.addWidget(self.note_output)
        self.content.addWidget(card)

    def _build_passwords(self) -> None:
        card = Card("Password generator",
                    "Generated with the operating system's cryptographic random "
                    "source. Nothing is sent anywhere — no breach lookup, no "
                    "“check my password” call.", ACCENT, "⚿")

        r = QHBoxLayout()
        r.setSpacing(10)
        r.addWidget(QLabel("Length"))
        self.length_spin = QSpinBox()
        self.length_spin.setRange(6, 128)
        self.length_spin.setValue(20)
        self.length_spin.setMaximumWidth(80)
        r.addWidget(self.length_spin)

        self.opt_upper = ToggleSwitch(True)
        self.opt_digits = ToggleSwitch(True)
        self.opt_symbols = ToggleSwitch(True)
        self.opt_unambiguous = ToggleSwitch(True)
        for label, toggle in (("A-Z", self.opt_upper), ("0-9", self.opt_digits),
                              ("symbols", self.opt_symbols),
                              ("avoid 0/O/1/l", self.opt_unambiguous)):
            r.addWidget(toggle)
            r.addWidget(muted(label, 11))
        r.addWidget(button("Generate", "primary", self._gen_password))
        r.addStretch()
        card.body.addLayout(r)

        r2 = QHBoxLayout()
        r2.setSpacing(10)
        r2.addWidget(QLabel("Passphrase words"))
        self.words_spin = QSpinBox()
        self.words_spin.setRange(3, 12)
        self.words_spin.setValue(5)
        self.words_spin.setMaximumWidth(70)
        r2.addWidget(self.words_spin)
        r2.addWidget(button("Passphrase", "ghost", self._gen_passphrase))
        r2.addWidget(button("PIN", "ghost", self._gen_pin))
        r2.addWidget(button("256-bit key", "ghost", self._gen_hex))
        r2.addWidget(button("Batch of 10", "ghost", self._gen_batch))
        r2.addStretch()
        card.body.addLayout(r2)

        self.password_output = QPlainTextEdit()
        self.password_output.setObjectName("Mono")
        self.password_output.setReadOnly(True)
        self.password_output.setMaximumHeight(140)
        card.body.addWidget(self.password_output)

        r3 = QHBoxLayout()
        r3.addWidget(button("Copy to clipboard", "ghost", self._copy_password))
        r3.addStretch()
        card.body.addLayout(r3)

        card.body.addWidget(muted(
            f"The word list holds {passwords.wordlist_size():,} unique words, so "
            f"five words is {passwords.passphrase_entropy(5):.0f} bits — "
            "comparable to a nine-character random password and far easier to "
            "type on a phone. Strength figures here are entropy-based and "
            "describe how the password was generated, not an analysis of the "
            "string.", 11))
        self.content.addWidget(card)

    def _build_hashes(self) -> None:
        card = Card("File hashes",
                    "Verify a download matches its published checksum, or "
                    "confirm two files are identical.", ACCENT, "#")
        r = QHBoxLayout()
        r.setSpacing(10)
        self.hash_combo = QComboBox()
        self.hash_combo.addItems(crypto.AVAILABLE_HASHES)
        self.hash_combo.setCurrentText("sha256")
        self.hash_combo.setMaximumWidth(140)
        r.addWidget(self.hash_combo)
        r.addWidget(button("Hash a file…", "ghost", self._hash_file))
        r.addWidget(button("Hash the notes box", "ghost", self._hash_text))
        r.addStretch()
        card.body.addLayout(r)

        self.hash_output = QPlainTextEdit()
        self.hash_output.setObjectName("Mono")
        self.hash_output.setReadOnly(True)
        self.hash_output.setMaximumHeight(100)
        card.body.addWidget(self.hash_output)
        self.content.addWidget(card)

    def refresh(self) -> None:
        pass

    # ── helpers ──
    def _toggle_show(self) -> None:
        mode = (QLineEdit.Normal if self.pass1.echoMode() == QLineEdit.Password
                else QLineEdit.Password)
        self.pass1.setEchoMode(mode)
        self.pass2.setEchoMode(mode)

    def _suggest(self) -> None:
        phrase = passwords.generate_passphrase(6, capitalise=True)
        self.pass1.setText(phrase)
        self.pass2.setText(phrase)

    def _rate(self) -> None:
        value = self.pass1.text()
        if not value:
            self.strength_bar.set_value(0)
            self.strength_label.setText("")
            return
        s = passwords.estimate(value)
        self.strength_bar.set_value(min(1.0, s.entropy_bits / 128), s.colour)
        self.strength_label.setText(
            f"{s.label} — {s.entropy_bits:.0f} bits; an offline attacker would "
            f"need {s.crack_time}")
        self.strength_label.setStyleSheet(
            f"color: {s.colour}; font-size: 11px;")

    def _password(self, confirm_needed: bool = False):
        value = self.pass1.text()
        if not value:
            self.notify("Enter a passphrase first.", "warning")
            return None
        if confirm_needed and value != self.pass2.text():
            self.notify("The two passphrases do not match.", "critical")
            return None
        return value

    # ── files ──
    def _encrypt(self) -> None:
        ok, message = licensing.require("vault")
        if not ok:
            return self.notify(message, "warning")
        pw = self._password(True)
        if pw is None:
            return
        path, _ = QFileDialog.getOpenFileName(self, "Select a file to encrypt")
        if not path:
            return
        self.vault_status.setText("Encrypting…")

        def done(res):
            self.vault_status.setText(res.message)
            self.notify(res.message, "good" if res.ok else "critical")

        workers.run(lambda: crypto.encrypt_file(
            path, pw, shred_original=self.shred_toggle.isChecked()),
            on_result=done)

    def _decrypt(self) -> None:
        pw = self._password()
        if pw is None:
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Select a .pkv file", filter="PrivacyKit vault (*.pkv);;All files (*.*)")
        if not path:
            return
        self.vault_status.setText("Decrypting…")

        def done(res):
            self.vault_status.setText(res.message)
            self.notify(res.message, "good" if res.ok else "critical")

        workers.run(lambda: crypto.decrypt_file(path, pw), on_result=done)

    def _inspect(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Inspect a vault file")
        if not path:
            return
        info = crypto.inspect(path)
        if info.get("valid"):
            self.vault_status.setText(
                f"Valid PrivacyKit vault · {info['cipher']} · {info['kdf']} · "
                f"{info['size']:,} bytes")
        else:
            self.vault_status.setText(
                f"Not a PrivacyKit vault: {info.get('error', 'unknown')}")

    # ── notes ──
    def _encrypt_note(self) -> None:
        pw = self._password(True)
        if pw is None:
            return
        text = self.note_input.toPlainText()
        if not text.strip():
            return self.notify("Type a note first.", "warning")
        workers.run(lambda: crypto.encrypt_text(text, pw),
                    on_result=lambda r: (self.note_output.setPlainText(str(r)),
                                         self.notify("Note encrypted.", "good")))

    def _decrypt_note(self) -> None:
        pw = self._password()
        if pw is None:
            return
        blob = (self.note_output.toPlainText().strip()
                or self.note_input.toPlainText().strip())
        if not blob:
            return self.notify("Paste an encrypted note first.", "warning")

        def work():
            try:
                return True, crypto.decrypt_text(blob, pw)
            except Exception as exc:
                return False, str(exc)

        def done(result):
            ok, value = result
            if ok:
                self.note_input.setPlainText(value)
                self.notify("Note decrypted.", "good")
            else:
                self.notify(value, "critical")

        workers.run(work, on_result=done)

    def _copy_note(self) -> None:
        from PySide6.QtWidgets import QApplication
        text = self.note_output.toPlainText().strip()
        if text:
            QApplication.clipboard().setText(text)
            self.notify("Copied to the clipboard.", "info")

    def _clear_notes(self) -> None:
        self.note_input.clear()
        self.note_output.clear()

    # ── passwords ──
    def _emit(self, value: str, meta: str = "") -> None:
        self.password_output.setPlainText(value + ("\n\n" + meta if meta else ""))

    def _gen_password(self) -> None:
        value = passwords.generate_password(
            self.length_spin.value(), self.opt_upper.isChecked(),
            self.opt_digits.isChecked(), self.opt_symbols.isChecked(),
            self.opt_unambiguous.isChecked())
        s = passwords.estimate(value)
        self._emit(value, f"{s.entropy_bits:.0f} bits · {s.label} · offline "
                          f"guessing would take {s.crack_time}")

    def _gen_passphrase(self) -> None:
        words = self.words_spin.value()
        value = passwords.generate_passphrase(words, capitalise=True)
        self._emit(value, f"{passwords.passphrase_entropy(words):.0f} bits from a "
                          f"{passwords.wordlist_size():,}-word list")

    def _gen_pin(self) -> None:
        self._emit(passwords.generate_pin(6),
                   "6 digits · about 20 bits — only suitable where the device "
                   "limits attempts")

    def _gen_hex(self) -> None:
        self._emit(passwords.generate_hex_key(32),
                   "256 bits of random data, hex encoded — for API and "
                   "encryption keys, not for typing")

    def _gen_batch(self) -> None:
        values = passwords.batch(
            10, length=self.length_spin.value(),
            use_upper=self.opt_upper.isChecked(),
            use_digits=self.opt_digits.isChecked(),
            use_symbols=self.opt_symbols.isChecked(),
            unambiguous=self.opt_unambiguous.isChecked())
        self.password_output.setPlainText("\n".join(values))

    def _copy_password(self) -> None:
        from PySide6.QtWidgets import QApplication
        first = self.password_output.toPlainText().strip().split("\n")[0]
        if first:
            QApplication.clipboard().setText(first)
            self.notify("Copied — remember to clear the clipboard afterwards "
                        "(Cleanup page).", "info")

    # ── hashes ──
    def _hash_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select a file to hash")
        if not path:
            return
        algo = self.hash_combo.currentText()
        self.hash_output.setPlainText(f"Hashing with {algo}…")
        workers.run(lambda: crypto.hash_file(path, algo),
                    on_result=lambda d: self.hash_output.setPlainText(
                        f"{algo}  {path}\n\n{d}"))

    def _hash_text(self) -> None:
        text = self.note_input.toPlainText()
        if not text:
            return self.notify("Type text into the notes box first.", "warning")
        algo = self.hash_combo.currentText()
        self.hash_output.setPlainText(
            f"{algo} of the notes box\n\n{crypto.hash_text(text, algo)}")
