"""
Modal dialogs styled to match the application.

Qt's stock message boxes use the native theme, which on a dark custom-styled
window looks like a different program has opened. These are plain widgets
painted with the same tokens as everything else.
"""

from __future__ import annotations

from typing import List, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QDialog, QHBoxLayout, QLabel, QPlainTextEdit,
                               QVBoxLayout, QWidget)

from .theme import SEVERITY_COLOURS, theme
from .widgets.controls import button


class Dialog(QDialog):
    """Frameless modal with a title, body, and button row."""

    def __init__(self, parent: QWidget, title: str, body: str = "",
                 kind: str = "info", width: int = 520):
        super().__init__(parent)
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setModal(True)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 16, 16, 16)

        card = QWidget()
        card.setObjectName("Card")
        card.setStyleSheet(
            f"#Card {{ background: {theme.p.surface};"
            f"border: 1px solid {theme.p.border_strong}; border-radius: 14px; }}")
        card.setMinimumWidth(width)
        outer.addWidget(card)

        lay = QVBoxLayout(card)
        lay.setContentsMargins(26, 24, 26, 22)
        lay.setSpacing(14)

        head = QHBoxLayout()
        head.setSpacing(12)
        colour = SEVERITY_COLOURS.get(kind, theme.p.accent)
        glyph = {"critical": "✖", "warning": "▲", "good": "✔", "info": "●"}
        icon = QLabel(glyph.get(kind, "●"))
        icon.setStyleSheet(f"color: {colour}; font-size: 18px;")
        icon.setFixedWidth(22)
        icon.setAlignment(Qt.AlignTop)
        head.addWidget(icon)

        t = QLabel(title)
        t.setWordWrap(True)
        t.setStyleSheet(
            f"color: {theme.p.text}; font-size: 16px; font-weight: 700;")
        head.addWidget(t, 1)
        lay.addLayout(head)

        if body:
            b = QLabel(body)
            b.setWordWrap(True)
            b.setTextInteractionFlags(Qt.TextSelectableByMouse)
            b.setStyleSheet(
                f"color: {theme.p.text_dim}; font-size: 13px; line-height: 150%;")
            lay.addWidget(b)

        self.extra = QVBoxLayout()
        self.extra.setSpacing(9)
        lay.addLayout(self.extra)

        self.buttons = QHBoxLayout()
        self.buttons.setSpacing(9)
        self.buttons.addStretch()
        lay.addLayout(self.buttons)

        from .widgets.controls import shadow
        shadow(card, 40, 10, 130)

    def add_button(self, text: str, kind: str = "ghost",
                   result: int = 0) -> None:
        btn = button(text, kind, lambda: self.done(result))
        self.buttons.addWidget(btn)


def confirm(parent: QWidget, title: str, body: str,
            confirm_label: str = "Proceed", kind: str = "warning") -> bool:
    dlg = Dialog(parent, title, body, kind)
    dlg.add_button("Cancel", "ghost", 0)
    dlg.add_button(confirm_label,
                   "danger" if kind == "critical" else "primary", 1)
    return dlg.exec() == 1


def inform(parent: QWidget, title: str, body: str, kind: str = "info") -> None:
    dlg = Dialog(parent, title, body, kind)
    dlg.add_button("Close", "primary", 1)
    dlg.exec()


def show_log(parent: QWidget, title: str, lines: List[str],
             kind: str = "info") -> None:
    """Show a scrollable result log — used after presets and panic restore."""
    dlg = Dialog(parent, title, "", kind, width=620)
    box = QPlainTextEdit("\n".join(lines))
    box.setReadOnly(True)
    box.setObjectName("Mono")
    box.setMinimumHeight(260)
    dlg.extra.addWidget(box)
    dlg.add_button("Close", "primary", 1)
    dlg.exec()


def prompt(parent: QWidget, title: str, body: str, placeholder: str = "",
           password: bool = False) -> Optional[str]:
    from PySide6.QtWidgets import QLineEdit
    dlg = Dialog(parent, title, body)
    field = QLineEdit()
    field.setPlaceholderText(placeholder)
    if password:
        field.setEchoMode(QLineEdit.Password)
    dlg.extra.addWidget(field)
    dlg.add_button("Cancel", "ghost", 0)
    dlg.add_button("OK", "primary", 1)
    field.returnPressed.connect(lambda: dlg.done(1))
    if dlg.exec() == 1:
        return field.text().strip()
    return None
