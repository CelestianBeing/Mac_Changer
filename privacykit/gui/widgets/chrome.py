"""
Window chrome: custom titlebar and sidebar navigation.

The window is frameless so the titlebar can carry live status — protection
state, edition, and the panic control are visible from every screen without
spending vertical space on a second bar. That means re-implementing dragging,
snapping, and the window buttons, which is the cost of the look.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

from PySide6.QtCore import (QEasingCurve, QPoint, QPropertyAnimation, QRect,
                            QSize, Qt, Signal)
from PySide6.QtGui import QColor, QCursor, QFont, QPainter, QPen
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QPushButton,
                               QSizePolicy, QVBoxLayout, QWidget)

from ..theme import SECTION_COLOURS, Fonts, theme
from .controls import Badge
from .gauges import StatusDot


class TitleBar(QFrame):
    """Draggable titlebar with brand, live status, and window controls."""

    minimise_requested = Signal()
    maximise_requested = Signal()
    close_requested = Signal()
    panic_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("TitleBar")
        self.setFixedHeight(52)
        self._drag_offset: Optional[QPoint] = None

        lay = QHBoxLayout(self)
        lay.setContentsMargins(18, 0, 10, 0)
        lay.setSpacing(14)

        # ── brand ──
        brand = QHBoxLayout()
        brand.setSpacing(9)
        mark = QLabel("◆")
        mark.setStyleSheet(f"color: {theme.p.accent}; font-size: 17px;")
        brand.addWidget(mark)

        name = QLabel("PrivacyKit")
        name.setStyleSheet(
            f"color: {theme.p.text}; font-size: 15px; font-weight: 700;"
            "letter-spacing: 0.2px;")
        brand.addWidget(name)

        self.edition_badge = Badge("FREE", theme.p.text_muted)
        brand.addWidget(self.edition_badge)
        lay.addLayout(brand)

        lay.addSpacing(6)

        # ── live status ──
        self.status_dot = StatusDot(theme.p.text_faint, 8)
        lay.addWidget(self.status_dot)
        self.status_label = QLabel("Not protected")
        self.status_label.setStyleSheet(
            f"color: {theme.p.text_muted}; font-size: 12px; font-weight: 500;")
        lay.addWidget(self.status_label)

        lay.addStretch()

        # ── pending changes ──
        self.changes_badge = Badge("0 changes", theme.p.text_faint)
        self.changes_badge.setToolTip(
            "Changes PrivacyKit has applied that are still in effect")
        lay.addWidget(self.changes_badge)

        # ── panic ──
        self.panic_btn = QPushButton("  ⏻  Panic Restore  ")
        self.panic_btn.setObjectName("Danger")
        self.panic_btn.setCursor(Qt.PointingHandCursor)
        self.panic_btn.setToolTip(
            "Revert every change PrivacyKit has made to this machine")
        self.panic_btn.clicked.connect(self.panic_requested.emit)
        lay.addWidget(self.panic_btn)

        lay.addSpacing(8)

        # ── window buttons ──
        # Deliberately plain characters. Segoe MDL2 and similar icon glyphs are
        # not present on every system, and a close button that renders as a
        # blank box is worse than an unfashionable one. U+2212, U+25A1, and
        # U+00D7 are in essentially every font shipped with Windows.
        for glyph, name_, size, signal in (
                ("\u2212", "WinMin", 15, self.minimise_requested),
                ("\u25a1", "WinMax", 13, self.maximise_requested),
                ("\u00d7", "WinClose", 17, self.close_requested)):
            btn = QPushButton(glyph)
            btn.setObjectName(name_ if name_ == "WinClose" else "IconButton")
            btn.setFixedSize(34, 30)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(signal.emit)
            if name_ == "WinClose":
                btn.setStyleSheet(
                    "QPushButton { background: transparent; border: none;"
                    "padding: 0px; text-align: center;"
                    f"border-radius: 7px; color: {theme.p.text_muted};"
                    f"font-size: {size}px; }}"
                    f"QPushButton:hover {{ background: {theme.p.danger};"
                    "color: #FFFFFF; }")
            else:
                btn.setStyleSheet(
                    "QPushButton { background: transparent; border: none;"
                    "padding: 0px; text-align: center;"
                    f"border-radius: 7px; color: {theme.p.text_muted};"
                    f"font-size: {size}px; }}"
                    f"QPushButton:hover {{ background: {theme.p.surface_high};"
                    f"color: {theme.p.text}; }}")
            lay.addWidget(btn)

    def set_status(self, text: str, colour: str, pulse: bool = False) -> None:
        self.status_label.setText(text)
        self.status_label.setStyleSheet(
            f"color: {colour}; font-size: 12px; font-weight: 600;")
        self.status_dot.set_state(colour, pulse)

    def set_edition(self, text: str, colour: str) -> None:
        self.edition_badge.set_badge(text.upper(), colour)

    def set_changes(self, count: int) -> None:
        colour = theme.p.warning if count else theme.p.text_faint
        self.changes_badge.set_badge(
            f"{count} change{'s' if count != 1 else ''}", colour)

    # ── dragging ──
    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            window = self.window()
            self._drag_offset = (event.globalPosition().toPoint()
                                 - window.frameGeometry().topLeft())

    def mouseMoveEvent(self, event) -> None:
        if self._drag_offset is None or not (event.buttons() & Qt.LeftButton):
            return
        window = self.window()
        if window.isMaximized():
            # Restore first, keeping the cursor proportionally where it was, so
            # dragging a maximised window does not teleport it.
            ratio = event.globalPosition().x() / max(window.width(), 1)
            window.showNormal()
            new_x = int(event.globalPosition().x() - window.width() * ratio)
            self._drag_offset = QPoint(int(window.width() * ratio), 26)
            window.move(new_x, int(event.globalPosition().y()) - 26)
            return
        window.move(event.globalPosition().toPoint() - self._drag_offset)

    def mouseReleaseEvent(self, _event) -> None:
        self._drag_offset = None

    def mouseDoubleClickEvent(self, _event) -> None:
        self.maximise_requested.emit()


class NavButton(QFrame):
    """One entry in the sidebar, with an animated active indicator."""

    clicked = Signal(str)

    def __init__(self, key: str, label: str, icon: str, colour: str,
                 parent=None):
        super().__init__(parent)
        self.key = key
        self.colour = colour
        self._active = False
        self.setFixedHeight(40)
        self.setCursor(Qt.PointingHandCursor)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 12, 0)
        lay.setSpacing(0)

        self.indicator = QFrame()
        self.indicator.setFixedWidth(3)
        self.indicator.setStyleSheet("background: transparent;")
        lay.addWidget(self.indicator)

        lay.addSpacing(11)

        self.icon = QLabel(icon)
        self.icon.setFixedWidth(20)
        self.icon.setAlignment(Qt.AlignCenter)
        self.icon.setStyleSheet(
            f"color: {theme.p.text_faint}; font-size: 14px;")
        lay.addWidget(self.icon)

        lay.addSpacing(11)

        self.label = QLabel(label)
        self.label.setStyleSheet(
            f"color: {theme.p.text_muted}; font-size: 13px;")
        lay.addWidget(self.label, 1)

        self.badge = Badge("", theme.p.warning)
        self.badge.hide()
        lay.addWidget(self.badge)

        self._apply()

    def set_active(self, active: bool) -> None:
        if active == self._active:
            return
        self._active = active
        self._apply()

    def set_badge(self, text: str, colour: Optional[str] = None) -> None:
        if text:
            self.badge.set_badge(text, colour or theme.p.warning)
            self.badge.show()
        else:
            self.badge.hide()

    def _apply(self) -> None:
        if self._active:
            self.setStyleSheet(
                f"NavButton {{ background: {theme.p.surface}; "
                "border-radius: 0px; }")
            self.indicator.setStyleSheet(f"background: {self.colour};")
            self.icon.setStyleSheet(f"color: {self.colour}; font-size: 14px;")
            self.label.setStyleSheet(
                f"color: {theme.p.text}; font-size: 13px; font-weight: 600;")
        else:
            self.setStyleSheet("NavButton { background: transparent; }")
            self.indicator.setStyleSheet("background: transparent;")
            self.icon.setStyleSheet(
                f"color: {theme.p.text_faint}; font-size: 14px;")
            self.label.setStyleSheet(
                f"color: {theme.p.text_muted}; font-size: 13px;")

    def enterEvent(self, _event) -> None:
        if not self._active:
            self.setStyleSheet(
                f"NavButton {{ background: {theme.p.surface_alt}; }}")
            self.label.setStyleSheet(
                f"color: {theme.p.text_dim}; font-size: 13px;")
            self.icon.setStyleSheet(
                f"color: {theme.p.text_muted}; font-size: 14px;")

    def leaveEvent(self, _event) -> None:
        if not self._active:
            self._apply()

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self.key)


class Sidebar(QFrame):
    """Vertical navigation rail."""

    navigate = Signal(str)

    def __init__(self, sections: List[tuple], parent=None):
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self.setFixedWidth(212)
        self.buttons: Dict[str, NavButton] = {}

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 14, 0, 12)
        lay.setSpacing(2)

        current_group = None
        for key, label, icon, group in sections:
            if group != current_group:
                current_group = group
                if group:
                    hdr = QLabel(group.upper())
                    hdr.setStyleSheet(
                        f"color: {theme.p.text_faint}; font-size: 10px;"
                        "font-weight: 700; letter-spacing: 1.2px;"
                        "padding: 12px 0 5px 27px;")
                    lay.addWidget(hdr)

            btn = NavButton(key, label, icon,
                            SECTION_COLOURS.get(key, theme.p.accent))
            btn.clicked.connect(self.navigate.emit)
            self.buttons[key] = btn
            lay.addWidget(btn)

        lay.addStretch()

        self.footer = QVBoxLayout()
        self.footer.setContentsMargins(18, 0, 18, 0)
        self.footer.setSpacing(5)
        lay.addLayout(self.footer)

    def set_active(self, key: str) -> None:
        for k, btn in self.buttons.items():
            btn.set_active(k == key)

    def set_badge(self, key: str, text: str, colour: Optional[str] = None) -> None:
        btn = self.buttons.get(key)
        if btn:
            btn.set_badge(text, colour)

    def add_footer_widget(self, widget: QWidget) -> None:
        self.footer.addWidget(widget)


class Toast(QFrame):
    """
    A transient notification that slides in over the content area.

    Used for the results of actions that do not warrant a modal — most of them.
    A dialog for every DNS change would be exhausting.
    """

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setFixedHeight(50)
        self.setMinimumWidth(330)
        self.hide()

        lay = QHBoxLayout(self)
        lay.setContentsMargins(15, 0, 15, 0)
        lay.setSpacing(11)

        self.icon = QLabel("✔")
        self.icon.setFixedWidth(15)
        lay.addWidget(self.icon)

        self.message = QLabel("")
        self.message.setWordWrap(False)
        lay.addWidget(self.message, 1)

        self._anim = QPropertyAnimation(self, b"pos", self)
        self._anim.setDuration(260)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)

        from PySide6.QtCore import QTimer
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._hide_out)

    def show_message(self, text: str, kind: str = "good",
                     duration: int = 4200) -> None:
        from ..theme import SEVERITY_COLOURS
        colour = SEVERITY_COLOURS.get(kind, theme.p.info)
        glyph = {"good": "✔", "warning": "▲", "critical": "✖", "info": "●"}

        self.icon.setText(glyph.get(kind, "●"))
        self.icon.setStyleSheet(f"color: {colour}; font-size: 13px;")
        # One line only: a toast that grows to five lines is a dialog in denial.
        clipped = text if len(text) <= 108 else text[:105] + "…"
        self.message.setText(clipped)
        self.message.setStyleSheet(
            f"color: {theme.p.text}; font-size: 12px;")
        self.setToolTip(text)

        c = QColor(colour)
        self.setStyleSheet(
            f"background: {theme.p.surface_high};"
            f"border: 1px solid rgba({c.red()},{c.green()},{c.blue()},0.45);"
            "border-radius: 10px;")

        self.adjustSize()
        self.setFixedHeight(50)
        parent = self.parentWidget()
        if parent:
            x = parent.width() - self.width() - 26
            self.move(x, parent.height())
            self.show()
            self.raise_()
            self._anim.stop()
            self._anim.setStartValue(QPoint(x, parent.height()))
            self._anim.setEndValue(QPoint(x, parent.height() - self.height() - 22))
            self._anim.start()
        self._timer.start(duration)

    def _hide_out(self) -> None:
        parent = self.parentWidget()
        if not parent:
            self.hide()
            return
        self._anim.stop()
        self._anim.setStartValue(self.pos())
        self._anim.setEndValue(QPoint(self.x(), parent.height()))
        self._anim.start()
        from PySide6.QtCore import QTimer
        QTimer.singleShot(280, self.hide)
