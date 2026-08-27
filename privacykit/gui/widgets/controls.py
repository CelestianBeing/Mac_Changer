"""
Reusable building blocks: cards, toggles, badges, rows.

Every page is assembled from these, which is what keeps 11 screens looking like
one product rather than eleven separate opinions about spacing.
"""

from __future__ import annotations

from typing import Callable, List, Optional

from PySide6.QtCore import (Property, QEasingCurve, QPropertyAnimation, QRectF,
                            Qt, Signal)
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (QCheckBox, QFrame, QGraphicsDropShadowEffect,
                               QHBoxLayout, QLabel, QPushButton, QSizePolicy,
                               QVBoxLayout, QWidget)

from ..theme import Fonts, SEVERITY_COLOURS, theme
from .gauges import Sparkline, StatusDot


# ──────────────────────────────────────────────────────────────────────────────
# Toggle switch
# ──────────────────────────────────────────────────────────────────────────────

class ToggleSwitch(QWidget):
    """
    Sliding on/off switch.

    A checkbox states a fact; a switch states that flipping it *does something
    now*. Most of this application's options take effect immediately, so the
    switch is the honest control.
    """

    toggled = Signal(bool)

    def __init__(self, checked: bool = False, parent=None):
        super().__init__(parent)
        self._checked = checked
        self._offset = 1.0 if checked else 0.0
        self._enabled_look = True
        self.setFixedSize(42, 24)
        self.setCursor(Qt.PointingHandCursor)

        self._anim = QPropertyAnimation(self, b"offset", self)
        self._anim.setDuration(160)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)

    def get_offset(self) -> float:
        return self._offset

    def set_offset(self, v: float) -> None:
        self._offset = v
        self.update()

    offset = Property(float, get_offset, set_offset)

    def isChecked(self) -> bool:
        return self._checked

    def setChecked(self, value: bool, emit: bool = False) -> None:
        if value == self._checked:
            return
        self._checked = value
        self._anim.stop()
        self._anim.setStartValue(self._offset)
        self._anim.setEndValue(1.0 if value else 0.0)
        self._anim.start()
        if emit:
            self.toggled.emit(value)

    def setEnabled(self, value: bool) -> None:
        self._enabled_look = value
        super().setEnabled(value)
        self.setCursor(Qt.PointingHandCursor if value else Qt.ForbiddenCursor)
        self.update()

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton and self.isEnabled():
            self.setChecked(not self._checked, emit=True)

    def paintEvent(self, _event) -> None:
        p = theme.p
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        h = self.height()
        track = QRectF(0, 2, self.width(), h - 4)
        r = track.height() / 2

        on = QColor(p.accent)
        off = QColor(p.surface_high)
        if not self._enabled_look:
            on.setAlphaF(0.35)
            off.setAlphaF(0.5)

        colour = QColor(
            int(off.red() + (on.red() - off.red()) * self._offset),
            int(off.green() + (on.green() - off.green()) * self._offset),
            int(off.blue() + (on.blue() - off.blue()) * self._offset))
        painter.setBrush(colour)
        painter.setPen(QPen(QColor(p.border), 1) if self._offset < 0.5 else Qt.NoPen)
        painter.drawRoundedRect(track, r, r)

        knob_r = r - 3
        x = 3 + knob_r + self._offset * (self.width() - 2 * (knob_r + 3))
        painter.setBrush(QColor("#FFFFFF" if self._offset > 0.5 else p.text_muted))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(QRectF(x - knob_r, h / 2 - knob_r,
                                   knob_r * 2, knob_r * 2))
        painter.end()


# ──────────────────────────────────────────────────────────────────────────────
# Badges
# ──────────────────────────────────────────────────────────────────────────────

class Badge(QLabel):
    """A tinted pill. Used for statuses, counts, and Pro markers."""

    def __init__(self, text: str = "", colour: Optional[str] = None,
                 parent=None):
        super().__init__(text, parent)
        self._colour = colour or theme.p.text_muted
        self.setAlignment(Qt.AlignCenter)
        self.restyle()

    def set_badge(self, text: str, colour: Optional[str] = None) -> None:
        self.setText(text)
        if colour:
            self._colour = colour
        self.restyle()

    def restyle(self) -> None:
        c = QColor(self._colour)
        bg = QColor(c)
        bg.setAlphaF(0.16)
        self.setStyleSheet(
            f"background: rgba({bg.red()},{bg.green()},{bg.blue()},0.16);"
            f"color: {self._colour};"
            "border-radius: 9px; padding: 3px 10px;"
            "font-size: 11px; font-weight: 600;")


class SeverityBadge(Badge):
    def __init__(self, severity: str = "info", parent=None):
        super().__init__(severity.upper(),
                         SEVERITY_COLOURS.get(severity, theme.p.info), parent)


class ProBadge(Badge):
    def __init__(self, parent=None):
        super().__init__("PRO", theme.p.warning, parent)
        self.setToolTip("Available in the Pro edition")


# ──────────────────────────────────────────────────────────────────────────────
# Cards
# ──────────────────────────────────────────────────────────────────────────────

class Card(QFrame):
    """
    A titled panel. Content goes into ``self.body``.

    The optional accent stripe is a two-pixel bar at the top: enough to identify
    the section by colour, not enough to shout.
    """

    def __init__(self, title: str = "", subtitle: str = "",
                 accent: Optional[str] = None, icon: str = "",
                 parent=None, padding: int = 20):
        super().__init__(parent)
        self.setObjectName("Card")
        self._accent = accent

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        if accent:
            stripe = QFrame()
            stripe.setFixedHeight(2)
            stripe.setStyleSheet(
                f"background: {accent};"
                "border-top-left-radius: 12px; border-top-right-radius: 12px;")
            outer.addWidget(stripe)

        inner = QVBoxLayout()
        inner.setContentsMargins(padding, padding - (2 if accent else 0),
                                 padding, padding)
        inner.setSpacing(0)
        outer.addLayout(inner)

        if title:
            head = QVBoxLayout()
            head.setSpacing(3)
            row = QHBoxLayout()
            row.setSpacing(9)
            if icon:
                ic = QLabel(icon)
                ic.setStyleSheet(
                    f"color: {accent or theme.p.accent}; font-size: 15px;")
                row.addWidget(ic)
            t = QLabel(title)
            t.setObjectName("CardTitle")
            row.addWidget(t)
            row.addStretch()
            self.header_row = row
            head.addLayout(row)

            if subtitle:
                s = QLabel(subtitle)
                s.setObjectName("CardSubtitle")
                s.setWordWrap(True)
                head.addWidget(s)
            inner.addLayout(head)
            inner.addSpacing(15)

        self.body = QVBoxLayout()
        self.body.setSpacing(11)
        self.body.setContentsMargins(0, 0, 0, 0)
        inner.addLayout(self.body)

    def add_header_widget(self, widget: QWidget) -> None:
        """Place a control on the right-hand side of the card title row."""
        if hasattr(self, "header_row"):
            self.header_row.addWidget(widget)


class StatCard(QFrame):
    """
    A dashboard tile: label, large value, caption, optional sparkline.

    Clicking one navigates to the page that controls it, so the dashboard is a
    map of the application rather than a dead-end summary.
    """

    clicked = Signal()

    def __init__(self, label: str, icon: str = "", accent: Optional[str] = None,
                 sparkline: bool = False, parent=None):
        super().__init__(parent)
        self.setObjectName("StatCard")
        self.setMinimumHeight(112)
        self.setCursor(Qt.PointingHandCursor)
        self._accent = accent or theme.p.accent

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(2)

        top = QHBoxLayout()
        top.setSpacing(7)
        self.dot = StatusDot(self._accent, 7)
        top.addWidget(self.dot)
        lbl = QLabel(label.upper())
        lbl.setStyleSheet(
            f"color: {theme.p.text_faint}; font-size: 10px;"
            "font-weight: 700; letter-spacing: 1px;")
        top.addWidget(lbl)
        top.addStretch()
        if icon:
            ic = QLabel(icon)
            ic.setStyleSheet(f"color: {self._accent}; font-size: 14px;")
            top.addWidget(ic)
        lay.addLayout(top)

        self.value_label = QLabel("—")
        self.value_label.setStyleSheet(
            f"color: {self._accent}; font-size: 21px; font-weight: 700;")
        lay.addWidget(self.value_label)

        self.caption_label = QLabel("")
        self.caption_label.setStyleSheet(
            f"color: {theme.p.text_faint}; font-size: 11px;")
        self.caption_label.setWordWrap(True)
        lay.addWidget(self.caption_label)

        self.spark: Optional[Sparkline] = None
        if sparkline:
            lay.addSpacing(3)
            self.spark = Sparkline(height=26, colour=self._accent)
            lay.addWidget(self.spark)

        lay.addStretch()

    def set(self, value: str, caption: str = "", accent: Optional[str] = None,
            pulse: bool = False) -> None:
        self.value_label.setText(value)
        if caption:
            self.caption_label.setText(caption)
        if accent:
            self._accent = accent
            self.value_label.setStyleSheet(
                f"color: {accent}; font-size: 21px; font-weight: 700;")
            self.dot.set_state(accent, pulse)
        else:
            self.dot.set_state(self._accent, pulse)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self.clicked.emit()


class InfoRow(QWidget):
    """A label/value pair, aligned across a card."""

    def __init__(self, label: str, value: str = "—", mono: bool = False,
                 label_width: int = 150, parent=None):
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(14)

        self.label = QLabel(label)
        self.label.setStyleSheet(f"color: {theme.p.text_muted}; font-size: 12px;")
        self.label.setFixedWidth(label_width)
        self.label.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        lay.addWidget(self.label)

        self.value = QLabel(value)
        self.value.setWordWrap(True)
        self.value.setTextInteractionFlags(Qt.TextSelectableByMouse)
        if mono:
            self.value.setObjectName("Mono")
        self.value.setStyleSheet(
            f"color: {theme.p.text_dim}; font-size: 12px;"
            + (f"font-family: '{Fonts.mono}';" if mono else ""))
        lay.addWidget(self.value, 1)

    def set(self, value: str, colour: Optional[str] = None) -> None:
        self.value.setText(value)
        base = f"font-size: 12px; color: {colour or theme.p.text_dim};"
        if self.value.objectName() == "Mono":
            base += f"font-family: '{Fonts.mono}';"
        self.value.setStyleSheet(base)


class SettingRow(QWidget):
    """A titled setting with description and a control on the right."""

    def __init__(self, title: str, description: str = "",
                 control: Optional[QWidget] = None, badge: Optional[QWidget] = None,
                 parent=None):
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 7, 0, 7)
        lay.setSpacing(16)

        text = QVBoxLayout()
        text.setSpacing(3)
        head = QHBoxLayout()
        head.setSpacing(8)
        t = QLabel(title)
        t.setStyleSheet(
            f"color: {theme.p.text}; font-size: 13px; font-weight: 600;")
        head.addWidget(t)
        if badge:
            head.addWidget(badge)
        head.addStretch()
        text.addLayout(head)

        if description:
            d = QLabel(description)
            d.setWordWrap(True)
            d.setStyleSheet(f"color: {theme.p.text_muted}; font-size: 12px;")
            text.addWidget(d)
        lay.addLayout(text, 1)

        if control:
            lay.addWidget(control, 0, Qt.AlignRight | Qt.AlignVCenter)


class NoteBox(QFrame):
    """
    A tinted callout for caveats.

    Used heavily: this application makes a lot of changes whose costs the user
    deserves to see next to the button, not in a manual.
    """

    def __init__(self, text: str, kind: str = "warning", parent=None):
        super().__init__(parent)
        colour = SEVERITY_COLOURS.get(kind, theme.p.info)
        c = QColor(colour)
        self.setStyleSheet(
            f"background: rgba({c.red()},{c.green()},{c.blue()},0.09);"
            f"border: 1px solid rgba({c.red()},{c.green()},{c.blue()},0.30);"
            "border-radius: 9px;")

        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(11)

        glyph = {"critical": "✖", "warning": "!", "info": "i", "good": "✔"}
        ic = QLabel(glyph.get(kind, "i"))
        ic.setStyleSheet(f"color: {colour}; font-size: 13px; font-weight: 700;")
        ic.setFixedWidth(14)
        ic.setAlignment(Qt.AlignTop | Qt.AlignHCenter)
        lay.addWidget(ic)

        body = QLabel(text)
        body.setWordWrap(True)
        body.setStyleSheet(f"color: {theme.p.text_dim}; font-size: 12px;")
        lay.addWidget(body, 1)


class FindingRow(QFrame):
    """A severity-coloured finding with detail and a suggested remedy."""

    action_clicked = Signal()

    def __init__(self, title: str, severity: str = "info", detail: str = "",
                 advice: str = "", action_label: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("CardInner")
        colour = SEVERITY_COLOURS.get(severity, theme.p.info)

        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        stripe = QFrame()
        stripe.setFixedWidth(3)
        stripe.setStyleSheet(
            f"background: {colour}; border-top-left-radius: 10px;"
            "border-bottom-left-radius: 10px;")
        outer.addWidget(stripe)

        lay = QVBoxLayout()
        lay.setContentsMargins(15, 12, 15, 12)
        lay.setSpacing(5)
        outer.addLayout(lay, 1)

        head = QHBoxLayout()
        head.setSpacing(9)
        glyph = {"critical": "✖", "warning": "▲", "info": "●", "good": "✔"}
        ic = QLabel(glyph.get(severity, "●"))
        ic.setStyleSheet(f"color: {colour}; font-size: 12px;")
        head.addWidget(ic)
        t = QLabel(title)
        t.setWordWrap(True)
        t.setStyleSheet(
            f"color: {theme.p.text}; font-size: 13px; font-weight: 600;")
        head.addWidget(t, 1)
        lay.addLayout(head)

        if detail:
            d = QLabel(detail)
            d.setWordWrap(True)
            d.setStyleSheet(
                f"color: {theme.p.text_muted}; font-size: 12px;"
                "margin-left: 21px;")
            lay.addWidget(d)

        if advice:
            row = QHBoxLayout()
            row.setContentsMargins(21, 2, 0, 0)
            a = QLabel("→ " + advice)
            a.setWordWrap(True)
            a.setStyleSheet(f"color: {colour}; font-size: 12px;")
            row.addWidget(a, 1)
            lay.addLayout(row)

        if action_label:
            btn = QPushButton(action_label)
            btn.setObjectName("Link")
            btn.clicked.connect(self.action_clicked.emit)
            wrap = QHBoxLayout()
            wrap.setContentsMargins(19, 2, 0, 0)
            wrap.addWidget(btn)
            wrap.addStretch()
            lay.addLayout(wrap)


# ──────────────────────────────────────────────────────────────────────────────
# Small helpers
# ──────────────────────────────────────────────────────────────────────────────

def heading(text: str, size: int = 22) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("PageTitle")
    return lbl


def subheading(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("PageSubtitle")
    lbl.setWordWrap(True)
    return lbl


def section_label(text: str) -> QLabel:
    lbl = QLabel(text.upper())
    lbl.setObjectName("SectionLabel")
    return lbl


def muted(text: str, size: int = 12) -> QLabel:
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    lbl.setStyleSheet(f"color: {theme.p.text_muted}; font-size: {size}px;")
    return lbl


def divider() -> QFrame:
    line = QFrame()
    line.setFixedHeight(1)
    line.setStyleSheet(f"background: {theme.p.border};")
    return line


def button(text: str, kind: str = "default", on_click: Optional[Callable] = None,
           tooltip: str = "") -> QPushButton:
    btn = QPushButton(text)
    if kind != "default":
        btn.setObjectName(kind.capitalize() if kind != "default" else "")
    btn.setCursor(Qt.PointingHandCursor)
    if on_click:
        btn.clicked.connect(on_click)
    if tooltip:
        btn.setToolTip(tooltip)
    return btn


def row(*widgets, spacing: int = 10, stretch_last: bool = False) -> QWidget:
    """Lay widgets out horizontally in a container."""
    container = QWidget()
    lay = QHBoxLayout(container)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(spacing)
    for w in widgets:
        if w is None:
            lay.addStretch()
        else:
            lay.addWidget(w)
    if stretch_last:
        lay.addStretch()
    return container


def shadow(widget: QWidget, blur: int = 26, y: int = 5, alpha: int = 70) -> None:
    effect = QGraphicsDropShadowEffect(widget)
    effect.setBlurRadius(blur)
    effect.setXOffset(0)
    effect.setYOffset(y)
    effect.setColor(QColor(0, 0, 0, alpha))
    widget.setGraphicsEffect(effect)
