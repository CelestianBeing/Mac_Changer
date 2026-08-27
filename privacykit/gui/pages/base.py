"""
Shared page scaffolding.

Every screen is a :class:`Page`: a scrollable column with a title, a subtitle,
and an optional header control area. Doing this once means consistent margins
and scroll behaviour across eleven screens without each remembering to set them.
"""

from __future__ import annotations

from typing import Callable, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QScrollArea, QVBoxLayout,
                               QWidget)

from ..theme import SECTION_COLOURS, theme
from ..widgets.controls import Badge, ProBadge, button, heading, subheading
from ..widgets.gauges import StatusDot


class Page(QWidget):
    """
    Base class for every screen.

    Subclasses build into ``self.content`` and may override :meth:`refresh`,
    which the window calls whenever the page becomes visible.
    """

    #: Feature key checked against the licence. Empty means always available.
    feature_key: str = ""
    title: str = ""
    subtitle: str = ""
    icon: str = ""

    toast = Signal(str, str)

    def __init__(self, app, parent=None):
        super().__init__(parent)
        self.app = app
        self._built = False

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        outer.addWidget(self.scroll)

        holder = QWidget()
        self.scroll.setWidget(holder)

        self.column = QVBoxLayout(holder)
        self.column.setContentsMargins(30, 26, 30, 30)
        self.column.setSpacing(16)

        # ── header ──
        header = QHBoxLayout()
        header.setSpacing(14)

        titles = QVBoxLayout()
        titles.setSpacing(4)

        title_row = QHBoxLayout()
        title_row.setSpacing(11)
        if self.icon:
            ic = QLabel(self.icon)
            ic.setStyleSheet(
                f"color: {SECTION_COLOURS.get(self.title, theme.p.accent)};"
                "font-size: 20px;")
            title_row.addWidget(ic)
        title_row.addWidget(heading(self.title))
        self.title_row = title_row
        title_row.addStretch()
        titles.addLayout(title_row)

        if self.subtitle:
            titles.addWidget(subheading(self.subtitle))
        header.addLayout(titles, 1)

        self.header_controls = QHBoxLayout()
        self.header_controls.setSpacing(9)
        header.addLayout(self.header_controls)

        self.column.addLayout(header)
        self.column.addSpacing(4)

        self.content = QVBoxLayout()
        self.content.setSpacing(16)
        self.column.addLayout(self.content)
        self.column.addStretch()

    # ── lifecycle ──
    def ensure_built(self) -> None:
        if self._built:
            return
        self._built = True
        try:
            self.build()
        except Exception as exc:
            import traceback
            traceback.print_exc()
            self.content.addWidget(
                QLabel(f"This page failed to build: {type(exc).__name__}: {exc}"))

    def build(self) -> None:
        """Construct the page. Called once, lazily."""

    def refresh(self) -> None:
        """Re-read state. Called each time the page is shown."""

    def on_show(self) -> None:
        self.ensure_built()
        self.refresh()

    # ── helpers available to every page ──
    def notify(self, message: str, kind: str = "good") -> None:
        self.app.notify(message, kind)

    def add_header_button(self, text: str, on_click: Callable,
                          kind: str = "ghost") -> None:
        self.header_controls.addWidget(button(text, kind, on_click))

    def add_pro_badge(self) -> None:
        self.title_row.insertWidget(self.title_row.count() - 1, ProBadge())

    def locked(self) -> bool:
        """True when the licence does not cover this page's feature."""
        if not self.feature_key:
            return False
        from ...core import licensing
        return not licensing.has_feature(self.feature_key)

    def show_result(self, result) -> None:
        """
        Standard handler for core functions returning ``(ok, message)``.

        Nearly every action in the core layer uses that shape, so pages can wire
        a worker straight to this and get consistent toasts and refreshing.
        """
        if isinstance(result, tuple) and len(result) == 2:
            ok, message = result
            self.notify(str(message), "good" if ok else "critical")
        elif hasattr(result, "ok") and hasattr(result, "message"):
            self.notify(str(result.message), "good" if result.ok else "critical")
        elif isinstance(result, str):
            self.notify(result, "info")
        self.refresh()
        self.app.refresh_status()
