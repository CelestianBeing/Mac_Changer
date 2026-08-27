"""
Custom-painted indicators.

These are the pieces QSS cannot express. Each is a small QWidget that paints
itself with QPainter, which means there is no ceiling on how they look — and
they animate, which is most of what separates a product from a script with
buttons.
"""

from __future__ import annotations

import math
from typing import List, Optional

from PySide6.QtCore import (Property, QEasingCurve, QPointF, QPropertyAnimation,
                            QRectF, Qt, QTimer)
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QFont, QLinearGradient,
                           QPainter, QPainterPath, QPen)
from PySide6.QtWidgets import QSizePolicy, QWidget

from ..theme import Fonts, theme


class ScoreRing(QWidget):
    """
    Animated donut gauge for the privacy score.

    The sweep animates from the previous value rather than jumping, because a
    number that slides is read as a measurement while a number that snaps is
    read as a label. The gradient runs cold-to-warm along the arc so the colour
    carries the same information as the number for anyone who cannot easily
    distinguish the two.
    """

    def __init__(self, diameter: int = 168, thickness: int = 13, parent=None):
        super().__init__(parent)
        self._value = 0.0
        self._target = 0.0
        self._grade = ""
        self._caption = "not assessed"
        self.diameter = diameter
        self.thickness = thickness
        self.setFixedSize(diameter, diameter)

        self._anim = QPropertyAnimation(self, b"value", self)
        self._anim.setDuration(900)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)

    def get_value(self) -> float:
        return self._value

    def set_value(self, v: float) -> None:
        self._value = v
        self.update()

    value = Property(float, get_value, set_value)

    def set_score(self, score: int, grade: str = "", caption: str = "") -> None:
        self._grade = grade
        self._caption = caption
        self._target = max(0.0, min(100.0, float(score)))
        self._anim.stop()
        self._anim.setStartValue(self._value)
        self._anim.setEndValue(self._target)
        self._anim.start()

    def _colour(self) -> QColor:
        v = self._target
        p = theme.p
        if v >= 78:
            return QColor(p.success)
        if v >= 62:
            return QColor(p.accent)
        if v >= 45:
            return QColor(p.warning)
        return QColor(p.danger)

    def paintEvent(self, _event) -> None:
        p = theme.p
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        pad = self.thickness / 2 + 2
        rect = QRectF(pad, pad, self.width() - pad * 2, self.height() - pad * 2)

        # Track
        painter.setPen(QPen(QColor(p.surface_high), self.thickness, Qt.SolidLine,
                            Qt.RoundCap))
        painter.drawArc(rect, 0, 360 * 16)

        # Progress arc, drawn clockwise from 12 o'clock
        if self._value > 0:
            colour = self._colour()
            grad = QConicalGradient(rect.center(), 90)
            grad.setColorAt(0.0, colour.lighter(125))
            grad.setColorAt(0.5, colour)
            grad.setColorAt(1.0, colour.darker(115))
            painter.setPen(QPen(QBrush(grad), self.thickness, Qt.SolidLine,
                                Qt.RoundCap))
            painter.drawArc(rect, 90 * 16, -int(self._value / 100 * 360 * 16))

        # Score number
        painter.setPen(QColor(p.text))
        f = QFont(Fonts.display)
        f.setPointSize(int(self.diameter * 0.23))
        f.setWeight(QFont.Bold)
        painter.setFont(f)
        painter.drawText(
            QRectF(0, self.height() * 0.24, self.width(), self.height() * 0.34),
            Qt.AlignCenter, str(int(round(self._value))))

        # Grade
        if self._grade:
            painter.setPen(self._colour())
            f2 = QFont(Fonts.sans)
            f2.setPointSize(max(8, int(self.diameter * 0.075)))
            f2.setWeight(QFont.DemiBold)
            painter.setFont(f2)
            painter.drawText(
                QRectF(0, self.height() * 0.55, self.width(), self.height() * 0.13),
                Qt.AlignCenter, self._grade)

        # Caption
        painter.setPen(QColor(p.text_faint))
        f3 = QFont(Fonts.sans)
        f3.setPointSize(max(7, int(self.diameter * 0.055)))
        painter.setFont(f3)
        painter.drawText(
            QRectF(6, self.height() * 0.66, self.width() - 12, self.height() * 0.18),
            Qt.AlignHCenter | Qt.AlignTop | Qt.TextWordWrap, self._caption)
        painter.end()


class Sparkline(QWidget):
    """A compact filled line chart for showing a trend inside a stat card."""

    def __init__(self, points: Optional[List[float]] = None, height: int = 34,
                 colour: Optional[str] = None, parent=None):
        super().__init__(parent)
        self._points: List[float] = list(points or [])
        self._colour = colour
        self.setFixedHeight(height)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set_points(self, points: List[float], colour: Optional[str] = None) -> None:
        self._points = list(points)
        if colour:
            self._colour = colour
        self.update()

    def push(self, value: float, keep: int = 60) -> None:
        self._points.append(value)
        del self._points[:-keep]
        self.update()

    def paintEvent(self, _event) -> None:
        if len(self._points) < 2:
            return
        p = theme.p
        colour = QColor(self._colour or p.accent)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w, h = self.width(), self.height()
        lo, hi = min(self._points), max(self._points)
        span = (hi - lo) or 1.0
        step = w / max(len(self._points) - 1, 1)

        path = QPainterPath()
        fill = QPainterPath()
        fill.moveTo(0, h)
        for i, value in enumerate(self._points):
            x = i * step
            y = h - 3 - ((value - lo) / span) * (h - 8)
            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)
            fill.lineTo(x, y)
        fill.lineTo(w, h)
        fill.closeSubpath()

        grad = QLinearGradient(0, 0, 0, h)
        c1 = QColor(colour)
        c1.setAlphaF(0.28)
        c2 = QColor(colour)
        c2.setAlphaF(0.0)
        grad.setColorAt(0.0, c1)
        grad.setColorAt(1.0, c2)
        painter.fillPath(fill, QBrush(grad))

        painter.setPen(QPen(colour, 1.8, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        painter.drawPath(path)
        painter.end()


class StatusDot(QWidget):
    """
    A status dot with an optional slow pulse.

    The pulse is reserved for states that are actively running — live
    protection, decoy traffic. Animating a static state would be noise.
    """

    def __init__(self, colour: str = "#3DDC97", size: int = 9,
                 pulse: bool = False, parent=None):
        super().__init__(parent)
        self._colour = colour
        self._size = size
        self._phase = 0.0
        self._pulse = pulse
        self.setFixedSize(size * 2 + 6, size * 2 + 6)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        if pulse:
            self._timer.start(40)

    def set_state(self, colour: str, pulse: bool = False) -> None:
        self._colour = colour
        if pulse != self._pulse:
            self._pulse = pulse
            if pulse:
                self._timer.start(40)
            else:
                self._timer.stop()
                self._phase = 0.0
        self.update()

    def _tick(self) -> None:
        self._phase = (self._phase + 0.045) % (2 * math.pi)
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        cx, cy = self.width() / 2, self.height() / 2
        base = QColor(self._colour)

        if self._pulse:
            spread = (math.sin(self._phase) + 1) / 2
            halo = QColor(base)
            halo.setAlphaF(0.30 * (1 - spread))
            painter.setBrush(halo)
            painter.setPen(Qt.NoPen)
            r = self._size / 2 + spread * self._size
            painter.drawEllipse(QPointF(cx, cy), r, r)

        painter.setBrush(base)
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(QPointF(cx, cy), self._size / 2, self._size / 2)
        painter.end()


class MeterBar(QWidget):
    """A labelled horizontal meter, used for the score breakdown."""

    def __init__(self, height: int = 8, parent=None):
        super().__init__(parent)
        self._value = 0.0
        self._colour = None
        self.setFixedHeight(height)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._anim = QPropertyAnimation(self, b"value", self)
        self._anim.setDuration(700)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)

    def get_value(self) -> float:
        return self._value

    def set_value_raw(self, v: float) -> None:
        self._value = v
        self.update()

    value = Property(float, get_value, set_value_raw)

    def set_value(self, fraction: float, colour: Optional[str] = None) -> None:
        self._colour = colour
        self._anim.stop()
        self._anim.setStartValue(self._value)
        self._anim.setEndValue(max(0.0, min(1.0, fraction)))
        self._anim.start()

    def paintEvent(self, _event) -> None:
        p = theme.p
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        r = self.height() / 2

        painter.setBrush(QColor(p.surface_high))
        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(QRectF(0, 0, self.width(), self.height()), r, r)

        if self._value > 0:
            w = max(self.height(), self.width() * self._value)
            colour = QColor(self._colour or p.accent)
            grad = QLinearGradient(0, 0, w, 0)
            grad.setColorAt(0.0, colour.darker(112))
            grad.setColorAt(1.0, colour.lighter(118))
            painter.setBrush(QBrush(grad))
            painter.drawRoundedRect(QRectF(0, 0, w, self.height()), r, r)
        painter.end()


class ActivityGraph(QWidget):
    """
    Rolling bar graph of recent activity, used on the protection page.

    Bars rather than a line: the data is discrete events per interval, and a
    smoothed line would imply a continuity the measurements do not have.
    """

    def __init__(self, bars: int = 40, height: int = 56, parent=None):
        super().__init__(parent)
        self._values: List[float] = [0.0] * bars
        self._bars = bars
        self.setFixedHeight(height)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def push(self, value: float) -> None:
        self._values.append(value)
        del self._values[:-self._bars]
        self.update()

    def paintEvent(self, _event) -> None:
        p = theme.p
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        peak = max(self._values) or 1.0
        n = len(self._values)
        gap = 2.0
        bw = max(1.5, (self.width() - gap * (n - 1)) / n)

        for i, v in enumerate(self._values):
            x = i * (bw + gap)
            h = max(2.0, (v / peak) * (self.height() - 4))
            y = self.height() - h
            colour = QColor(p.accent if v else p.surface_high)
            if v:
                colour.setAlphaF(0.45 + 0.55 * (v / peak))
            painter.setBrush(colour)
            painter.setPen(Qt.NoPen)
            painter.drawRoundedRect(QRectF(x, y, bw, h), 1.5, 1.5)
        painter.end()
