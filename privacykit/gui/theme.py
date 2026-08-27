"""
Design system — tokens, palettes, and generated stylesheets.

Everything visual derives from this module. Colours are never written inline in
a page; they are pulled from the active :class:`Palette`, which is what makes
theme and accent switching work at runtime without restarting.

The palette is built around a near-black base with three elevation steps rather
than the flat grey most Tkinter and Qt applications default to. Depth is what
separates software that looks designed from software that looks assembled, and
it costs nothing but discipline about which surface a widget sits on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from PySide6.QtGui import QColor, QFont, QFontDatabase


# ──────────────────────────────────────────────────────────────────────────────
# Palettes
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Palette:
    name: str

    # Surfaces, darkest to lightest
    base: str            # window background
    surface: str         # cards
    surface_alt: str     # nested panels, hover
    surface_high: str    # inputs, pressed states
    border: str
    border_strong: str

    # Text
    text: str
    text_dim: str
    text_muted: str
    text_faint: str

    # Semantic
    accent: str
    accent_hover: str
    accent_press: str
    accent_fg: str       # text drawn on top of accent
    success: str
    warning: str
    danger: str
    info: str

    # Chrome
    titlebar: str
    sidebar: str
    shadow: str

    is_dark: bool = True


DARK = Palette(
    name="dark",
    base="#0A0C11",
    surface="#12151D",
    surface_alt="#181C26",
    surface_high="#1F2430",
    border="#232936",
    border_strong="#2E3644",
    text="#E8EDF7",
    text_dim="#B9C2D4",
    text_muted="#7D8799",
    text_faint="#5A6478",
    accent="#4C8DFF",
    accent_hover="#6BA1FF",
    accent_press="#3B7AE8",
    accent_fg="#07090D",
    success="#3DDC97",
    warning="#FFB020",
    danger="#FF5F5F",
    info="#56CCF2",
    titlebar="#0D1016",
    sidebar="#0D1016",
    shadow="#00000070",
    is_dark=True,
)

LIGHT = Palette(
    name="light",
    base="#F4F6FA",
    surface="#FFFFFF",
    surface_alt="#F7F9FC",
    surface_high="#EDF1F7",
    border="#DFE5EE",
    border_strong="#C8D1DF",
    text="#111826",
    text_dim="#3A4557",
    text_muted="#6B7688",
    text_faint="#98A2B3",
    accent="#2563EB",
    accent_hover="#1D4ED8",
    accent_press="#1E40AF",
    accent_fg="#FFFFFF",
    success="#0E9F6E",
    warning="#C2760A",
    danger="#DC2626",
    info="#0284C7",
    titlebar="#FFFFFF",
    sidebar="#FFFFFF",
    shadow="#0B142814",
    is_dark=False,
)

#: Selectable accents. Each entry is (base, hover, pressed, foreground).
ACCENTS: Dict[str, tuple] = {
    "blue":   ("#4C8DFF", "#6BA1FF", "#3B7AE8", "#07090D"),
    "violet": ("#A78BFA", "#BBA4FC", "#8B6DF0", "#0B0714"),
    "teal":   ("#2DD4BF", "#5EE7D6", "#14B8A6", "#04120F"),
    "green":  ("#4ADE80", "#6EE7A0", "#22C55E", "#04120A"),
    "amber":  ("#FBBF24", "#FCD34D", "#F59E0B", "#140E02"),
    "rose":   ("#FB7185", "#FDA4AF", "#F43F5E", "#140508"),
}

#: One hue per section, used on nav icons and card accent bars so each area of
#: the app is recognisable before you read the label.
SECTION_COLOURS = {
    "Dashboard":   "#4C8DFF",
    "Identity":    "#2DD4BF",
    "Connection":  "#A78BFA",
    "Location":    "#38BDF8",
    "Protection":  "#FB7185",
    "Privacy":     "#F472B6",
    "Diagnostics": "#FBBF24",
    "Cleanup":     "#FB923C",
    "Vault":       "#4ADE80",
    "Journal":     "#94A3B8",
    "Settings":    "#8B95A8",
}

SEVERITY_COLOURS = {
    "critical": "#FF5F5F",
    "warning": "#FFB020",
    "info": "#56CCF2",
    "good": "#3DDC97",
}


# ──────────────────────────────────────────────────────────────────────────────
# Active theme
# ──────────────────────────────────────────────────────────────────────────────

class Theme:
    """Holds the active palette and hands out the generated stylesheet."""

    def __init__(self):
        self.palette: Palette = DARK
        self.accent_name = "blue"
        self._listeners: List = []

    def set_mode(self, mode: str) -> None:
        base = LIGHT if mode == "light" else DARK
        self.palette = Palette(**{**base.__dict__})
        self.set_accent(self.accent_name, notify=False)
        self._notify()

    def set_accent(self, name: str, notify: bool = True) -> None:
        if name not in ACCENTS:
            name = "blue"
        self.accent_name = name
        accent, hover, press, fg = ACCENTS[name]
        self.palette.accent = accent
        self.palette.accent_hover = hover
        self.palette.accent_press = press
        # On a light theme, accent text is white regardless of the dark-theme
        # foreground the accent ships with.
        self.palette.accent_fg = fg if self.palette.is_dark else "#FFFFFF"
        if notify:
            self._notify()

    def on_change(self, callback) -> None:
        self._listeners.append(callback)

    def _notify(self) -> None:
        for cb in list(self._listeners):
            try:
                cb()
            except Exception:
                pass

    # ── convenience ──
    @property
    def p(self) -> Palette:
        return self.palette

    def colour(self, name: str) -> QColor:
        return QColor(getattr(self.palette, name, "#000000"))

    def alpha(self, hex_colour: str, alpha: float) -> str:
        """Return ``#RRGGBBAA`` for a token colour at the given opacity."""
        c = QColor(hex_colour)
        c.setAlphaF(max(0.0, min(1.0, alpha)))
        return f"rgba({c.red()}, {c.green()}, {c.blue()}, {c.alphaF():.3f})"

    def mix(self, a: str, b: str, t: float) -> str:
        """Blend two colours; used for tinted badges and hover fills."""
        ca, cb = QColor(a), QColor(b)
        return QColor(
            int(ca.red() + (cb.red() - ca.red()) * t),
            int(ca.green() + (cb.green() - ca.green()) * t),
            int(ca.blue() + (cb.blue() - ca.blue()) * t),
        ).name()

    def stylesheet(self) -> str:
        return build_stylesheet(self.palette)


theme = Theme()


# ──────────────────────────────────────────────────────────────────────────────
# Fonts
# ──────────────────────────────────────────────────────────────────────────────

def pick_family(candidates: List[str], fallback: str) -> str:
    available = set(QFontDatabase.families())
    for name in candidates:
        if name in available:
            return name
    return fallback


class Fonts:
    """Resolved once at startup, after QApplication exists."""

    sans = "Segoe UI"
    mono = "Consolas"
    display = "Segoe UI"

    @classmethod
    def resolve(cls) -> None:
        cls.sans = pick_family(
            ["Segoe UI Variable Display", "Segoe UI", "Inter", "Roboto",
             "DejaVu Sans", "Noto Sans"], "sans-serif")
        cls.display = pick_family(
            ["Segoe UI Variable Display", "Segoe UI Semibold", "Segoe UI",
             "Inter", "DejaVu Sans"], cls.sans)
        cls.mono = pick_family(
            ["Cascadia Mono", "Consolas", "JetBrains Mono", "Fira Code",
             "DejaVu Sans Mono", "Courier New"], "monospace")

    @classmethod
    def font(cls, size: int = 10, weight: int = QFont.Normal,
             mono: bool = False) -> QFont:
        f = QFont(cls.mono if mono else cls.sans)
        f.setPointSize(size)
        f.setWeight(weight)
        return f


# ──────────────────────────────────────────────────────────────────────────────
# Stylesheet
# ──────────────────────────────────────────────────────────────────────────────

def build_stylesheet(p: Palette) -> str:
    """
    Generate the application stylesheet for a palette.

    Written as one string rather than per-widget styles so that a theme switch
    is a single ``setStyleSheet`` call — per-widget styling would need every
    widget to be found and updated, which is both slower and easy to get
    incomplete.
    """
    return f"""
/* ── base ─────────────────────────────────────────────────────────── */
QWidget {{
    background: transparent;
    color: {p.text};
    font-family: "{Fonts.sans}";
    font-size: 13px;
}}

#Root {{
    background: {p.base};
    border: 1px solid {p.border};
    border-radius: 12px;
}}

#TitleBar {{
    background: {p.titlebar};
    border-top-left-radius: 12px;
    border-top-right-radius: 12px;
    border-bottom: 1px solid {p.border};
}}

#Sidebar {{
    background: {p.sidebar};
    border-right: 1px solid {p.border};
}}

#Content {{
    background: {p.base};
}}

/* ── typography ───────────────────────────────────────────────────── */
#PageTitle   {{ font-size: 22px; font-weight: 700; color: {p.text}; }}
#PageSubtitle{{ font-size: 13px; color: {p.text_muted}; }}
#CardTitle   {{ font-size: 14px; font-weight: 600; color: {p.text}; }}
#CardSubtitle{{ font-size: 12px; color: {p.text_muted}; }}
#SectionLabel{{ font-size: 11px; font-weight: 700; color: {p.text_faint};
                letter-spacing: 1.2px; }}
#Muted       {{ color: {p.text_muted}; }}
#Faint       {{ color: {p.text_faint}; font-size: 12px; }}
#Mono        {{ font-family: "{Fonts.mono}"; font-size: 12px; color: {p.text_dim}; }}
#ValueBig    {{ font-size: 26px; font-weight: 700; color: {p.text}; }}

/* ── cards ────────────────────────────────────────────────────────── */
#Card {{
    background: {p.surface};
    border: 1px solid {p.border};
    border-radius: 12px;
}}
#CardInner {{
    background: {p.surface_alt};
    border: 1px solid {p.border};
    border-radius: 10px;
}}
#StatCard {{
    background: {p.surface};
    border: 1px solid {p.border};
    border-radius: 12px;
}}
#StatCard:hover {{
    border: 1px solid {p.border_strong};
    background: {p.surface_alt};
}}

/* ── buttons ──────────────────────────────────────────────────────── */
QPushButton {{
    background: {p.surface_high};
    color: {p.text_dim};
    border: 1px solid {p.border};
    border-radius: 8px;
    padding: 8px 16px;
    font-size: 13px;
    font-weight: 500;
}}
QPushButton:hover  {{ background: {p.border}; color: {p.text};
                      border-color: {p.border_strong}; }}
QPushButton:pressed{{ background: {p.surface_alt}; }}
QPushButton:disabled {{ color: {p.text_faint}; background: {p.surface_alt};
                        border-color: {p.border}; }}

QPushButton#Primary {{
    background: {p.accent}; color: {p.accent_fg};
    border: none; font-weight: 600;
}}
QPushButton#Primary:hover   {{ background: {p.accent_hover}; }}
QPushButton#Primary:pressed {{ background: {p.accent_press}; }}
QPushButton#Primary:disabled{{ background: {p.surface_high}; color: {p.text_faint}; }}

QPushButton#Danger {{
    background: {p.danger}; color: #FFFFFF; border: none; font-weight: 600;
}}
QPushButton#Danger:hover {{ background: {p.danger}; }}

QPushButton#Ghost {{
    background: transparent; border: 1px solid {p.border}; color: {p.text_muted};
}}
QPushButton#Ghost:hover {{ background: {p.surface_high}; color: {p.text}; }}

QPushButton#Link {{
    background: transparent; border: none; color: {p.accent};
    padding: 2px 4px; font-weight: 500; text-align: left;
}}
QPushButton#Link:hover {{ color: {p.accent_hover}; }}

QPushButton#IconButton {{
    background: transparent; border: none; border-radius: 7px;
    padding: 6px; color: {p.text_muted};
}}
QPushButton#IconButton:hover {{ background: {p.surface_high}; color: {p.text}; }}

QPushButton#WinClose:hover {{ background: {p.danger}; color: #FFFFFF; }}

/* ── inputs ───────────────────────────────────────────────────────── */
QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox {{
    background: {p.surface_high};
    border: 1px solid {p.border};
    border-radius: 8px;
    padding: 8px 11px;
    color: {p.text};
    selection-background-color: {p.accent};
    selection-color: {p.accent_fg};
}}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QSpinBox:focus {{
    border: 1px solid {p.accent};
    background: {p.surface_alt};
}}
QLineEdit:disabled {{ color: {p.text_faint}; }}
QLineEdit#Mono, QPlainTextEdit#Mono, QTextEdit#Mono {{
    font-family: "{Fonts.mono}"; font-size: 12px;
}}

QComboBox {{
    background: {p.surface_high};
    border: 1px solid {p.border};
    border-radius: 8px;
    padding: 7px 12px;
    color: {p.text};
    min-height: 18px;
}}
QComboBox:hover {{ border-color: {p.border_strong}; }}
QComboBox:focus {{ border-color: {p.accent}; }}
QComboBox::drop-down {{ border: none; width: 26px; }}
QComboBox QAbstractItemView {{
    background: {p.surface_alt};
    border: 1px solid {p.border_strong};
    border-radius: 8px;
    selection-background-color: {p.accent};
    selection-color: {p.accent_fg};
    color: {p.text};
    padding: 4px;
    outline: none;
}}

/* ── checkboxes ───────────────────────────────────────────────────── */
QCheckBox {{ spacing: 9px; color: {p.text_dim}; }}
QCheckBox::indicator {{
    width: 17px; height: 17px;
    border: 1px solid {p.border_strong};
    border-radius: 5px;
    background: {p.surface_high};
}}
QCheckBox::indicator:hover {{ border-color: {p.accent}; }}
QCheckBox::indicator:checked {{
    background: {p.accent}; border-color: {p.accent};
}}
QCheckBox::indicator:disabled {{ background: {p.surface_alt};
                                 border-color: {p.border}; }}

/* ── tables ───────────────────────────────────────────────────────── */
QTableWidget, QTreeWidget, QListWidget {{
    background: {p.surface};
    alternate-background-color: {p.surface_alt};
    border: 1px solid {p.border};
    border-radius: 10px;
    gridline-color: {p.border};
    color: {p.text_dim};
    outline: none;
}}
QTableWidget::item, QTreeWidget::item, QListWidget::item {{
    padding: 7px 9px; border: none;
}}
QTableWidget::item:selected, QTreeWidget::item:selected,
QListWidget::item:selected {{
    background: {p.accent}; color: {p.accent_fg};
}}
QHeaderView::section {{
    background: {p.surface_alt};
    color: {p.text_faint};
    border: none;
    border-bottom: 1px solid {p.border};
    padding: 9px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.6px;
}}
QTableCornerButton::section {{ background: {p.surface_alt}; border: none; }}

/* ── scrollbars ───────────────────────────────────────────────────── */
QScrollBar:vertical {{
    background: transparent; width: 10px; margin: 2px;
}}
QScrollBar::handle:vertical {{
    background: {p.border_strong}; border-radius: 5px; min-height: 32px;
}}
QScrollBar::handle:vertical:hover {{ background: {p.text_faint}; }}
QScrollBar:horizontal {{
    background: transparent; height: 10px; margin: 2px;
}}
QScrollBar::handle:horizontal {{
    background: {p.border_strong}; border-radius: 5px; min-width: 32px;
}}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
QScrollArea {{ border: none; background: transparent; }}

/* ── progress ─────────────────────────────────────────────────────── */
QProgressBar {{
    background: {p.surface_high}; border: none; border-radius: 4px;
    height: 7px; text-align: center; color: transparent;
}}
QProgressBar::chunk {{ background: {p.accent}; border-radius: 4px; }}

/* ── tooltips ─────────────────────────────────────────────────────── */
QToolTip {{
    background: {p.surface_high};
    color: {p.text};
    border: 1px solid {p.border_strong};
    border-radius: 7px;
    padding: 7px 10px;
}}

/* ── misc ─────────────────────────────────────────────────────────── */
QSplitter::handle {{ background: {p.border}; }}
QMenu {{
    background: {p.surface_alt}; border: 1px solid {p.border_strong};
    border-radius: 9px; padding: 6px; color: {p.text};
}}
QMenu::item {{ padding: 8px 26px 8px 14px; border-radius: 6px; }}
QMenu::item:selected {{ background: {p.accent}; color: {p.accent_fg}; }}
QMenu::separator {{ height: 1px; background: {p.border}; margin: 5px 8px; }}
"""
