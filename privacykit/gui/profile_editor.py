"""
Custom profile editor.

Builds its form from :data:`privacykit.core.settings.ACTION_CATALOGUE` rather
than hardcoding a widget per action, so adding a new action to the catalogue
makes it appear here automatically.
"""

from __future__ import annotations

from typing import Dict, List

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QComboBox, QHBoxLayout, QLabel, QLineEdit,
                               QListWidget, QListWidgetItem, QVBoxLayout,
                               QWidget)

from ..core import licensing
from ..core.settings import ACTION_CATALOGUE, ACTIONS_BY_KEY, CustomProfile
from .dialogs import Dialog
from .theme import theme
from .widgets.controls import (Badge, button, divider, muted, section_label)


class ProfileEditor(Dialog):
    def __init__(self, parent, profile: CustomProfile):
        super().__init__(parent, f"Edit “{profile.name}”",
                         "Pick the actions this profile should run, in order.",
                         "info", 640)
        self.profile = profile

        name_row = QHBoxLayout()
        name_row.setSpacing(9)
        self.name_input = QLineEdit(profile.name)
        self.name_input.setPlaceholderText("Profile name")
        name_row.addWidget(self.name_input, 2)
        self.icon_input = QLineEdit(profile.icon)
        self.icon_input.setMaximumWidth(56)
        self.icon_input.setAlignment(Qt.AlignCenter)
        name_row.addWidget(self.icon_input)
        self.extra.addLayout(name_row)

        self.desc_input = QLineEdit(profile.description)
        self.desc_input.setPlaceholderText("Short description (optional)")
        self.extra.addWidget(self.desc_input)

        self.extra.addWidget(divider())
        self.extra.addWidget(section_label("Available actions"))

        add_row = QHBoxLayout()
        add_row.setSpacing(9)
        self.action_combo = QComboBox()
        for spec in ACTION_CATALOGUE:
            locked = not licensing.has_feature(spec.get("feature", ""))
            label = spec["title"] + ("   (Pro)" if locked else "")
            self.action_combo.addItem(label, spec["key"])
        add_row.addWidget(self.action_combo, 1)

        self.arg_input = QLineEdit()
        self.arg_input.setPlaceholderText("option (e.g. cloudflare, de, all)")
        self.arg_input.setMaximumWidth(200)
        add_row.addWidget(self.arg_input)

        add_row.addWidget(button("Add", "ghost", self._add))
        self.extra.addLayout(add_row)

        self.extra.addWidget(muted(
            "The option box is only needed for actions that take one — a DNS "
            "provider key, a country code, or 'all' versus the default set.",
            11))

        self.extra.addWidget(section_label("This profile runs"))
        self.list = QListWidget()
        self.list.setMinimumHeight(170)
        self.extra.addWidget(self.list)

        controls = QHBoxLayout()
        controls.setSpacing(9)
        controls.addWidget(button("Move up", "ghost", lambda: self._move(-1)))
        controls.addWidget(button("Move down", "ghost", lambda: self._move(1)))
        controls.addWidget(button("Remove", "ghost", self._remove))
        controls.addStretch()
        self.extra.addLayout(controls)

        self._reload()

        self.add_button("Cancel", "ghost", 0)
        self.add_button("Save profile", "primary", 1)

    def _reload(self) -> None:
        self.list.clear()
        for step in self.profile.actions:
            spec = ACTIONS_BY_KEY.get(step.get("action", ""))
            title = spec["title"] if spec else step.get("action", "?")
            args = step.get("args") or {}
            suffix = ("  ·  " + ", ".join(f"{k}={v}" for k, v in args.items())
                      if args else "")
            self.list.addItem(QListWidgetItem(title + suffix))

    def _add(self) -> None:
        key = self.action_combo.currentData()
        spec = ACTIONS_BY_KEY.get(key)
        if not spec:
            return
        args = {}
        value = self.arg_input.text().strip()
        if value and spec.get("args"):
            # Take the first declared argument name; the catalogue lists them in
            # the order they matter, and a single free-text box keeps the editor
            # simple enough to actually use.
            first = list(spec["args"].keys())[0]
            args[first] = value
        self.profile.actions.append({"action": key, "args": args})
        self.arg_input.clear()
        self._reload()

    def _remove(self) -> None:
        row = self.list.currentRow()
        if 0 <= row < len(self.profile.actions):
            self.profile.actions.pop(row)
            self._reload()

    def _move(self, delta: int) -> None:
        row = self.list.currentRow()
        target = row + delta
        if 0 <= row < len(self.profile.actions) and 0 <= target < len(self.profile.actions):
            actions = self.profile.actions
            actions[row], actions[target] = actions[target], actions[row]
            self._reload()
            self.list.setCurrentRow(target)

    def accept(self) -> None:
        self._commit()
        super().accept()

    def done(self, result: int) -> None:
        if result == 1:
            self._commit()
        super().done(result)

    def _commit(self) -> None:
        self.profile.name = self.name_input.text().strip() or self.profile.name
        self.profile.icon = self.icon_input.text().strip() or "★"
        self.profile.description = self.desc_input.text().strip()
