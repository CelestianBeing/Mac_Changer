"""
The change journal — PrivacyKit's undo system.

Design
------
Every function in this toolkit that mutates the machine must, *before* making
the change, record an entry describing how to put things back. An entry is:

    {
      "id":     unique string,
      "ts":     unix time,
      "module": "mac" | "dns" | "firewall" | ...,
      "action": human-readable description shown in the UI,
      "undo":   {"kind": "<handler name>", ...handler-specific payload},
      "before": free-form snapshot (shown in the journal tab),
      "undone": bool
    }

Modules register an undo handler for each ``kind`` they emit via
:func:`register_undo`. Panic Restore then walks the journal newest-first and
dispatches each un-undone entry to its handler. Newest-first matters: if a
user changed DNS twice, replaying in reverse lands on the original value.

The journal lives under %LOCALAPPDATA%\\PrivacyKit so it survives the app being
moved, deleted, or run from removable media. It is written atomically (temp
file + replace) so a crash mid-write cannot leave an unparseable journal — a
corrupt journal would mean an unrecoverable machine, which is the one failure
mode this module exists to prevent.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from . import sysinfo

_LOCK = threading.RLock()
_UNDO_HANDLERS: Dict[str, Callable[[dict], tuple]] = {}


def journal_path() -> Path:
    return sysinfo.appdata_dir() / "journal.json"


def baseline_path() -> Path:
    return sysinfo.appdata_dir() / "baseline.json"


# ──────────────────────────────────────────────────────────────────────────────
# Entry model
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Entry:
    module: str
    action: str
    undo: dict
    before: dict = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    ts: float = field(default_factory=time.time)
    undone: bool = False
    undone_ts: Optional[float] = None
    note: str = ""

    @property
    def when(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts))

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Entry":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


# ──────────────────────────────────────────────────────────────────────────────
# Undo handler registry
# ──────────────────────────────────────────────────────────────────────────────

def register_undo(kind: str):
    """
    Decorator registering a handler for one undo ``kind``.

        @register_undo("mac.restore")
        def _undo_mac(payload) -> (bool, str): ...

    Handlers return ``(ok, message)`` and must be safe to call when the change
    has already been reverted by other means — undoing twice is common (user
    clicks Restore, then later hits Panic Restore) and must not error.
    """
    def deco(fn: Callable[[dict], tuple]):
        _UNDO_HANDLERS[kind] = fn
        return fn
    return deco


def has_handler(kind: str) -> bool:
    return kind in _UNDO_HANDLERS


def registered_kinds() -> List[str]:
    return sorted(_UNDO_HANDLERS)


# ──────────────────────────────────────────────────────────────────────────────
# Persistence
# ──────────────────────────────────────────────────────────────────────────────

def _read_raw() -> dict:
    p = journal_path()
    if not p.exists():
        return {"version": 1, "entries": []}
    try:
        with open(p, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict) or "entries" not in data:
            raise ValueError("malformed journal")
        return data
    except Exception:
        # Never lose a damaged journal silently: keep it for forensics, start
        # fresh so the app stays usable.
        try:
            p.replace(p.with_suffix(f".corrupt-{int(time.time())}.json"))
        except Exception:
            pass
        return {"version": 1, "entries": []}


def _write_raw(data: dict) -> None:
    p = journal_path()
    tmp = p.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, p)  # atomic on Windows and POSIX


def load() -> List[Entry]:
    with _LOCK:
        return [Entry.from_dict(e) for e in _read_raw().get("entries", [])]


def record(module: str, action: str, undo: dict, before: dict | None = None,
           note: str = "") -> Entry:
    """
    Append an undo entry. Call this *before* performing the change.

    If the change then fails, call :func:`drop` with the returned id so the
    journal does not offer to undo something that never happened.
    """
    entry = Entry(module=module, action=action, undo=undo,
                  before=before or {}, note=note)
    with _LOCK:
        data = _read_raw()
        data["entries"].append(entry.to_dict())
        _write_raw(data)
    return entry


def drop(entry_id: str) -> None:
    """Remove an entry entirely (used when the change it describes failed)."""
    with _LOCK:
        data = _read_raw()
        data["entries"] = [e for e in data["entries"] if e.get("id") != entry_id]
        _write_raw(data)


def mark_undone(entry_id: str) -> None:
    with _LOCK:
        data = _read_raw()
        for e in data["entries"]:
            if e.get("id") == entry_id:
                e["undone"] = True
                e["undone_ts"] = time.time()
        _write_raw(data)


def pending() -> List[Entry]:
    """Entries representing changes still applied to the machine."""
    return [e for e in load() if not e.undone]


def pending_count() -> int:
    return len(pending())


def pending_by_module() -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for e in pending():
        counts[e.module] = counts.get(e.module, 0) + 1
    return counts


def clear_history(keep_pending: bool = True) -> int:
    """
    Delete journal entries. With ``keep_pending`` (the default) only already-
    undone entries are purged, so the ability to restore is never lost.
    """
    with _LOCK:
        data = _read_raw()
        before = len(data["entries"])
        if keep_pending:
            data["entries"] = [e for e in data["entries"] if not e.get("undone")]
        else:
            data["entries"] = []
        _write_raw(data)
        return before - len(data["entries"])


# ──────────────────────────────────────────────────────────────────────────────
# Undo / Panic Restore
# ──────────────────────────────────────────────────────────────────────────────

def undo_entry(entry: Entry) -> tuple:
    """Undo a single entry. Returns ``(ok, message)``."""
    kind = (entry.undo or {}).get("kind")
    if not kind:
        return False, "entry has no undo kind"
    handler = _UNDO_HANDLERS.get(kind)
    if handler is None:
        return False, f"no handler registered for '{kind}' (module not loaded)"
    try:
        ok, msg = handler(entry.undo)
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    if ok:
        mark_undone(entry.id)
    return ok, msg


def undo_by_id(entry_id: str) -> tuple:
    for e in load():
        if e.id == entry_id:
            if e.undone:
                return True, "already reverted"
            return undo_entry(e)
    return False, "entry not found"


def panic_restore(progress: Callable[[str, bool], None] | None = None,
                  modules: Optional[List[str]] = None) -> dict:
    """
    Revert every outstanding change, newest first.

    ``modules`` optionally limits the restore to specific modules. ``progress``
    is called as ``(message, ok)`` per entry so the GUI can stream results.

    Returns a summary dict. Note that failures do not stop the walk: one
    stubborn adapter must not block DNS and firewall from being restored.
    """
    entries = [e for e in pending() if not modules or e.module in modules]
    entries.sort(key=lambda e: e.ts, reverse=True)  # newest first

    done, failed, skipped = 0, 0, 0
    details: List[str] = []

    for e in entries:
        kind = (e.undo or {}).get("kind", "?")
        if not has_handler(kind):
            skipped += 1
            msg = f"SKIP  {e.module}: {e.action} (handler '{kind}' unavailable)"
            details.append(msg)
            if progress:
                progress(msg, False)
            continue
        ok, msg = undo_entry(e)
        line = f"{'OK  ' if ok else 'FAIL'}  {e.module}: {e.action}" + (f" — {msg}" if msg else "")
        details.append(line)
        if progress:
            progress(line, ok)
        if ok:
            done += 1
        else:
            failed += 1

    return {
        "attempted": len(entries),
        "restored": done,
        "failed": failed,
        "skipped": skipped,
        "details": details,
        "remaining": pending_count(),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Baseline snapshot
# ──────────────────────────────────────────────────────────────────────────────

def save_baseline(data: dict, overwrite: bool = False) -> bool:
    """
    Store a first-run snapshot of the machine's original settings.

    This is the safety net *behind* the journal: if a user deletes the journal,
    or a change was made outside PrivacyKit, the baseline still records what
    "factory" looked like. It is written once and never silently overwritten.
    """
    p = baseline_path()
    if p.exists() and not overwrite:
        return False
    payload = {"captured": time.time(), "data": data}
    tmp = p.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
    os.replace(tmp, p)
    return True


def load_baseline() -> Optional[dict]:
    p = baseline_path()
    if not p.exists():
        return None
    try:
        with open(p, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def has_baseline() -> bool:
    return baseline_path().exists()
