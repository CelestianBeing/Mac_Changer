"""
Background work.

Qt widgets may only be touched from the GUI thread. Everything in
:mod:`privacykit.core` blocks — shelling out to netsh, waiting on network round
trips, cycling an adapter — so every call from a page goes through here.

``Worker`` runs a callable on a thread pool and delivers the result back on the
GUI thread as a signal, which is the only safe way to close that loop.
"""

from __future__ import annotations

import traceback
from typing import Any, Callable, Optional

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot


class WorkerSignals(QObject):
    finished = Signal(object)
    failed = Signal(str)
    progress = Signal(str, bool)
    done = Signal()


class Worker(QRunnable):
    """
    Run ``fn(*args, **kwargs)`` off the GUI thread.

    A ``progress`` keyword is injected when the target accepts one, so core
    functions can stream status without knowing anything about Qt.
    """

    def __init__(self, fn: Callable, *args, pass_progress: bool = False, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()
        if pass_progress:
            self.kwargs["progress"] = self._emit_progress

    def _emit_progress(self, message: str, ok: bool = True) -> None:
        self.signals.progress.emit(str(message), bool(ok))

    @Slot()
    def run(self) -> None:
        try:
            result = self.fn(*self.args, **self.kwargs)
        except Exception as exc:
            traceback.print_exc()
            self.signals.failed.emit(f"{type(exc).__name__}: {exc}")
        else:
            self.signals.finished.emit(result)
        finally:
            self.signals.done.emit()


_pool: Optional[QThreadPool] = None


def pool() -> QThreadPool:
    global _pool
    if _pool is None:
        _pool = QThreadPool.globalInstance()
        # Several pages fire multiple probes at once; the default cap is fine
        # but a floor of 6 keeps a slow netsh call from queueing the others.
        _pool.setMaxThreadCount(max(6, _pool.maxThreadCount()))
    return _pool


def run(fn: Callable, on_result: Optional[Callable] = None,
        on_error: Optional[Callable] = None,
        on_progress: Optional[Callable] = None,
        pass_progress: bool = False, *args, **kwargs) -> Worker:
    """Convenience wrapper: build a Worker, wire it up, and start it."""
    worker = Worker(fn, *args, pass_progress=pass_progress, **kwargs)
    if on_result:
        worker.signals.finished.connect(on_result)
    if on_error:
        worker.signals.failed.connect(on_error)
    elif on_result:
        # Without an explicit error handler, surface the failure through the
        # normal result path rather than letting it vanish.
        worker.signals.failed.connect(lambda msg: on_result((False, msg)))
    if on_progress:
        worker.signals.progress.connect(on_progress)
    pool().start(worker)
    return worker
