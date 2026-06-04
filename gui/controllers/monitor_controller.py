from __future__ import annotations

from typing import Any

from PySide6.QtCore import QObject, QThread, Signal, Slot

from backend.config import config_from_gui_dict
from backend.engine import MonitorEngine


class MonitorWorker(QObject):
    event = Signal(dict)
    failed = Signal(str)
    finished = Signal(dict)

    def __init__(self, config: dict[str, Any]):
        super().__init__()
        self._config = config

    @Slot()
    def run(self) -> None:
        try:
            runtime_config = config_from_gui_dict(self._config, event_sink=self.event.emit)
            result = MonitorEngine().start(runtime_config)
            self.finished.emit(result.as_dict())
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class MonitorController(QObject):
    event = Signal(dict)
    failed = Signal(str)
    finished = Signal(dict)
    started = Signal()

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._thread: QThread | None = None
        self._worker: MonitorWorker | None = None

    def start(self, config: dict[str, Any]) -> None:
        if self._thread is not None and self._thread.isRunning():
            raise RuntimeError("Monitor workflow is already running")

        self._thread = QThread(self)
        self._worker = MonitorWorker(config)
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.event.connect(self.event.emit)
        self._worker.failed.connect(self.failed.emit)
        self._worker.finished.connect(self.finished.emit)
        self._worker.failed.connect(self._thread.quit)
        self._worker.finished.connect(self._thread.quit)
        self._thread.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._on_thread_finished)

        self._thread.start()
        self.started.emit()

    @Slot()
    def _on_thread_finished(self) -> None:
        self._thread = None
        self._worker = None

