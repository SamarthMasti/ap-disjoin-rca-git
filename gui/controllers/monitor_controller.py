from __future__ import annotations

import logging
import queue
from typing import Any

from PySide6.QtCore import QObject, QThread, Signal, Slot, QTimer

from backend.config import config_from_gui_dict
from backend.engine import MonitorEngine


class _GuiLogHandler(logging.Handler):
    def __init__(self, sink):
        super().__init__()
        self._sink = sink

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            self._sink({"type": "log_line", "line": msg})
        except Exception:
            pass


class _StdoutCapture:
    def __init__(self, sink):
        self._sink = sink
        self._buf = ""

    def write(self, text: str) -> None:
        self._buf += text
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            if line.strip():
                self._sink({"type": "log_line", "line": line})

    def flush(self) -> None:
        if self._buf.strip():
            self._sink({"type": "log_line", "line": self._buf})
            self._buf = ""

    def fileno(self) -> int:
        import sys as _sys
        if _sys.__stdout__ is not None:
            return _sys.__stdout__.fileno()
        return -1


class MonitorWorker(QObject):
    event = Signal(dict)
    failed = Signal(str)
    finished = Signal(dict)

    def __init__(self, config: dict[str, Any]):
        super().__init__()
        self._config = config
        self._engine: MonitorEngine | None = None
        self._last_engine_failure: dict[str, Any] | None = None
        self._event_queue: queue.Queue = queue.Queue()

    def _emit_event(self, event: dict[str, Any]) -> None:
        """
        Thread-safe event enqueue.
        Called from ANY thread.
        """
        
        if event.get("type") == "engine_failed":
            self._last_engine_failure = event

        self._event_queue.put(event)

    @Slot()
    def _drain_queue(self) -> None:
        """
        Drain queued events on the worker's Qt thread.
        """
        try:
            while True:
                ev = self._event_queue.get_nowait()
                self.event.emit(ev)
        except queue.Empty:
            pass

    @Slot()
    def run(self) -> None:
        import sys

        # IMPORTANT:
        # Timer MUST be created after moveToThread(),
        # otherwise Qt timer warnings/crashes happen.
        

        _orig_stdout = sys.stdout
        _orig_stderr = sys.stderr

        try:
            runtime_config = config_from_gui_dict(
                self._config,
                event_sink=self._emit_event,
            )
            # Tell the controller which run dir was resolved
            self._emit_event({
                "type": "run_dir_resolved",
                "run_dir": runtime_config.report_dir,
            })

            self._engine = MonitorEngine()

            result = self._engine.start(runtime_config)

            self.finished.emit(result.as_dict())

        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"

            if (
                self._last_engine_failure
                and self._last_engine_failure.get("session_log")
            ):
                message = (
                    f"{message} | session log: "
                    f"{self._last_engine_failure['session_log']}"
                )

            self.failed.emit(message)

        finally:
            sys.stdout = _orig_stdout
            sys.stderr = _orig_stderr

            


class MonitorController(QObject):
    event = Signal(dict)
    failed = Signal(str)
    finished = Signal(dict)
    started = Signal()
    stats_updated = Signal(dict)   # carries {"events": int, "aps": int}

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._drain_timer = QTimer(self)
        self._drain_timer.setInterval(50)
        self._drain_timer.timeout.connect(self._drain_worker_queue)
        self._stats_timer = QTimer(self)
        self._stats_timer.setInterval(2000)
        self._stats_timer.timeout.connect(self._poll_stats)
        self._report_dir: str = "reports"
        self._thread: QThread | None = None
        self._worker: MonitorWorker | None = None
        self._log_handler: _GuiLogHandler | None = None

    def start(self, config: dict[str, Any]) -> None:
        if self._thread is not None and self._thread.isRunning():
            raise RuntimeError("Monitor workflow is already running")

        self._thread = QThread(self)

        self._worker = MonitorWorker(config)

        self._worker.moveToThread(self._thread)

        # Thread lifecycle
        self._thread.started.connect(self._worker.run)

        # Event forwarding
        self._worker.event.connect(self.event.emit)
        self._worker.failed.connect(self.failed.emit)
        self._worker.finished.connect(self.finished.emit)

        # Shutdown handling
        self._worker.failed.connect(self._thread.quit)
        self._worker.finished.connect(self._thread.quit)

        self._thread.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.finished.connect(self._on_thread_finished)

        # Logging bridge
        self._log_handler = _GuiLogHandler(self._worker._emit_event)

        self._log_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%SZ",
            )
        )

        logging.getLogger().addHandler(self._log_handler)

        self._thread.start()
        self._drain_timer.start()
        # report_dir in config is still the base dir from the form.
        # The worker resolves the actual run dir inside config_from_gui_dict.
        # We read it back from the worker once it has built the runtime config.
        # Until then, fall back to base dir (stats won't show until first poll anyway).
        self._report_dir = config.get("report_dir", "reports")
        self._stats_timer.start()
        self.started.emit()

    def stop(self) -> None:
        if self._thread is None:
            return

        if not self._thread.isRunning():
            return

        if (
            self._worker is not None
            and self._worker._engine is not None
        ):
            try:
                self._worker._engine._stop_requested = True
                live_monitor = None
                if hasattr(self._worker._engine, '_live_monitor'):
                    live_monitor = self._worker._engine._live_monitor
                if live_monitor is not None:
                    # Set stop event so the listen() loop exits cleanly
                    live_monitor.stop_event.set()
                    # Force-kill the gRPC server immediately — don't wait
                    # for the loop to notice stop_event (may be blocked in SSH)
                    grpc_server = getattr(live_monitor, '_grpc_server', None)
                    if grpc_server is not None:
                        try:
                            grpc_server.stop(0)   # grace=0 = immediate kill
                        except Exception:
                            pass
            except Exception:
                pass

        self._thread.quit()
        self._thread.wait(5000)

    @Slot()
    def _on_thread_finished(self) -> None:
        self._drain_timer.stop()
        self._stats_timer.stop()
        self._poll_stats()   # final read
        if self._worker is not None:
            self._drain_worker_queue()
        if self._log_handler is not None:
            logging.getLogger().removeHandler(self._log_handler)
            self._log_handler = None

        self._thread = None
        self._worker = None
    @Slot()
    def _drain_worker_queue(self) -> None:
        if self._worker is None:
            return
        try:
            while True:
                ev = self._worker._event_queue.get_nowait()
                if ev.get("type") == "run_dir_resolved":
                    self._report_dir = ev["run_dir"]
                self.event.emit(ev)
        except Exception:
            pass
    @Slot()
    def _poll_stats(self) -> None:
        import json
        from pathlib import Path
        try:
            f = Path(self._report_dir) / "disjoin_event_history.json"
            events = 0
            if f.exists():
                data = json.loads(f.read_text(encoding="utf-8"))
                events = data.get("completed_count", 0)
        except Exception:
            events = 0
        try:
            f2 = Path(self._report_dir) / "finalized_aps_history.json"
            aps = 0
            if f2.exists():
                data2 = json.loads(f2.read_text(encoding="utf-8"))
                aps = len(data2) if isinstance(data2, list) else 0
        except Exception:
            aps = 0
        self.stats_updated.emit({"events": events, "aps": aps})