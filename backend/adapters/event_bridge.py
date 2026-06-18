# backend/adapters/event_bridge.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


BackendEventSink = Callable[[dict[str, Any]], None]


@dataclass(slots=True)
class BackendEventBridge:
    """Frontend-neutral event bridge for live backend updates."""

    sink: BackendEventSink | None = None

    def emit(self, event_type: str, **payload: Any) -> None:
        if self.sink is None:
            return
        self.sink({"type": event_type, **payload})

    def workflow_started(self, **payload: Any) -> None:
        self.emit("workflow_started", **payload)

    def event_detected(self, **payload: Any) -> None:
        self.emit("event_detected", **payload)

    def telemetry_received(self, **payload: Any) -> None:
        self.emit("telemetry_received", **payload)

    def workflow_finalized(self, **payload: Any) -> None:
        self.emit("workflow_finalized", **payload)

    def report_generated(self, **payload: Any) -> None:
        self.emit("report_generated", **payload)

    # ── Added: engine lifecycle events ───────────────────────────────────
    def engine_started(self, **payload: Any) -> None:
        self.emit("engine_started", **payload)

    def engine_completed(self, **payload: Any) -> None:
        self.emit("engine_completed", **payload)
