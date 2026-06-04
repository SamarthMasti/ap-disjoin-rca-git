from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Callable


DEFAULT_EVENT_HISTORY = {"completed_count": 0, "events": []}


def load_disjoin_event_history(report_dir: Path, event_history_file: Path) -> dict:
    report_dir.mkdir(parents=True, exist_ok=True)
    if not event_history_file.exists():
        return dict(DEFAULT_EVENT_HISTORY)
    try:
        data = json.loads(event_history_file.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return dict(DEFAULT_EVENT_HISTORY)
        return data
    except Exception:
        return dict(DEFAULT_EVENT_HISTORY)


def save_disjoin_event_history(
    data: dict,
    report_dir: Path,
    event_history_file: Path,
    warn: Callable[[str], None],
) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    tmp = event_history_file.with_suffix(".json.tmp")
    try:
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(event_history_file)
    except Exception as exc:
        warn(f"WARNING: Could not save disjoin event history: {exc}")
        tmp.unlink(missing_ok=True)


def append_disjoin_event_history(
    event: dict,
    report_dir: Path,
    event_history_file: Path,
    lock: Lock,
    warn: Callable[[str], None],
) -> int:
    with lock:
        data = load_disjoin_event_history(report_dir, event_history_file)
        data["completed_count"] = data.get("completed_count", 0) + 1
        event["event_id"] = data["completed_count"]
        data.setdefault("events", []).append(event)
        save_disjoin_event_history(data, report_dir, event_history_file, warn)
    return data["completed_count"]

