from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Callable


def load_disjoin_occurrences(report_dir: Path, occurrences_file: Path) -> list:
    report_dir.mkdir(parents=True, exist_ok=True)
    if not occurrences_file.exists():
        return []
    try:
        data = json.loads(occurrences_file.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def save_disjoin_occurrences(
    occurrences: list,
    report_dir: Path,
    occurrences_file: Path,
    warn: Callable[[str], None],
) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    tmp = occurrences_file.with_suffix(".json.tmp")
    try:
        tmp.write_text(json.dumps(occurrences, indent=2), encoding="utf-8")
        tmp.replace(occurrences_file)
    except Exception as exc:
        warn(f"WARNING: Could not save disjoin occurrences: {exc}")
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass


def append_disjoin_occurrence(
    mac: str,
    ap_name: str | None,
    ip: str | None,
    report_dir: Path,
    occurrences_file: Path,
    lock: Lock,
    warn: Callable[[str], None],
) -> list:
    with lock:
        occurrences = load_disjoin_occurrences(report_dir, occurrences_file)
        occurrences.append({
            "ap_name": ap_name,
            "mac": mac,
            "ip": ip,
            "timestamp": time.time(),
            "event_time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "used": False,
        })
        save_disjoin_occurrences(occurrences, report_dir, occurrences_file, warn)
        return list(occurrences)

