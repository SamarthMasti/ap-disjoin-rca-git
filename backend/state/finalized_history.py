from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Callable


def load_finalized_aps_history(report_dir: Path, finalized_aps_file: Path) -> list:
    report_dir.mkdir(parents=True, exist_ok=True)
    if not finalized_aps_file.exists():
        return []
    try:
        data = json.loads(finalized_aps_file.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def save_finalized_aps_history(
    data: list,
    report_dir: Path,
    finalized_aps_file: Path,
    warn: Callable[[str], None],
) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    tmp = finalized_aps_file.with_suffix(".json.tmp")
    try:
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(finalized_aps_file)
    except Exception as exc:
        warn(f"WARNING: Could not save finalized AP history: {exc}")


def append_finalized_ap(
    mac: str,
    ap_name: str | None,
    ip: str | None,
    report_dir: Path,
    finalized_aps_file: Path,
    lock: Lock,
    now: Callable[[], str],
    warn: Callable[[str], None],
) -> None:
    with lock:
        history = load_finalized_aps_history(report_dir, finalized_aps_file)
        history.append({
            "finalized_time": now(),
            "ap_name": ap_name,
            "mac": mac,
            "ip": ip,
        })
        save_finalized_aps_history(history, report_dir, finalized_aps_file, warn)

